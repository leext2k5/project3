"""Sensor giám sát: bắt gói, ghép luồng TCP, giải mã Modbus, ghép request-response,
và gửi event về backend một cách tin cậy.

Chế độ:
  - Live:    python sensor.py                (sniff interface, mặc định br-ics)
  - Offline: python sensor.py <file.pcap>     (đọc lại pcap để kiểm thử)

Khắc phục so với bản đầu:
  (1) Ghép lại luồng TCP theo sequence number: ADU bị chia nhiều segment được gộp
      đủ rồi mới giải mã; gói truyền lại (retransmission) bị loại, không sinh event trùng.
  (2) Giải mã đầy đủ FC15/16 (giữ giá trị ghi), FC5 chặt (giá trị lạ -> invalid),
      cắt bit đệm theo quantity của request, giữ raw ADU + parse_error khi lỗi.
  (4) Giữ nguyên độ phân giải timestamp capture (không làm tròn).
  (5) Gửi theo lô có retry/backoff, chỉ xóa khỏi hàng đợi khi backend xác nhận;
      mỗi event có event_id ổn định để backend chống trùng; flush nốt khi dừng.
  (9) Phát sinh event TCP (SYN) phục vụ phát hiện quét cổng, tách khỏi event Modbus.
"""

import json
import logging
import os
import sys
import threading
import time
import uuid
from collections import deque

import urllib.request

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Ether, Raw, sniff  # noqa: E402

IFACE = os.getenv("SENSOR_IFACE", "br-ics")
MODBUS_PORT = 502
BACKEND_URL = os.getenv("BACKEND_URL")
FLUSH_INTERVAL = 0.5          # giây giữa hai lần gửi lô
MAX_QUEUE = 20000             # giới hạn hàng đợi event (chống phình bộ nhớ)
FLOW_TIMEOUT = 30.0           # giây: dọn flow TCP không hoạt động
MAX_FLOW_BYTES = 64 * 1024    # giới hạn buffer mỗi flow

FC_NAMES = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
}
EXC_NAMES = {
    1: "ILLEGAL FUNCTION", 2: "ILLEGAL DATA ADDRESS", 3: "ILLEGAL DATA VALUE",
    4: "SERVER DEVICE FAILURE", 5: "ACKNOWLEDGE", 6: "SERVER DEVICE BUSY",
}
WRITE_FCS = {5, 6, 15, 16}

_stop = threading.Event()


def u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


def need(pdu: bytes, n: int) -> None:
    if len(pdu) < n:
        raise ValueError(f"PDU ngắn: cần {n} byte, có {len(pdu)}")


def bits_from_bytes(data: bytes) -> list[int]:
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(len(data) * 8)]


def parse_pdu(pdu: bytes, is_response: bool) -> dict:
    """Giải mã PDU. Ném ValueError nếu độ dài không hợp lệ (gói malformed)."""
    need(pdu, 1)
    fc = pdu[0]
    if fc & 0x80:  # gói lỗi
        exc = pdu[1] if len(pdu) > 1 else None
        return {"function_code": fc & 0x7F, "is_exception": True,
                "exception_code": exc, "exception_name": EXC_NAMES.get(exc, "UNKNOWN")}

    out = {"function_code": fc, "is_exception": False, "is_write": fc in WRITE_FCS}
    if not is_response:  # ----- REQUEST -----
        if fc in (1, 2, 3, 4):
            need(pdu, 5); out["address"] = u16(pdu, 1); out["count"] = u16(pdu, 3)
        elif fc == 5:
            need(pdu, 5); out["address"] = u16(pdu, 1); raw = u16(pdu, 3)
            if raw == 0xFF00:
                out["value"] = 1
            elif raw == 0x0000:
                out["value"] = 0
            else:  # giá trị lạ: ghi nhận là không hợp lệ, KHÔNG coi là lệnh tắt
                out["value"] = raw; out["invalid"] = True
        elif fc == 6:
            need(pdu, 5); out["address"] = u16(pdu, 1); out["value"] = u16(pdu, 3)
        elif fc == 15:  # ghi nhiều coil: giữ các bit được ghi
            need(pdu, 6); out["address"] = u16(pdu, 1); out["count"] = u16(pdu, 3)
            bc = pdu[5]; need(pdu, 6 + bc)
            out["values"] = bits_from_bytes(pdu[6:6 + bc])[:out["count"]]
        elif fc == 16:  # ghi nhiều register: giữ các giá trị được ghi
            need(pdu, 6); out["address"] = u16(pdu, 1); out["count"] = u16(pdu, 3)
            bc = pdu[5]; need(pdu, 6 + bc)
            out["values"] = [u16(pdu, 6 + 2 * i) for i in range(bc // 2)]
    else:               # ----- RESPONSE -----
        if fc in (1, 2):
            need(pdu, 2); bc = pdu[1]; need(pdu, 2 + bc)
            out["values"] = bits_from_bytes(pdu[2:2 + bc])  # cắt theo quantity khi ghép được request
        elif fc in (3, 4):
            need(pdu, 2); bc = pdu[1]; need(pdu, 2 + bc)
            out["values"] = [u16(pdu, 2 + 2 * i) for i in range(bc // 2)]
        elif fc == 5:
            need(pdu, 5); out["address"] = u16(pdu, 1); raw = u16(pdu, 3)
            out["value"] = 1 if raw == 0xFF00 else (0 if raw == 0x0000 else raw)
            if raw not in (0x0000, 0xFF00):
                out["invalid"] = True
        elif fc == 6:
            need(pdu, 5); out["address"] = u16(pdu, 1); out["value"] = u16(pdu, 3)
        elif fc in (15, 16):
            need(pdu, 5); out["address"] = u16(pdu, 1); out["count"] = u16(pdu, 3)
    return out


# --------------------------- Ghép luồng TCP ---------------------------------
class Flow:
    """Một phiên TCP hai chiều. Mỗi chiều có stream byte + seq riêng (seq theo
    từng chiều); bảng pending dùng chung để ghép request với response."""
    __slots__ = ("streams", "pending", "last")

    def __init__(self):
        self.streams: dict = {}      # (src_ip, src_port) -> [buf: bytes, next_seq: int]
        self.pending: dict = {}      # (unit, tid) -> request đang chờ response
        self.last = time.time()


flows: dict = {}
flows_lock = threading.Lock()


def reassemble(ip, tcp, payload: bytes, now: float, pkt) -> list[dict]:
    """Gộp payload vào đúng chiều của phiên theo seq, loại truyền lại, trả event."""
    # Khóa phiên không phụ thuộc chiều: request và response chung một Flow.
    ckey = tuple(sorted(((ip.src, int(tcp.sport)), (ip.dst, int(tcp.dport)))))
    dkey = (ip.src, int(tcp.sport))          # chiều hiện tại
    seq = int(tcp.seq)
    with flows_lock:
        fl = flows.get(ckey) or flows.setdefault(ckey, Flow())
        fl.last = now
        st = fl.streams.get(dkey)
        if st is None:
            st = fl.streams[dkey] = [b"", seq]
        buf, nxt = st
        end = seq + len(payload)
        if end <= nxt:
            return []                        # đã nhận hết (truyền lại) -> bỏ
        if seq > nxt:                        # khoảng trống / đến khác thứ tự
            buf, nxt = b"", seq              # giữ an toàn: resync tới seq hiện tại
        elif seq < nxt:                      # chồng lấn một phần -> cắt phần đã có
            payload = payload[nxt - seq:]
            seq = nxt
        buf += payload
        nxt = seq + len(payload)
        if len(buf) > MAX_FLOW_BYTES:        # chống phình bộ nhớ
            st[0], st[1] = b"", nxt
            return []
        events, buf = parse_stream(fl, buf, ip, tcp, now, pkt)
        st[0], st[1] = buf, nxt
        return events


def parse_stream(fl: Flow, buf: bytes, ip, tcp, now: float, pkt):
    """Tách các ADU hoàn chỉnh khỏi buffer; chỉ giải mã khi đủ theo MBAP Length."""
    out, off = [], 0
    is_response = int(tcp.sport) == MODBUS_PORT
    while len(buf) - off >= 8:
        if u16(buf, off + 2) != 0:           # Protocol ID phải = 0
            off = len(buf); break
        length = u16(buf, off + 4)
        if length < 2:
            off = len(buf); break
        adu_end = off + 6 + length
        if adu_end > len(buf):
            break                            # chưa đủ -> chờ segment sau
        out.append(build_event(ip, tcp, now, pkt, u16(buf, off),
                               buf[off + 6], buf[off + 7:adu_end], is_response, fl))
        off = adu_end
    return out, buf[off:]


def build_event(ip, tcp, now, pkt, tid, unit, pdu, is_response, fl) -> dict:
    ev = {
        "event_id": str(uuid.uuid4()), "kind": "modbus", "ts": now,
        "src_ip": ip.src, "dst_ip": ip.dst,
        "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
        "src_port": int(tcp.sport), "dst_port": int(tcp.dport),
        "transaction_id": tid, "unit_id": unit,
        "direction": "response" if is_response else "request",
        "raw": pdu.hex(),                    # giữ ADU thô làm bằng chứng
    }
    try:
        ev.update(parse_pdu(pdu, is_response))
    except ValueError as exc:
        ev["parse_error"] = True
        ev["parse_reason"] = str(exc)
        ev["function_code"] = pdu[0] if pdu else None

    # Ghép request-response trong cùng phiên theo (unit, transaction_id).
    pkey = (unit, tid)
    if not is_response:
        fl.pending[pkey] = {"address": ev.get("address"), "count": ev.get("count"),
                            "fc": ev.get("function_code"), "ts": now}
    else:
        req = fl.pending.pop(pkey, None)
        ev["matched"] = req is not None
        if req:
            ev["req_address"], ev["req_count"] = req["address"], req["count"]
            ev["rtt_ms"] = (now - req["ts"]) * 1000.0
            # Cắt bit đệm của response coil/discrete input theo quantity của request.
            if ev.get("function_code") in (1, 2) and ev.get("values") and req["count"]:
                ev["values"] = ev["values"][:req["count"]]
    ev["fc_name"] = FC_NAMES.get(ev.get("function_code"), f"FC{ev.get('function_code')}")
    return ev


def prune_flows(now: float) -> None:
    with flows_lock:
        for k in [k for k, fl in flows.items() if now - fl.last > FLOW_TIMEOUT]:
            del flows[k]


# --------------------------- Gửi event tin cậy ------------------------------
_queue: deque = deque()
_qlock = threading.Lock()
_dropped = 0


def emit(ev: dict) -> None:
    global _dropped
    if not BACKEND_URL:
        print(json.dumps(ev), flush=True)
        return
    with _qlock:
        if len(_queue) >= MAX_QUEUE:          # quá tải: bỏ event cũ nhất + đếm
            _queue.popleft(); _dropped += 1
        _queue.append(ev)


def _post(batch: list[dict]) -> None:
    req = urllib.request.Request(BACKEND_URL, data=json.dumps(batch).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        r.read()


def flush_once() -> bool:
    """Gửi lô hiện có; chỉ xóa khỏi hàng đợi khi backend xác nhận thành công."""
    with _qlock:
        batch = list(_queue)
    if not batch:
        return True
    try:
        _post(batch)
    except Exception as exc:  # noqa: BLE001
        print(f"[sensor] gửi backend lỗi, giữ lại {len(batch)} event: {exc}",
              file=sys.stderr, flush=True)
        return False
    with _qlock:                              # xóa đúng số đã gửi khỏi đầu hàng đợi
        for _ in range(min(len(batch), len(_queue))):
            _queue.popleft()
    return True


def flush_loop() -> None:
    backoff = FLUSH_INTERVAL
    while not _stop.is_set():
        ok = flush_once()
        prune_flows(time.time())
        backoff = FLUSH_INTERVAL if ok else min(backoff * 2, 10.0)
        _stop.wait(backoff)


def drain(timeout: float = 15.0) -> None:
    """Flush nốt các event còn chờ (dùng khi dừng hoặc kết thúc đọc offline)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with _qlock:
            empty = not _queue
        if empty or flush_once():
            with _qlock:
                if not _queue:
                    return
        time.sleep(0.2)


# --------------------------- Bắt gói ----------------------------------------
def handle(pkt) -> None:
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    tcp, ip, now = pkt[TCP], pkt[IP], float(pkt.time)
    flags = int(tcp.flags)
    # (9) SYN không kèm ACK = một lần thử kết nối -> event TCP cho luật quét cổng.
    if (flags & 0x02) and not (flags & 0x10):
        emit({"event_id": str(uuid.uuid4()), "kind": "tcp", "ts": now,
              "src_ip": ip.src, "dst_ip": ip.dst,
              "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
              "src_port": int(tcp.sport), "dst_port": int(tcp.dport), "flags": str(tcp.flags)})
    # Chỉ ghép/giải mã Modbus với lưu lượng cổng 502 có payload.
    if tcp.sport != MODBUS_PORT and tcp.dport != MODBUS_PORT:
        return
    if not pkt.haslayer(Raw):
        return
    for ev in reassemble(ip, tcp, bytes(pkt[Raw].load), now, pkt):
        emit(ev)


def main() -> None:
    offline = len(sys.argv) > 1
    if BACKEND_URL:
        threading.Thread(target=flush_loop, daemon=True).start()
    try:
        if offline:
            print(f"sensor đọc offline: {sys.argv[1]}", file=sys.stderr, flush=True)
            sniff(offline=sys.argv[1], prn=handle, store=False)
        else:
            dest = BACKEND_URL or "stdout"
            print(f"sensor sniffing {IFACE} -> {dest}", file=sys.stderr, flush=True)
            # Bắt lưu lượng Modbus (cổng 502) VÀ mọi gói SYN (phục vụ phát hiện quét cổng).
            sniff(iface=IFACE, filter="tcp port 502 or (tcp[tcpflags] & tcp-syn != 0)",
                  prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        _stop.set()
        if BACKEND_URL:
            drain()


if __name__ == "__main__":
    main()
