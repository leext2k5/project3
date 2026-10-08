"""Detection Engine: học baseline hành vi bình thường và áp các luật phát hiện.

Hai chế độ: Học (chưa freeze, tích lũy baseline, không cảnh báo) và Phát hiện
(đã freeze, so với baseline). Mỗi cảnh báo được chống trùng theo (luật, nguồn).

Sửa theo review:
  (8) Quyền ghi xét theo chữ ký (nguồn, PLC đích, Unit ID, function code, địa chỉ),
      không chỉ theo IP nguồn. Baseline là bản riêng được chốt, không phải bảng assets.
  (9) Luật quét cổng dùng event TCP (SYN): một nguồn chạm nhiều cổng đích trong
      thời gian ngắn.
"""

import time
from collections import defaultdict, deque


class Detector:
    def __init__(self, rate_threshold: int = 30, cooldown: float = 20.0,
                 scan_window: float = 5.0, scan_threshold: int = 10):
        self.frozen = False
        self.devices: set[str] = set()
        self.connections: set[tuple] = set()
        self.writers: set[str] = set()                 # IP từng ghi hợp lệ (tham khảo)
        self.write_rules: set[tuple] = set()            # (src, dst, unit, fc, address) hợp lệ
        self.rate_threshold = rate_threshold
        self.cooldown = cooldown
        self.scan_window = scan_window
        self.scan_threshold = scan_threshold
        self._rate: dict[str, deque] = defaultdict(deque)
        self._scan: dict[str, deque] = defaultdict(deque)
        self._last_alert: dict[tuple, float] = {}

    # ----- baseline -----
    def learn(self, events: list[dict]) -> None:
        for ev in events:
            src, dst = ev.get("src_ip"), ev.get("dst_ip")
            if src:
                self.devices.add(src)
            if dst:
                self.devices.add(dst)
            if ev.get("direction") == "request" and src and dst:
                self.connections.add((src, dst, ev.get("dst_port")))
                if ev.get("is_write"):
                    self.writers.add(src)
                    self.write_rules.add((src, dst, ev.get("unit_id"),
                                          ev.get("function_code"), ev.get("address")))

    def freeze(self) -> None:
        self.frozen = True

    def export(self) -> dict:
        return {
            "frozen": self.frozen,
            "devices": sorted(self.devices),
            "connections": [list(c) for c in self.connections],
            "writers": sorted(self.writers),
            "write_rules": [list(r) for r in self.write_rules],
        }

    def load(self, data: dict) -> None:
        self.frozen = data.get("frozen", False)
        self.devices = set(data.get("devices", []))
        self.connections = {tuple(c) for c in data.get("connections", [])}
        self.writers = set(data.get("writers", []))
        self.write_rules = {tuple(r) for r in data.get("write_rules", [])}

    # ----- phát hiện -----
    def _emit(self, out, rule, severity, src, dst, desc, ev):
        key = (rule, src)
        now = time.time()
        if now - self._last_alert.get(key, 0) < self.cooldown:
            return
        self._last_alert[key] = now
        # ts = thời điểm capture gói gây cảnh báo; detected_at = thời điểm sinh cảnh báo.
        out.append({"ts": ev.get("ts"), "detected_at": now, "severity": severity,
                    "rule": rule, "src_ip": src, "dst_ip": dst,
                    "description": desc, "evidence": [ev]})

    def check(self, events: list[dict]) -> list[dict]:
        """Áp các luật trên event Modbus."""
        if not self.frozen:
            return []
        alerts: list[dict] = []
        for ev in events:
            if ev.get("direction") == "request":
                src, dst, dport = ev.get("src_ip"), ev.get("dst_ip"), ev.get("dst_port")

                ts = ev.get("ts", time.time())        # DoS: request/giây theo nguồn
                dq = self._rate[src]
                dq.append(ts)
                while dq and ts - dq[0] > 1.0:
                    dq.popleft()
                if len(dq) > self.rate_threshold:
                    self._emit(alerts, "dos", "High", src, dst,
                               f"Vượt ngưỡng tần suất: hơn {self.rate_threshold} request "
                               f"trong 1 giây từ {src}", ev)

                if src not in self.devices:           # thiết bị lạ
                    self._emit(alerts, "unknown_device", "High", src, dst,
                               f"Thiết bị lạ {src} truy cập {dst}", ev)

                if (src, dst, dport) not in self.connections:   # kết nối mới
                    self._emit(alerts, "new_connection", "Low", src, dst,
                               f"Kết nối mới {src} → {dst}:{dport}", ev)

                if ev.get("is_write"):                 # ghi trái phép (theo chữ ký)
                    sig = (src, dst, ev.get("unit_id"), ev.get("function_code"), ev.get("address"))
                    if sig not in self.write_rules:
                        self._emit(alerts, "unauthorized_write", "Critical", src, dst,
                                   f"Ghi trái phép ({ev.get('fc_name')}) vào {dst} "
                                   f"địa chỉ {ev.get('address')} từ {src}", ev)

            if ev.get("is_exception"):                 # truy cập thanh ghi bất thường
                offender = ev.get("dst_ip")
                self._emit(alerts, "abnormal_register", "Medium", offender, ev.get("src_ip"),
                           f"Truy cập thanh ghi bất thường (exception code "
                           f"{ev.get('exception_code')}) từ {offender}", ev)
        return alerts

    def check_tcp(self, tcp_events: list[dict]) -> list[dict]:
        """Luật quét cổng: một nguồn chạm nhiều cổng đích khác nhau trong cửa sổ ngắn."""
        if not self.frozen:
            return []
        alerts: list[dict] = []
        for ev in tcp_events:
            src, ts = ev.get("src_ip"), ev.get("ts", time.time())
            dq = self._scan[src]
            dq.append((ts, ev.get("dst_port")))
            while dq and ts - dq[0][0] > self.scan_window:
                dq.popleft()
            distinct = len({p for _, p in dq})
            if distinct > self.scan_threshold:
                self._emit(alerts, "port_scan", "Medium", src, ev.get("dst_ip"),
                           f"Quét cổng: {distinct} cổng khác nhau từ {src} "
                           f"trong {self.scan_window:.0f}s", ev)
        return alerts
