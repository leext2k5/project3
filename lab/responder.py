"""Responder (executor ứng phó): thực thi biện pháp ĐÃ ĐƯỢC DUYỆT bằng iptables.

Chạy ở chế độ mạng host + NET_ADMIN để tác động lên bridge br-ics — nơi thực sự
xử lý traffic ICS. Chỉ thực thi hành động ở trạng thái 'approved'/'undo_requested'
(tức đã qua bước operator duyệt), rồi báo kết quả về backend để ghi audit.
"""

import json
import os
import subprocess
import time
import urllib.request

BACKEND = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
POLL = 2.0
CHAIN = "DOCKER-USER"   # chuỗi iptables tác động lên forward qua bridge Docker


def http(method: str, path: str, data=None):
    req = urllib.request.Request(
        BACKEND + path, method=method,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read() or "null")


def rule_exists(ip: str) -> bool:
    return subprocess.run(["iptables", "-C", CHAIN, "-s", ip, "-j", "DROP"],
                          capture_output=True).returncode == 0


def block(ip: str) -> None:
    if not rule_exists(ip):   # idempotent
        subprocess.run(["iptables", "-I", CHAIN, "-s", ip, "-j", "DROP"],
                       check=True, capture_output=True, text=True)


def unblock(ip: str) -> None:
    while rule_exists(ip):     # gỡ hết các bản sao của luật
        subprocess.run(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"],
                       check=True, capture_output=True, text=True)


def report(rid: int, status: str, msg: str = "") -> None:
    http("POST", f"/api/responses/{rid}/result", {"status": status, "result": msg})


def main() -> None:
    print(f"responder sẵn sàng, poll {BACKEND}", flush=True)
    while True:
        try:
            actions = http("GET", "/api/responses?limit=50") or []
        except Exception:
            time.sleep(POLL)
            continue
        for a in actions:
            rid, ip = a["id"], a.get("src_ip")
            try:
                if a["status"] == "approved":
                    if a["action"] == "block_ip" and ip:
                        block(ip)
                        report(rid, "executed", f"đã chặn {ip} (iptables DROP trên {CHAIN})")
                        print(f"CHẶN {ip}", flush=True)
                    else:   # 'monitor' hoặc loại khác: chỉ ghi nhận, không chặn
                        report(rid, "executed", "theo dõi, không chặn")
                elif a["status"] == "undo_requested":
                    if a["action"] == "block_ip" and ip:
                        unblock(ip)
                    report(rid, "undone", f"đã gỡ chặn {ip}")
                    print(f"GỠ CHẶN {ip}", flush=True)
            except subprocess.CalledProcessError as exc:
                report(rid, "failed", (exc.stderr or str(exc))[:200])
            except Exception as exc:  # noqa: BLE001
                report(rid, "failed", str(exc)[:200])
        time.sleep(POLL)


if __name__ == "__main__":
    main()
