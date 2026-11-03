#!/usr/bin/env python3
"""
Đối chiếu audit log của WAF với log của Flask (kiểm thử #10).

Câu hỏi cần trả lời: request bị WAF chặn có thật sự KHÔNG tới được ứng dụng không?
Với mỗi sự kiện có luật khớp trong audit log, script tìm request tương ứng trong
access log của Gunicorn (cùng method, cùng URI thô, gần cùng thời điểm):
  - bị chặn (403)   -> mong đợi KHÔNG có trong log Flask
  - không bị chặn   -> mong đợi CÓ trong log Flask (nhóm đối chứng: chứng minh
                       phép đối chiếu hoạt động, không phải "không thấy" vì tìm sai)

    python3 scripts/verify_blocking.py                 # mọi sự kiện có luật khớp
    python3 scripts/verify_blocking.py --since 30m     # chỉ 30 phút gần nhất
    python3 scripts/verify_blocking.py --markdown      # in bảng để dán vào báo cáo

Chỉ dùng thư viện chuẩn. Log Flask lấy bằng `docker logs` của container web.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote_plus

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parse_audit import DEFAULT_LOG, read_events  # noqa: E402

DOCKER_BIN = "/Applications/Docker.app/Contents/Resources/bin"
WEB_CONTAINER = "waf-lab-web"
# Dòng access log của Gunicorn (định dạng mặc định) có timestamp của Docker ở đầu:
# 2026-11-03T09:35:29.126907584Z 172.20.0.3 - - [03/Nov/2026:09:35:29 +0000] "GET /x?y=1 HTTP/1.1" 200 34 ...
ACCESS_RE = re.compile(r'^(\S+Z) \S+ \S+ \S+ \[[^\]]+\] "(\S+) (\S+) HTTP/[\d.]+" (\d{3})')
# Request tới backend sau thời điểm WAF ghi nhận một chút (thời gian xử lý của WAF + Flask)
WINDOW_BEFORE, WINDOW_AFTER = timedelta(seconds=2), timedelta(seconds=10)


def parse_since(raw: str | None) -> datetime | None:
    if not raw:
        return None
    m = re.fullmatch(r"(\d+)([mhd])", raw)
    if m:
        unit = {"m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
        return datetime.now(timezone.utc) - timedelta(**{unit: int(m.group(1))})
    dt = datetime.fromisoformat(raw)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def docker_time(raw: str) -> datetime:
    # Docker in tới nano giây; datetime chỉ nhận tới micro giây
    base, _, frac = raw.rstrip("Z").partition(".")
    return datetime.fromisoformat(f"{base}.{frac[:6] or '0'}").replace(tzinfo=timezone.utc)


def flask_requests(since: datetime | None) -> list[tuple[datetime, str, str, int]]:
    cmd = ["docker", "logs", "--timestamps", WEB_CONTAINER]
    if since:
        cmd[2:2] = ["--since", (since - WINDOW_AFTER).strftime("%Y-%m-%dT%H:%M:%SZ")]
    env = {**os.environ, "PATH": f"{os.environ.get('PATH', '')}:{DOCKER_BIN}"}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=True, env=env)
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Không đọc được log của {WEB_CONTAINER}: {exc}")
    rows = []
    for line in (out.stdout + out.stderr).splitlines():
        m = ACCESS_RE.match(line)
        if m:
            rows.append((docker_time(m.group(1)), m.group(2), m.group(3), int(m.group(4))))
    return rows


def reached_backend(event: dict, flask: list) -> bool:
    t = datetime.fromisoformat(event["time"])
    return any(
        method == event["method"] and uri == event["uri"]
        and t - WINDOW_BEFORE <= ft <= t + WINDOW_AFTER
        for ft, method, uri, _ in flask
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Đối chiếu audit log WAF với log Flask")
    ap.add_argument("logfile", nargs="?", type=Path, default=DEFAULT_LOG)
    ap.add_argument("--since", help="chỉ xét sự kiện từ thời điểm này: 30m, 2h, 1d hoặc ISO 8601 (UTC)")
    ap.add_argument("--markdown", action="store_true", help="in bảng Markdown để dán vào báo cáo")
    ap.add_argument("--include-noise", action="store_true",
                    help="giữ cả nhiễu đã biết: 920350 (Host là IP) và request của benign_check.py")
    args = ap.parse_args()

    since = parse_since(args.since)
    events = [e for e in read_events(args.logfile) if e["rules"]]
    if since:
        events = [e for e in events if datetime.fromisoformat(e["time"]) >= since]
    if not args.include_noise:
        events = [e for e in events
                  if {r["id"] for r in e["rules"]} != {"920350"}
                  and "benign-check" not in (e["user_agent"] or "")]
    if not events:
        print("Không có sự kiện nào có luật khớp trong khoảng thời gian đã chọn.")
        return 1

    flask = flask_requests(since)
    rows, consistent = [], 0
    for e in events:
        reached = reached_backend(e, flask)
        ok = reached != e["blocked"]  # chặn -> không tới Flask; không chặn -> tới Flask
        consistent += ok
        uri = unquote_plus(e["uri"] or "")
        rows.append({
            "time": e["time"][:19].replace("T", " "),
            "request": f"{e['method']} {uri if len(uri) <= 60 else uri[:57] + '...'}",
            "category": ", ".join(e["categories"]) or "-",
            "rules": ", ".join(r["id"] for r in e["rules"]),
            "score": e["anomaly_score"],
            "waf": f"{e['status']} " + ("CHẶN" if e["blocked"] else f"cho qua ({e['engine']})"),
            "flask": "CÓ" if reached else "KHÔNG",
            "verdict": "Đạt" if ok else "KHÔNG ĐẠT",
        })

    headers = ["Thời gian (UTC)", "Request", "Loại tấn công", "Luật khớp", "Điểm", "WAF", "Tới Flask", "Đánh giá"]
    keys = ["time", "request", "category", "rules", "score", "waf", "flask", "verdict"]
    if args.markdown:
        print("| " + " | ".join(headers) + " |")
        print("|" + "---|" * len(headers))
        for r in rows:
            cells = [str(r[k]).replace("|", "\\|") for k in keys]
            cells[1] = f"`{cells[1]}`"
            print("| " + " | ".join(cells) + " |")
    else:
        for r in rows:
            print(f"[{r['time']}] {r['waf']:<26} Flask: {r['flask']:<6} {r['verdict']:<9} {r['request']}")
            print(f"    loại: {r['category']} | luật: {r['rules']} | điểm: {r['score']}")

    blocked = [e for e in events if e["blocked"]]
    by_cat = Counter(c for e in events for c in (e["categories"] or ["(không phân loại)"]))
    blocked_cat = Counter(c for e in blocked for c in (e["categories"] or ["(không phân loại)"]))
    print("\n=== KẾT QUẢ ĐỐI CHIẾU ===")
    print(f"Sự kiện có luật khớp            : {len(events)}")
    print(f"Bị WAF chặn                     : {len(blocked)}")
    print(f"Bị chặn nhưng vẫn tới Flask     : {sum(r['flask'] == 'CÓ' for r, e in zip(rows, events) if e['blocked'])}")
    print(f"Nhất quán giữa WAF và Flask     : {consistent}/{len(events)}")
    print("Theo loại tấn công (bị chặn/tổng):")
    for c, n in by_cat.most_common():
        print(f"  {blocked_cat[c]}/{n}  {c}")
    return 0 if consistent == len(events) else 1


if __name__ == "__main__":
    sys.exit(main())
