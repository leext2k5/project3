#!/usr/bin/env python3
"""
Phân tích audit log JSON của ModSecurity v3 (OWASP CRS).

Mỗi dòng trong logs/waf/modsec_audit.json là một transaction. Script chuẩn hóa
thành "sự kiện" gọn: ai gửi, gửi gì, luật nào khớp, loại tấn công, anomaly score,
có bị chặn không. Đây là định dạng đầu vào dự kiến cho module AI ở giai đoạn sau.

Ví dụ:
    python3 scripts/parse_audit.py                   # 20 sự kiện gần nhất
    python3 scripts/parse_audit.py --last 50 --attacks-only
    python3 scripts/parse_audit.py --summary         # thống kê tổng hợp
    python3 scripts/parse_audit.py --json > events.jsonl
    python3 scripts/parse_audit.py --follow          # theo dõi realtime (như tail -f)

Chỉ dùng thư viện chuẩn của Python.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import unquote_plus

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "logs" / "waf" / "modsec_audit.json"

# Luật "tổng hợp" của CRS: không phải dấu hiệu tấn công, chỉ đánh giá điểm
META_RULES = {"949110", "959100", "980170", "980099", "949111", "959101"}

SEVERITY_NAMES = {
    "0": "EMERGENCY", "1": "ALERT", "2": "CRITICAL", "3": "ERROR",
    "4": "WARNING", "5": "NOTICE", "6": "INFO", "7": "DEBUG",
}
# Điểm anomaly mặc định của CRS theo severity
SEVERITY_SCORE = {"2": 5, "3": 4, "4": 3, "5": 2}

CATEGORY_NAMES = {
    "attack-sqli": "SQL Injection",
    "attack-xss": "Cross-Site Scripting",
    "attack-rce": "Command Injection / RCE",
    "attack-lfi": "Path Traversal / LFI",
    "attack-rfi": "Remote File Inclusion",
    "attack-php": "PHP Injection",
    "attack-java": "Java Injection",
    "attack-nodejs": "Node.js Injection",
    "attack-generic": "Generic Attack",
    "attack-injection-generic": "Generic Injection",
    "attack-session-fixation": "Session Fixation",
    "attack-multipart-header": "Multipart Attack",
    "attack-protocol": "Protocol Attack",
    "attack-reputation-scanner": "Scanner Detection",
    "attack-disclosure": "Data Leakage",
    "attack-fixation": "Session Fixation",
}

TOTAL_SCORE_RE = re.compile(r"Total Score:\s*(\d+)")
PL_TAG_RE = re.compile(r"paranoia-level/(\d)")


def parse_timestamp(raw: str) -> str:
    """'Mon Oct 19 02:56:23 2026' (UTC) -> ISO 8601."""
    try:
        dt = datetime.strptime(raw, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        return raw or ""


def header(headers: dict, name: str) -> str:
    name = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return ""


def categorize(tags: list[str]) -> str | None:
    for t in tags:
        if t in CATEGORY_NAMES:
            return CATEGORY_NAMES[t]
    for t in tags:
        if t.startswith("attack-"):
            return t
    return None


def normalize(record: dict) -> dict:
    """Chuyển một transaction ModSecurity thành sự kiện chuẩn hóa."""
    tx = record.get("transaction", record)
    req = tx.get("request", {}) or {}
    resp = tx.get("response", {}) or {}
    headers = req.get("headers", {}) or {}

    rules, total_score = [], None
    for m in tx.get("messages", []) or []:
        d = m.get("details", {}) or {}
        rid = str(d.get("ruleId", ""))
        if rid in META_RULES:
            found = TOTAL_SCORE_RE.search(m.get("message", "") + " " + d.get("data", ""))
            if found:
                total_score = max(total_score or 0, int(found.group(1)))
            continue
        tags = d.get("tags", []) or []
        pl = next((int(x.group(1)) for x in map(PL_TAG_RE.search, tags) if x), None)
        sev = str(d.get("severity", ""))
        rules.append({
            "id": rid,
            "msg": m.get("message", ""),
            "severity": SEVERITY_NAMES.get(sev, sev),
            "score": SEVERITY_SCORE.get(sev, 0),
            "paranoia_level": pl,
            "category": categorize(tags),
            "data": d.get("data", ""),
            "tags": [t for t in tags if t not in ("modsecurity", "OWASP_CRS")],
        })

    # 949110 chỉ được ghi khi điểm >= ngưỡng; dưới ngưỡng thì tự cộng điểm theo severity
    computed = sum(r["score"] for r in rules)
    anomaly_score = total_score if total_score is not None else computed

    status = resp.get("http_code")
    engine = (tx.get("producer", {}) or {}).get("secrules_engine", "")
    return {
        "id": tx.get("unique_id"),
        "time": parse_timestamp(tx.get("time_stamp", "")),
        # Không lấy từ header X-Real-IP/X-Forwarded-For của request: client tự gửi được -> giả mạo IP.
        # Không có proxy nào đứng trước WAF nên client_ip do ModSecurity ghi nhận là IP thật.
        "client_ip": tx.get("client_ip"),
        "method": req.get("method"),
        "uri": req.get("uri"),
        "host": header(headers, "Host"),
        "user_agent": header(headers, "User-Agent"),
        "request_body": req.get("body", ""),
        "status": status,
        "engine": engine,
        "blocked": bool(tx.get("is_interrupted")) or status == 403,
        "anomaly_score": anomaly_score,
        "categories": sorted({r["category"] for r in rules if r["category"]}),
        "rules": rules,
    }


def read_events(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield normalize(json.loads(line))
            except json.JSONDecodeError:
                continue


def follow_events(path: Path) -> Iterator[dict]:
    while not path.exists():
        time.sleep(0.5)
    with path.open(encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.3)
                continue
            try:
                yield normalize(json.loads(line))
            except json.JSONDecodeError:
                continue


# --------------------------------------------------------------------------- #
# Hiển thị
# --------------------------------------------------------------------------- #
def fmt_event(e: dict, verbose: bool = False) -> str:
    action = "BLOCKED " if e["blocked"] else "DETECTED" if e["rules"] else "PASS    "
    uri = unquote_plus(e["uri"] or "")
    if len(uri) > 90:
        uri = uri[:87] + "..."
    lines = [
        f"[{e['time']}] {action} {e['status']} score={e['anomaly_score']:<3} "
        f"{e['client_ip']} {e['method']} {uri}"
    ]
    if e["categories"]:
        lines.append(f"    loại tấn công : {', '.join(e['categories'])}")
    for r in e["rules"]:
        lines.append(f"    - {r['id']} [{r['severity']}, PL{r['paranoia_level'] or '?'}] {r['msg']}")
        if verbose and r["data"]:
            lines.append(f"        {r['data'][:200]}")
    return "\n".join(lines)


def summarize(events: Iterable[dict]) -> str:
    events = list(events)
    attacks = [e for e in events if e["rules"]]
    blocked = [e for e in events if e["blocked"]]
    by_rule, by_cat, by_ip, by_uri = Counter(), Counter(), Counter(), Counter()
    rule_msgs = {}
    for e in attacks:
        by_ip[e["client_ip"]] += 1
        by_uri[(e["uri"] or "").split("?")[0]] += 1
        for c in e["categories"] or ["(không phân loại)"]:
            by_cat[c] += 1
        for r in e["rules"]:
            by_rule[r["id"]] += 1
            rule_msgs[r["id"]] = r["msg"]

    out = [
        "=== THỐNG KÊ AUDIT LOG WAF ===",
        f"Tổng transaction được ghi : {len(events)}",
        f"Có luật khớp (nghi vấn)   : {len(attacks)}",
        f"Bị chặn (403)             : {len(blocked)}",
        "",
        "Theo loại tấn công:",
    ]
    out += [f"  {n:>4}  {c}" for c, n in by_cat.most_common()]
    out += ["", "Top 15 luật bị kích hoạt:"]
    out += [f"  {n:>4}  {rid}  {rule_msgs[rid][:80]}" for rid, n in by_rule.most_common(15)]
    out += ["", "Top IP nguồn:"]
    out += [f"  {n:>4}  {ip}" for ip, n in by_ip.most_common(10)]
    out += ["", "Top endpoint bị nhắm tới:"]
    out += [f"  {n:>4}  {u}" for u, n in by_uri.most_common(10)]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Phân tích audit log ModSecurity/CRS")
    ap.add_argument("logfile", nargs="?", type=Path, default=DEFAULT_LOG)
    ap.add_argument("--last", type=int, default=20, help="số sự kiện gần nhất (0 = tất cả)")
    ap.add_argument("--attacks-only", action="store_true", help="chỉ hiện request có luật khớp")
    ap.add_argument("--summary", action="store_true", help="thống kê tổng hợp")
    ap.add_argument("--json", action="store_true", help="xuất JSON Lines (cho AI/SIEM)")
    ap.add_argument("--follow", "-f", action="store_true", help="theo dõi log realtime")
    ap.add_argument("--verbose", "-v", action="store_true", help="hiện dữ liệu khớp của từng luật")
    args = ap.parse_args()

    if args.follow:
        try:
            for e in follow_events(args.logfile):
                if args.attacks_only and not e["rules"]:
                    continue
                print(json.dumps(e, ensure_ascii=False) if args.json else fmt_event(e, args.verbose),
                      flush=True)
        except KeyboardInterrupt:
            return 0

    if not args.logfile.exists():
        print(f"Không tìm thấy log: {args.logfile}", file=sys.stderr)
        return 1

    events = list(read_events(args.logfile))
    if args.attacks_only:
        events = [e for e in events if e["rules"]]
    if args.summary:
        print(summarize(events))
        return 0
    if args.last:
        events = events[-args.last:]
    for e in events:
        print(json.dumps(e, ensure_ascii=False) if args.json else fmt_event(e, args.verbose))
    return 0


if __name__ == "__main__":
    sys.exit(main())
