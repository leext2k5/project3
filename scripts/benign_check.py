#!/usr/bin/env python3
"""
Kiểm tra false positive: WAF có chặn nhầm người dùng hợp lệ không.

Script chỉ gửi các thao tác bình thường mà người dùng thật làm trên website
(xem trang, đăng nhập, tìm kiếm, xem sản phẩm, gửi góp ý, gọi API), rồi:
  1. so mã trạng thái HTTP với kết quả mong đợi (403 = bị chặn nhầm);
  2. đọc phần audit log mới sinh ra trong lúc chạy: request hợp lệ không được
     làm khớp luật nào. Có luật khớp = false positive, kể cả khi chưa đủ điểm để chặn.

Nên chạy ở chế độ chặn (./scripts/waf-mode.sh block). Chỉ dùng thư viện chuẩn.

    python3 scripts/benign_check.py
    python3 scripts/benign_check.py --base-url http://localhost:8080
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parse_audit import DEFAULT_LOG, normalize  # noqa: E402

# Đánh dấu request của script trong User-Agent để lọc đúng bản ghi trong audit log
MARKER = "benign-check/1.0"
USER_AGENT = f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 {MARKER}"


def multipart(fields: dict, files: dict) -> tuple[bytes, str]:
    boundary = f"----benigncheck{int(time.time() * 1000)}"
    parts = []
    for k, v in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for k, (filename, content, ctype) in files.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{filename}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n".encode() + content + b"\r\n"
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def build_cases() -> list[dict]:
    """(mô tả, method, path, body, content-type, mã mong đợi)."""
    form = "application/x-www-form-urlencoded"
    cases = [
        ("Trang chủ", "GET", "/", None, None, {200}),
        ("Mở form đăng nhập", "GET", "/login", None, None, {200}),
        ("Đăng nhập đúng tài khoản", "POST", "/login",
         urlencode({"username": "alice", "password": "alice123"}), form, {200}),
        ("Đăng nhập sai mật khẩu", "POST", "/login",
         urlencode({"username": "bob", "password": "quenmatkhau"}), form, {200}),
        ("Tìm kiếm một từ", "GET", "/search?" + urlencode({"q": "laptop"}), None, None, {200}),
        ("Tìm kiếm nhiều từ + lọc danh mục", "GET",
         "/search?" + urlencode({"q": "tai nghe bluetooth", "category": "am-thanh"}), None, None, {200}),
        ("Tìm kiếm tiếng Việt có dấu", "GET",
         "/search?" + urlencode({"q": "màn hình 27 inch"}), None, None, {200}),
        ("Chọn danh mục, không nhập từ khóa", "GET",
         "/search?" + urlencode({"q": "", "category": "mang"}), None, None, {200}),
    ]
    cases += [(f"Xem sản phẩm id={i}", "GET", f"/product?id={i}", None, None, {200}) for i in range(1, 7)]
    cases += [
        ("Sản phẩm với view và ref", "GET",
         "/product?" + urlencode({"id": 2, "view": "specs", "ref": "homepage"}), None, None, {200}),
        ("Sản phẩm không tồn tại (id hợp lệ)", "GET", "/product?id=999", None, None, {200}),
        ("Mở form góp ý", "GET", "/feedback", None, None, {200}),
        ("Gửi góp ý (form thường)", "POST", "/feedback",
         urlencode({"name": "Nguyễn Văn An", "email": "an.nguyen@example.com",
                    "content": "Shop giao hàng nhanh, đóng gói cẩn thận. Sẽ ủng hộ tiếp!"}), form, {302}),
        ("Góp ý có tên chứa dấu nháy đơn", "POST", "/feedback",
         urlencode({"name": "Mary O'Neil", "email": "mary.oneil@example.com",
                    "content": "I'd like to know when the 27-inch monitor is back in stock."}), form, {302}),
        ("Góp ý có đường link và email có dấu +", "POST", "/feedback",
         urlencode({"name": "Trần Bình", "email": "binh+shop@example.com",
                    "content": "Mình thấy giá rẻ hơn ở https://example.com/san-pham, shop xem lại giúp nhé."}),
         form, {302}),
    ]
    body, ctype = multipart(
        {"name": "Lê Hoa", "content": "Gửi kèm ảnh hóa đơn để shop kiểm tra."},
        {"attachment": ("hoa-don.txt", "Hóa đơn số 0001 - Tổng: 1.250.000 VNĐ\n".encode(), "text/plain")},
    )
    cases += [
        ("Gửi góp ý kèm tệp (multipart)", "POST", "/feedback", body, ctype, {302}),
        ("API: gửi góp ý JSON", "POST", "/api/feedback",
         json.dumps({"name": "Phạm Minh", "email": "minh@example.com",
                     "content": "Ứng dụng dùng ổn, mong có thêm thanh toán qua ví điện tử."},
                    ensure_ascii=False), "application/json", {201}),
        ("API: danh sách sản phẩm", "GET", "/api/products", None, None, {200}),
    ]
    return [dict(zip(("name", "method", "path", "body", "ctype", "expect"), c)) for c in cases]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # giữ nguyên mã 302 của mẫu Post/Redirect/Get để kiểm tra


def send(base: str, case: dict) -> int | str:
    data = case["body"]
    if isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(base + case["path"], data=data, method=case["method"])
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
    req.add_header("Accept-Language", "vi-VN,vi;q=0.9,en;q=0.8")
    if case["ctype"]:
        req.add_header("Content-Type", case["ctype"])
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError) as exc:
        return f"lỗi kết nối: {exc}"


def new_events(log: Path, offset: int) -> list[dict]:
    if not log.exists():
        return []
    with log.open(encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        out = []
        for line in fh:
            try:
                e = normalize(json.loads(line))
            except json.JSONDecodeError:
                continue
            if MARKER in (e["user_agent"] or ""):
                out.append(e)
        return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Kiểm tra WAF có chặn nhầm request hợp lệ không")
    ap.add_argument("--base-url", default="http://localhost:8080")
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    offset = args.log.stat().st_size if args.log.exists() else 0
    cases = build_cases()

    print(f"Gửi {len(cases)} request hợp lệ tới {base}\n")
    failed = 0
    for c in cases:
        status = send(base, c)
        ok = status in c["expect"]
        failed += not ok
        tag = "OK  " if ok else ("CHẶN" if status == 403 else "SAI ")
        print(f"  [{tag}] {status!s:<4} {c['method']:<4} {c['name']}")

    time.sleep(1)  # chờ ModSecurity ghi xong bản ghi cuối
    events = new_events(args.log, offset)
    fp_rules = sorted({r["id"] for e in events for r in e["rules"]})

    print("\n=== KẾT QUẢ ===")
    print(f"Request đi qua đúng như mong đợi : {len(cases) - failed}/{len(cases)}")
    print(f"Bị chặn nhầm (403)               : {sum(e['blocked'] for e in events)}")
    print(f"Bản ghi audit log có luật khớp   : {sum(bool(e['rules']) for e in events)}")
    print(f"Luật báo nhầm                    : {', '.join(fp_rules) if fp_rules else 'không có'}")
    for e in events:
        if e["rules"]:
            print(f"  - {e['method']} {e['uri']}: "
                  + ", ".join(f"{r['id']} ({r['msg']})" for r in e["rules"]))
    return 0 if failed == 0 and not fp_rules else 1


if __name__ == "__main__":
    sys.exit(main())
