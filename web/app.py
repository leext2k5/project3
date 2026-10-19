"""
Website thử nghiệm cho lab WAF (Giai đoạn 1).

CẢNH BÁO: Một số chức năng CỐ Ý chứa lỗ hổng (SQL Injection, Reflected XSS)
để minh họa giá trị của WAF: ở chế độ DetectionOnly tấn công thành công,
ở chế độ Blocking tấn công bị chặn trước khi tới ứng dụng.
Chỉ chạy trong mạng nội bộ Docker phía sau WAF, KHÔNG triển khai ra Internet.
"""

import logging
import os
import sqlite3
import time
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

DB_PATH = os.environ.get("DB_PATH", "/tmp/lab.db")
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/tmp/uploads"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB
# WAF (Nginx) đứng trước Flask: lấy IP thật của client từ X-Forwarded-For
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [web] %(message)s")
log = logging.getLogger("web")


# --------------------------------------------------------------------------- #
# Cơ sở dữ liệu SQLite mẫu
# --------------------------------------------------------------------------- #
SEED_USERS = [
    ("admin", "Adm1n@2026", "administrator"),
    ("alice", "alice123", "user"),
    ("bob", "b0b_secret", "user"),
]

SEED_PRODUCTS = [
    (1, "Laptop ThinkPad X1", "Laptop doanh nhân, 14 inch, 16GB RAM", 32990000, "laptop"),
    (2, "Chuột Logitech MX Master 3", "Chuột không dây công thái học", 2490000, "phu-kien"),
    (3, "Bàn phím cơ Keychron K8", "Bàn phím cơ TKL, switch Brown", 2190000, "phu-kien"),
    (4, "Màn hình Dell U2723QE", "Màn hình 27 inch 4K USB-C", 13490000, "man-hinh"),
    (5, "Tai nghe Sony WH-1000XM5", "Tai nghe chống ồn chủ động", 7990000, "am-thanh"),
    (6, "Router WiFi 6 TP-Link AX55", "Router băng tần kép, hỗ trợ WPA3", 1890000, "mang"),
]


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS feedback;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT,
                               price INTEGER, category TEXT);
        CREATE TABLE feedback (id INTEGER PRIMARY KEY, name TEXT, email TEXT, content TEXT,
                               content_type TEXT, attachment TEXT, created_at TEXT);
        """
    )
    conn.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", SEED_USERS)
    conn.executemany("INSERT INTO products VALUES (?, ?, ?, ?, ?)", SEED_PRODUCTS)
    conn.commit()
    conn.close()
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def log_request(resp):
    # Log phía backend: nếu một request tấn công xuất hiện ở đây nghĩa là nó đã vượt qua WAF
    log.info("%s %s %s -> %s", request.remote_addr, request.method, request.full_path.rstrip("?"),
             resp.status_code)
    return resp


# --------------------------------------------------------------------------- #
# Chức năng 1: Trang chủ — truy cập HTTP bình thường
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    products = get_db().execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template("index.html", products=products)


@app.route("/health")
def health():
    return jsonify(status="ok", time=int(time.time()))


# --------------------------------------------------------------------------- #
# Chức năng 2: Form đăng nhập — CỐ Ý có lỗi SQL Injection
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login():
    result = None
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # LỖ HỔNG CỐ Ý: ghép chuỗi trực tiếp vào câu SQL.
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            user = get_db().execute(query).fetchone()
            if user:
                result = {"ok": True, "msg": f"Đăng nhập thành công. Xin chào {user['username']} (role: {user['role']})"}
            else:
                result = {"ok": False, "msg": "Sai tên đăng nhập hoặc mật khẩu."}
        except sqlite3.Error as exc:
            # Lộ thông báo lỗi SQL — một dấu hiệu kinh điển mà CRS (nhóm RESPONSE-951) có thể phát hiện
            result = {"ok": False, "msg": f"Lỗi cơ sở dữ liệu: {exc}"}
        return render_template("login.html", result=result, username=username, query=query)
    return render_template("login.html", result=result, username=username, query=None)


# --------------------------------------------------------------------------- #
# Chức năng 3: Form tìm kiếm — CỐ Ý có lỗi SQL Injection + Reflected XSS
# --------------------------------------------------------------------------- #
@app.route("/search")
def search():
    q = request.args.get("q", "")
    category = request.args.get("category", "")
    rows, error = [], None
    if q or category:
        # LỖ HỔNG CỐ Ý: ghép chuỗi vào mệnh đề LIKE
        query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{q}%'"
        if category:
            query += f" AND category = '{category}'"
        try:
            rows = get_db().execute(query).fetchall()
        except sqlite3.Error as exc:
            error = str(exc)
    # LỖ HỔNG CỐ Ý: template render biến q bằng |safe (không escape) -> Reflected XSS
    return render_template("search.html", q=q, category=category, rows=rows, error=error)


# --------------------------------------------------------------------------- #
# Chức năng 4: Trang chi tiết sản phẩm — kiểm tra tham số trên URL
# --------------------------------------------------------------------------- #
@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    view = request.args.get("view", "default")  # tham số phụ để thử Path Traversal
    ref = request.args.get("ref", "")
    error = None
    item = None
    # LỖ HỔNG CỐ Ý: tham số số nhưng không ép kiểu -> Numeric SQL Injection
    try:
        item = get_db().execute(f"SELECT * FROM products WHERE id = {pid}").fetchone()
    except sqlite3.Error as exc:
        error = str(exc)
    # 'view' chỉ được chấp nhận từ danh sách cho phép — ứng dụng không đọc file theo input người dùng
    if view not in ("default", "compact", "specs"):
        view = "default"
    return render_template("product.html", item=item, pid=pid, view=view, ref=ref, error=error)


# --------------------------------------------------------------------------- #
# Chức năng 5: Form nhập nội dung — nhiều dạng request body
#   - application/x-www-form-urlencoded (form thường)
#   - multipart/form-data (form có file đính kèm)
#   - application/json (API /api/feedback)
# --------------------------------------------------------------------------- #
def save_feedback(name, email, content, content_type, attachment=None):
    db = get_db()
    db.execute(
        "INSERT INTO feedback (name, email, content, content_type, attachment, created_at) "
        "VALUES (?, ?, ?, ?, ?, datetime('now'))",
        (name, email, content, content_type, attachment),
    )
    db.commit()


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    message = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        content = request.form.get("content", "").strip()
        attachment = None
        f = request.files.get("attachment")
        if f and f.filename:
            # Không dùng tên file của người dùng để ghi đĩa (tránh path traversal ở ứng dụng)
            attachment = f.filename
            f.save(UPLOAD_DIR / f"upload_{int(time.time() * 1000)}.bin")
        if not content:
            message = "Nội dung không được để trống."
        else:
            save_feedback(name, email, content, request.mimetype, attachment)
            return redirect(url_for("feedback", sent=1))
    if request.args.get("sent"):
        message = "Đã gửi góp ý. Cảm ơn bạn!"
    items = get_db().execute("SELECT * FROM feedback ORDER BY id DESC LIMIT 20").fetchall()
    # Nội dung góp ý được escape bình thường khi hiển thị (Jinja2 autoescape)
    return render_template("feedback.html", items=items, message=message)


@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data.get("content"):
        return jsonify(error="Body phải là JSON có trường 'content'"), 400
    save_feedback(str(data.get("name", "")), str(data.get("email", "")), str(data["content"]),
                  request.mimetype)
    return jsonify(status="saved", received=data), 201


@app.route("/api/products")
def api_products():
    rows = get_db().execute("SELECT * FROM products ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
