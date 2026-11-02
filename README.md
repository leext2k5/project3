# AI-WAF Lab — Web Application Firewall tích hợp AI

Đề tài: **Nghiên cứu và phát triển hệ thống Web Application Firewall (WAF) tích hợp AI hỗ trợ phân tích và phát hiện tấn công ứng dụng web.**

Hệ thống dùng **Nginx + ModSecurity v3 + OWASP Core Rule Set (CRS)** làm reverse proxy bảo vệ một website Flask thử nghiệm, ghi log cảnh báo dạng JSON để làm đầu vào cho module AI phân tích (giai đoạn sau).

> ⚠️ **Cảnh báo:** website Flask trong `web/` **cố ý chứa lỗ hổng** (SQL Injection, Reflected XSS) để minh họa khả năng phát hiện/chặn của WAF. Chỉ chạy trong môi trường lab cục bộ. Không triển khai ra Internet.

## Tiến độ

| Giai đoạn | Nội dung | Trạng thái |
|---|---|---|
| 1 | WAF cơ bản: ModSecurity + CRS + Flask, ghi log, kiểm thử phát hiện/chặn và false positive | Đang thực hiện |
| 2 | Quản lý cảnh báo: thu thập và chuẩn hóa log, FastAPI + SQLite, dashboard | Chưa bắt đầu |
| 3 | Tích hợp AI: phân loại, giải thích, đánh giá false positive, đề xuất xử lý | Chưa bắt đầu |
| 4 | Đánh giá (Precision/Recall/F1) và hoàn thiện | Chưa bắt đầu |

## Kiến trúc

```
Client ──► 127.0.0.1:8080 ──► [waf]  Nginx 1.30 + ModSecurity v3.0.17 + OWASP CRS 4.30.0
                                 │    (mạng frontend + backend)
                                 ▼
                              [web]  Flask + Gunicorn :5000
                                      (chỉ mạng backend, internal: true — không truy cập trực tiếp được)
```

- Chỉ cổng WAF được công bố, và chỉ trên `127.0.0.1`.
- Container `web` không công bố cổng và nằm trong mạng `internal`, nên không thể đi vòng qua WAF.
- CRS dùng cơ chế **anomaly scoring**: mỗi luật khớp cộng điểm, tổng điểm ≥ ngưỡng (mặc định 5) thì chặn khi ở chế độ `On`.

## Yêu cầu

- Docker Engine và Docker Compose v2
- Python 3.9+ (chạy công cụ phân tích log, chỉ dùng thư viện chuẩn)

## Cài đặt và chạy

```bash
git clone https://github.com/leext2k5/project3.git
cd project3
docker compose up -d --build
docker compose ps          # cả hai container phải ở trạng thái healthy
```

Mở http://localhost:8080 (dùng `localhost`; truy cập bằng `127.0.0.1` sẽ kích hoạt luật CRS 920350 "Host header là địa chỉ IP").

## Cấu hình (`.env`)

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `WAF_MODE` | `DetectionOnly` | `DetectionOnly`: chỉ phát hiện và ghi log · `On`: chặn · `Off` |
| `PARANOIA` | `1` | Paranoia level dùng để chặn (1–4) |
| `DETECTION_PARANOIA` | `1` | Paranoia level dùng để ghi log (≥ `PARANOIA`) |
| `ANOMALY_INBOUND` | `5` | Ngưỡng điểm chặn request |
| `ANOMALY_OUTBOUND` | `4` | Ngưỡng điểm chặn response |
| `WAF_PORT` | `8080` | Cổng WAF trên máy host |

Đổi chế độ nhanh:

```bash
./scripts/waf-mode.sh detect       # DetectionOnly
./scripts/waf-mode.sh block        # On (chặn)
./scripts/waf-mode.sh status       # chế độ đang chạy trong container
./scripts/waf-mode.sh clear-logs   # xóa log
```

> `waf-mode.sh` dùng cú pháp `sed -i ''` của macOS. Trên Linux, sửa `WAF_MODE` trong `.env` rồi chạy `docker compose up -d waf`.

## Log

| Nguồn | Vị trí | Nội dung |
|---|---|---|
| Audit log ModSecurity | `logs/waf/modsec_audit.json` | Request có luật khớp: luật, dữ liệu khớp, điểm, chặn hay không (JSON, mỗi dòng một transaction) |
| Access log Nginx | `logs/waf/access.log` | Mọi request đi qua WAF và mã trạng thái |
| Error log Nginx | `logs/waf/error.log` | Thông báo chặn của ModSecurity |
| Log Flask | `docker compose logs -f web` | Request đã tới được ứng dụng |

Công cụ phân tích audit log:

```bash
python3 scripts/parse_audit.py                    # 20 sự kiện gần nhất
python3 scripts/parse_audit.py --last 10 -v       # kèm dữ liệu khớp của từng luật
python3 scripts/parse_audit.py --attacks-only -f  # theo dõi realtime
python3 scripts/parse_audit.py --summary          # thống kê theo loại tấn công, luật, IP, endpoint
python3 scripts/parse_audit.py --json             # xuất JSON Lines (đầu vào cho AI)
```

Kiểm tra false positive (WAF có chặn nhầm người dùng hợp lệ không), nên chạy ở chế độ `block`:

```bash
python3 scripts/benign_check.py   # gửi các thao tác bình thường trên 5 chức năng, đối chiếu mã HTTP và audit log
```

Script trả mã thoát `0` khi mọi request đi qua và không làm khớp luật nào, `1` nếu có request bị chặn hoặc có luật báo nhầm.

## Website thử nghiệm

| Chức năng | Đường dẫn | Mục đích kiểm thử |
|---|---|---|
| Trang chủ | `/` | Truy cập bình thường |
| Đăng nhập | `/login` | Dữ liệu trong body form (cố ý có lỗi SQLi) |
| Tìm kiếm | `/search?q=` | Tham số GET (cố ý có lỗi SQLi, Reflected XSS) |
| Chi tiết sản phẩm | `/product?id=` | Tham số URL (cố ý có lỗi SQLi kiểu số) |
| Góp ý | `/feedback`, `/api/feedback` | Body urlencoded, multipart, JSON |

## Luật tùy chỉnh

`waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` (nạp trước CRS):

- **1000100 — Virtual patch:** tham số `id` của `/product` chỉ hợp lệ khi là 1–9 chữ số; vi phạm thì cộng điểm CRITICAL (5) vào anomaly score.
- Mẫu xử lý false positive (`ctl:ruleRemoveTargetById`, `ctl:ruleRemoveTargetByTag`), đang tắt.

Sau khi sửa luật: `docker compose restart waf`.

## Cấu trúc thư mục

```
├── docker-compose.yml        # 2 container (waf, web) và 2 mạng (frontend, backend)
├── .env / .env.example       # cấu hình WAF
├── web/                      # website Flask thử nghiệm
├── waf/rules/                # luật ModSecurity tùy chỉnh
├── scripts/
│   ├── parse_audit.py        # phân tích audit log
│   ├── benign_check.py       # kiểm tra false positive
│   └── waf-mode.sh           # đổi chế độ WAF
├── logs/waf/                 # log do WAF ghi ra (không đưa lên git)
└── evidence/                 # bản sao log và kết quả kiểm thử làm minh chứng
```

## Tài liệu tham khảo

- OWASP CRS: https://coreruleset.org/docs/
- modsecurity-crs-docker: https://github.com/coreruleset/modsecurity-crs-docker
- ModSecurity v3: https://github.com/owasp-modsecurity/ModSecurity
- OWASP Top 10: https://owasp.org/Top10/
