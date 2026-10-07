# Nền tảng giám sát, phát hiện và ứng phó tấn công ICS/OT (Modbus/TCP)

Hệ thống giám sát an ninh cho mạng điều khiển công nghiệp dùng Modbus/TCP:
thu thập lưu lượng theo thời gian thực, nhận diện thiết bị, phát hiện hành vi
bất thường/tấn công, sinh cảnh báo và hỗ trợ người vận hành ứng phó.

Luồng mục tiêu: **Monitor → Discover → Detect → Alert → Investigate → Respond.**

## Trạng thái hiện tại

Đã hoàn thành **Giai đoạn 1–5, 7, 8** — trọn luồng **Monitor → Discover → Detect →
Alert → Investigate → Respond** — cùng một đợt rà soát/củng cố độ tin cậy. Đang chờ
làm: gom sự cố (6), demo & đánh giá (9). Chi tiết xem [docs/BaoCao.md](docs/BaoCao.md).

## Kiến trúc

```
   ┌──────── Mạng ICS giả lập (ics_net) ────────┐      ┌──── Nền tảng giám sát (mon_net) ────┐
   │  HMI ──Modbus/TCP:502──► PLC ──► bồn nước   │      │  Backend (FastAPI) ──► PostgreSQL    │
   │ .20                      .10                │      │        ▲         └──► WebSocket /ws  │
   │     └──── bridge br-ics ────┘               │      └────────┼─────────────────────────────┘
   └──────────────────┬──────────────────────────┘             │ POST /api/events (event JSON)
                     │ bắt gói thụ động                         │
                 Sensor (Scapy, network_mode host) ────────────┘
```

- **PLC** ([lab/plc_sim.py](lab/plc_sim.py)): Modbus/TCP server + điều khiển bơm
  hai ngưỡng + mô phỏng bồn nước. Tách trạng thái auto khỏi lệnh tay, từ chối
  setpoint sai, theo dõi lượng tràn.
- **HMI** ([lab/hmi_sim.py](lab/hmi_sim.py)): đọc trạng thái mỗi giây, ghi setpoint
  định kỳ (kiểm tra PLC chấp nhận).
- **Sensor** ([lab/sensor.py](lab/sensor.py)): bắt gói, **ghép luồng TCP**, giải mã
  Modbus, ghép request–response, gửi event tin cậy (retry + `event_id` chống trùng);
  phát thêm event TCP SYN cho luật quét cổng.
- **Backend** ([lab/backend.py](lab/backend.py)): nhận/kiểm tra/lưu event, phát hiện
  thiết bị, Detection Engine, WebSocket. API dưới.
- **Detection Engine** ([lab/detection.py](lab/detection.py)): học baseline rồi áp
  6 luật phát hiện.
- **Máy tấn công** ([lab/attacker.py](lab/attacker.py)): các kịch bản kiểm chứng.

- **PLC** ([lab/plc_sim.py](lab/plc_sim.py)): Modbus/TCP server, chu kỳ quét
  0,5 giây. Bật bơm khi mức nước xuống dưới ngưỡng thấp, tắt khi vượt ngưỡng
  cao, và mô phỏng mức nước thay đổi theo bơm/van.
- **HMI** ([lab/hmi_sim.py](lab/hmi_sim.py)): mỗi giây đọc trạng thái PLC
  (FC1/2/3/4), mỗi 60 giây ghi lại setpoint (FC6) như thao tác của người vận hành.
- **Bảng địa chỉ Modbus** ([lab/modbus_map.py](lab/modbus_map.py)): dùng chung
  cho PLC, HMI và các script kiểm thử.

### Bảng địa chỉ Modbus

| Vùng | FC | Địa chỉ | Ý nghĩa |
|---|---|---|---|
| Coil | 1 đọc · 5/15 ghi | 0 / 1 / 2 | bơm / van xả / chế độ auto |
| Discrete input | 2 | 0 / 1 | báo mức cao / báo mức thấp |
| Input register | 4 | 0 / 1 / 2 | mức nước / lưu lượng vào / lưu lượng ra |
| Holding register | 3 đọc · 6/16 ghi | 0 / 1 | ngưỡng tắt bơm / ngưỡng bật bơm |

Giá trị thanh ghi lưu dạng số nguyên nhân 10: `800` = 80,0 %. Địa chỉ không
khai báo trong PLC sẽ trả về exception *ILLEGAL DATA ADDRESS* (mã 2) — dùng làm
bằng chứng cho luật "truy cập thanh ghi bất thường".

## Chạy hệ thống

Cần Docker Desktop đang chạy.

```bash
docker compose up -d --build     # dựng toàn bộ: plc, hmi, sensor, backend, db
docker compose logs -f sensor    # xem event Modbus giải mã
docker compose logs -f backend   # xem backend nhận event
docker compose down              # dừng (thêm -v để xóa dữ liệu DB)
```

Trên Mac host (cổng backend đã publish):

```
http://localhost:8000/api/stats          http://localhost:8000/api/alerts
http://localhost:8000/api/assets         http://localhost:8000/api/connections
http://localhost:8000/api/events?limit=20
```

Nếu gặp lỗi `docker-credential-desktop: executable file not found`, thêm vào
`~/.zshrc`:

```bash
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
```

## API backend

| Phương thức | Đường dẫn | Chức năng |
|---|---|---|
| POST | `/api/events` | Sensor gửi lô event (kiểm tra schema, chống trùng theo `event_id`) |
| GET | `/api/events?limit=N&after_id=K` | Lấy event (reconnect dùng `after_id`) |
| GET | `/api/assets`, `/api/connections` | Thiết bị & kết nối tự phát hiện |
| GET | `/api/alerts` | Cảnh báo kèm bằng chứng |
| GET | `/api/stats` | Thống kê |
| GET/POST | `/api/baseline`, `/api/baseline/freeze`, `/api/baseline/reset` | Quản lý baseline |
| WS | `/ws` | Đẩy event + cảnh báo real-time |

## Demo: học baseline rồi tấn công tràn bồn

Modbus/TCP không có xác thực — bất kỳ ai tới được cổng 502 đều ghi được. Kịch bản:

```bash
docker compose up -d --build
sleep 20                                                   # học baseline
curl -X POST http://localhost:8000/api/baseline/freeze     # chốt baseline
# tấn công từ một máy lạ (IP 172.28.0.66):
docker run --rm --network project3_ics_net --ip 172.28.0.66 ics-lab python attacker.py write
curl http://localhost:8000/api/alerts                      # thấy cảnh báo Critical
```

Các mode tấn công khác: `probe` (thiết bị lạ), `recon` (truy cập thanh ghi bất
thường), `dos` (tần suất), `scan` (quét cổng). Kẻ tấn công chuyển PLC sang chế độ
tay (`auto=0`), đóng van, ép bơm — vô hiệu hóa điều khiển an toàn và làm tràn bồn;
đây là điểm yếu **chủ ý** của lab để minh họa.

## Bắt gói trên macOS

Docker trên macOS chạy trong một VM Linux ẩn, nên Wireshark trên máy host không
thấy lưu lượng giữa các container. Sensor sẽ chạy trong một container ở chế độ
mạng host để nghe trực tiếp trên bridge `br-ics`, tương đương một cổng SPAN trên
switch thật.

## Công nghệ

Python · pymodbus 3.15 · Scapy · FastAPI + WebSocket · PostgreSQL · Docker Compose.
Các giai đoạn sau: React + React Flow (dashboard), iptables/nftables (ứng phó).

> Lưu ý: PLC viết bằng Python thay cho OpenPLC để có lab chạy ngay. Hệ giám sát
> chỉ nhìn gói Modbus/TCP nên có thể thay bằng OpenPLC sau mà không ảnh hưởng
> phần còn lại.

## Lộ trình

| # | Giai đoạn | Nội dung |
|---|---|---|
| 1 | Lab ICS | PLC, bồn nước, HMI trong Docker — **đã xong** |
| 2 | Sensor | Scapy bắt gói, ghép luồng TCP, phân tích MBAP/PDU, ghép request–response — **đã xong** |
| 3 | Backend + DB | FastAPI, PostgreSQL, API nhận event, WebSocket — **đã xong** |
| 4 | Phát hiện thiết bị | Suy ra tài sản và kết nối từ traffic — **đã xong** |
| 5 | Detection + attacker | Baseline + 6 luật phát hiện, mỗi luật kèm script tấn công — **đã xong** |
| 6 | Cảnh báo + incident | Phân mức, bằng chứng, gom cảnh báo thành incident |
| 7 | Ứng phó | Gợi ý hành động, operator duyệt, thực thi iptables, hoàn tác — **đã xong** |
| 8 | Dashboard | React: tổng quan, tài sản, topology, cảnh báo, ứng phó — **đã xong** |
| 9 | Demo + đánh giá | Kịch bản tràn bồn, đo tỉ lệ phát hiện/báo động giả, báo cáo |

### Sáu luật phát hiện (giai đoạn 5)

| Hành vi | Cách phát hiện | Mức |
|---|---|---|
| Unauthorized Modbus Write | FC ghi (5/6/15/16) từ nguồn không được phép | Critical |
| Thiết bị lạ truy cập PLC | IP/MAC nguồn không có trong tài sản đã học | High |
| Tần suất bất thường / DoS | Request mỗi giây vượt ngưỡng baseline | High |
| Truy cập thanh ghi bất thường | Địa chỉ ngoài dải đã học / PLC trả exception | Medium |
| Port scanning | Một nguồn quét nhiều cổng trong thời gian ngắn | Medium |
| Kết nối mới tới PLC | Cặp nguồn–đích–cổng chưa từng thấy trong baseline | Low |
