# Xây dựng nền tảng giám sát, phát hiện và hỗ trợ ứng phó tấn công trong mạng điều khiển công nghiệp ICS/OT sử dụng giao thức Modbus/TCP

**Báo cáo đồ án**

| | |
|---|---|
| Sinh viên thực hiện | *(điền tên)* |
| Mã số sinh viên | *(điền MSSV)* |
| Lớp / Chương trình | *(điền)* |
| Giảng viên hướng dẫn | *(điền tên GVHD)* |
| Trường | Đại học Bách khoa Hà Nội |
| Thời gian | Học kỳ *(điền)* |

> **Ghi chú về trạng thái:** Báo cáo được viết theo tiến độ thực hiện. Tính đến
> bản này, **các Giai đoạn 1–5 đã hoàn thành và kiểm thử**: mô hình ICS giả lập
> và công cụ phân tích gói (GĐ1), sensor bắt và phân tích Modbus (GĐ2), backend
> + cơ sở dữ liệu + WebSocket (GĐ3), phát hiện thiết bị và kết nối (GĐ4), học
> baseline và phát hiện tấn công (GĐ5), và **Dashboard giám sát (GĐ8)** — tức trọn
> các bước *Monitor*, *Discover*, *Detect*, *Alert* và *Investigate*. Còn lại:
> ứng phó có duyệt (GĐ7, cơ chế chặn đã kiểm chứng) và demo + đánh giá (GĐ9).
> Những mục chưa làm xong được đánh dấu *(kế hoạch)*. Dự án cũng đã trải qua một **đợt rà soát và
> củng cố** (mục 4.7): sửa các lỗi về ghép luồng TCP, giải mã, độ tin cậy
> truyền/lưu event, kiểm tra đầu vào và logic PLC/HMI.

---

## Mục lục

- [Chương 1. Giới thiệu đề tài](#chương-1-giới-thiệu-đề-tài)
- [Chương 2. Cơ sở lý thuyết](#chương-2-cơ-sở-lý-thuyết)
- [Chương 3. Phân tích và thiết kế hệ thống](#chương-3-phân-tích-và-thiết-kế-hệ-thống)
- [Chương 4. Xây dựng hệ thống](#chương-4-xây-dựng-hệ-thống)
- [Chương 5. Phương pháp và quy trình phát triển](#chương-5-phương-pháp-và-quy-trình-phát-triển)
- [Chương 6. Kết luận và hướng phát triển](#chương-6-kết-luận-và-hướng-phát-triển)
- [Tài liệu tham khảo](#tài-liệu-tham-khảo)
- [Phụ lục A. Hướng dẫn cài đặt và chạy](#phụ-lục-a-hướng-dẫn-cài-đặt-và-chạy)
- [Phụ lục B. Bảng tham số và biến](#phụ-lục-b-bảng-tham-số-và-biến)

---

## Chương 1. Giới thiệu đề tài

### 1.1. Đặt vấn đề

Hệ thống điều khiển công nghiệp (Industrial Control System – ICS) là nền tảng vận
hành của các hạ tầng trọng yếu như nhà máy điện, cấp thoát nước, dầu khí và dây
chuyền sản xuất. Khác với hệ thống công nghệ thông tin (IT) thông thường, ICS
điều khiển trực tiếp các quá trình vật lý; một sự cố an ninh ở đây có thể gây hậu
quả vật lý thực sự: tràn bồn, dừng dây chuyền, hư hỏng thiết bị, mất an toàn lao
động.

Nhiều giao thức công nghiệp phổ biến, tiêu biểu là **Modbus** (công bố năm 1979),
được thiết kế trong bối cảnh mạng cô lập nên **không có cơ chế xác thực, không mã
hóa và không kiểm soát truy cập**. Khi các mạng OT ngày càng kết nối với mạng IT
và Internet, điểm yếu cố hữu này trở thành bề mặt tấn công nghiêm trọng. Các sự
cố thực tế như Stuxnet (2010), tấn công lưới điện Ukraine (2015) hay sự việc tại
nhà máy nước Oldsmar (2021) đều cho thấy kẻ tấn công chỉ cần tiếp cận được mạng
điều khiển là có thể thao túng thiết bị vật lý.

Do đặc thù đó, việc **giám sát an ninh thụ động** – quan sát lưu lượng mạng công
nghiệp mà không can thiệp vào quá trình điều khiển – là hướng tiếp cận phù hợp để
phát hiện sớm hành vi bất thường mà không làm gián đoạn sản xuất.

### 1.2. Mục tiêu

Xây dựng một nền tảng giám sát an ninh cho mạng ICS/OT sử dụng Modbus/TCP, có khả
năng:

1. Thu thập và phân tích lưu lượng Modbus/TCP theo thời gian thực.
2. Tự động nhận diện các thiết bị trong mạng (PLC, HMI, máy trạm).
3. Hiển thị sơ đồ kết nối giữa các thiết bị.
4. Phát hiện các hành vi bất thường/tấn công phổ biến.
5. Quản lý cảnh báo theo mức độ, kèm bằng chứng chi tiết.
6. Đề xuất và hỗ trợ thực hiện biện pháp ứng phó, có xác nhận của người vận hành.
7. Cung cấp dashboard theo dõi tài sản, lưu lượng, cảnh báo theo thời gian thực.

Luồng hoạt động mục tiêu: **Monitor → Discover → Detect → Alert → Investigate →
Respond**.

### 1.3. Phạm vi và giới hạn

- Tập trung vào giao thức **Modbus/TCP** (cổng 502), là giao thức công nghiệp phổ
  biến và tiêu biểu cho lớp giao thức thiếu an toàn.
- Môi trường thử nghiệm là **mô hình ICS giả lập** (mô phỏng bồn nước), triển
  khai bằng Docker, không sử dụng thiết bị phần cứng thật.
- Hệ thống hoạt động ở chế độ **giám sát thụ động** (passive IDS); chức năng ứng
  phó luôn yêu cầu người vận hành xác nhận trước khi tác động tới mạng.

### 1.4. Bố cục báo cáo

Chương 2 trình bày cơ sở lý thuyết về ICS/OT, giao thức Modbus/TCP và giám sát an
ninh. Chương 3 phân tích và thiết kế kiến trúc hệ thống. Chương 4 trình bày quá
trình xây dựng theo từng giai đoạn. Chương 5 mô tả phương pháp và quy trình phát
triển. Chương 6 kết luận và nêu hướng phát triển.

---

## Chương 2. Cơ sở lý thuyết

### 2.1. Hệ thống điều khiển công nghiệp ICS/OT

**OT (Operational Technology)** là lớp công nghệ vận hành, điều khiển trực tiếp
các quá trình vật lý, phân biệt với **IT (Information Technology)** vốn xử lý dữ
liệu. Một khác biệt cốt lõi về an ninh: trong IT, thứ tự ưu tiên thường là Bảo
mật – Toàn vẹn – Sẵn sàng (C-I-A); trong OT, thứ tự này **đảo ngược** thành Sẵn
sàng – Toàn vẹn – Bảo mật, vì yêu cầu hàng đầu là hệ thống không được dừng và
phải an toàn về mặt vật lý. Đặc điểm này chi phối mọi quyết định thiết kế của một
hệ giám sát ICS, trong đó có nguyên tắc "giám sát thụ động, không tự ý can thiệp".

### 2.2. Các thiết bị chính

- **PLC (Programmable Logic Controller):** bộ điều khiển logic khả trình, trực
  tiếp đọc cảm biến và điều khiển cơ cấu chấp hành (bơm, van). PLC hoạt động theo
  **chu kỳ quét (scan cycle)**: lặp vô tận ba bước đọc đầu vào → chạy logic →
  xuất đầu ra.
- **HMI (Human-Machine Interface):** giao diện người-máy, hiển thị trạng thái và
  cho phép người vận hành ra lệnh. HMI đóng vai trò client, định kỳ đọc dữ liệu
  từ PLC.
- **SCADA:** hệ giám sát và thu thập dữ liệu ở cấp cao hơn, điều phối nhiều PLC.
- **Cảm biến / cơ cấu chấp hành (sensor/actuator):** thành phần đo lường và tác
  động lên quá trình vật lý.

### 2.3. Giao thức Modbus/TCP

#### 2.3.1. Mô hình hỏi–đáp (client/server)

Modbus hoạt động theo mô hình client/server (master/slave). Chỉ **client** (HMI)
chủ động gửi **request**; **server** (PLC) trả về **response**. PLC không bao giờ
tự phát dữ liệu. Mỗi giao dịch là độc lập.

#### 2.3.2. Bốn vùng dữ liệu

PLC lưu trạng thái trong bốn vùng dữ liệu:

| Vùng | Kích thước | Quyền client | Minh họa trong đề tài |
|---|---|---|---|
| Coil | 1 bit | đọc + ghi | bơm, van, chế độ tự động |
| Discrete Input | 1 bit | chỉ đọc | cờ báo mức cao/thấp |
| Input Register | 16 bit | chỉ đọc | mức nước, lưu lượng |
| Holding Register | 16 bit | đọc + ghi | ngưỡng bật/tắt bơm |

Quy tắc: "Input" chỉ đọc; "Coil/Holding" ghi được. Vì vậy mọi tấn công gây tác
động vật lý đều phải **ghi** vào Coil hoặc Holding Register.

#### 2.3.3. Function Code (mã chức năng)

Mỗi request mang một Function Code (FC) xác định thao tác:

| FC | Thao tác | Vùng | Loại |
|---|---|---|---|
| 1 | Read Coils | Coil | đọc |
| 2 | Read Discrete Inputs | Discrete Input | đọc |
| 3 | Read Holding Registers | Holding | đọc |
| 4 | Read Input Registers | Input Register | đọc |
| 5 | Write Single Coil | Coil | ghi |
| 6 | Write Single Register | Holding | ghi |
| 15 | Write Multiple Coils | Coil | ghi |
| 16 | Write Multiple Registers | Holding | ghi |

#### 2.3.4. Cấu trúc khung Modbus/TCP

Một thông điệp Modbus/TCP gồm **MBAP header (7 byte)** và **PDU (Protocol Data
Unit)**.

MBAP header:

| Byte | Trường | Ý nghĩa |
|---|---|---|
| 0–1 | Transaction ID | Số định danh giao dịch, dùng ghép response với request |
| 2–3 | Protocol ID | Luôn bằng 0 (Modbus) |
| 4–5 | Length | Số byte còn lại (Unit ID + PDU) |
| 6 | Unit ID | Địa chỉ thiết bị |

PDU = Function Code (1 byte) + dữ liệu.

**Ví dụ thực tế (bắt được từ mô hình thử nghiệm):** HMI đọc 3 Input Register.

Request (12 byte):
```
TID TID 00 00 00 06 01 | 04 00 00 00 03
└──── MBAP (7B) ─────┘   └── PDU (5B) ──┘
  04      = FC Read Input Registers
  00 00   = địa chỉ bắt đầu (0)
  00 03   = số lượng (3 thanh ghi)
  Length 00 06 = 1 (Unit ID) + 5 (PDU)
```

Response (15 byte):
```
TID TID 00 00 00 09 01 | 04 06 01 D8 00 00 00 08
└──── MBAP (7B) ─────┘   └──── PDU (8B) ───────┘
  04      = FC (lặp lại xác nhận)
  06      = byte count (6 byte dữ liệu)
  01 D8   = 472 → mức nước 47,2%
  00 00   = lưu lượng vào = 0
  00 08   = 8 → lưu lượng ra 0,8
```

#### 2.3.5. Exception Response (gói báo lỗi)

Khi PLC không thực hiện được yêu cầu, nó trả về gói lỗi với dấu hiệu đặc trưng:
**Function Code bị cộng thêm 0x80** (bật bit cao nhất), kèm một **Exception
Code**. Ví dụ, đọc một Holding Register không tồn tại khiến PLC trả về FC `0x83`
(= `0x03 + 0x80`) với Exception Code `0x02` (ILLEGAL DATA ADDRESS). Quy tắc nhận
biết: **mọi gói có Function Code ≥ 0x80 (128) đều là gói lỗi**. Dấu hiệu này được
khai thác trong luật phát hiện "truy cập thanh ghi bất thường", vì hành vi dò la
thường sinh ra nhiều exception.

### 2.4. An ninh trong ICS và các dạng tấn công

Do Modbus không xác thực, bất kỳ thực thể nào kết nối được tới cổng 502 đều có thể
đọc/ghi. Các dạng tấn công tiêu biểu mà đề tài hướng tới phát hiện:

| Hành vi | Mô tả |
|---|---|
| Unauthorized Modbus Write | Ghi trái phép vào Coil/Holding Register để thao túng thiết bị |
| Thiết bị lạ truy cập PLC | Một host không được phép giao tiếp với PLC |
| DoS / tần suất bất thường | Dồn dập request làm PLC quá tải hoặc không phản hồi |
| Truy cập thanh ghi bất thường | Đọc/ghi ngoài dải địa chỉ hợp lệ (dò la) |
| Port scanning | Quét cổng để lập bản đồ dịch vụ |
| Kết nối mới tới PLC | Xuất hiện cặp kết nối chưa từng thấy |

### 2.5. Giám sát an ninh và hệ thống phát hiện xâm nhập (IDS)

Hệ thống của đề tài thuộc loại **IDS (Intrusion Detection System)** chuyên biệt
cho ICS: đứng ngoài quan sát, không chặn đường truyền. Phương pháp phát hiện kết
hợp:

- **Dựa trên dấu hiệu/luật (signature/rule-based):** so khớp hành vi với các mẫu
  tấn công đã biết (ví dụ: FC ghi từ nguồn không hợp lệ).
- **Dựa trên bất thường (anomaly-based):** học một **baseline** (mẫu hành vi bình
  thường: ai giao tiếp với ai, dùng FC nào, dải địa chỉ nào, tần suất bao nhiêu),
  rồi cảnh báo khi lưu lượng lệch khỏi baseline đó.

Chức năng ứng phó mang yếu tố **IPS (Intrusion Prevention System)** nhưng luôn
yêu cầu người vận hành xác nhận, nhằm tránh làm gián đoạn sản xuất do báo động
giả — phù hợp nguyên tắc ưu tiên "sẵn sàng" của OT.

---

## Chương 3. Phân tích và thiết kế hệ thống

### 3.1. Kiến trúc tổng thể

Hệ thống gồm hai phần: **mạng ICS giả lập** (đối tượng được giám sát) và **nền
tảng giám sát** (sensor, backend, cơ sở dữ liệu, dashboard).

```
   ┌──────────── Mạng ICS giả lập (Docker) ────────────┐
   │   HMI ───Modbus/TCP:502───► PLC ──► bồn nước       │
   │ 172.28.0.20              172.28.0.10               │
   │         └──── bridge "br-ics" ────┘                │
   └───────────────────┬───────────────────────────────┘
                       │ bắt gói thụ động
                 ┌─────▼─────┐   events   ┌──────────┐   WebSocket  ┌───────────┐
                 │  Sensor   ├───────────►│ Backend  ├─────────────►│ Dashboard │
                 │ (Scapy)   │            │ FastAPI  │              │  (React)  │
                 └───────────┘            │ +Detect  │              └───────────┘
                                          └────┬─────┘
                                          ┌────▼─────┐
                                          │PostgreSQL│
                                          └──────────┘
```

### 3.2. Luồng hoạt động

| Bước | Tên | Chức năng |
|---|---|---|
| 1 | Monitor | Sensor bắt mọi gói Modbus/TCP trên bridge |
| 2 | Discover | Suy ra danh sách thiết bị và kết nối từ lưu lượng |
| 3 | Detect | So với baseline và luật, phát hiện bất thường |
| 4 | Alert | Sinh cảnh báo có mức độ và bằng chứng |
| 5 | Investigate | Người vận hành xem chi tiết, gom thành sự cố |
| 6 | Respond | Đề xuất và thực thi biện pháp sau khi duyệt |

### 3.3. Các thành phần

- **Sensor (Scapy):** bắt gói, phân tích MBAP/PDU, ghép request–response, xuất
  event chuẩn hóa.
- **Backend (FastAPI) + Detection Engine:** nhận event, lưu trữ, học baseline,
  áp luật phát hiện, phát cảnh báo qua WebSocket.
- **Cơ sở dữ liệu (PostgreSQL):** lưu tài sản, kết nối, sự kiện, cảnh báo, sự cố,
  hành động ứng phó.
- **Dashboard (React + React Flow):** hiển thị tổng quan, tài sản, sơ đồ mạng,
  cảnh báo và duyệt ứng phó.

### 3.4. Lộ trình thực hiện

| # | Giai đoạn | Trạng thái |
|---|---|---|
| 1 | Mô hình ICS giả lập + công cụ bắt gói | **Hoàn thành** |
| 2 | Sensor bắt và phân tích gói Modbus | **Hoàn thành** |
| 3 | Backend + cơ sở dữ liệu + WebSocket | **Hoàn thành** |
| 4 | Phát hiện thiết bị và kết nối | **Hoàn thành** |
| 5 | Baseline + luật phát hiện + script tấn công | **Hoàn thành** (6/6 luật, gồm quét cổng) |
| 6 | Quản lý cảnh báo và sự cố | *(kế hoạch)* |
| 7 | Hỗ trợ ứng phó có xác nhận | *(kế hoạch)* |
| 8 | Dashboard | **Hoàn thành** (5 trang + Acknowledge/Resolve) |
| 9 | Demo và đánh giá | *(kế hoạch)* |

---

## Chương 4. Xây dựng hệ thống

### 4.1. Môi trường phát triển

| Thành phần | Phiên bản / ghi chú |
|---|---|
| Hệ điều hành | macOS (Apple Silicon, arm64) |
| Ảo hóa / triển khai | Docker Desktop, Docker Compose |
| Ngôn ngữ | Python 3.13 |
| Thư viện Modbus | pymodbus 3.15 (cố định phiên bản) |
| Phân tích gói | tcpdump, Wireshark (bộ giải mã Modbus sẵn có) |

### 4.2. Giai đoạn 1: Mô hình ICS giả lập (bồn nước)

#### 4.2.1. Thiết kế mô hình

Mô hình mô phỏng một bồn nước với: một **bơm** cấp nước, một **van xả**, và cảm
biến **mức nước**. PLC điều khiển bơm theo hai ngưỡng (bật khi mức xuống thấp, tắt
khi lên cao); HMI định kỳ giám sát trạng thái. Toàn bộ quá trình vật lý được mô
phỏng bằng phần mềm.

#### 4.2.2. Bản đồ địa chỉ Modbus

Một module dùng chung (`lab/modbus_map.py`) định nghĩa ý nghĩa từng địa chỉ, bảo
đảm PLC, HMI và các script kiểm thử hiểu nhất quán:

| Vùng | Địa chỉ | Ý nghĩa |
|---|---|---|
| Coil | 0 / 1 / 2 | bơm / van xả / chế độ tự động |
| Discrete Input | 0 / 1 | báo mức cao / báo mức thấp |
| Input Register | 0 / 1 / 2 | mức nước / lưu lượng vào / lưu lượng ra |
| Holding Register | 0 / 1 | ngưỡng tắt bơm / ngưỡng bật bơm |

Giá trị thanh ghi lưu dưới dạng số nguyên nhân 10 (ví dụ 800 = 80,0%).

#### 4.2.3. PLC giả lập

`lab/plc_sim.py` hiện thực một Modbus/TCP server (cổng 502) cùng logic điều khiển
và mô phỏng vật lý, gồm:

- **Khai báo vùng nhớ** với giá trị ban đầu; địa chỉ không khai báo sẽ trả về
  exception ILLEGAL DATA ADDRESS.
- **Chu kỳ quét** (0,5 giây/vòng): đọc coil và ngưỡng → chạy logic điều khiển hai
  ngưỡng (có trễ, tránh bơm bật/tắt liên tục) → mô phỏng mức nước thay đổi theo
  bơm/van → cập nhật giá trị cảm biến cho HMI.
- Vòng quét được bọc trong cơ chế bắt lỗi để không dừng đột ngột khi có sự cố
  nhất thời, mô phỏng tính liên tục của PLC thực.

#### 4.2.4. HMI giả lập

`lab/hmi_sim.py` đóng vai trò người vận hành: mỗi giây đọc trạng thái PLC (FC
1/2/3/4) và mỗi 60 giây ghi lại ngưỡng điều khiển (FC 6). Hành vi đều đặn này tạo
thành lưu lượng "bình thường" làm cơ sở cho baseline ở giai đoạn phát hiện.

#### 4.2.5. Đóng gói bằng Docker

`Dockerfile` đóng gói Python và pymodbus thành một image dùng chung. `docker-
compose.yml` dựng mạng riêng (`172.28.0.0/24`), gán **IP tĩnh** cho PLC
(`172.28.0.10`) và HMI (`172.28.0.20`) — cần thiết vì việc phát hiện dựa trên
danh tính thiết bị — và đặt **tên bridge cố định `br-ics`** để sensor bắt gói
đúng interface.

#### 4.2.6. Công cụ bắt và phân tích gói

Trên macOS, Docker Desktop chạy container trong một máy ảo Linux; bridge `br-ics`
và lưu lượng giữa các container nằm trong máy ảo đó, nên Wireshark chạy trực tiếp
trên host **không quan sát được**. Giải pháp là bắt gói từ một container ở chế độ
mạng host (quan sát được bridge trong máy ảo) rồi đưa dữ liệu ra ngoài:

- Script `lab/capture.sh` bắt gói và ghi ra file `.pcap` trong thư mục dự án để
  mở offline bằng Wireshark.
- Có thể xem trực tiếp theo thời gian thực bằng cách đẩy luồng tcpdump vào
  Wireshark qua pipe.

Cách tiếp cận này tương đương một **cổng SPAN/mirror** trên switch công nghiệp
thực, và chính là cơ chế mà sensor ở Giai đoạn 2 sẽ sử dụng.

#### 4.2.7. Kết quả kiểm thử Giai đoạn 1

| Nội dung kiểm thử | Kết quả |
|---|---|
| HMI đọc mức nước, biến thiên theo bơm/van | Đạt — vòng hỏi–đáp Modbus hoạt động đúng |
| Client ghi coil (tắt auto, bật bơm, đóng van) | Đạt — mức nước tăng từ 46,4% lên 52,4% trong 3 giây |
| Đọc địa chỉ không tồn tại | Đạt — PLC trả exception code 2 (ILLEGAL DATA ADDRESS) |
| Bắt gói trên `br-ics` | Đạt — 140 gói trong 15 giây, 112 gói Modbus |
| Wireshark giải mã Modbus | Đạt — hiển thị đúng FC, địa chỉ, số lượng |

Kết quả kiểm thử việc ghi coil cũng chứng minh luận điểm an ninh trung tâm của đề
tài: do Modbus không xác thực, PLC chấp nhận lệnh ghi từ bất kỳ nguồn nào, mở ra
kịch bản tấn công "tràn bồn" dùng để minh họa ở các giai đoạn sau.

#### 4.2.8. Các thuật toán sử dụng trong mô hình

Mô hình Giai đoạn 1 sử dụng các thuật toán và kỹ thuật sau:

**a) Chu kỳ quét đọc–tính–ghi (scan cycle).** PLC được mô phỏng theo vòng lặp vô
tận ba bước đặc trưng của PLC thực: đọc trạng thái đầu vào từ bộ nhớ → chạy logic
điều khiển → ghi kết quả ra bộ nhớ, với chu kỳ 0,5 giây. Trạng thái được đọc lại
ở mỗi vòng để lệnh ghi từ bên ngoài (HMI hoặc kẻ tấn công) có hiệu lực ngay ở
vòng kế tiếp. Logic điều khiển và giao tiếp Modbus qua mạng dùng chung một vùng
dữ liệu — đó là điểm liên kết giữa hai luồng xử lý.

**b) Điều khiển bang-bang có vùng trễ (hysteresis control).** Việc bật/tắt bơm
dùng hai ngưỡng: bật khi mức nước giảm xuống dưới ngưỡng thấp (30%), tắt khi vượt
ngưỡng cao (80%); trong khoảng giữa, bơm giữ nguyên trạng thái. Vùng giữa hai
ngưỡng (dead band) ngăn hiện tượng bơm đóng/mở liên tục (chattering) vốn xảy ra
nếu chỉ dùng một ngưỡng — tương tự nguyên lý của rơ-le nhiệt (thermostat). Logic
này chỉ hoạt động ở chế độ tự động; khi bị ghi tắt chế độ tự động, toàn bộ cơ chế
an toàn này bị vô hiệu — đây chính là điểm bị khai thác trong kịch bản tấn công.

**c) Tích phân số Euler tiến (forward Euler integration).** Mức nước tuân theo
phương trình vi phân:

    d(level)/dt = flow_in − flow_out

Do không thể giải liên tục bằng máy tính, mô hình rời rạc hóa bằng phương pháp
Euler tiến:

    level(t + Δt) = level(t) + (flow_in − flow_out) · Δt

với Δt là chu kỳ quét (0,5 giây), lưu lượng vào bằng 2,0%/giây khi bơm chạy và
lưu lượng ra 0,8%/giây khi van mở. Giá trị mức nước được kẹp trong khoảng [0,
100]% để mô phỏng giới hạn vật lý của bồn (không âm, không vượt đầy).

**d) Poll định kỳ và lập lịch bằng bộ đếm (HMI).** HMI đọc trạng thái PLC mỗi 1
giây (tần suất cố định) và dùng phép chia lấy dư trên một bộ đếm vòng lặp để thực
hiện thao tác ghi setpoint thưa hơn (mỗi 60 vòng). Lưu lượng đều đặn này là cơ sở
để xây dựng baseline ở giai đoạn phát hiện.

**e) Tự kết nối lại khi lỗi (HMI).** HMI kiểm tra trạng thái kết nối ở mỗi vòng và
tự kết nối lại khi mất kết nối, bảo đảm hoạt động liên tục kể cả khi PLC khởi động
chậm hơn hoặc mạng gián đoạn tạm thời.

**f) Bắt gói qua container ở chế độ mạng host.** Để vượt qua giới hạn của Docker
trên macOS (lưu lượng giữa các container nằm trong máy ảo Linux), gói tin được bắt
từ một container chạy ở chế độ mạng host — quan sát được bridge bên trong máy ảo —
với quyền NET_RAW, rồi ghi ra file `.pcap` thông qua một thư mục được mount về máy
host. Kỹ thuật này tương đương một cổng SPAN/mirror trên switch công nghiệp và là
nền tảng cho sensor ở Giai đoạn 2.

### 4.3. Giai đoạn 2: Sensor bắt và phân tích gói Modbus

#### 4.3.1. Vai trò và nguyên lý

Sensor (`lab/sensor.py`) là thành phần đầu tiên của nền tảng giám sát, hiện thực
bước **Monitor**. Nó bắt **thụ động** lưu lượng Modbus trên bridge `br-ics`, giải
mã từng thông điệp và xuất ra các **event chuẩn hóa** để các thành phần phía sau
(backend, detection engine) xử lý. Sensor chạy ở chế độ mạng host (như mục
4.2.6), không tham gia mạng `ics_net` nên không bị PLC/HMI "nhìn thấy" — đúng
tính chất giám sát thụ động. Việc bắt gói dùng thư viện **Scapy**.

Sensor hỗ trợ hai chế độ: *live* (sniff trực tiếp trên interface) và *offline*
(đọc lại file `.pcap`), giúp kiểm thử logic giải mã mà không cần bắt gói thật.

#### 4.3.2. Phân tích gói

Mỗi gói TCP cổng 502 được tách thành các ADU Modbus (MBAP 7 byte + PDU), theo các
quy tắc:

- **Phân biệt request/response theo hướng:** gói đi *tới* cổng 502 là request, đi
  *từ* cổng 502 là response. Cùng một function code có cách đọc dữ liệu khác nhau
  giữa hai hướng.
- **Phát hiện gói lỗi:** function code ≥ 0x80 là exception; byte tiếp theo là
  Exception Code (ví dụ 2 = ILLEGAL DATA ADDRESS).
- **Nhiều ADU trong một segment:** một segment TCP có thể chứa nhiều thông điệp
  Modbus, nên sensor lặp tách theo trường Length trong MBAP.
- **Giải mã PDU theo function code:** lệnh đọc (FC 1–4) có địa chỉ + số lượng;
  ghi đơn (FC 5/6) có địa chỉ + giá trị; phản hồi lệnh đọc có byte-count kèm dữ
  liệu (bit cho coil, thanh ghi 16-bit cho register).

#### 4.3.3. Cấu trúc event chuẩn hóa

Mỗi thông điệp Modbus được chuyển thành một bản ghi JSON với các trường:

| Trường | Ý nghĩa |
|---|---|
| `ts` | Thời điểm bắt gói |
| `src_ip` / `dst_ip` | Địa chỉ IP nguồn / đích |
| `src_mac` | Địa chỉ MAC nguồn (nhận diện thiết bị ở tầng 2) |
| `src_port` / `dst_port` | Cổng TCP nguồn / đích |
| `transaction_id` | Mã giao dịch (dùng ghép request với response) |
| `unit_id` | Địa chỉ thiết bị Modbus |
| `direction` | `request` hoặc `response` |
| `function_code` / `fc_name` | Mã và tên chức năng |
| `is_write` | Có phải lệnh ghi (FC 5/6/15/16) |
| `is_exception` / `exception_code` / `exception_name` | Thông tin gói lỗi |
| `address` / `count` | Địa chỉ và số lượng (lệnh đọc / ghi nhiều) |
| `value` / `values` | Giá trị ghi đơn / danh sách giá trị đọc/ghi được |
| `event_id` | Định danh duy nhất của event (để backend chống trùng) |
| `kind` | Loại event: `modbus` hoặc `tcp` (SYN cho luật quét cổng) |
| `raw` | ADU thô dạng hex, giữ làm bằng chứng điều tra |
| `matched` / `req_address` / `req_count` / `rtt_ms` | Kết quả ghép với request và thời gian đáp ứng |

Đây chính là đầu vào cho việc phát hiện thiết bị (Giai đoạn 4) và các luật phát
hiện (Giai đoạn 5). Ở Giai đoạn 3, sensor sẽ gửi các event này tới backend thay
vì in ra màn hình.

#### 4.3.4. Kết quả kiểm thử

| Nội dung kiểm thử | Kết quả |
|---|---|
| Giải mã offline file `.pcap` | Đạt — đọc đúng chuỗi HMI poll: FC4 → `[488, 0, 8]` (mức 48,8%), FC1 → `[0,1,1,…]` (bơm tắt, van mở, auto bật), FC3 → `[800, 300]` (ngưỡng 80%/30%) |
| Giải mã live trong container | Đạt — sensor in event thời gian thực khi lab chạy |
| Bắt lệnh ghi | Đạt — nhận diện FC6 (ghi thanh ghi) và FC5 (ghi coil) với `is_write=true`, kèm IP/MAC nguồn |
| Giải mã exception | Đạt — FC ≥ 0x80 được nhận là gói lỗi, đọc đúng Exception Code |

Đáng chú ý, trong kiểm thử lệnh ghi, nguồn gửi lệnh là một địa chỉ **khác HMI**;
sensor ghi nhận đầy đủ IP/MAC nguồn và cờ `is_write`. Đây chính là dữ liệu mà luật
"ghi trái phép từ thiết bị lạ" ở Giai đoạn 5 sẽ dựa vào.

### 4.4. Giai đoạn 3: Backend, cơ sở dữ liệu và WebSocket

#### 4.4.1. Kiến trúc và tách mạng

Backend (`lab/backend.py`, dùng **FastAPI**) là trung tâm nền tảng giám sát: nhận
event từ sensor, lưu vào **PostgreSQL** và đẩy real-time cho dashboard qua
**WebSocket**. Luồng dữ liệu:

```
Sensor (br-ics) --lô event JSON--> POST /api/events --> Backend (FastAPI)
                                                          │            │
                                                    PostgreSQL     WebSocket /ws --> Dashboard
```

Nền tảng giám sát (backend + database) được đặt trên **một mạng riêng
(`mon_net`)**, tách khỏi mạng công nghiệp `ics_net`. Sensor chạy ở chế độ mạng
host và gửi event về backend qua cổng 8000 đã publish. Việc tách mạng phản ánh
đúng thực tế: hệ giám sát không nằm chung mạng với thiết bị bị giám sát.

#### 4.4.2. Cơ chế xử lý

- **Gửi theo lô, bất đồng bộ:** sensor gom event vào buffer và một luồng nền gửi
  cả lô mỗi 0,5 giây. Việc này tách HTTP khỏi luồng bắt gói, để khi lưu lượng dồn
  dập (ví dụ tấn công DoS ở giai đoạn sau) không làm nghẽn việc sniff. Lỗi mạng
  chỉ được ghi log, không làm sensor dừng.
- **Ghi theo lô:** backend dùng `executemany` để chèn cả lô event trong một lần.
- **Tự kết nối lại DB:** PostgreSQL cần vài giây để sẵn sàng, backend thử kết nối
  lại nhiều lần trước khi phục vụ.
- **Phát tán:** sau khi lưu, backend gửi lô event tới mọi WebSocket client đang
  kết nối; client nào rớt sẽ bị loại khỏi danh sách.

#### 4.4.3. Giao diện API

| Phương thức | Đường dẫn | Chức năng |
|---|---|---|
| POST | `/api/events` | Nhận một lô event (JSON array) từ sensor |
| GET | `/api/events?limit=N` | Lấy N event gần nhất (cho dashboard/kiểm thử) |
| GET | `/api/stats` | Thống kê nhanh: tổng event, số lệnh ghi, gói lỗi, số thiết bị, số kết nối |
| WS | `/ws` | Kênh đẩy event thời gian thực cho dashboard |

#### 4.4.4. Cơ sở dữ liệu

Bảng `events` (`db/init.sql`) lưu toàn bộ các trường của event chuẩn hóa, trong
đó giá trị ghi đơn vào cột `value`, danh sách giá trị đọc được vào cột JSONB
`values_json`. Có chỉ mục theo thời gian, IP nguồn và function code để truy vấn
nhanh. Script được PostgreSQL tự chạy khi khởi tạo database.

#### 4.4.5. Kết quả kiểm thử

| Nội dung kiểm thử | Kết quả |
|---|---|
| Sensor gửi event về backend | Đạt — backend nhận POST `/api/events` trả 200 OK liên tục |
| Lưu vào PostgreSQL | Đạt — truy vấn `/api/events` và `/api/stats` thấy 494 event, giải mã đúng (vd holding register `[800, 300]`) |
| Đẩy real-time qua WebSocket | Đạt — client nhận được lô 8 event ngay khi lab sinh traffic |
| Cờ phục vụ phát hiện | Đạt — lệnh ghi (`is_write`) và gói lỗi (`is_exception`, exception code 2) được lưu đúng; thống kê ghi nhận 4 lệnh ghi, 1 gói lỗi, lưu lượng từ 3 địa chỉ nguồn |

Kết quả cho thấy toàn bộ đường đi dữ liệu Monitor đã hoàn chỉnh: từ gói tin trên
dây, qua giải mã, lưu trữ, tới hiển thị thời gian thực — sẵn sàng cho việc nhận
diện thiết bị (Giai đoạn 4) và phát hiện tấn công (Giai đoạn 5).

### 4.5. Giai đoạn 4: Phát hiện thiết bị và kết nối

#### 4.5.1. Nguyên lý

Đây là bước **Discover**. Backend tự suy ra danh sách thiết bị (tài sản) và các
kết nối trực tiếp từ dòng event, **không cần cấu hình thủ công**. Quy ước phân
vai dựa trên hướng gói:

- **request:** nguồn là *client* (HMI/máy trạm), đích là *server* (PLC).
- **response:** nguồn là *server* (PLC), đích là *client*.

Nói cách khác, thiết bị **phục vụ ở cổng 502** là PLC, thiết bị **chủ động gọi
tới** là HMI/máy trạm. Vai trò server được ưu tiên (*server wins*): một thiết bị
từng đóng vai PLC luôn giữ nhãn `plc`. Địa chỉ MAC chỉ biết được của bên gửi
(`src_mac` trong event) nên bên nhận để trống, sẽ được điền khi chính nó đóng vai
bên gửi ở một event khác.

#### 4.5.2. Lưu trữ

Hai bảng mới:

- `assets` (ip, mac, role, first_seen, last_seen, event_count): mỗi thiết bị một
  dòng.
- `connections` (src_ip, dst_ip, dst_port, first_seen, last_seen, request_count):
  mỗi cặp client → server:port một dòng.

Cả hai được cập nhật bằng câu lệnh **UPSERT** theo từng lô event, nằm trong **cùng
giao dịch** với việc ghi event để dữ liệu luôn nhất quán. Backend tự chạy DDL tạo
bảng lúc khởi động (idempotent) nên hoạt động kể cả khi database đã có từ trước.

#### 4.5.3. API

| Phương thức | Đường dẫn | Chức năng |
|---|---|---|
| GET | `/api/assets` | Danh sách thiết bị tự phát hiện (kèm vai trò, MAC, số event) |
| GET | `/api/connections` | Danh sách kết nối client → server:port (kèm số request) |

#### 4.5.4. Kết quả kiểm thử

Cho lab chạy với lưu lượng bình thường, sau đó thêm một "máy lạ" (`172.28.0.2`)
gửi vài lệnh tới PLC:

| Nội dung kiểm thử | Kết quả |
|---|---|
| Nhận diện PLC | Đạt — `172.28.0.10` được gán vai trò **plc** |
| Nhận diện HMI | Đạt — `172.28.0.20` được gán vai trò **hmi/workstation** |
| Nhận diện máy lạ | Đạt — `172.28.0.2` xuất hiện thành một tài sản riêng (client) |
| Phát hiện kết nối | Đạt — `172.28.0.20 → 172.28.0.10:502` (80 request) và `172.28.0.2 → 172.28.0.10:502` (2 request) |

Việc máy lạ hiện ra thành một tài sản và một kết nối riêng biệt chính là cơ sở để
các luật "thiết bị lạ truy cập PLC" và "kết nối mới tới PLC" ở Giai đoạn 5 hoạt
động: baseline chỉ gồm HMI và PLC, nên mọi thiết bị/kết nối ngoài baseline đều
đáng ngờ.

### 4.6. Giai đoạn 5: Học baseline và phát hiện tấn công

Đây là phần lõi của đề tài, hiện thực hai bước **Detect** và **Alert**.

#### 4.6.1. Kiến trúc Detection Engine

Logic phát hiện được tách thành module riêng (`lab/detection.py`, lớp `Detector`)
để backend gọi mỗi khi nhận một lô event. Detection Engine có **hai chế độ**:

- **Học** (chưa chốt baseline): tích lũy baseline từ lưu lượng bình thường,
  **không** sinh cảnh báo.
- **Phát hiện** (đã chốt baseline): so từng event với baseline và sinh cảnh báo
  khi phát hiện lệch.

Baseline được lưu vào database (bảng `baseline`) nên tồn tại qua các lần khởi động
lại. Engine kết hợp hai phương pháp đã nêu ở mục 2.5: **dựa trên luật** (thiết bị
lạ, ghi trái phép, kết nối mới, gói lỗi) và **dựa trên thống kê** (tần suất bất
thường theo cửa sổ trượt). Mỗi cảnh báo được **chống trùng** bằng cooldown theo
cặp (luật, nguồn), để một đợt tấn công không tạo ra hàng loạt cảnh báo giống nhau.

#### 4.6.2. Baseline (đường cơ sở)

Trong pha học, hệ thống ghi nhận ba tập hợp: **thiết bị đã biết** (IP), **kết nối
đã biết** (nguồn → đích:cổng), và **nguồn được phép ghi**. Quy trình vận hành:
chạy hệ thống trong một khoảng mạng sạch để học, sau đó gọi
`POST /api/baseline/freeze` để chốt baseline và bật chế độ phát hiện.

> **Giả định quan trọng:** mạng phải "sạch" (không có tấn công) trong pha học.
> Nếu học nhầm lúc đang bị tấn công, hệ thống sẽ coi hành vi tấn công là bình
> thường và bỏ sót về sau.

#### 4.6.3. Các luật phát hiện

| Luật | Điều kiện kích hoạt | Mức |
|---|---|---|
| Ghi trái phép | Lệnh ghi không khớp chữ ký được phép (nguồn, PLC đích, Unit ID, FC, địa chỉ) | Critical |
| Thiết bị lạ | Nguồn (IP) không có trong baseline gửi request tới PLC | High |
| Tần suất bất thường / DoS | Số request/giây từ một nguồn vượt ngưỡng (cửa sổ trượt 1 giây) | High |
| Truy cập thanh ghi bất thường | PLC trả về gói lỗi (exception) do truy cập địa chỉ không hợp lệ | Medium |
| Quét cổng | Một nguồn chạm nhiều cổng đích khác nhau trong thời gian ngắn (từ event TCP SYN) | Medium |
| Kết nối mới tới PLC | Cặp (nguồn, đích, cổng) chưa từng thấy trong baseline | Low |

Mỗi cảnh báo được lưu kèm **bằng chứng** (các event gây ra nó) trong bảng `alerts`,
và được đẩy real-time cho dashboard qua WebSocket.

#### 4.6.4. Kịch bản tấn công kiểm chứng

Một máy tấn công giả lập (`lab/attacker.py`) chạy từ IP lạ `172.28.0.66`, với bốn
chế độ, mỗi chế độ nhắm một luật:

| Mode | Hành vi | Luật minh họa |
|---|---|---|
| `probe` | Kết nối và đọc một lần | Thiết bị lạ + Kết nối mới |
| `write` | Tắt auto, đóng van, ép bơm chạy (kịch bản tràn bồn) | Ghi trái phép |
| `recon` | Đọc 30 địa chỉ không tồn tại | Truy cập thanh ghi bất thường |
| `dos` | Gửi 400 request liên tiếp | Tần suất bất thường / DoS |
| `scan` | Thử kết nối tới 18 cổng khác nhau | Quét cổng |

#### 4.6.5. Kết quả kiểm thử

Sau khi học baseline (2 thiết bị, 1 kết nối, chữ ký ghi hợp lệ của HMI là
`FC6 → HR0`) rồi chốt, lần lượt chạy năm kịch bản tấn công:

| Nội dung kiểm thử | Kết quả |
|---|---|
| Không báo động giả | Đạt — **0 cảnh báo** trong suốt lưu lượng bình thường sau khi chốt baseline |
| Ghi trái phép | Đạt — cảnh báo **Critical**: ghi coil `auto` từ `172.28.0.66` |
| Thiết bị lạ | Đạt — cảnh báo **High**: `172.28.0.66` không có trong baseline |
| DoS | Đạt — cảnh báo **High**: ~31 request/giây từ `172.28.0.66` |
| Truy cập thanh ghi bất thường | Đạt — cảnh báo **Medium**: exception code 2 |
| Quét cổng | Đạt — cảnh báo **Medium**: 11 cổng khác nhau từ `172.28.0.66` trong 5s |
| Kết nối mới | Đạt — cảnh báo **Low**: `172.28.0.66 → 172.28.0.10:502` |

Kết quả cho thấy cả sáu luật hoạt động đúng, mỗi kịch bản tấn công sinh đúng loại
cảnh báo của nó, trong khi lưu lượng bình thường không gây cảnh báo nào — tức tỉ
lệ phát hiện cao và tỉ lệ báo động giả bằng không trên tập kiểm thử này.

#### 4.6.6. Giao diện API bổ sung

| Phương thức | Đường dẫn | Chức năng |
|---|---|---|
| GET | `/api/alerts` | Danh sách cảnh báo (kèm bằng chứng) |
| GET | `/api/baseline` | Xem baseline hiện tại |
| POST | `/api/baseline/freeze` | Chốt baseline, bật chế độ phát hiện |
| POST | `/api/baseline/reset` | Xóa baseline, quay lại chế độ học |

### 4.7. Rà soát, sửa lỗi và củng cố độ tin cậy

Sau khi hoàn thành các giai đoạn 1–5, dự án được rà soát một lượt để tăng độ
chính xác của dữ liệu giám sát, độ tin cậy của việc truyền/lưu event và tính nhất
quán của thiết kế. Các nhóm vấn đề đã xử lý và cách kiểm chứng:

| # | Vấn đề | Đã sửa | Kiểm chứng |
|---|---|---|---|
| 1 | Giải mã từng segment TCP rời rạc → mất ADU bị chia, đếm trùng khi truyền lại | Ghép luồng TCP hai chiều theo sequence number; loại gói truyền lại; chỉ giải mã khi đủ theo MBAP Length | Request chia 2 segment → đúng 1 event; truyền lại → 0 event thêm |
| 2 | FC15/16 không giữ giá trị ghi; FC5 giá trị lạ bị chuẩn hóa sai; thiếu bằng chứng | Giải mã đủ FC15/16 (giữ `values`), FC5 lạ đánh dấu `invalid`, cắt bit đệm theo quantity, giữ `raw` ADU và `parse_error` | `[800,300]` khác `[1200,300]`; malformed sinh `parse_error`, không sập |
| 3 | Chưa ghép request–response; đếm ghi lẫn request+response | Ghép theo (phiên, Unit ID, Transaction ID), gắn địa chỉ/quantity của request, tính RTT; đếm ghi theo request | Thống kê `write_requests` đếm 1 cho mỗi giao dịch ghi |
| 4 | Làm tròn timestamp còn 3 chữ số | Giữ nguyên độ phân giải capture (epoch, microsecond) | Lưu `1700000000.123456` không bị cắt |
| 5 | Xóa buffer trước khi gửi thành công → mất event khi lỗi mạng | Chỉ xóa khỏi hàng đợi khi backend xác nhận; retry có backoff; `event_id` + chống trùng; flush nốt khi dừng; hàng đợi có giới hạn | Khi backend lỗi 500, sensor giữ lại event và gửi lại được sau khi sửa |
| 6 | Broadcast WebSocket duyệt trực tiếp tập client; client chậm chặn ingest | Duyệt bản sao, có timeout mỗi client, phát nền tách khỏi đường nhận event; thêm `after_id` để dashboard lấy lại event | Ingest trả kết quả ngay sau khi lưu, không phụ thuộc WebSocket |
| 7 | `list[dict]` không kiểm tra; IP/MAC do bên gọi tự khai | Schema pydantic; event sai → quarantine (không lỗi DB); chống trùng theo `event_id`; token sensor tùy chọn | Event thiếu `ts` → quarantine, HTTP 200; gửi trùng → 1 dòng |
| 8 | Discovery giữ MAC đầu; dùng assets làm baseline | `first_seen=min`, `last_seen=max`; lưu lịch sử MAC; vai trò là suy đoán (`role_source`); baseline là bản chốt riêng; quyền ghi theo chữ ký (nguồn/đích/unit/FC/địa chỉ) | Pha học bao phủ ghi setpoint hợp lệ của HMI (write_rule) |
| 9 | Sensor chỉ bắt cổng 502, bỏ gói không payload | Bắt thêm gói SYN, phát event TCP riêng (`kind=tcp`); luật quét cổng dùng event này | `scan` 18 cổng → cảnh báo quét cổng |
| 10 | Bơm trong auto lấy lại từ coil; thiếu kiểm tra setpoint; kẹp mức 100% | Tách trạng thái auto khỏi lệnh tay (auto ghi đè coil); từ chối setpoint sai qua action hook; theo dõi lượng tràn; HMI kiểm tra response ghi | Setpoint sai bị PLC từ chối; auto ghi đè lệnh bơm ngoài; chế độ tay vẫn cho tấn công |

**Giới hạn còn lại (được ghi nhận có chủ đích):**

- Ghép luồng TCP xử lý tốt chia nhỏ, gộp và truyền lại; với gói **đến khác thứ
  tự** thì resync an toàn (bỏ phần dở) thay vì sắp xếp lại đầy đủ — chấp nhận được
  trong mạng ICS nội bộ ít mất gói.
- Quyền ghi kiểm tra tới mức địa chỉ; **kiểm tra theo dải giá trị** cho phép là
  hướng mở rộng.
- Xác thực nguồn sensor bằng token dùng chung (bật khi đặt `SENSOR_TOKEN`); chưa
  dùng chứng chỉ/mTLS.

### 4.8. Thiết kế ứng phó và đánh giá (định hướng, chưa triển khai)

Phần này mô tả thiết kế và *hợp đồng dữ liệu* cho các chức năng chưa code (Giai
đoạn 7 và 9), để báo cáo phản ánh đúng hiện trạng.

**Quy trình ứng phó (Giai đoạn 7):** phát hiện → operator **duyệt** → cô lập nguồn
→ phục hồi trạng thái qua kênh vận hành được phép → xác minh → ghi **audit**. Các
điểm thiết kế quan trọng:

- Executor thực thi firewall phải nằm trong **namespace thực sự xử lý traffic ICS**
  (container `NET_ADMIN` chèn luật vào chuỗi tác động lên bridge `br-ics`), và phải
  có hiệu lực **cả với kết nối đã tồn tại**, không chỉ kết nối mới.
  > **Đã kiểm chứng cơ chế (A0):** container `--network host --cap-add NET_ADMIN`
  > chạy `iptables -I DOCKER-USER -s <IP> -j DROP` chặn đúng IP nguồn trên bridge
  > (attacker `.66` mất kết nối tới PLC, thiết bị `.50` và HMI `.20` vẫn hoạt động),
  > ngắt cả kết nối đang mở, và gỡ được bằng `-D`. Rủi ro khả thi của chức năng
  > chặn đã được loại bỏ; phần còn lại là quy trình duyệt + khôi phục + audit.
- **Chặn nguồn tấn công KHÔNG đồng nghĩa khôi phục trạng thái PLC**: sau khi cô
  lập, vẫn phải phục hồi trạng thái vật lý (bật lại auto, mở van, đặt lại setpoint)
  qua kênh được phép, rồi **xác minh** mức nước trở lại vùng an toàn.
- Phân biệt **hoàn tác firewall** (gỡ luật chặn) với **phục hồi quá trình vật lý**
  (hai hành động độc lập, audit riêng).
- Hợp đồng dữ liệu: bảng `response_actions` (id, alert_id, loại hành động, tham số,
  trạng thái duyệt, người duyệt, thời điểm, kết quả, audit).

**Đo lường đánh giá (Giai đoạn 9):**

- **Tỉ lệ phát hiện / báo động giả** tính theo **sự cố (incident)**, không theo
  từng cảnh báo hay từng gói: một cuộc tấn công sinh nhiều cảnh báo vẫn là một sự
  cố; một giao dịch gồm request+response là một đơn vị, không đếm đôi.
- **Độ trễ phát hiện** = thời điểm sinh cảnh báo − thời điểm gói tấn công đầu tiên
  (dùng các mốc thời gian đã phân biệt: capture, nhận, lưu, cảnh báo).

### 4.9. Giai đoạn 8: Dashboard giám sát

Dashboard trực quan hóa toàn bộ dữ liệu đã có, hiện thực bước **Investigate**.

#### 4.9.1. Kiến trúc

Dashboard là một trang tĩnh (`web/index.html`) **phục vụ ngay từ backend** qua
`StaticFiles` (cùng origin với API nên không vướng CORS, không cần thêm service).
Dùng **React qua CDN** (không cần bước build dễ vỡ), **topology vẽ bằng SVG**, cập
nhật **thời gian thực qua WebSocket** kết hợp poll định kỳ các API.

#### 4.9.2. Các trang

| Trang | Nguồn dữ liệu | Nội dung |
|---|---|---|
| Tổng quan | `/api/stats`, `/api/baseline/*` | Thẻ số liệu, điều khiển chốt/học lại baseline, cảnh báo theo mức |
| Thiết bị | `/api/assets` | Danh sách tài sản (IP, vai trò suy đoán, MAC, số sự kiện, thời điểm) |
| Topology | `/api/assets` + `/api/connections` | Sơ đồ mạng; nguồn có cảnh báo tô **đỏ** |
| Live Traffic | `WS /ws` | Lưu lượng Modbus giải mã chạy thời gian thực |
| Cảnh báo | `/api/alerts` + `WS /ws` | Bảng cảnh báo theo mức, xem bằng chứng, nút **Acknowledge/Resolve** |

Nút Acknowledge/Resolve gọi `POST /api/alerts/{id}/status` để đổi trạng thái cảnh
báo (`new → acknowledged → resolved`).

#### 4.9.3. Kết quả kiểm thử

| Nội dung | Kết quả |
|---|---|
| Backend phục vụ dashboard tại `/` | Đạt — trả `index.html`, API `/api/*` và `/ws` không bị che |
| JSX biên dịch | Đạt — không lỗi cú pháp |
| Acknowledge/Resolve | Đạt — đổi và lưu đúng trạng thái cảnh báo |
| Hiển thị real-time | Đạt — cảnh báo và lưu lượng cập nhật qua WebSocket; topology đánh dấu nguồn tấn công |

### 4.10. Các giai đoạn tiếp theo

*(Đang thực hiện — còn: hoàn thiện ứng phó có duyệt (chặn IP + khôi phục, cơ chế
đã kiểm chứng ở mục 4.8), gom sự cố, và demo + đánh giá định lượng.)*

---

## Chương 5. Phương pháp và quy trình phát triển

Quá trình xây dựng tuân theo một quy trình có kiểm chứng từng bước, nhằm giảm rủi
ro kỹ thuật sớm:

1. **Khảo sát môi trường:** xác định cấu hình máy và công cụ sẵn có trước khi
   viết mã (kiến trúc CPU, Docker, Python, công cụ bắt gói).
2. **Điều tra API thư viện:** do pymodbus bản 3.15 thay đổi mô hình lập trình so
   với các tài liệu phổ biến, API được khảo sát trực tiếp từ mã nguồn và **cố
   định phiên bản** để bảo đảm khả năng tái lập.
3. **Phát triển theo hướng kiểm thử:** kiểm thử logic cục bộ trước khi đóng gói
   Docker để rút ngắn vòng lặp thử–sửa.
4. **Gỡ rủi ro sớm:** hai rủi ro lớn nhất — khả năng bắt gói giữa các container
   trên macOS, và khả năng ghi trái phép vào PLC — được kiểm chứng ngay từ đầu.
5. **Hoàn thiện và kiểm thử hồi quy:** bổ sung tài liệu, cơ chế chịu lỗi và chạy
   lại kiểm thử sau mỗi thay đổi.

---

## Chương 6. Kết luận và hướng phát triển

*(Sơ bộ — sẽ hoàn thiện ở cuối đồ án.)*

Đến thời điểm hiện tại, đề tài đã xây dựng thành công một **mô hình ICS giả lập**
hoàn chỉnh dựa trên Modbus/TCP, kèm công cụ bắt và phân tích gói, tạo nền tảng cho
việc phát triển nền tảng giám sát. Mô hình đã kiểm chứng được cả hoạt động bình
thường lẫn khả năng bị thao túng, phục vụ cho việc phát triển và đánh giá các luật
phát hiện.

Hướng phát triển tiếp theo bám theo lộ trình ở mục 3.4: hoàn thiện sensor, backend
và cơ sở dữ liệu, bộ luật phát hiện, dashboard, và cuối cùng là kịch bản demo kèm
đánh giá định lượng (tỉ lệ phát hiện, tỉ lệ báo động giả, độ trễ phát hiện). Có
thể thay PLC phần mềm bằng OpenPLC để tăng tính thực tế.

---

## Tài liệu tham khảo

1. Modbus Organization, *MODBUS Application Protocol Specification V1.1b3*, 2012.
2. Modbus Organization, *MODBUS Messaging on TCP/IP Implementation Guide V1.0b*.
3. NIST, *SP 800-82 Rev. 3 – Guide to Operational Technology (OT) Security*, 2023.
4. MITRE, *ATT&CK for ICS* — https://attack.mitre.org/matrices/ics/
5. pymodbus — Tài liệu thư viện — https://pymodbus.readthedocs.io/
6. Scapy — Tài liệu thư viện — https://scapy.readthedocs.io/
7. FastAPI — Tài liệu khung web — https://fastapi.tiangolo.com/
8. PostgreSQL — Tài liệu — https://www.postgresql.org/docs/
9. *(Bổ sung các nguồn khác khi hoàn thiện các chương sau.)*

---

## Phụ lục A. Hướng dẫn cài đặt và chạy

Yêu cầu: Docker Desktop đang chạy.

```bash
# Khởi động mô hình ICS giả lập
docker compose up -d --build
docker compose logs -f plc      # theo dõi mức nước dao động 30%–80%
docker compose logs -f hmi      # theo dõi HMI đọc trạng thái PLC

# Bắt gói Modbus ra file để phân tích bằng Wireshark
./lab/capture.sh 30 capture.pcap
open -a Wireshark capture.pcap

# Dừng mô hình
docker compose down
```

Nếu gặp lỗi `docker-credential-desktop: executable file not found`, bổ sung vào
`~/.zshrc`:

```bash
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
```

---

## Phụ lục B. Bảng tham số và biến

### B.1. Tham số cấu hình

| Tham số | Giá trị | Đơn vị | Ý nghĩa |
|---|---|---|---|
| `SCAN_TIME` | 0,5 | giây | Chu kỳ quét của PLC (bước thời gian Δt trong tích phân Euler) |
| `PUMP_RATE` | 2,0 | %/giây | Tốc độ tăng mức nước khi bơm chạy |
| `DRAIN_RATE` | 0,8 | %/giây | Tốc độ giảm mức nước khi van mở |
| `ALARM_HIGH` / `ALARM_LOW` | 90 / 10 | % | Ngưỡng bật cờ cảnh báo mức cao/thấp |
| `sp_high` / `sp_low` | 80 / 30 | % | Ngưỡng tắt/bật bơm (lưu trong holding register) |
| `POLL_INTERVAL` | 1,0 | giây | Chu kỳ HMI đọc trạng thái PLC |
| `SETPOINT_EVERY` | 60 | vòng | Chu kỳ HMI ghi lại setpoint |
| `PORT` | 502 | — | Cổng Modbus/TCP |
| `DEVICE_ID` | 1 | — | Unit ID của PLC |

**Lưu ý:** hệ thống có hai bộ ngưỡng riêng biệt. `ALARM_HIGH/ALARM_LOW` là hằng
số cố định chỉ dùng để bật cờ cảnh báo (discrete input); còn `sp_high/sp_low` là
ngưỡng điều khiển bơm, được lưu trong holding register nên **có thể bị HMI hoặc
kẻ tấn công ghi thay đổi** — đây là điểm liên quan trực tiếp tới an ninh.

### B.2. Biến trạng thái chính

| Biến | Kiểu | Ý nghĩa |
|---|---|---|
| `level` | số thực | Mức nước hiện tại (0–100%); là biến trạng thái duy nhất mang "trí nhớ" của mô phỏng — giá trị mỗi vòng phụ thuộc vòng trước |
| `pump` / `valve` / `auto` | luận lý | Trạng thái bơm / van / chế độ tự động, đọc từ coil mỗi vòng quét |
| `flow_in` / `flow_out` | số thực | Lưu lượng vào/ra tức thời, đầu vào cho công thức tích phân Euler |
| `cycle` (HMI) | số nguyên | Bộ đếm vòng poll, dùng để lập lịch ghi setpoint định kỳ |

### B.3. Bản đồ địa chỉ Modbus

Xem chi tiết tại mục [4.2.2](#422-bản-đồ-địa-chỉ-modbus). Toàn bộ địa chỉ được định
nghĩa tập trung trong module `lab/modbus_map.py` để PLC, HMI và các thành phần
khác dùng nhất quán.
