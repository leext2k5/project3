#!/usr/bin/env sh
# Bắt lưu lượng Modbus giữa các container, lưu ra file .pcap để mở bằng Wireshark.
#
# Vì sao cần script này: trên macOS, bridge "br-ics" nằm trong máy ảo Linux của
# Docker Desktop, nên Wireshark chạy trên Mac KHÔNG thấy interface này. Ta bắt
# gói từ một container ở chế độ mạng host (nhìn thấy bridge trong VM), rồi ghi
# file .pcap ra thư mục dự án trên Mac để mở offline.
#
# Dùng:   ./lab/capture.sh [số_giây] [tên_file]
# Ví dụ:  ./lab/capture.sh 30 capture.pcap

DUR="${1:-30}"
OUT="${2:-capture.pcap}"
IFACE="${IFACE:-br-ics}"
FILTER="${FILTER:-tcp port 502}"

DIR="$(cd "$(dirname "$0")/.." && pwd)"   # thư mục gốc dự án (nơi lưu file .pcap)
echo "Bắt gói $DUR giây trên $IFACE (lọc: $FILTER) -> $OUT"
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$DIR:/out" alpine sh -c \
  "apk add -q --no-cache tcpdump >/dev/null 2>&1; \
   timeout $DUR tcpdump -i $IFACE -U -w /out/$OUT '$FILTER'"
echo "Xong -> $DIR/$OUT"
echo "Mở bằng: open -a Wireshark $DIR/$OUT   (hoặc Wireshark > File > Open)"
