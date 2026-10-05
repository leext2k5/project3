"""PLC giả lập: Modbus/TCP server + logic điều khiển + mô phỏng vật lý bồn nước.

Sửa theo review (mục 10):
  - Tách trạng thái điều khiển tự động (auto_pump nội bộ) khỏi lệnh tay: ở chế độ
    auto, PLC tự quyết định bơm và GHI ĐÈ coil mỗi chu kỳ nên lệnh ghi ngoài không
    có hiệu lực trong vùng giữa hai ngưỡng; ở chế độ tay, bơm theo lệnh coil.
  - Kiểm tra setpoint hợp lệ (0 ≤ SP_LOW < SP_HIGH ≤ 1000) bằng action hook, kiểm
    tra toàn bộ giá trị của lệnh ghi nhiều thanh ghi cùng nhau; sai thì TỪ CHỐI.
  - Theo dõi lượng nước tràn (vượt 100%) thành đại lượng có đơn vị rõ ràng.
"""

import asyncio
import logging
import os

from pymodbus.constants import ExcCodes
from pymodbus.server import ModbusTcpServer
from pymodbus.simulator import DataType, SimData, SimDevice

import modbus_map as m

log = logging.getLogger("plc")

PORT = int(os.getenv("PLC_PORT", "502"))
SCAN_TIME = 0.5
PUMP_RATE = 2.0
DRAIN_RATE = 0.8
ALARM_HIGH = 90.0
ALARM_LOW = 10.0
SP_MAX = 1000  # giới hạn trên của setpoint (= 100.0%)


async def setpoint_guard(function_code, start_address, address, count,
                         current_registers, set_values):
    """Action hook: từ chối lệnh ghi holding register làm setpoint không hợp lệ.

    Kiểm tra toàn bộ giá trị dự kiến CÙNG NHAU: dựng ảnh thanh ghi sau khi ghi rồi
    xét 0 ≤ SP_LOW < SP_HIGH ≤ 1000. Chỉ áp cho ghi holding register (FC 6/16).
    """
    if set_values is None or function_code not in (6, 16):
        return None
    regs = list(current_registers)
    for i, v in enumerate(set_values):
        idx = address - start_address + i
        if 0 <= idx < len(regs):
            regs[idx] = v
    if len(regs) <= max(m.HR_SP_HIGH, m.HR_SP_LOW):
        return None
    sp_high, sp_low = regs[m.HR_SP_HIGH], regs[m.HR_SP_LOW]
    if not (0 <= sp_low < sp_high <= SP_MAX):
        log.warning("từ chối setpoint không hợp lệ: SP_LOW=%s SP_HIGH=%s", sp_low, sp_high)
        return ExcCodes.ILLEGAL_VALUE
    return None


def build_device() -> SimDevice:
    # (coils, discrete inputs, holding registers, input registers).
    # Lưu ý: pymodbus đệm vùng coil/discrete input tới bội số 16 bit, nên đọc địa
    # chỉ trong phần đệm trả về 0; chỉ địa chỉ ngoài vùng khai báo (vd holding
    # register >= 2) mới sinh exception ILLEGAL DATA ADDRESS.
    return SimDevice(
        m.DEVICE_ID,
        simdata=(
            [SimData(0, values=[False, True, True], datatype=DataType.BITS)],
            [SimData(0, values=[False, False], datatype=DataType.BITS)],
            [SimData(0, values=[800, 300], datatype=DataType.REGISTERS)],
            [SimData(0, values=[500, 0, 0, 0], datatype=DataType.REGISTERS)],
        ),
        action=setpoint_guard,
    )


async def scan_cycle(server: ModbusTcpServer) -> None:
    level = 50.0
    overflow = 0.0        # tổng lượng nước đã tràn (đơn vị %), cộng dồn
    auto_pump = False     # trạng thái điều khiển tự động NỘI BỘ, tách khỏi coil
    tick = 0
    while True:
        try:
            pump_coil, valve, auto = await server.async_getValues(m.DEVICE_ID, 1, 0, 3)
            sp_high, sp_low = await server.async_getValues(m.DEVICE_ID, 3, 0, 2)

            if auto:
                # Điều khiển hai ngưỡng dùng trạng thái nội bộ; PLC ghi đè coil mỗi
                # chu kỳ nên lệnh ghi ngoài không có hiệu lực khi đang auto.
                if level * 10 <= sp_low:
                    auto_pump = True
                elif level * 10 >= sp_high:
                    auto_pump = False
                pump = auto_pump
                await server.async_setValues(m.DEVICE_ID, 5, m.COIL_PUMP, [pump])
            else:
                # Chế độ tay: bơm theo lệnh coil (kể cả lệnh của kẻ tấn công).
                pump = bool(pump_coil)

            # Quá trình vật lý + theo dõi lượng tràn.
            flow_in = PUMP_RATE if pump else 0.0
            flow_out = DRAIN_RATE if valve and level > 0 else 0.0
            new_level = level + (flow_in - flow_out) * SCAN_TIME
            if new_level > 100.0:
                overflow += new_level - 100.0
                new_level = 100.0
            level = max(0.0, new_level)

            await server.async_setValues(
                m.DEVICE_ID, 4, m.IR_LEVEL,
                [round(level * 10), round(flow_in * 10), round(flow_out * 10),
                 min(65535, round(overflow * 10))],
            )
            await server.async_setValues(
                m.DEVICE_ID, 2, m.DI_LEVEL_HIGH,
                [level >= ALARM_HIGH, level <= ALARM_LOW],
            )

            tick += 1
            if tick % 10 == 0:
                log.info(
                    "level=%5.1f%% pump=%d valve=%d auto=%d sp=[%d..%d] overflow=%.1f%%",
                    level, pump, valve, auto, sp_low, sp_high, overflow,
                )
        except Exception:
            log.exception("lỗi trong chu kỳ quét, bỏ qua vòng này")
        await asyncio.sleep(SCAN_TIME)


async def main() -> None:
    server = ModbusTcpServer(build_device(), address=("0.0.0.0", PORT))
    await server.serve_forever(background=True)
    log.info("PLC listening on Modbus/TCP port %d", PORT)
    await scan_cycle(server)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(main())
