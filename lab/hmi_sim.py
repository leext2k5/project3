"""HMI giả lập: poll PLC mỗi giây, thỉnh thoảng operator chỉnh setpoint."""

import asyncio
import logging
import os
import random

from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusException

import modbus_map as m

log = logging.getLogger("hmi")

PLC_HOST = os.getenv("PLC_HOST", "127.0.0.1")
PLC_PORT = int(os.getenv("PLC_PORT", "502"))
POLL_INTERVAL = 1.0
SETPOINT_EVERY = 10  # số chu kỳ poll giữa 2 lần operator chỉnh setpoint
                     # (đủ ngắn để pha học baseline bắt được thao tác ghi hợp lệ)


async def poll(client: AsyncModbusTcpClient) -> None:
    ir = await client.read_input_registers(0, count=3, device_id=m.DEVICE_ID)
    co = await client.read_coils(0, count=3, device_id=m.DEVICE_ID)
    di = await client.read_discrete_inputs(0, count=2, device_id=m.DEVICE_ID)
    hr = await client.read_holding_registers(0, count=2, device_id=m.DEVICE_ID)
    if any(r.isError() for r in (ir, co, di, hr)):
        log.warning("PLC trả về lỗi: %s", [r for r in (ir, co, di, hr) if r.isError()])
        return
    log.info(
        "level=%5.1f%% in=%.1f out=%.1f | pump=%d valve=%d auto=%d | hi=%d lo=%d | sp=[%d..%d]",
        ir.registers[m.IR_LEVEL] / 10,
        ir.registers[m.IR_FLOW_IN] / 10,
        ir.registers[m.IR_FLOW_OUT] / 10,
        co.bits[m.COIL_PUMP], co.bits[m.COIL_VALVE], co.bits[m.COIL_AUTO],
        di.bits[m.DI_LEVEL_HIGH], di.bits[m.DI_LEVEL_LOW],
        hr.registers[m.HR_SP_LOW], hr.registers[m.HR_SP_HIGH],
    )


async def main() -> None:
    client = AsyncModbusTcpClient(PLC_HOST, port=PLC_PORT)
    cycle = 0
    while True:
        try:
            if not client.connected:
                await client.connect()
            await poll(client)
            # Ghi setpoint ngay vòng đầu (cycle=0) rồi định kỳ mỗi SETPOINT_EVERY
            # vòng. Việc ghi sớm giúp HMI được học là "thiết bị được phép ghi".
            if cycle % SETPOINT_EVERY == 0:
                sp_high = random.choice([750, 800, 850])
                rr = await client.write_register(m.HR_SP_HIGH, sp_high, device_id=m.DEVICE_ID)
                if rr.isError():   # chỉ coi là thành công khi PLC chấp nhận
                    log.warning("PLC TỪ CHỐI ghi SP_HIGH=%d: %s", sp_high, rr)
                else:
                    log.info("operator đặt SP_HIGH=%d (PLC chấp nhận)", sp_high)
            cycle += 1
        except ModbusException as exc:
            log.warning("mất kết nối tới PLC %s:%d: %s", PLC_HOST, PLC_PORT, exc)
        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    asyncio.run(main())
