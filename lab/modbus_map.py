"""Bảng địa chỉ Modbus của PLC bồn nước (dùng chung cho PLC, HMI và các script tấn công)."""

DEVICE_ID = 1

# Coils - FC1 đọc, FC5/FC15 ghi
COIL_PUMP = 0   # bơm cấp nước
COIL_VALVE = 1  # van xả
COIL_AUTO = 2   # 1 = PLC tự điều khiển bơm, 0 = điều khiển tay

# Discrete inputs - FC2 (chỉ đọc)
DI_LEVEL_HIGH = 0  # cảnh báo mức cao
DI_LEVEL_LOW = 1   # cảnh báo mức thấp

# Input registers - FC4 (chỉ đọc), đơn vị 0.1
IR_LEVEL = 0     # mức nước: 0..1000 = 0.0..100.0 %
IR_FLOW_IN = 1   # lưu lượng vào
IR_FLOW_OUT = 2  # lưu lượng ra
IR_OVERFLOW = 3  # tổng lượng nước đã tràn (vượt 100%), đơn vị 0.1 %

# Holding registers - FC3 đọc, FC6/FC16 ghi, đơn vị 0.1 %
HR_SP_HIGH = 0  # mức tắt bơm
HR_SP_LOW = 1   # mức bật bơm
