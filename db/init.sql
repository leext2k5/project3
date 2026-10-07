-- Schema khởi tạo cho nền tảng giám sát ICS (đồng bộ với SCHEMA_SQL trong backend).
-- Postgres tự chạy file này một lần khi khởi tạo database rỗng. Backend cũng chạy
-- DDL tương đương (idempotent, kèm ALTER ... ADD COLUMN IF NOT EXISTS) lúc khởi
-- động nên schema luôn đầy đủ kể cả trên database đã tồn tại.

-- Mọi thông điệp Modbus đã giải mã (event_id để chống trùng).
CREATE TABLE IF NOT EXISTS events (
    id              BIGSERIAL PRIMARY KEY,
    event_id        TEXT,
    kind            TEXT DEFAULT 'modbus',
    ts              DOUBLE PRECISION NOT NULL,     -- epoch, giữ đủ microsecond
    src_ip          TEXT, dst_ip TEXT, src_mac TEXT,
    src_port        INTEGER, dst_port INTEGER,
    transaction_id  INTEGER, unit_id INTEGER, direction TEXT,
    function_code   INTEGER, fc_name TEXT,
    is_write        BOOLEAN DEFAULT FALSE,
    is_exception    BOOLEAN DEFAULT FALSE,
    exception_code  INTEGER, address INTEGER, count INTEGER, value INTEGER,
    values_json     JSONB,
    raw             TEXT,                          -- ADU thô (hex) làm bằng chứng
    req_address     INTEGER, req_count INTEGER,    -- từ request đã ghép
    matched         BOOLEAN, rtt_ms DOUBLE PRECISION,
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_events_event_id ON events (event_id);
CREATE INDEX IF NOT EXISTS idx_events_ts  ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events (src_ip);

-- Event TCP (SYN) phục vụ luật phát hiện quét cổng.
CREATE TABLE IF NOT EXISTS tcp_events (
    id         BIGSERIAL PRIMARY KEY, event_id TEXT, ts DOUBLE PRECISION,
    src_ip     TEXT, dst_ip TEXT, src_mac TEXT, src_port INTEGER, dst_port INTEGER,
    flags      TEXT, created_at TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tcp_event_id ON tcp_events (event_id);

-- Tài sản tự phát hiện. Vai trò là SUY ĐOÁN từ traffic (role_source='inferred'),
-- không phải thiết bị được tin cậy; lịch sử MAC lưu ở mac_history.
CREATE TABLE IF NOT EXISTS assets (
    ip           TEXT PRIMARY KEY, mac TEXT,
    role         TEXT, role_source TEXT DEFAULT 'inferred',
    mac_history  JSONB DEFAULT '[]'::jsonb,
    first_seen   DOUBLE PRECISION, last_seen DOUBLE PRECISION,
    event_count  BIGINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connections (
    src_ip         TEXT, dst_ip TEXT, dst_port INTEGER,
    first_seen     DOUBLE PRECISION, last_seen DOUBLE PRECISION,
    request_count  BIGINT DEFAULT 0,
    PRIMARY KEY (src_ip, dst_ip, dst_port)
);

-- Baseline đã được duyệt/chốt (bản riêng, có thời điểm học), tách khỏi bảng assets.
CREATE TABLE IF NOT EXISTS baseline (
    id          INT PRIMARY KEY DEFAULT 1, frozen BOOLEAN DEFAULT FALSE,
    data        JSONB, learned_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY, ts DOUBLE PRECISION,
    severity    TEXT, rule TEXT, src_ip TEXT, dst_ip TEXT,
    description TEXT, evidence JSONB, status TEXT DEFAULT 'new',
    created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts (severity);

-- Event bị từ chối do dữ liệu sai (giữ lại kèm lý do để điều tra).
CREATE TABLE IF NOT EXISTS quarantine (
    id          BIGSERIAL PRIMARY KEY, received_at TIMESTAMPTZ DEFAULT now(),
    reason      TEXT, payload JSONB
);

-- Giai đoạn 7: nhật ký ứng phó (đề xuất -> duyệt -> thực thi -> hoàn tác).
CREATE TABLE IF NOT EXISTS response_actions (
    id          BIGSERIAL PRIMARY KEY, alert_id BIGINT, src_ip TEXT, action TEXT,
    params      JSONB, status TEXT DEFAULT 'suggested', result TEXT,
    created_at  TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now()
);
