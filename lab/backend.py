"""Backend giám sát: nhận event (có kiểm tra), lưu PostgreSQL (chống trùng),
phát hiện thiết bị, phát hiện tấn công, đẩy real-time qua WebSocket.

Sửa theo review:
  (3) Đếm ghi theo giao dịch: chỉ đếm request-ghi, tách số ghi bị PLC từ chối.
  (6) Broadcast WebSocket duyệt bản sao danh sách client, có timeout, chạy nền
      tách khỏi đường nhận/lưu event; có API lấy lại event theo after_id.
  (7) Xác thực event bằng schema (pydantic); event sai -> quarantine, không gây
      lỗi DB; chống trùng theo event_id; xác thực nguồn bằng token tùy chọn.
  (8) first_seen=min, last_seen=max; ghi lịch sử MAC; vai trò là suy đoán; baseline
      là bản riêng đã duyệt (bảng baseline), không dùng bảng assets làm baseline.
  (9) Nhận event TCP (SYN) phục vụ luật quét cổng.
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Literal, Optional

import asyncpg
from fastapi import Body, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, ValidationError

from detection import Detector

log = logging.getLogger("backend")
DB_DSN = os.getenv("DB_DSN", "postgresql://ics:ics@db:5432/ics")
SENSOR_TOKEN = os.getenv("SENSOR_TOKEN")  # nếu đặt, mọi POST event phải kèm token

EVENT_COLS = [
    "event_id", "kind", "ts", "src_ip", "dst_ip", "src_mac", "src_port", "dst_port",
    "transaction_id", "unit_id", "direction", "function_code", "fc_name",
    "is_write", "is_exception", "exception_code", "address", "count", "value",
    "values_json", "raw", "req_address", "req_count", "matched", "rtt_ms",
]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY, event_id TEXT, kind TEXT DEFAULT 'modbus',
    ts DOUBLE PRECISION NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_mac TEXT, src_port INTEGER, dst_port INTEGER,
    transaction_id INTEGER, unit_id INTEGER, direction TEXT,
    function_code INTEGER, fc_name TEXT,
    is_write BOOLEAN DEFAULT FALSE, is_exception BOOLEAN DEFAULT FALSE,
    exception_code INTEGER, address INTEGER, count INTEGER, value INTEGER,
    values_json JSONB, raw TEXT, req_address INTEGER, req_count INTEGER,
    matched BOOLEAN, rtt_ms DOUBLE PRECISION, created_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE events ADD COLUMN IF NOT EXISTS event_id TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS kind TEXT DEFAULT 'modbus';
ALTER TABLE events ADD COLUMN IF NOT EXISTS raw TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS req_address INTEGER;
ALTER TABLE events ADD COLUMN IF NOT EXISTS req_count INTEGER;
ALTER TABLE events ADD COLUMN IF NOT EXISTS matched BOOLEAN;
ALTER TABLE events ADD COLUMN IF NOT EXISTS rtt_ms DOUBLE PRECISION;
CREATE UNIQUE INDEX IF NOT EXISTS uq_events_event_id ON events (event_id);
CREATE INDEX IF NOT EXISTS idx_events_ts  ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events (src_ip);

CREATE TABLE IF NOT EXISTS tcp_events (
    id BIGSERIAL PRIMARY KEY, event_id TEXT, ts DOUBLE PRECISION,
    src_ip TEXT, dst_ip TEXT, src_mac TEXT, src_port INTEGER, dst_port INTEGER,
    flags TEXT, created_at TIMESTAMPTZ DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tcp_event_id ON tcp_events (event_id);

CREATE TABLE IF NOT EXISTS assets (
    ip TEXT PRIMARY KEY, mac TEXT, role TEXT, role_source TEXT DEFAULT 'inferred',
    mac_history JSONB DEFAULT '[]'::jsonb,
    first_seen DOUBLE PRECISION, last_seen DOUBLE PRECISION, event_count BIGINT DEFAULT 0
);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS role_source TEXT DEFAULT 'inferred';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS mac_history JSONB DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS connections (
    src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
    first_seen DOUBLE PRECISION, last_seen DOUBLE PRECISION,
    request_count BIGINT DEFAULT 0, PRIMARY KEY (src_ip, dst_ip, dst_port)
);
CREATE TABLE IF NOT EXISTS baseline (
    id INT PRIMARY KEY DEFAULT 1, frozen BOOLEAN DEFAULT FALSE,
    data JSONB, learned_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY, ts DOUBLE PRECISION, severity TEXT, rule TEXT,
    src_ip TEXT, dst_ip TEXT, description TEXT, evidence JSONB,
    status TEXT DEFAULT 'new', created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts (severity);
CREATE TABLE IF NOT EXISTS quarantine (
    id BIGSERIAL PRIMARY KEY, received_at TIMESTAMPTZ DEFAULT now(),
    reason TEXT, payload JSONB
);
CREATE TABLE IF NOT EXISTS response_actions (
    id BIGSERIAL PRIMARY KEY, alert_id BIGINT, src_ip TEXT, action TEXT,
    params JSONB, status TEXT DEFAULT 'suggested', result TEXT,
    created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now()
);
"""

UPSERT_SERVER = """
INSERT INTO assets (ip, mac, role, role_source, mac_history, first_seen, last_seen, event_count)
VALUES ($1,$2::text,'plc','inferred',
        CASE WHEN $2::text IS NULL THEN '[]'::jsonb ELSE jsonb_build_array($2::text) END,$3,$3,1)
ON CONFLICT (ip) DO UPDATE SET role='plc',
  mac=COALESCE(EXCLUDED.mac, assets.mac),
  first_seen=LEAST(assets.first_seen, EXCLUDED.first_seen),
  last_seen=GREATEST(assets.last_seen, EXCLUDED.last_seen),
  event_count=assets.event_count+1,
  mac_history = CASE
    WHEN EXCLUDED.mac IS NULL THEN assets.mac_history
    WHEN assets.mac_history @> jsonb_build_array(EXCLUDED.mac) THEN assets.mac_history
    ELSE assets.mac_history || jsonb_build_array(EXCLUDED.mac) END
"""
UPSERT_CLIENT = UPSERT_SERVER.replace("'plc','inferred'", "'hmi/workstation','inferred'") \
    .replace("role='plc'", "role=CASE WHEN assets.role='plc' THEN 'plc' ELSE 'hmi/workstation' END")
UPSERT_CONN = """
INSERT INTO connections (src_ip, dst_ip, dst_port, first_seen, last_seen, request_count)
VALUES ($1,$2,$3,$4,$4,1)
ON CONFLICT (src_ip, dst_ip, dst_port) DO UPDATE SET
  first_seen=LEAST(connections.first_seen, EXCLUDED.first_seen),
  last_seen=GREATEST(connections.last_seen, EXCLUDED.last_seen),
  request_count=connections.request_count+1
"""

clients: set[WebSocket] = set()
detector = Detector()


# --------------------------- Xác thực đầu vào -------------------------------
class EventIn(BaseModel):
    """Schema tối thiểu cho event; cho phép trường mở rộng."""
    model_config = ConfigDict(extra="allow")
    event_id: str
    kind: Literal["modbus", "tcp"]
    ts: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    direction: Optional[Literal["request", "response"]] = None


def validate(ev: dict) -> dict:
    m = EventIn(**ev)
    if m.kind == "modbus" and m.direction is None:
        raise ValueError("event modbus thiếu direction")
    for p in (m.src_port, m.dst_port):
        if p is not None and not 0 <= p <= 65535:
            raise ValueError("port ngoài phạm vi 0..65535")
    return ev


# --------------------------- Vòng đời ---------------------------------------
async def connect_db_with_retry(retries: int = 30) -> asyncpg.Pool:
    for attempt in range(retries):
        try:
            return await asyncpg.create_pool(DB_DSN, min_size=1, max_size=5)
        except (OSError, asyncpg.PostgresError) as exc:
            log.warning("chờ DB (%d/%d): %s", attempt + 1, retries, exc)
            await asyncio.sleep(1)
    raise RuntimeError("không kết nối được PostgreSQL")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await connect_db_with_retry()
    async with app.state.pool.acquire() as con:
        await con.execute(SCHEMA_SQL)
        row = await con.fetchrow("SELECT data FROM baseline WHERE id=1")
        if row and row["data"]:
            detector.load(json.loads(row["data"]))
            log.info("đã nạp baseline (frozen=%s)", detector.frozen)
    log.info("backend sẵn sàng")
    yield
    await app.state.pool.close()


app = FastAPI(title="ICS Monitoring Backend", lifespan=lifespan)


# --------------------------- Lưu trữ ----------------------------------------
async def insert_events(con, modbus: list[dict]) -> None:
    if not modbus:
        return
    rows = []
    for ev in modbus:
        vals = ev.get("values")
        rows.append((
            ev.get("event_id"), ev.get("kind", "modbus"), ev.get("ts"), ev.get("src_ip"),
            ev.get("dst_ip"), ev.get("src_mac"), ev.get("src_port"), ev.get("dst_port"),
            ev.get("transaction_id"), ev.get("unit_id"), ev.get("direction"),
            ev.get("function_code"), ev.get("fc_name"), ev.get("is_write", False),
            ev.get("is_exception", False), ev.get("exception_code"), ev.get("address"),
            ev.get("count"), ev.get("value"),
            json.dumps(vals) if vals is not None else None, ev.get("raw"),
            ev.get("req_address"), ev.get("req_count"), ev.get("matched"), ev.get("rtt_ms"),
        ))
    ph = ", ".join(f"${i + 1}" for i in range(len(EVENT_COLS)))
    await con.executemany(
        f"INSERT INTO events ({', '.join(EVENT_COLS)}) VALUES ({ph}) "
        f"ON CONFLICT (event_id) DO NOTHING", rows)


async def insert_tcp(con, tcp: list[dict]) -> None:
    if not tcp:
        return
    rows = [(e.get("event_id"), e.get("ts"), e.get("src_ip"), e.get("dst_ip"),
             e.get("src_mac"), e.get("src_port"), e.get("dst_port"), e.get("flags"))
            for e in tcp]
    await con.executemany(
        "INSERT INTO tcp_events (event_id, ts, src_ip, dst_ip, src_mac, src_port, dst_port, flags) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (event_id) DO NOTHING", rows)


async def discover(con, modbus: list[dict]) -> None:
    for ev in modbus:
        ts, src, dst, mac = ev.get("ts"), ev.get("src_ip"), ev.get("dst_ip"), ev.get("src_mac")
        if not src or not dst or ts is None:
            continue
        if ev.get("direction") == "request":
            await con.execute(UPSERT_CLIENT, src, mac, ts)
            await con.execute(UPSERT_SERVER, dst, None, ts)
            await con.execute(UPSERT_CONN, src, dst, ev.get("dst_port"), ts)
        else:
            await con.execute(UPSERT_SERVER, src, mac, ts)
            await con.execute(UPSERT_CLIENT, dst, None, ts)


async def store_alerts(con, alerts: list[dict]) -> None:
    for a in alerts:
        a["id"] = await con.fetchval(
            "INSERT INTO alerts (ts, severity, rule, src_ip, dst_ip, description, evidence) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
            a["ts"], a["severity"], a["rule"], a["src_ip"], a["dst_ip"],
            a["description"], json.dumps(a["evidence"]))


async def quarantine(con, items: list[tuple]) -> None:
    if items:
        await con.executemany(
            "INSERT INTO quarantine (reason, payload) VALUES ($1, $2)",
            [(r, json.dumps(ev)) for r, ev in items])


# --------------------------- WebSocket (tách rời) ---------------------------
async def broadcast(kind: str, data) -> None:
    msg = json.dumps({"type": kind, "data": data})
    for ws in list(clients):                     # duyệt BẢN SAO, tránh lỗi đổi kích thước
        try:
            await asyncio.wait_for(ws.send_text(msg), timeout=2.0)
        except Exception:
            clients.discard(ws)                  # client chậm/lỗi -> loại, không chặn ingest


@app.post("/api/events")
async def ingest(events: list[dict] = Body(...), x_sensor_token: str = Header(default=None)):
    if SENSOR_TOKEN and x_sensor_token != SENSOR_TOKEN:
        raise HTTPException(status_code=401, detail="token sensor không hợp lệ")

    modbus, tcp, bad = [], [], []
    for ev in events:
        try:
            validate(ev)
        except (ValidationError, ValueError) as exc:
            bad.append((str(exc), ev))
            continue
        (tcp if ev.get("kind") == "tcp" else modbus).append(ev)

    alerts = (detector.check(modbus) + detector.check_tcp(tcp)) if detector.frozen else []
    async with app.state.pool.acquire() as con:
        async with con.transaction():
            await insert_events(con, modbus)
            await insert_tcp(con, tcp)
            await discover(con, modbus)
            await quarantine(con, bad)
            if alerts:
                await store_alerts(con, alerts)
    if not detector.frozen:
        detector.learn(modbus)

    # Phát WebSocket chạy nền, KHÔNG để ảnh hưởng phản hồi nhận event.
    asyncio.create_task(broadcast("events", modbus + tcp))
    if alerts:
        asyncio.create_task(broadcast("alert", alerts))
    return {"stored": len(modbus), "tcp": len(tcp), "quarantined": len(bad), "alerts": len(alerts)}


@app.get("/api/events")
async def list_events(limit: int = 50, after_id: int = 0):
    """Lấy event. after_id>0: lấy event có id lớn hơn (để dashboard lấy lại khi reconnect)."""
    if after_id:
        rows = await app.state.pool.fetch(
            f"SELECT id, {', '.join(EVENT_COLS)} FROM events WHERE id > $1 "
            f"ORDER BY id ASC LIMIT $2", after_id, limit)
    else:
        rows = await app.state.pool.fetch(
            f"SELECT id, {', '.join(EVENT_COLS)} FROM events ORDER BY id DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@app.get("/api/assets")
async def list_assets():
    rows = await app.state.pool.fetch(
        "SELECT ip, mac, mac_history, role, role_source, first_seen, last_seen, event_count "
        "FROM assets ORDER BY role, ip")
    return [dict(r) for r in rows]


@app.get("/api/connections")
async def list_connections():
    rows = await app.state.pool.fetch(
        "SELECT src_ip, dst_ip, dst_port, first_seen, last_seen, request_count "
        "FROM connections ORDER BY request_count DESC")
    return [dict(r) for r in rows]


@app.get("/api/alerts")
async def list_alerts(limit: int = 100):
    rows = await app.state.pool.fetch(
        "SELECT id, ts, severity, rule, src_ip, dst_ip, description, evidence, status "
        "FROM alerts ORDER BY id DESC LIMIT $1", limit)
    out = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("evidence"), str):   # JSONB về dạng chuỗi -> parse cho dashboard
            try:
                d["evidence"] = json.loads(d["evidence"])
            except json.JSONDecodeError:
                pass
        out.append(d)
    return out


@app.post("/api/alerts/{alert_id}/status")
async def set_alert_status(alert_id: int, status: str = Body(..., embed=True)):
    """Operator xác nhận/giải quyết một cảnh báo: new -> acknowledged -> resolved."""
    if status not in ("new", "acknowledged", "resolved"):
        raise HTTPException(status_code=400, detail="status không hợp lệ")
    await app.state.pool.execute("UPDATE alerts SET status=$1 WHERE id=$2", status, alert_id)
    return {"id": alert_id, "status": status}


# --------------------------- Ứng phó (có duyệt) -----------------------------
# Quy trình: đề xuất (suggested) -> operator duyệt (approved) -> executor thực
# thi (executed) -> hoàn tác (undo_requested -> undone). Executor là service
# riêng (responder) chạy iptables; backend chỉ quản lý quy trình + audit.
@app.post("/api/responses")
async def suggest_response(alert_id: int = Body(..., embed=True)):
    """Sinh đề xuất biện pháp ứng phó cho một cảnh báo."""
    a = await app.state.pool.fetchrow(
        "SELECT severity, src_ip FROM alerts WHERE id=$1", alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="không có cảnh báo")
    if a["severity"] in ("Critical", "High", "Medium"):
        action, params = "block_ip", {"ip": a["src_ip"]}
    else:
        action, params = "monitor", {}
    rid = await app.state.pool.fetchval(
        "INSERT INTO response_actions (alert_id, src_ip, action, params) "
        "VALUES ($1,$2,$3,$4) RETURNING id",
        alert_id, a["src_ip"], action, json.dumps(params))
    return {"id": rid, "alert_id": alert_id, "src_ip": a["src_ip"],
            "action": action, "status": "suggested"}


@app.post("/api/responses/{rid}/approve")
async def approve_response(rid: int):
    """Operator DUYỆT biện pháp -> executor sẽ thực thi."""
    await app.state.pool.execute(
        "UPDATE response_actions SET status='approved', updated_at=now() "
        "WHERE id=$1 AND status='suggested'", rid)
    return {"id": rid, "status": "approved"}


@app.post("/api/responses/{rid}/undo")
async def undo_response(rid: int):
    """Yêu cầu hoàn tác -> executor sẽ gỡ luật chặn."""
    await app.state.pool.execute(
        "UPDATE response_actions SET status='undo_requested', updated_at=now() "
        "WHERE id=$1 AND status='executed'", rid)
    return {"id": rid, "status": "undo_requested"}


@app.post("/api/responses/{rid}/result")
async def response_result(rid: int, status: str = Body(...), result: str = Body(default="")):
    """Executor báo lại kết quả thực thi (executed/undone/failed)."""
    await app.state.pool.execute(
        "UPDATE response_actions SET status=$1, result=$2, updated_at=now() WHERE id=$3",
        status, result, rid)
    return {"id": rid, "status": status}


@app.get("/api/responses")
async def list_responses(limit: int = 100):
    rows = await app.state.pool.fetch(
        "SELECT id, alert_id, src_ip, action, params, status, result, created_at, updated_at "
        "FROM response_actions ORDER BY id DESC LIMIT $1", limit)
    return [dict(r) for r in rows]


@app.get("/api/baseline")
async def get_baseline():
    return detector.export()


@app.post("/api/baseline/freeze")
async def freeze_baseline():
    detector.freeze()
    data = detector.export()
    async with app.state.pool.acquire() as con:
        await con.execute(
            "INSERT INTO baseline (id, frozen, data, learned_at) VALUES (1, TRUE, $1, now()) "
            "ON CONFLICT (id) DO UPDATE SET frozen=TRUE, data=$1, learned_at=now()",
            json.dumps(data))
    return {"frozen": True, "devices": len(detector.devices),
            "connections": len(detector.connections),
            "write_rules": len(detector.write_rules), "writers": sorted(detector.writers)}


@app.post("/api/baseline/reset")
async def reset_baseline():
    global detector
    detector = Detector()
    async with app.state.pool.acquire() as con:
        await con.execute("DELETE FROM baseline WHERE id=1")
    return {"frozen": False}


@app.get("/api/stats")
async def stats():
    async with app.state.pool.acquire() as con:
        return {
            "total_events": await con.fetchval("SELECT count(*) FROM events"),
            "tcp_events": await con.fetchval("SELECT count(*) FROM tcp_events"),
            # (3) đếm GHI theo request (một giao dịch ghi = một lần), tách số bị từ chối.
            "write_requests": await con.fetchval(
                "SELECT count(*) FROM events WHERE direction='request' AND is_write"),
            "write_rejected": await con.fetchval(
                "SELECT count(*) FROM events WHERE is_exception AND function_code IN (5,6,15,16)"),
            "exceptions": await con.fetchval("SELECT count(*) FROM events WHERE is_exception"),
            "assets": await con.fetchval("SELECT count(*) FROM assets"),
            "connections": await con.fetchval("SELECT count(*) FROM connections"),
            "alerts": await con.fetchval("SELECT count(*) FROM alerts"),
            "quarantined": await con.fetchval("SELECT count(*) FROM quarantine"),
            "baseline_frozen": detector.frozen,
        }


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(ws)


# Phục vụ dashboard tĩnh (cùng origin với API). Mount SAU các route API nên
# /api/* và /ws vẫn được ưu tiên; mọi đường còn lại trả file trong thư mục web/.
if os.path.isdir("web"):
    app.mount("/", StaticFiles(directory="web", html=True), name="web")


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    uvicorn.run(app, host="0.0.0.0", port=8000)
