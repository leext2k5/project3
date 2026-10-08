"""Đánh giá định lượng hệ giám sát trên lab (Giai đoạn 9).

Chạy trên máy host (chỉ dùng thư viện chuẩn Python):
    python3 tools/evaluate.py

LƯU Ý: script DỰNG LẠI LAB TỪ ĐẦU (docker compose down -v) để kết quả tái lập được,
nên dữ liệu đang có trong CSDL của lab sẽ bị xóa.

Quy trình:
  1. Dựng lab sạch, chờ backend sẵn sàng.
  2. Học baseline LEARN_S giây rồi chốt.
  3. Giai đoạn bình thường NORMAL_S giây -> đếm báo động giả (cảnh báo / sự cố).
  4. Chạy các kịch bản kiểm thử có sẵn trong lab, mỗi kịch bản từ một IP riêng ->
     xét phát hiện THEO SỰ CỐ (không theo từng cảnh báo / từng gói), đo độ trễ
     capture -> sinh cảnh báo.
  5. Ứng phó: đề xuất + duyệt chặn nguồn của một sự cố, đo thời gian đến khi
     executor báo đã thực thi, kiểm tra nguồn đó không còn tới được PLC, rồi hoàn tác.
  6. Ghi kết quả ra docs/evaluation.json.
"""

import json
import os
import statistics
import subprocess
import time
import urllib.request

API = "http://localhost:8000"
NET = "project3_ics_net"
LEARN_S = 25
NORMAL_S = 90
OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "evaluation.json")

# Kịch bản: (tên, cách chạy, IP nguồn, luật chính phải phát hiện, luật KHÔNG được có)
SCENARIOS = [
    ("probe",          "run",  "172.28.0.61", "unknown_device",     None),
    ("recon",          "run",  "172.28.0.62", "abnormal_register",  None),
    ("dos",            "run",  "172.28.0.63", "dos",                None),
    ("scan",           "run",  "172.28.0.64", "port_scan",          None),
    ("write",          "run",  "172.28.0.65", "unauthorized_write", None),
    # Ghi sai từ CHÍNH thiết bị tin cậy (HMI .20): luật ghi theo chữ ký vẫn phải bắt,
    # và không được báo nhầm là "thiết bị lạ".
    ("write_from_hmi", "exec", "172.28.0.20", "unauthorized_write", "unknown_device"),
]


def env():
    e = dict(os.environ)
    dd = "/Applications/Docker.app/Contents/Resources/bin"
    if os.path.isdir(dd):
        e["PATH"] = dd + os.pathsep + e.get("PATH", "")
    return e


def sh(*args, check=True):
    return subprocess.run(list(args), check=check, capture_output=True, text=True, env=env())


def api(method, path, data=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or "null")


def psql(sql):
    return sh("docker", "compose", "exec", "-T", "db", "psql", "-U", "ics", "-d", "ics",
              "-tAc", sql).stdout.strip()


def wait_ready(timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        try:
            api("GET", "/api/stats")
            return
        except Exception:
            time.sleep(2)
    raise SystemExit("backend không sẵn sàng")


def can_reach_plc(ip):
    """Từ một container IP cho trước, thử đọc PLC; True nếu đọc được."""
    code = ("import asyncio\n"
            "from pymodbus.client import AsyncModbusTcpClient\n"
            "async def m():\n"
            "    c=AsyncModbusTcpClient('172.28.0.10',port=502,timeout=3,retries=0)\n"
            "    try:\n"
            "        await asyncio.wait_for(c.connect(),4)\n"
            "        r=await asyncio.wait_for(c.read_holding_registers(0,count=1,device_id=1),4)\n"
            "        print('OK' if not r.isError() else 'ERR')\n"
            "    except Exception:\n"
            "        print('NO')\n"
            "    finally:\n"
            "        c.close()\n"
            "asyncio.run(m())\n")
    r = sh("docker", "run", "--rm", "--network", NET, "--ip", ip, "ics-lab",
           "python", "-c", code, check=False)
    return r.stdout.strip().endswith("OK")


def peak_rate(ip):
    """Số request lớn nhất trong một giây (theo thời điểm capture) từ một nguồn."""
    v = psql(f"select coalesce(max(c),0) from (select count(*) c from events "
             f"where src_ip='{ip}' and direction='request' group by floor(ts)) x")
    return int(v or 0)


def main():
    t0 = time.time()
    print("1) Dựng lab sạch...")
    sh("docker", "compose", "down", "-v", check=False)
    sh("docker", "compose", "up", "-d", "--build")
    wait_ready()

    print(f"2) Học baseline {LEARN_S}s rồi chốt...")
    time.sleep(LEARN_S)
    baseline = api("POST", "/api/baseline/freeze")

    print(f"3) Lưu lượng bình thường {NORMAL_S}s (đếm báo động giả)...")
    s0 = api("GET", "/api/stats")
    time.sleep(NORMAL_S)
    s1 = api("GET", "/api/stats")
    normal = {
        "duration_s": NORMAL_S,
        "modbus_events": s1["total_events"] - s0["total_events"],
        "write_requests": s1["write_requests"] - s0["write_requests"],
        "false_positive_alerts": s1["alerts"] - s0["alerts"],
        "false_positive_incidents": s1["incidents"] - s0["incidents"],
        "hmi_peak_rate_req_s": peak_rate("172.28.0.20"),
    }

    print("4) Chạy các kịch bản kiểm thử...")
    results = []
    for name, how, ip, expect, forbid in SCENARIOS:
        if how == "run":
            sh("docker", "run", "--rm", "--network", NET, "--ip", ip, "ics-lab",
               "python", "attacker.py", name, check=False)
        else:
            sh("docker", "compose", "exec", "-T", "hmi", "python", "attacker.py", "write",
               check=False)
        time.sleep(4)
        alerts = [a for a in api("GET", "/api/alerts?limit=500") if a["src_ip"] == ip]
        incidents = [i for i in api("GET", "/api/incidents?limit=500") if i["src_ip"] == ip]
        rules = sorted({a["rule"] for a in alerts})
        key = [a for a in alerts if a["rule"] == expect]
        lat = [(a["detected_at"] - a["ts"]) * 1000 for a in alerts if a.get("detected_at")]
        results.append({
            "scenario": name, "src_ip": ip, "expected_rule": expect,
            "detected": bool(key) and (forbid not in rules),
            "rules_fired": rules, "alerts": len(alerts), "incidents": len(incidents),
            "latency_ms_key_rule": round((key[0]["detected_at"] - key[0]["ts"]) * 1000, 1)
                                   if key and key[0].get("detected_at") else None,
            "latency_ms_max": round(max(lat), 1) if lat else None,
            "peak_rate_req_s": peak_rate(ip),
        })
        print(f"   {name:15} -> {'PHÁT HIỆN' if results[-1]['detected'] else 'BỎ SÓT'} {rules}")

    print("5) Ứng phó: đề xuất + duyệt chặn nguồn của kịch bản 'write'...")
    w = next(r for r in results if r["scenario"] == "write")
    inc = next(i for i in api("GET", "/api/incidents?limit=500") if i["src_ip"] == w["src_ip"])
    reach_before = can_reach_plc(w["src_ip"])
    sug = api("POST", "/api/responses", {"alert_id": inc["top_alert_id"]})
    t_approve = time.time()
    api("POST", f"/api/responses/{sug['id']}/approve")
    status = None
    while time.time() - t_approve < 30:
        status = next(r for r in api("GET", "/api/responses") if r["id"] == sug["id"])["status"]
        if status in ("executed", "failed"):
            break
        time.sleep(0.2)
    t_exec = time.time() - t_approve
    reach_after = can_reach_plc(w["src_ip"])
    api("POST", f"/api/responses/{sug['id']}/undo")
    time.sleep(4)
    reach_undo = can_reach_plc(w["src_ip"])
    response = {
        "action": sug["action"], "target": w["src_ip"], "status": status,
        "approve_to_executed_s": round(t_exec, 2),
        "reach_before": reach_before, "reach_after_block": reach_after,
        "reach_after_undo": reach_undo,
        # một thiết bị khác (.50) vẫn tới được PLC -> chặn đúng mục tiêu
        "other_device_reaches_plc": can_reach_plc("172.28.0.50"),
    }

    detected = sum(r["detected"] for r in results)
    lats = [r["latency_ms_key_rule"] for r in results if r["latency_ms_key_rule"] is not None]
    summary = {
        "scenarios": len(results), "detected": detected,
        "detection_rate": round(detected / len(results), 3),
        "false_positive_incidents_normal": normal["false_positive_incidents"],
        "latency_ms_mean": round(statistics.mean(lats), 1) if lats else None,
        "latency_ms_max": round(max(lats), 1) if lats else None,
        "alerts_total": sum(r["alerts"] for r in results),
        "incidents_total": sum(r["incidents"] for r in results),
    }
    out = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "runtime_s": round(time.time() - t0),
           "baseline": baseline, "normal": normal, "scenarios": results,
           "response": response, "summary": summary}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("\n=== TÓM TẮT ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("Ứng phó:", json.dumps(response, ensure_ascii=False))
    print("Đã ghi", os.path.normpath(OUT))


if __name__ == "__main__":
    main()
