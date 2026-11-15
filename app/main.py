"""
Securinix - Next-Gen SIEM & Autonomous Incident Response Platform
FastAPI Server with WebSockets, Real-Time Correlation, and SOAR Automation.
"""
import os
import asyncio
import json
from contextlib import asynccontextmanager
from typing import List, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.models.schemas import (
    DetectionRule, RuleUpdateRequest, RuleToggleRequest,
    PlaybookExecutionRequest, SimulationRequest
)
from app.engine.rules import rules_manager
from app.engine.detector import detector
from app.engine.soar import soar_manager
from app.engine.sniffer import sniffer
from app.engine.ueba import ueba_engine

# Active WebSocket subscribers
active_connections: Set[WebSocket] = set()

async def broadcast_ws(payload: dict):
    if not active_connections:
        return
    message = json.dumps(payload)
    disconnected = set()
    for ws in list(active_connections):
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.add(ws)
    for ws in disconnected:
        active_connections.discard(ws)

def on_network_event(event_dict: dict):
    # Queue for broadcast
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcast_ws({"type": "EVENT", "data": event_dict}))
    except RuntimeError:
        pass

def on_alert_detected(alert_dict: dict):
    # Queue for broadcast
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcast_ws(alert_dict))
    except RuntimeError:
        pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Register callbacks
    sniffer.register_event_callback(on_network_event)
    detector.register_alert_callback(on_alert_detected)
    # Start background packet sniffer / telemetry task
    sniffer_task = asyncio.create_task(sniffer.start())
    print("[Securinix] Engine initialized successfully.")
    yield
    sniffer.stop()
    sniffer_task.cancel()
    print("[Securinix] Engine shutdown complete.")

app = FastAPI(
    title="Securinix SIEM & SOAR",
    description="Enterprise Next-Gen SIEM, UEBA, and Autonomous Incident Response Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- REST API ROUTES -----------------

@app.get("/api/status")
async def get_system_status():
    stats = sniffer.get_stats()
    incidents = soar_manager.get_all()
    open_incidents = [i for i in incidents if i.status in ["New", "Investigating"]]
    critical_count = len([i for i in open_incidents if i.severity == "CRITICAL"])
    
    # Calculate global threat index (0 - 100)
    threat_index = 15
    if critical_count > 0:
        threat_index = min(100, 60 + critical_count * 10)
    elif open_incidents:
        threat_index = min(80, 30 + len(open_incidents) * 5)

    return {
        "status": "ONLINE",
        "threat_index": threat_index,
        "telemetry": stats,
        "rules_total": len(rules_manager.get_all()),
        "rules_enabled": len([r for r in rules_manager.get_all() if r.enabled]),
        "incidents_total": len(incidents),
        "incidents_open": len(open_incidents),
        "critical_incidents": critical_count,
        "mean_time_to_detect": "1.12s"
    }

# Rules Management
@app.get("/api/rules")
async def list_rules():
    return rules_manager.get_all()

@app.post("/api/rules")
async def create_rule(rule_data: dict = Body(...)):
    new_rule = rules_manager.create_rule(rule_data)
    await broadcast_ws({"type": "RULES_UPDATED"})
    return new_rule

@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: str, updates: RuleUpdateRequest):
    updated = rules_manager.update_rule(rule_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    await broadcast_ws({"type": "RULES_UPDATED"})
    return updated

@app.patch("/api/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, req: RuleToggleRequest):
    updated = rules_manager.toggle_rule(rule_id, req.enabled)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    await broadcast_ws({"type": "RULES_UPDATED"})
    return updated

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str):
    success = rules_manager.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    await broadcast_ws({"type": "RULES_UPDATED"})
    return {"success": True}

# Incidents & SOAR
@app.get("/api/incidents")
async def list_incidents(limit: int = 50):
    return soar_manager.get_all(limit=limit)

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    inc = soar_manager.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@app.post("/api/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, status_data: dict = Body(...)):
    new_status = status_data.get("status")
    analyst = status_data.get("analyst", "SOC Analyst")
    inc = soar_manager.update_status(incident_id, new_status, analyst)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    await broadcast_ws({"type": "INCIDENT_UPDATED", "incident": inc.model_dump()})
    return inc

@app.post("/api/incidents/{incident_id}/note")
async def add_incident_note(incident_id: str, note_data: dict = Body(...)):
    author = note_data.get("author", "Security Lead")
    content = note_data.get("content", "")
    inc = soar_manager.add_note(incident_id, author, content)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    await broadcast_ws({"type": "INCIDENT_UPDATED", "incident": inc.model_dump()})
    return inc

@app.post("/api/incidents/playbook")
async def execute_playbook(req: PlaybookExecutionRequest):
    res = soar_manager.execute_playbook(req.incident_id, req.playbook_id, req.parameters)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    # Broadcast SOAR action
    await broadcast_ws({
        "type": "PLAYBOOK_EXECUTED",
        "incident_id": req.incident_id,
        "playbook": res["playbook"]
    })
    return res

# Events & Packet Stream
@app.get("/api/events")
async def get_recent_events(limit: int = 60):
    return sniffer.get_recent_events(limit=limit)

@app.post("/api/events/ingest")
async def ingest_event(event_data: dict = Body(...)):
    evt = sniffer.ingest_custom_event(event_data)
    return evt

# Attack Scenario Simulator
@app.post("/api/simulate")
async def run_simulation(req: SimulationRequest):
    asyncio.create_task(sniffer.trigger_scenario(
        scenario=req.scenario,
        intensity=req.intensity,
        duration_seconds=req.duration_seconds
    ))
    return {
        "status": "STARTED",
        "scenario": req.scenario,
        "intensity": req.intensity,
        "message": f"Simulating '{req.scenario}' attack vector against network boundary."
    }

# UEBA & MITRE
@app.get("/api/ueba")
async def get_ueba_analytics():
    return ueba_engine.get_all_entities()

@app.get("/api/mitre")
async def get_mitre_coverage():
    incidents = soar_manager.get_all()
    tactics_summary = {
        "TA0043 (Reconnaissance)": 0,
        "TA0001 (Initial Access)": 0,
        "TA0006 (Credential Access)": 0,
        "TA0008 (Lateral Movement)": 0,
        "TA0011 (Command & Control)": 0,
        "TA0010 (Exfiltration)": 0,
        "TA0040 (Impact / DoS)": 0
    }
    for inc in incidents:
        tac = inc.mitre_tactic
        for key in tactics_summary:
            code = key.split()[0]
            if code in tac:
                tactics_summary[key] += 1
    return tactics_summary

# ----------------- WEBSOCKET -----------------

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        # Send initial snapshot
        initial_data = {
            "type": "INIT",
            "stats": sniffer.get_stats(),
            "recent_events": [e.model_dump() for e in sniffer.get_recent_events(limit=30)],
            "incidents": [i.model_dump() for i in soar_manager.get_all(limit=15)]
        }
        await websocket.send_text(json.dumps(initial_data))
        
        while True:
            # Keep connection alive & receive client messages (e.g. ping)
            data = await websocket.receive_text()
            # Echo ping
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        active_connections.discard(websocket)
    except Exception:
        active_connections.discard(websocket)

# ----------------- STATIC FRONTEND -----------------

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Securinix API online. Web interface loading..."}
