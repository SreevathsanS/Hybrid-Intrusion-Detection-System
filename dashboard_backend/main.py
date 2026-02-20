# dashboard_backend/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket, WebSocketDisconnect
import asyncio
 
from dashboard_backend.log_reader import read_recent_logs
from dashboard_backend.state import (
    read_status,
    read_recent_attacks,
    get_attack_distribution,
    get_attack_timeline,
    read_blockchain_status,
    read_live_attacks
)


app = FastAPI(title="Hybrid ML IPS Dashboard")

# Allow React frontend later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================
# BASIC STATUS ENDPOINT
# =========================================
@app.get("/status")
def get_status():
    return read_status()
    


# =========================================
# BLOCKCHAIN / ATTACK LOGS
# =========================================
@app.get("/logs")
def get_logs():
    return read_recent_logs()


# =========================================
# HEALTH CHECK
# =========================================
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/attacks")
def get_attacks():
    return read_recent_attacks()

@app.get("/analytics/distribution")
def attack_distribution():
    return get_attack_distribution()


@app.get("/analytics/timeline")
def attack_timeline():
    return get_attack_timeline()


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            payload = {
                "status": read_status(),
                "blockchain": read_blockchain_status(),
                "live_attacks": read_live_attacks(),
                "recent_attacks": read_recent_attacks(limit=20),
                "distribution": get_attack_distribution(),
                "timeline": get_attack_timeline()
            }

            await websocket.send_json(payload)

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        print("WebSocket disconnected")

@app.get("/blockchain/status")
def blockchain_status():
    return read_blockchain_status()

@app.get("/live-attacks")
def live_attacks():
    return read_live_attacks()