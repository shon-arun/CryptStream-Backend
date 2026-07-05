from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
import os
import secrets
import base64
import sqlite3
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel

app = FastAPI()

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"detail": "Malformed request: Invalid, missing, or malformed parameters."}
    )

def init_db():
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                public_key TEXT,
                ip_address TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                pointer TEXT PRIMARY KEY,
                encrypted_blob BLOB
            )
        """)
        conn.commit()

init_db()

challenges = {}
verified_devices = set()
device_locations = {}

class ServeRequest(BaseModel):
    device_id: str
    lat: float
    lon: float

class LocationPayload(BaseModel):
    device_id: str
    lat: float
    lon: float

class ChallengeRequest(BaseModel):
    device_id: str
    lat: float
    lon: float

class SignatureAndLocationRequest(BaseModel):
    device_id: str
    signature: str
    lat: float
    lon: float

class RegisterRequest(BaseModel):
    device_id: str
    public_key: str

class UploadPayloadRequest(BaseModel):
    device_id: str
    lat: float
    lon: float
    pointer: str
    base64_blob: str

class FetchPayloadRequest(BaseModel):
    device_id: str
    lat: float
    lon: float
    pointer: str

MIN_LAT = 9.74
MAX_LAT = 9.76
MIN_LON = 76.69
MAX_LON = 76.71

def is_out_of_bounds(lat: float, lon: float) -> bool:
    return not (MIN_LAT <= lat <= MAX_LAT and MIN_LON <= lon <= MAX_LON)

@app.post("/register")
async def register_device(payload: RegisterRequest, request: Request):
    client_ip = request.client.host
    
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO devices (device_id, public_key, ip_address) VALUES (?, ?, ?)",
            (payload.device_id, payload.public_key, client_ip)
        )
        conn.commit()
        
    return {"status": "registered", "ip_locked": client_ip}
    
@app.post("/payload/upload")
async def upload_payload(payload: UploadPayloadRequest, request: Request):
    client_ip = request.client.host
    
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM devices WHERE device_id = ?", (payload.device_id,))
        row = cursor.fetchone()
        
    if not row:
        raise HTTPException(status_code=404, detail="Device not registered")
        
    stored_ip = row[0]
    if stored_ip != client_ip:
        raise HTTPException(status_code=403, detail="IP address mismatch. Verification failed.")
        
    if payload.device_id not in verified_devices:
        raise HTTPException(status_code=403, detail="Device not verified")

    if is_out_of_bounds(payload.lat, payload.lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")
        
    try:
        raw_bytes = base64.b64decode(payload.base64_blob)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 payload provided.")

    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO payloads (pointer, encrypted_blob) VALUES (?, ?)",
            (payload.pointer, raw_bytes)
        )
        conn.commit()
        
    return {"status": "success", "detail": f"Payload {payload.pointer} uploaded successfully"}

@app.post("/payload/fetch")
async def fetch_payload(payload: FetchPayloadRequest, request: Request):
    from fastapi.responses import Response
    
    client_ip = request.client.host
    
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM devices WHERE device_id = ?", (payload.device_id,))
        row = cursor.fetchone()
        
    if not row:
        raise HTTPException(status_code=404, detail="Device not registered")
        
    if row[0] != client_ip:
        raise HTTPException(status_code=403, detail="IP address mismatch. Verification failed.")
        
    if payload.device_id not in verified_devices:
        raise HTTPException(status_code=403, detail="Device not verified")

    if is_out_of_bounds(payload.lat, payload.lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")

    # Fetch the blob using the pointer (e.g., "root")
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_blob FROM payloads WHERE pointer = ?", (payload.pointer,))
        blob_row = cursor.fetchone()
        
    if not blob_row:
        raise HTTPException(status_code=404, detail="Payload pointer not found")
        
    # Return raw binary data for the Dart Isolate to decrypt
    return Response(content=blob_row[0], media_type="application/octet-stream")

@app.post("/")
def serve_ciphertext(payload: ServeRequest):
    if not payload.device_id:
        raise HTTPException(status_code=403, detail="Device identity required")

    if payload.device_id not in verified_devices:
        raise HTTPException(status_code=403, detail="Device not verified")
    
    if is_out_of_bounds(payload.lat, payload.lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")
    
    file_path = "sample.enc"

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Ciphertext asset not found.")
    
    return FileResponse(
        path=file_path,
        media_type='application/octet-stream',
        filename='cryptstream_payload.enc'
    )

@app.post("/heartbeat")
async def receive_heartbeat(payload: LocationPayload):
    if is_out_of_bounds(payload.lat, payload.lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")
        
    device_locations[payload.device_id] = {
        "lat": payload.lat,
        "lon": payload.lon
    }
    return {"status": "received"}

@app.post("/request-challenge")
def get_challenge(payload: ChallengeRequest):
    if is_out_of_bounds(payload.lat, payload.lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")
    
    challenge = secrets.token_hex(32)
    challenges[payload.device_id] = challenge
    return {"challenge": challenge}

@app.post("/verify")
async def verify_device(payload: SignatureAndLocationRequest, request: Request):
    client_ip = request.client.host
    
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key, ip_address FROM devices WHERE device_id = ?", (payload.device_id,))
        row = cursor.fetchone()
        
    if not row:
        raise HTTPException(status_code=404, detail="Device not registered")
        
    stored_pub_key_b64, stored_ip = row
    
    if stored_ip != client_ip:
        raise HTTPException(status_code=403, detail="IP address mismatch. Verification failed.")

    signature = base64.b64decode(payload.signature)
    challenge = challenges.get(payload.device_id)

    lat = payload.lat
    lon = payload.lon

    if is_out_of_bounds(lat, lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")
    
    if not challenge:
        raise HTTPException(status_code=400, detail="No challenge found")

    try:
        public_key_bytes = base64.b64decode(stored_pub_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        
        public_key.verify(signature, challenge.encode())
        verified_devices.add(payload.device_id)
        return {"status": "verified"}
    except Exception:
        raise HTTPException(status_code=401, detail="Signature invalid")