from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, Response
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
                ip_address TEXT,
                vault_salt TEXT,
                authorized BOOLEAN DEFAULT 0
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

# New Pydantic model for the bulk deletion endpoint
class DeletePayloadRequest(BaseModel):
    device_id: str
    lat: float
    lon: float
    pointers: list[str]

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
        
        cursor.execute("SELECT vault_salt FROM devices WHERE device_id = ? AND authorized", (payload.device_id,))
        row = cursor.fetchone()
        
        if row and row[0]:
            vault_salt_b64 = row[0]
        else:
            vault_salt_b64 = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
            
        cursor.execute(
            "INSERT OR IGNORE INTO devices (device_id, public_key, ip_address, vault_salt) VALUES (?, ?, ?, ?)",
            (payload.device_id, payload.public_key, client_ip, vault_salt_b64)
        )
        conn.commit()
        
    return {
        "status": "registered", 
        "ip_locked": client_ip,
        "vault_salt": vault_salt_b64
    }
    
@app.post("/payload/upload")
async def upload_payload(payload: UploadPayloadRequest, request: Request):
    client_ip = request.client.host
    
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM devices WHERE device_id = ? AND authorized", (payload.device_id,))
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
    client_ip = request.client.host
    
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM devices WHERE device_id = ? AND authorized", (payload.device_id,))
        row = cursor.fetchone()
        
    if not row:
        raise HTTPException(status_code=404, detail="Device not registered")
        
    if row[0] != client_ip:
        raise HTTPException(status_code=403, detail="IP address mismatch. Verification failed.")
        
    if payload.device_id not in verified_devices:
        raise HTTPException(status_code=403, detail="Device not verified")

    if is_out_of_bounds(payload.lat, payload.lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")

    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_blob FROM payloads WHERE pointer = ?", (payload.pointer,))
        blob_row = cursor.fetchone()
        
    if not blob_row:
        raise HTTPException(status_code=404, detail="Payload pointer not found")
        
    return Response(content=blob_row[0], media_type="application/octet-stream")

# New bulk deletion endpoint
@app.post("/payload/delete")
async def delete_payloads(payload: DeletePayloadRequest, request: Request):
    client_ip = request.client.host
    
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM devices WHERE device_id = ? AND authorized", (payload.device_id,))
        row = cursor.fetchone()
        
    if not row:
        raise HTTPException(status_code=404, detail="Device not registered")
        
    if row[0] != client_ip:
        raise HTTPException(status_code=403, detail="IP address mismatch. Verification failed.")
        
    if payload.device_id not in verified_devices:
        raise HTTPException(status_code=403, detail="Device not verified")

    if is_out_of_bounds(payload.lat, payload.lon):
        raise HTTPException(status_code=403, detail="Access denied: Out of bounds")

    if not payload.pointers:
        return {"status": "success", "detail": "No pointers provided for deletion."}

    # Execute a bulk SQL transaction to wipe the blocks
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(payload.pointers))
        query = f"DELETE FROM payloads WHERE pointer IN ({placeholders})"
        cursor.execute(query, payload.pointers)
        conn.commit()
        deleted_count = cursor.rowcount
        
    return {"status": "success", "detail": f"Successfully wiped {deleted_count} blocks."}

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
        cursor.execute("SELECT public_key, ip_address FROM devices WHERE device_id = ? AND authorized", (payload.device_id,))
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

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard():
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        # Fetch all registered devices
        devices = cursor.execute("SELECT device_id, public_key, authorized FROM devices").fetchall()
        
        # Build a simple HTML table
        rows = "".join([f"<tr><td>{d[0]}</td><td>{d[1][:20]}...</td><td>{d[2]}</td><td><form method='POST' action='/admin/toggle'><input type='hidden' name='device_id' value='{d[0]}'><button type='submit'>Toggle Auth</button></form></td></tr>" for d in devices])
        
        return f"""
        <html><body>
            <h1>CryptStream Admin Dashboard</h1>
            <table border='1'><tr><th>ID</th><th>Public Key</th><th>Auth</th><th>Action</th></tr>{rows}</table>
        </body></html>
        """

@app.post("/admin/toggle")
async def toggle_device(device_id: str = Form(...)):
    with sqlite3.connect("devices.db") as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE devices SET authorized = NOT authorized WHERE device_id = ?", (device_id,))
        conn.commit()
    return HTMLResponse(content="<script>window.location.href='/admin';</script>")