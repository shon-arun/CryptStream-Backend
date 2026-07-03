from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import os
import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

# Configuration
PUBLIC_KEY_BASE64 = "0/gtmOAs3AfX1bAFVlvw/vHFu2tHTZKMsmOb1OD0bxE="
PUBLIC_KEY_BYTES = base64.b64decode(PUBLIC_KEY_BASE64)
public_key = ed25519.Ed25519PublicKey.from_public_bytes(PUBLIC_KEY_BYTES)
challenges = {} # Stores {device_id: challenge_string}
verified_devices = set()

class SignatureRequest(BaseModel):
    signature: str

@app.get("/")
def serve_ciphertext(device_id: Optional[str] = None):
    if not device_id:
        raise HTTPException(status_code=403, detail="Device identity required")

    if device_id not in verified_devices:
        raise HTTPException(status_code=403, detail="Device not verified")
    
    file_path = "sample.enc"

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Ciphertext asset not found.")
    
    return FileResponse(
        path=file_path,
        media_type='application/octet-stream',
        filename='cryptstream_payload.enc'
    )

@app.get("/request-challenge/{device_id}")
def get_challenge(device_id: str):
    challenge = secrets.token_hex(32)
    challenges[device_id] = challenge
    return {"challenge": challenge}

@app.post("/verify/{device_id}")
async def verify_device(device_id: str, payload: SignatureRequest):
    signature = base64.b64decode(payload.signature)
    challenge = challenges.get(device_id)

    if not challenge:
        raise HTTPException(status_code=400, detail="No challenge found")

    try:
        public_key.verify(signature, challenge.encode())
        verified_devices.add(device_id)
        return {"status": "verified"}
    except Exception:
        raise HTTPException(status_code=401, detail="Signature invalid")

@app.get("/shady-object-0") # Should be removed ASAP
def serve_image():
    return FileResponse("sample.jpg")