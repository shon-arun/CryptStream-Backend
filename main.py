from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import os

app = FastAPI()

@app.get("/")
def serve_ciphertext():
    file_path = "sample.enc"

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Ciphertext asset not found.")
    
    return FileResponse(
        path=file_path,
        media_type='application/octet-stream',
        filename='cryptstream_payload.enc'
    )

@app.get("/shady-object-0") # Should be removed ASAP
def serve_image():
    return FileResponse("sample.jpg")