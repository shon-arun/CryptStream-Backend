from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()

@app.get("/")
def serve_image():
    return FileResponse("sample.jpg")