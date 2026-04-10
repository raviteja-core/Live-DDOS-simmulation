from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_allowed_origins, load_env_file
from .routers import health, threats

load_env_file()

app = FastAPI(title="DDoS Attack Map API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Accept", "Content-Type"],
)

app.include_router(health.router)
app.include_router(threats.router)

@app.get("/")
async def root():
    return {"message": "DDoS Attack Map API"}
