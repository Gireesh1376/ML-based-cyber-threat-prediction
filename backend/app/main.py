from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import dashboard, detect

app = FastAPI(
    title="ML-Based Cyber Threat Prediction",
    description="Hybrid Autoencoder + XGBoost IDS focused on zero-day / unknown attacks.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router, prefix="/api")
app.include_router(detect.router, prefix="/api")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "cyber-threat-prediction"}
