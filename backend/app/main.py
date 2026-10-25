import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.db import check_es_connection, init_alerts_index
from app.routers import adversarial, dashboard, detect, encrypted

logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Elasticsearch index and demo data if available
    try:
        init_alerts_index()
    except Exception as exc:
        logger.warning("Elasticsearch startup check notice: %s", exc)
    yield


app = FastAPI(
    title="ML-Based Cyber Threat Prediction",
    description="Hybrid Autoencoder + XGBoost IDS focused on zero-day / unknown attacks and adversarial robustness.",
    version="0.2.0",
    lifespan=lifespan,
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
app.include_router(encrypted.router, prefix="/api")
app.include_router(adversarial.router)


@app.get("/api/health")
def health():
    es_status = check_es_connection()
    return {
        "status": "ok",
        "service": "cyber-threat-prediction",
        "database": {
            "type": "elasticsearch",
            "connected": es_status.get("connected", False),
        },
    }
