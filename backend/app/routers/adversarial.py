"""
FastAPI router for Problem 4: Adversarial Evasion Robustness & Defense Lab.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ml.adversarial import (
    load_adversarial_metrics,
    simulate_adversarial_flow,
)
from app.routers.detect import PRESETS

router = APIRouter(prefix="/api/adversarial", tags=["adversarial"])


class AdversarialSimulateRequest(BaseModel):
    preset: str | None = Field(default=None, description="Optional preset name (e.g. known_dos, probe_scan)")
    flow: dict[str, Any] | None = Field(default=None, description="Raw network flow attributes")
    method: str = Field(default="demgan", description="Perturbation method: demgan, uap, or fgsm")
    epsilon: float = Field(default=0.20, ge=0.01, le=0.50, description="Perturbation budget ε")

    class Config:
        extra = "allow"


@router.get("/metrics")
def get_adversarial_metrics() -> dict[str, Any]:
    """Returns the empirical adversarial robustness benchmark metrics."""
    try:
        return load_adversarial_metrics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load adversarial metrics: {e}")


@router.get("/presets")
def get_adversarial_presets() -> dict[str, Any]:
    """Returns preset attack vectors and method documentation for interactive testing."""
    return {
        "presets": PRESETS,
        "methods": {
            "demgan": {
                "name": "DEMGAN (Xu et al. 2025)",
                "description": "Multi-generator GAN evasion scheme tailored per threat family. Drifts mutable timing, error, and rate characteristics toward normal distributions with calibrated variance.",
                "type": "Generative / Black-Box",
            },
            "uap": {
                "name": "Universal Adversarial Perturbation (Zhang et al. 2025)",
                "description": "Pre-computed universal perturbation vector applied across high-throughput packet streams without per-flow latency.",
                "type": "Universal / High-Speed",
            },
            "fgsm": {
                "name": "Constrained FGSM (Gradient Approximation)",
                "description": "Directional gradient sensitivity approximation that steps mutable features toward the decision boundary of benign traffic.",
                "type": "White-Box / Gradient",
            },
        },
    }


@router.post("/simulate")
def simulate_evasion(req: AdversarialSimulateRequest) -> dict[str, Any]:
    """Simulates adversarial flow perturbation and evaluates Baseline vs Hardened detector."""
    # Determine input flow
    if req.preset:
        if req.preset not in PRESETS:
            raise HTTPException(status_code=400, detail=f"Unknown preset '{req.preset}'. Available: {list(PRESETS.keys())}")
        payload = PRESETS[req.preset].copy()
    elif req.flow:
        payload = req.flow.copy()
    else:
        # Default to known_dos if neither is provided
        payload = PRESETS["known_dos"].copy()

    try:
        result = simulate_adversarial_flow(payload, method=req.method, epsilon=req.epsilon)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {e}")
