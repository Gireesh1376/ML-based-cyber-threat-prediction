"""
FastAPI router for Problem 4: Adversarial Evasion Robustness & Defense Lab.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.ml.adversarial import (
    load_adversarial_metrics,
    simulate_adversarial_flow,
)
from app.routers.detect import PRESETS

router = APIRouter(prefix="/api/adversarial", tags=["adversarial"])


class AdversarialSimulateRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    preset: str | None = Field(default=None, description="Optional preset name (e.g. known_dos, probe_scan)")
    flow: dict[str, Any] | None = Field(default=None, description="Raw network flow attributes")
    method: str = Field(default="demgan", description="Perturbation method: demgan, uap, or fgsm")
    epsilon: float = Field(default=0.20, ge=0.01, le=0.50, description="Perturbation budget ε")
    adaptive: bool = Field(default=False, description="Whether attack adapts to the hardened model directly")


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
                "name": "DEMGAN Manifold Drift (Xu et al. 2025 Approximation)",
                "description": "Empirical manifold drift approximation towards benign traffic distribution with calibrated stochastic jitter. (Note: Evaluated as a surrogate approximation; does not use a trained neural GAN generator).",
                "type": "Manifold Drift / Approximation",
            },
            "uap": {
                "name": "Universal Adversarial Perturbation (Zhang et al. 2025)",
                "description": "Genuine universal perturbation vector optimized against detector feedback across multiple network flows to evade detection with zero per-flow latency.",
                "type": "Universal / Model-Optimized",
            },
            "fgsm": {
                "name": "Constrained FGSM (White-Box Gradient)",
                "description": "Genuine gradient-based perturbation utilizing the trained hybrid model's gradients to identify minimal input changes causing misclassification.",
                "type": "White-Box / Gradient-Feedback",
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
        result = simulate_adversarial_flow(
            payload,
            method=req.method,
            epsilon=req.epsilon,
            adaptive=req.adaptive,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {e}")
