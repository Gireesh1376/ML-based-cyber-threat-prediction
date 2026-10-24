"""
FastAPI router for Problem 4: Adversarial Evasion Robustness & Defense Lab.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.ml.adversarial import (
    get_adversarial_evidence,
    get_evidence_case_by_id,
    load_adversarial_metrics,
    simulate_adversarial_flow,
)
from app.routers.detect import PRESETS

router = APIRouter(prefix="/api/adversarial", tags=["adversarial"])

SUPPORTED_METHODS = ("fgsm", "uap", "demgan")
SupportedMethod = Literal["fgsm", "uap", "demgan"]


class AdversarialSimulateRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    preset: str | None = Field(default=None, description="Optional preset name (e.g. known_dos, probe_scan)")
    sample_id: str | None = Field(default=None, description="Optional verified evaluation sample ID from held-out test data")
    flow: dict[str, Any] | None = Field(default=None, description="Raw network flow attributes")
    method: SupportedMethod = Field(default="demgan", description="Perturbation method: fgsm, uap, or demgan")
    epsilon: float = Field(default=0.20, ge=0.01, le=0.50, description="Perturbation budget ε")
    adaptive: bool = Field(default=False, description="Whether attack adapts to the hardened model directly")


@router.get("/metrics")
def get_adversarial_metrics() -> dict[str, Any]:
    """Returns the empirical adversarial robustness benchmark metrics."""
    try:
        return load_adversarial_metrics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load adversarial metrics: {e}")


@router.get("/evidence")
def get_adversarial_evidence_endpoint(
    method: SupportedMethod = "fgsm",
    epsilon: float = 0.20,
) -> dict[str, Any]:
    """Returns empirical evaluation evidence across held-out test attacks comparing Baseline vs Hardened."""
    if method not in SUPPORTED_METHODS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported method '{method}'. Allowed methods: {list(SUPPORTED_METHODS)}",
        )
    try:
        return get_adversarial_evidence(method=method, epsilon=epsilon)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load adversarial evidence: {e}")


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
    if req.method not in SUPPORTED_METHODS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported method '{req.method}'. Allowed methods: {list(SUPPORTED_METHODS)}",
        )

    gt_label = None
    gt_family = None

    # Determine input flow
    if req.sample_id:
        case = get_evidence_case_by_id(req.sample_id)
        if not case:
            raise HTTPException(status_code=404, detail=f"Verified sample '{req.sample_id}' not found.")
        payload = case["original_flow"].copy()
        gt_label = case.get("ground_truth_label")
        gt_family = case.get("ground_truth_family")
    elif req.preset:
        if req.preset not in PRESETS:
            raise HTTPException(status_code=400, detail=f"Unknown preset '{req.preset}'. Available: {list(PRESETS.keys())}")
        payload = PRESETS[req.preset].copy()
        if req.preset == "known_dos":
            gt_label, gt_family = "neptune", "dos"
        elif req.preset == "probe_scan":
            gt_label, gt_family = "ipsweep", "probe"
        elif req.preset == "zero_day_like":
            gt_label, gt_family = "tftp", "novel"
    elif req.flow:
        payload = req.flow.copy()
        gt_label = payload.get("label")
        gt_family = payload.get("family")
    else:
        # Default to known_dos if neither is provided
        payload = PRESETS["known_dos"].copy()
        gt_label, gt_family = "neptune", "dos"

    try:
        result = simulate_adversarial_flow(
            payload,
            method=req.method,
            epsilon=req.epsilon,
            adaptive=req.adaptive,
            ground_truth_label=gt_label,
            ground_truth_family=gt_family,
        )
        if req.sample_id:
            result["sample_id"] = req.sample_id
        return result
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {e}")

