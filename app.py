"""FastAPI inference service for SQL injection detection."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


MODEL_PATH = Path(os.getenv("MODEL_PATH", "sql_injection_svm_model.joblib"))
THRESHOLD = float(os.getenv("THRESHOLD", "-0.40"))
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "https://demo.example.com",
    "https://frontend.example.com",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("sql_injection_api")

app = FastAPI(title="SQL Injection Detection API")
model = None
model_load_error: str | None = None

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class QueryRequest(BaseModel):
    """Request schema for SQL query classification."""

    query: str


def load_model() -> None:
    """Load the trained model once and store any startup error."""
    global model, model_load_error

    if not MODEL_PATH.exists():
        model = None
        model_load_error = (
            f"Model file not found: {MODEL_PATH.resolve()}. "
            "Train the model before starting the API."
        )
        logger.error(model_load_error)
        return

    try:
        model = joblib.load(MODEL_PATH)
        model_load_error = None
        logger.info("Model loaded successfully from %s", MODEL_PATH.resolve())
    except Exception as exc:  # pragma: no cover - defensive API startup path
        model = None
        model_load_error = f"Failed to load model from {MODEL_PATH.resolve()}: {exc}"
        logger.exception("Model loading failed")


@app.on_event("startup")
def startup_event() -> None:
    """Load the model when the API starts."""
    load_model()


@app.get("/")
def health_check() -> dict[str, object]:
    """Return API health information."""
    response: dict[str, object] = {"status": "ok", "model_loaded": model is not None}
    if model_load_error:
        response["error"] = model_load_error
    return response


@app.get("/health")
def detailed_health_check() -> dict[str, object]:
    """Return production health information for probes and monitors."""
    return {"status": "ok", "model_loaded": model is not None}


@app.post("/predict")
def predict(request: QueryRequest) -> dict[str, object]:
    """Score a query and classify it with the fixed decision threshold."""
    if model is None:
        detail = model_load_error or (
            "Model is not available. Train the model before making predictions."
        )
        raise HTTPException(status_code=503, detail=detail)

    query = request.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query must not be empty.")

    score = float(model.decision_function([query])[0])
    label = int(score >= THRESHOLD)
    prediction = "Malicious" if label == 1 else "Normal"
    allowed = label == 0

    logger.info(
        "prediction=%s score=%.4f allowed=%s",
        prediction,
        score,
        allowed,
    )

    return {
        "query": request.query,
        "score": score,
        "prediction": prediction,
        "label": label,
        "allowed": allowed,
    }
