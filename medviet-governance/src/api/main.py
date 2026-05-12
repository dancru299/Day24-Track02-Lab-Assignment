# src/api/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
import pandas as pd
from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()

RAW_DATA_PATH = "data/raw/patients_raw.csv"

# --- ENDPOINT 1 ---
@app.get("/api/patients/raw")
@require_permission(resource="patient_data", action="read")
async def get_raw_patients(
    current_user: dict = Depends(get_current_user)
):
    """Trả về raw patient data (chỉ admin)."""
    try:
        df = pd.read_csv(RAW_DATA_PATH, dtype=str)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Raw data not found")
    return {"data": df.head(10).to_dict("records"), "user": current_user["username"]}

# --- ENDPOINT 2 ---
@app.get("/api/patients/anonymized")
@require_permission(resource="training_data", action="read")
async def get_anonymized_patients(
    current_user: dict = Depends(get_current_user)
):
    """Trả về anonymized data (ml_engineer và admin)."""
    try:
        df = pd.read_csv(RAW_DATA_PATH, dtype=str)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Raw data not found")
    df_anon = anonymizer.anonymize_dataframe(df)
    return {"data": df_anon.head(10).to_dict("records"), "user": current_user["username"]}

# --- ENDPOINT 3 ---
@app.get("/api/metrics/aggregated")
@require_permission(resource="aggregated_metrics", action="read")
async def get_aggregated_metrics(
    current_user: dict = Depends(get_current_user)
):
    """Trả về aggregated metrics — không có PII (data_analyst, ml_engineer, admin)."""
    try:
        df = pd.read_csv(RAW_DATA_PATH, dtype=str)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Raw data not found")
    metrics = {
        "disease_distribution": df["benh"].value_counts().to_dict(),
        "total_patients": len(df),
        "avg_test_result": round(pd.to_numeric(df["ket_qua_xet_nghiem"], errors="coerce").mean(), 2),
    }
    return {"metrics": metrics, "user": current_user["username"]}

# --- ENDPOINT 4 ---
@app.delete("/api/patients/{patient_id}")
@require_permission(resource="patient_data", action="delete")
async def delete_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Chỉ admin được xóa bệnh nhân."""
    return {
        "message": f"Patient {patient_id} deleted successfully",
        "deleted_by": current_user["username"]
    }

@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}
