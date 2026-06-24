"""
Sentinel AI - Export Scan Results as Dataset
Mengekspor hasil scan dari database menjadi dataset berlabel
untuk training model ML.

Cara pakai:
    cd backend
    python app/ml/training/export_scan_dataset.py

Sebelum pakai:
    1. Scan beberapa website di Sentinel AI
    2. Verifikasi hasil scan (tandai true positive / false positive)
    3. Jalankan script ini untuk export ke CSV
    4. Gabungkan dengan dataset lain
    5. Jalankan train.py
"""

import os
import sys
import asyncio
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "../../.."))

PROCESSED_DIR = os.path.join(BASE_DIR, "../../../../datasets/processed")
os.makedirs(PROCESSED_DIR, exist_ok=True)


async def export():
    print("=" * 60)
    print("Sentinel AI - Export Scan Results sebagai Dataset")
    print("=" * 60)

    from app.core.database import AsyncSessionLocal
    from app.models.models import AIPrediction, Endpoint, Scan
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    records = []

    async with AsyncSessionLocal() as db:
        # Ambil semua prediksi yang sudah diverifikasi
        preds = (await db.execute(
            select(AIPrediction)
            .where(AIPrediction.is_false_positive == 0)
            .limit(5000)
        )).scalars().all()

        print(f"\n  Ditemukan {len(preds)} prediksi terverifikasi")

        for p in preds:
            evidence = p.evidence or {}

            record = {
                "status_code":       evidence.get("status_code", 200),
                "response_time":     evidence.get("response_time", 500),
                "response_length":   evidence.get("content_length", 1000),
                "header_count":      len(evidence.get("present_security_headers", [])),
                "cookie_count":      evidence.get("cookie_count", 0),
                "redirect_count":    0,
                "framework_encoded": 0,
                "server_encoded":    0,
                "authentication":    int(bool(evidence.get("set_cookie"))),
                "param_count":       0,
                "form_count":        int(bool(evidence.get("has_upload_form"))),
                "endpoint_count":    1,
                "depth":             1,
                "has_password_field": int(bool(evidence.get("has_password"))),
                "has_file_upload":   int(bool(evidence.get("has_file_upload"))),
                "has_search_form":   int(bool(evidence.get("has_search"))),
                "label":             p.prediction,
            }
            records.append(record)

    if not records:
        print("\n  Belum ada data scan. Lakukan scan terlebih dahulu.")
        print("  Jalankan beberapa scan di Sentinel AI, lalu jalankan script ini.")
        return

    df = pd.DataFrame(records)
    df = df.fillna(0)

    print("\n  Distribusi label dari scan:")
    for label, count in df["label"].value_counts().items():
        print(f"  {label:<25} {count}")

    out_path = os.path.join(PROCESSED_DIR, "sentinel_dataset_from_scans.csv")
    df.to_csv(out_path, index=False)
    print(f"\n  ✓ Dataset disimpan: {out_path}")
    print(f"  ✓ Total: {len(df)} record")
    print("\n  Sekarang jalankan training:")
    print("  python app/ml/training/train.py")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(export())
