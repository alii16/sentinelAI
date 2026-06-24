"""
Sentinel AI - Dataset Merger
Menggabungkan semua dataset dari berbagai sumber menjadi satu
dataset final yang siap untuk training.

Cara pakai:
    cd backend
    python app/ml/training/merge_datasets.py

Output: datasets/processed/sentinel_final_dataset.csv
"""

import os
import sys
import pandas as pd
import numpy as np

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
PROCESSED_DIR = os.path.join(BASE_DIR, "../../../../datasets/processed")
os.makedirs(PROCESSED_DIR, exist_ok=True)

REQUIRED_COLS = [
    "status_code", "response_time", "response_length",
    "header_count", "cookie_count", "redirect_count",
    "framework_encoded", "server_encoded", "authentication",
    "param_count", "form_count", "endpoint_count", "depth",
    "has_password_field", "has_file_upload", "has_search_form",
    "label"
]

VALID_LABELS = [
    "Authentication", "Authorization", "Configuration",
    "Input Validation", "Session", "Header",
    "Information", "Safe",
    # Alias yang bisa masuk dari CSIC / Kaggle
    "SQL Injection", "XSS", "Path Traversal", "Command Injection",
]

# Map alias ke label standar Sentinel AI
LABEL_MAP = {
    "sql injection":       "Input Validation",
    "sqli":                "Input Validation",
    "xss":                 "Input Validation",
    "cross-site scripting":"Input Validation",
    "path traversal":      "Authorization",
    "directory traversal": "Authorization",
    "command injection":   "Input Validation",
    "normal":              "Safe",
    "safe":                "Safe",
    "benign":              "Safe",
    "anomalous":           "Configuration",
    "attack":              "Configuration",
    "dos":                 "Configuration",
    "ddos":                "Configuration",
    "probe":               "Information",
    "r2l":                 "Authorization",
    "u2r":                 "Authorization",
    "generic":             "Configuration",
    "exploits":            "Input Validation",
    "fuzzers":             "Input Validation",
    "backdoor":            "Authorization",
    "analysis":            "Information",
    "reconnaissance":      "Information",
    "shellcode":           "Input Validation",
    "worms":               "Configuration",
    "information":         "Information",
    "authentication":      "Authentication",
    "authorization":       "Authorization",
    "configuration":       "Configuration",
    "input validation":    "Input Validation",
    "session":             "Session",
    "header":              "Header",
}


def normalize_label(label: str) -> str:
    """Normalisasi label ke standar Sentinel AI."""
    if not label:
        return "Safe"
    label_lower = str(label).strip().lower()
    return LABEL_MAP.get(label_lower, "Configuration")


def load_csv(filepath: str, label_col: str = "label") -> pd.DataFrame:
    """Load CSV dan normalisasi ke format Sentinel AI."""
    try:
        df = pd.read_csv(filepath, low_memory=False)
        print(f"    Loaded {len(df)} rows dari {os.path.basename(filepath)}")
    except Exception as e:
        print(f"    Gagal load {filepath}: {e}")
        return pd.DataFrame()

    # Cari kolom label
    label_found = None
    for col in [label_col, "Label", "label", "class", "Class", "category",
                "Category", "attack_type", "type", "Type"]:
        if col in df.columns:
            label_found = col
            break

    if not label_found:
        print(f"    Kolom label tidak ditemukan, skip")
        return pd.DataFrame()

    # Normalisasi label
    df["label"] = df[label_found].apply(normalize_label)

    # Pastikan semua kolom required ada
    for col in REQUIRED_COLS:
        if col not in df.columns and col != "label":
            df[col] = 0

    # Ambil hanya kolom yang dibutuhkan
    available = [c for c in REQUIRED_COLS if c in df.columns]
    df = df[available].copy()

    # Fill missing
    df = df.fillna(0)

    # Konversi tipe
    numeric_cols = [c for c in REQUIRED_COLS if c != "label"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    return df


def balance_dataset(df: pd.DataFrame, min_per_label: int = 200,
                    max_per_label: int = 2000) -> pd.DataFrame:
    """
    Seimbangkan dataset:
    - Upsample label yang kurang dari min_per_label
    - Downsample label yang lebih dari max_per_label
    """
    parts = []
    for label in df["label"].unique():
        subset = df[df["label"] == label]
        n = len(subset)

        if n < min_per_label:
            # Upsample dengan replacement
            upsampled = subset.sample(min_per_label, replace=True, random_state=42)
            parts.append(upsampled)
            print(f"    {label:<25} {n:>5} → {min_per_label} (upsampled)")
        elif n > max_per_label:
            # Downsample
            downsampled = subset.sample(max_per_label, replace=False, random_state=42)
            parts.append(downsampled)
            print(f"    {label:<25} {n:>5} → {max_per_label} (downsampled)")
        else:
            parts.append(subset)
            print(f"    {label:<25} {n:>5} (unchanged)")

    return pd.concat(parts, ignore_index=True)


def merge():
    print("=" * 60)
    print("Sentinel AI - Dataset Merger")
    print("=" * 60)

    all_dfs = []

    # ── 1. Cari semua CSV di processed/ ──────────────────────────
    print("\n[1] Mencari dataset di datasets/processed/ ...")
    csv_files = [f for f in os.listdir(PROCESSED_DIR)
                 if f.endswith(".csv") and f != "sentinel_final_dataset.csv"]

    if not csv_files:
        print("    Tidak ada CSV ditemukan.")
        print("    Jalankan dulu: python app/ml/training/convert_csic.py")
    else:
        for fname in csv_files:
            print(f"\n  → {fname}")
            df = load_csv(os.path.join(PROCESSED_DIR, fname))
            if not df.empty:
                df["_source"] = fname
                all_dfs.append(df)

    # ── 2. Cek folder raw untuk CSV Kaggle langsung ───────────────
    raw_dir = os.path.join(BASE_DIR, "../../../../datasets/raw")
    print(f"\n[2] Mencari CSV di datasets/raw/ ...")
    if os.path.exists(raw_dir):
        kaggle_csvs = [f for f in os.listdir(raw_dir) if f.endswith(".csv")]
        if kaggle_csvs:
            for fname in kaggle_csvs:
                print(f"\n  → {fname} (Kaggle/raw)")
                df = load_csv(os.path.join(raw_dir, fname))
                if not df.empty:
                    df["_source"] = fname
                    all_dfs.append(df)
        else:
            print("    Tidak ada CSV di raw/")
    else:
        print("    Folder raw/ tidak ada")

    # ── 3. Gabungkan ──────────────────────────────────────────────
    if not all_dfs:
        print("\n  Tidak ada dataset ditemukan!")
        print("  Menggunakan dataset sintetis bawaan...")
        # Import train.py synthetic generator
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from train import generate_synthetic_dataset
        df_synth = generate_synthetic_dataset(3000)
        all_dfs.append(df_synth)

    print(f"\n[3] Menggabungkan {len(all_dfs)} dataset...")
    merged = pd.concat(all_dfs, ignore_index=True)

    # Hapus kolom helper
    merged = merged.drop(columns=["_source"], errors="ignore")

    # Pastikan semua kolom ada
    for col in REQUIRED_COLS:
        if col not in merged.columns:
            merged[col] = 0

    merged = merged[REQUIRED_COLS].fillna(0)

    print(f"\n    Total sebelum balancing: {len(merged)} record")
    print(f"\n    Distribusi label sebelum balancing:")
    for label, count in merged["label"].value_counts().items():
        bar = "█" * min(count // 50, 25)
        print(f"    {label:<25} {count:>6}  {bar}")

    # ── 4. Balance ────────────────────────────────────────────────
    print(f"\n[4] Menyeimbangkan dataset...")
    balanced = balance_dataset(merged, min_per_label=300, max_per_label=2000)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\n    Total setelah balancing: {len(balanced)} record")

    # ── 5. Simpan ─────────────────────────────────────────────────
    out_path = os.path.join(PROCESSED_DIR, "sentinel_final_dataset.csv")
    balanced.to_csv(out_path, index=False)

    print(f"\n[5] Dataset final disimpan:")
    print(f"    {out_path}")
    print(f"    {len(balanced)} record × {len(balanced.columns)} kolom")

    print("\n" + "=" * 60)
    print("  Langkah selanjutnya:")
    print("  python app/ml/training/train.py")
    print("=" * 60)


if __name__ == "__main__":
    merge()
