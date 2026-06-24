"""
Sentinel AI - Dataset Converter
Mengkonversi HTTP CSIC 2010 dataset ke format Sentinel AI

Cara pakai:
    cd backend
    python app/ml/training/convert_csic.py

Input  : datasets/raw/*.txt (HTTP CSIC 2010)
Output : datasets/processed/sentinel_dataset_csic.csv
"""

import os
import re
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs

# ── Path ────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
RAW_DIR      = os.path.join(BASE_DIR, "../../../../datasets/raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "../../../../datasets/processed")

os.makedirs(PROCESSED_DIR, exist_ok=True)

# ── Label mapping dari CSIC ─────────────────────────────────────
# CSIC: normal → Safe
# CSIC: anomalous → kita deteksi lebih lanjut dari URL/body

ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b)",
        r"('|\"|--|;|\/\*|\*\/)",
        r"(or\s+1=1|and\s+1=1|'\s+or\s+')",
        r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
    ],
    "XSS": [
        r"(<script|<\/script>|javascript:|onerror=|onload=)",
        r"(alert\s*\(|document\.cookie|window\.location)",
        r"(<img|<iframe|<svg|<body)",
    ],
    "Path Traversal": [
        r"(\.\./|\.\.\\|%2e%2e)",
        r"(\/etc\/passwd|\/etc\/shadow|\/windows\/system32)",
    ],
    "Command Injection": [
        r"(;|\||&&|\$\(|`)",
        r"(wget|curl|nc\s|netcat|bash|sh\s+-c)",
        r"(cat\s+\/|ls\s+-|id\s*;|whoami)",
    ],
    "Information": [
        r"(\bphpinfo\b|\bphpinfo\.php\b)",
        r"(\.env|\.git|\.htaccess|web\.config)",
        r"(backup|dump|config|\.sql|\.bak)",
    ],
}

SERVER_ENCODING = {
    "apache": 1, "nginx": 2, "iis": 3, "litespeed": 4,
    "tomcat": 5, "unknown": 0
}

FRAMEWORK_ENCODING = {
    "php": 1, "asp": 2, "jsp": 3, "django": 4,
    "rails": 5, "laravel": 6, "unknown": 0
}


def detect_label(method: str, url: str, body: str, headers: dict) -> str:
    """Deteksi label serangan dari konten request."""
    content = f"{url} {body}".lower()

    for label, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return label

    # Cek berdasarkan method dan karakteristik
    if method in ("PUT", "DELETE"):
        return "Authorization"

    if "cookie" in headers and len(headers.get("cookie","")) > 200:
        return "Session"

    return "Safe"


def extract_features(method: str, url: str, body: str,
                     headers: dict, label: str) -> dict:
    """Ekstrak fitur numerik dari HTTP request."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path_parts = [p for p in parsed.path.split("/") if p]

    # Body params
    body_params = {}
    if body:
        try:
            body_params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
        except Exception:
            pass

    total_params = len(params) + len(body_params)

    # Detect framework/server dari headers
    server_raw = headers.get("server", "").lower()
    server_enc = next((v for k, v in SERVER_ENCODING.items() if k in server_raw), 0)

    powered = headers.get("x-powered-by", "").lower()
    framework_enc = next((v for k, v in FRAMEWORK_ENCODING.items() if k in powered), 0)

    # Security headers
    security_headers = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options",
        "x-xss-protection", "referrer-policy"
    ]
    header_count = sum(1 for h in security_headers if h in headers)

    # Cookie analysis
    cookie_str = headers.get("cookie", "")
    cookie_count = len([c for c in cookie_str.split(";") if c.strip()])

    # Form detection from body
    has_password = int(any(
        k.lower() in ("password", "passwd", "pwd", "pass")
        for k in list(params.keys()) + list(body_params.keys())
    ))
    has_file = int("multipart/form-data" in headers.get("content-type", ""))
    has_search = int(any(
        k.lower() in ("q", "query", "search", "keyword", "s")
        for k in list(params.keys()) + list(body_params.keys())
    ))

    # Auth detection
    has_auth = int(
        "authorization" in headers or
        "cookie" in headers or
        any(k.lower() in ("username","email","login") for k in params.keys())
    )

    # URL depth
    depth = len(path_parts)

    # Response time estimation (synthetic, based on complexity)
    est_response_time = 100 + len(url) * 2 + len(body) // 10

    # Response length estimation
    est_response_length = 1000 + len(body) * 3

    return {
        "status_code": 200,
        "response_time": min(est_response_time, 5000),
        "response_length": min(est_response_length, 50000),
        "header_count": header_count,
        "cookie_count": cookie_count,
        "redirect_count": 0,
        "framework_encoded": framework_enc,
        "server_encoded": server_enc,
        "authentication": has_auth,
        "param_count": total_params,
        "form_count": int(len(body_params) > 0),
        "endpoint_count": depth,
        "depth": depth,
        "has_password_field": has_password,
        "has_file_upload": has_file,
        "has_search_form": has_search,
        "label": label,
        # Extra context (tidak dipakai ML, tapi berguna untuk analisis)
        "_method": method,
        "_url": url[:200],
    }


def parse_http_requests(filepath: str, default_label: str = None) -> list:
    """Parse file HTTP request CSIC format."""
    records = []
    current = {}
    body_lines = []
    in_body = False

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"  File tidak ditemukan: {filepath}")
        return []

    for line in lines:
        line_stripped = line.rstrip("\n")

        # Baris kosong setelah header = mulai body
        if line_stripped == "" and current.get("method"):
            if not in_body:
                in_body = True
                continue

        # Request line baru
        if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s", line_stripped):
            # Simpan record sebelumnya
            if current.get("method"):
                body = "&".join(body_lines).strip()
                label = default_label
                if not label:
                    label = detect_label(
                        current["method"],
                        current.get("url", "/"),
                        body,
                        current.get("headers", {})
                    )
                feat = extract_features(
                    current["method"],
                    current.get("url", "/"),
                    body,
                    current.get("headers", {}),
                    label
                )
                records.append(feat)

            # Parse new request line
            parts = line_stripped.split()
            current = {
                "method": parts[0] if len(parts) > 0 else "GET",
                "url": parts[1] if len(parts) > 1 else "/",
                "headers": {}
            }
            body_lines = []
            in_body = False

        # Header line
        elif ":" in line_stripped and not in_body and current.get("method"):
            key, _, val = line_stripped.partition(":")
            current["headers"][key.strip().lower()] = val.strip()

        # Body line
        elif in_body and line_stripped:
            body_lines.append(line_stripped)

    # Simpan record terakhir
    if current.get("method"):
        body = "&".join(body_lines).strip()
        label = default_label
        if not label:
            label = detect_label(
                current["method"],
                current.get("url", "/"),
                body,
                current.get("headers", {})
            )
        feat = extract_features(
            current["method"],
            current.get("url", "/"),
            body,
            current.get("headers", {}),
            label
        )
        records.append(feat)

    return records


def add_synthetic_samples(records: list, n: int = 500) -> list:
    """
    Tambah sampel sintetis untuk label yang kurang representasi.
    Memastikan semua 8 label ada di dataset.
    """
    np.random.seed(42)

    extra_labels = {
        "Authentication": 80,
        "Authorization":  80,
        "Configuration":  60,
        "Input Validation": 80,
        "Session":        60,
        "Header":         100,
        "Information":    60,
    }

    for label, count in extra_labels.items():
        existing = sum(1 for r in records if r.get("label") == label)
        if existing < count:
            needed = count - existing
            for _ in range(needed):
                base = {
                    "status_code": np.random.choice([200, 302, 400, 403, 500]),
                    "response_time": int(np.random.randint(50, 2000)),
                    "response_length": int(np.random.randint(100, 10000)),
                    "header_count": int(np.random.randint(0, 8)),
                    "cookie_count": int(np.random.randint(0, 4)),
                    "redirect_count": int(np.random.randint(0, 3)),
                    "framework_encoded": int(np.random.randint(0, 6)),
                    "server_encoded": int(np.random.randint(0, 5)),
                    "authentication": int(np.random.randint(0, 2)),
                    "param_count": int(np.random.randint(0, 8)),
                    "form_count": int(np.random.randint(0, 3)),
                    "endpoint_count": int(np.random.randint(1, 10)),
                    "depth": int(np.random.randint(0, 5)),
                    "has_password_field": int(np.random.randint(0, 2)),
                    "has_file_upload": int(np.random.randint(0, 2)),
                    "has_search_form": int(np.random.randint(0, 2)),
                    "label": label,
                    "_method": "GET",
                    "_url": f"/synthetic/{label.lower().replace(' ','_')}"
                }

                # Tweak berdasarkan label
                if label == "Header":
                    base["header_count"] = int(np.random.randint(0, 3))
                elif label == "Authentication":
                    base["has_password_field"] = 1
                    base["authentication"] = 1
                elif label == "Session":
                    base["cookie_count"] = int(np.random.randint(1, 5))
                elif label == "Configuration":
                    base["header_count"] = int(np.random.randint(0, 4))

                records.append(base)

    return records


def convert():
    print("=" * 60)
    print("Sentinel AI - Dataset Converter (HTTP CSIC 2010)")
    print("=" * 60)

    all_records = []

    # File mapping: (filename, label_override)
    # label_override=None berarti auto-detect dari konten
    file_configs = [
        ("normalTrafficTest.txt",      "Safe"),
        ("normalTrafficTraining.txt",  "Safe"),
        ("anomalousTrafficTest.txt",   None),   # Auto-detect
    ]

    found_any = False
    for filename, label_override in file_configs:
        filepath = os.path.join(RAW_DIR, filename)
        print(f"\n  Memproses: {filename}")
        records = parse_http_requests(filepath, label_override)
        if records:
            found_any = True
            print(f"  → {len(records)} record ditemukan")
            all_records.extend(records)
        else:
            print(f"  → File tidak ditemukan atau kosong, dilewati")

    if not found_any:
        print("\n  Tidak ada file CSIC ditemukan di datasets/raw/")
        print("  Menggunakan data sintetis saja...")

    # Tambah sampel sintetis untuk keseimbangan
    print(f"\n  Total sebelum augmentasi: {len(all_records)} record")
    all_records = add_synthetic_samples(all_records)
    print(f"  Total setelah augmentasi: {len(all_records)} record")

    # Buat DataFrame
    df = pd.DataFrame(all_records)

    # Hapus kolom helper
    df = df.drop(columns=["_method", "_url"], errors="ignore")

    # Pastikan semua kolom ada
    required_cols = [
        "status_code", "response_time", "response_length",
        "header_count", "cookie_count", "redirect_count",
        "framework_encoded", "server_encoded", "authentication",
        "param_count", "form_count", "endpoint_count", "depth",
        "has_password_field", "has_file_upload", "has_search_form",
        "label"
    ]
    for col in required_cols:
        if col not in df.columns:
            df[col] = 0

    df = df[required_cols]
    df = df.fillna(0)

    # Label distribution
    print("\n  Distribusi label:")
    for label, count in df["label"].value_counts().items():
        bar = "█" * min(count // 10, 30)
        print(f"  {label:<20} {count:>5}  {bar}")

    # Simpan
    out_path = os.path.join(PROCESSED_DIR, "sentinel_dataset_csic.csv")
    df.to_csv(out_path, index=False)
    print(f"\n  ✓ Dataset disimpan: {out_path}")
    print(f"  ✓ Total: {len(df)} record, {len(df.columns)} kolom")
    print("\n  Sekarang jalankan training:")
    print("  python app/ml/training/train.py")
    print("=" * 60)


if __name__ == "__main__":
    convert()