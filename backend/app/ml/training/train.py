"""
Sentinel AI - Machine Learning Training Pipeline
Melatih 4 model: Random Forest, XGBoost, Decision Tree, SVM
dan menyimpan model terbaik sebagai active model.
"""

import os
import sys
import json
import time
import logging
import numpy as np
import pandas as pd
import joblib
import warnings
warnings.filterwarnings("ignore")

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report, confusion_matrix
)
from xgboost import XGBClassifier
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel.ml.train")

# ── Paths ───────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "../../../../datasets/processed")
MODEL_DIR   = os.path.join(BASE_DIR, "../../../../models/saved")
EVAL_DIR    = os.path.join(BASE_DIR, "../../../../models/evaluations")

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(EVAL_DIR, exist_ok=True)

# ── Label mapping ────────────────────────────────────────────────
LABELS = ["Authentication","Authorization","Configuration",
          "Input Validation","Session","Header","Information","Safe"]

# ── Feature columns ─────────────────────────────────────────────
FEATURE_COLS = [
    "status_code","response_time","response_length",
    "header_count","cookie_count","redirect_count",
    "framework_encoded","server_encoded","authentication",
    "param_count","form_count","endpoint_count","depth",
    "has_password_field","has_file_upload","has_search_form",
]


def generate_synthetic_dataset(n=3000):
    """
    Generate synthetic training data for demonstration.
    In production, replace with real verified audit data.
    """
    np.random.seed(42)
    records = []

    for _ in range(n):
        label = np.random.choice(LABELS, p=[.12,.10,.18,.15,.08,.17,.12,.08])
        
        if label == "Authentication":
            row = dict(
                status_code=np.random.choice([200,302,401,403], p=[.5,.2,.2,.1]),
                response_time=np.random.randint(50,800),
                response_length=np.random.randint(500,8000),
                header_count=np.random.randint(3,8),
                cookie_count=np.random.randint(1,4),
                redirect_count=np.random.randint(0,3),
                framework_encoded=np.random.randint(0,5),
                server_encoded=np.random.randint(0,4),
                authentication=1,
                param_count=np.random.randint(0,5),
                form_count=np.random.randint(1,3),
                endpoint_count=np.random.randint(1,10),
                depth=np.random.randint(1,4),
                has_password_field=1,
                has_file_upload=0,
                has_search_form=0,
            )
        elif label == "Input Validation":
            row = dict(
                status_code=np.random.choice([200,500,400,422], p=[.4,.3,.2,.1]),
                response_time=np.random.randint(100,1500),
                response_length=np.random.randint(200,5000),
                header_count=np.random.randint(2,7),
                cookie_count=np.random.randint(0,3),
                redirect_count=0,
                framework_encoded=np.random.randint(0,5),
                server_encoded=np.random.randint(0,4),
                authentication=np.random.randint(0,2),
                param_count=np.random.randint(2,8),
                form_count=np.random.randint(1,4),
                endpoint_count=np.random.randint(2,15),
                depth=np.random.randint(1,5),
                has_password_field=np.random.randint(0,2),
                has_file_upload=np.random.randint(0,2),
                has_search_form=np.random.randint(0,2),
            )
        elif label == "Header":
            row = dict(
                status_code=np.random.choice([200,301], p=[.8,.2]),
                response_time=np.random.randint(30,300),
                response_length=np.random.randint(100,3000),
                header_count=np.random.randint(1,5),  # Low = missing headers
                cookie_count=np.random.randint(0,2),
                redirect_count=np.random.randint(0,2),
                framework_encoded=np.random.randint(0,5),
                server_encoded=np.random.randint(0,4),
                authentication=0,
                param_count=0,
                form_count=0,
                endpoint_count=np.random.randint(1,5),
                depth=np.random.randint(0,2),
                has_password_field=0,
                has_file_upload=0,
                has_search_form=0,
            )
        elif label == "Safe":
            row = dict(
                status_code=np.random.choice([200,304], p=[.9,.1]),
                response_time=np.random.randint(20,200),
                response_length=np.random.randint(500,20000),
                header_count=np.random.randint(8,15),  # Many = good headers
                cookie_count=np.random.randint(0,2),
                redirect_count=0,
                framework_encoded=np.random.randint(0,5),
                server_encoded=np.random.randint(0,4),
                authentication=0,
                param_count=0,
                form_count=0,
                endpoint_count=np.random.randint(1,8),
                depth=np.random.randint(0,3),
                has_password_field=0,
                has_file_upload=0,
                has_search_form=0,
            )
        else:
            row = dict(
                status_code=np.random.choice([200,302,400,403,500]),
                response_time=np.random.randint(50,2000),
                response_length=np.random.randint(100,10000),
                header_count=np.random.randint(2,10),
                cookie_count=np.random.randint(0,5),
                redirect_count=np.random.randint(0,3),
                framework_encoded=np.random.randint(0,5),
                server_encoded=np.random.randint(0,4),
                authentication=np.random.randint(0,2),
                param_count=np.random.randint(0,6),
                form_count=np.random.randint(0,3),
                endpoint_count=np.random.randint(1,20),
                depth=np.random.randint(0,5),
                has_password_field=np.random.randint(0,2),
                has_file_upload=np.random.randint(0,2),
                has_search_form=np.random.randint(0,2),
            )
        row["label"] = label
        records.append(row)

    df = pd.DataFrame(records)
    path = os.path.join(DATASET_DIR, "sentinel_dataset_v1.csv")
    df.to_csv(path, index=False)
    logger.info(f"Generated synthetic dataset: {len(df)} records → {path}")
    return df


def load_dataset():
    """
    Load dataset dengan prioritas:
    1. sentinel_final_dataset.csv (hasil merge_datasets.py)
    2. sentinel_dataset_csic.csv (hasil convert_csic.py)
    3. sentinel_dataset_from_scans.csv (hasil export_scan_dataset.py)
    4. File CSV lain di processed/
    5. Generate sintetis jika tidak ada sama sekali
    """
    # Prioritas 1: final merged dataset
    final_path = os.path.join(DATASET_DIR, "sentinel_final_dataset.csv")
    if os.path.exists(final_path):
        df = pd.read_csv(final_path)
        logger.info(f"Loaded final dataset: {len(df)} records")
        return df

    # Prioritas 2-4: cari CSV lain
    csv_files = [f for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]
    if not csv_files:
        logger.warning("No dataset found, generating synthetic data...")
        return generate_synthetic_dataset()

    dfs = []
    for f in csv_files:
        try:
            dfs.append(pd.read_csv(os.path.join(DATASET_DIR, f)))
            logger.info(f"Loaded: {f}")
        except Exception as e:
            logger.warning(f"Could not read {f}: {e}")

    df = pd.concat(dfs, ignore_index=True) if dfs else generate_synthetic_dataset()
    logger.info(f"Loaded {len(df)} records from {len(csv_files)} file(s)")
    return df


def preprocess(df):
    """Feature engineering and preprocessing."""
    df = df.copy()

    # Fill missing
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0

    # Encode label
    le = LabelEncoder()
    le.fit(LABELS)
    df["label_enc"] = le.transform(df["label"].fillna("Safe"))

    X = df[FEATURE_COLS].fillna(0).values
    y = df["label_enc"].values

    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Save scaler
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(le, os.path.join(MODEL_DIR, "label_encoder.joblib"))

    return X_scaled, y, le, scaler


def evaluate_model(model, X_test, y_test, model_name, le):
    """Evaluate a trained model and return metrics."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec  = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1   = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    
    roc = 0.0
    if y_proba is not None:
        try:
            from sklearn.preprocessing import label_binarize
            y_bin = label_binarize(y_test, classes=list(range(len(le.classes_))))
            roc = roc_auc_score(y_bin, y_proba, average="macro", multi_class="ovr")
        except Exception:
            roc = 0.0

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(8,6))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.colorbar(im)
    ax.set_xticks(range(len(le.classes_)))
    ax.set_yticks(range(len(le.classes_)))
    ax.set_xticklabels(le.classes_, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(le.classes_, fontsize=8)
    ax.set_title(f"Confusion Matrix - {model_name}", fontsize=12)
    ax.set_xlabel("Predicted"); ax.set_ylabel("True")
    plt.tight_layout()
    cm_path = os.path.join(EVAL_DIR, f"cm_{model_name.lower().replace(' ','_')}.png")
    plt.savefig(cm_path, dpi=100)
    plt.close()

    metrics = {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "roc_auc": roc}
    logger.info(f"{model_name}: Acc={acc:.4f} F1={f1:.4f} ROC={roc:.4f}")
    return metrics


def sync_to_database(results: dict, best_model_name: str, total_samples: int):
    """
    Sync hasil training ke tabel ml_models di database.
    Menggunakan pymysql langsung (sync) karena train.py dijalankan
    sebagai script terpisah, bukan dalam konteks FastAPI async.
    """
    logger.info("\n── Menyinkronkan hasil ke database...")

    # Load .env untuk koneksi database
    env_path = os.path.join(BASE_DIR, "../../../../.env")
    db_config = {
        "host":     "localhost",
        "port":     3306,
        "user":     "root",
        "password": "",
        "database": "sentinel_ai",
        "charset":  "utf8mb4",
    }

    # Baca .env jika ada
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key == "MYSQL_HOST":     db_config["host"]     = val
                if key == "MYSQL_PORT":     db_config["port"]     = int(val or 3306)
                if key == "MYSQL_USERNAME": db_config["user"]     = val
                if key == "MYSQL_PASSWORD": db_config["password"] = val
                if key == "MYSQL_DATABASE": db_config["database"] = val

    # Map nama model ke algorithm slug di database
    algo_map = {
        "Random Forest": "random_forest",
        "XGBoost":       "xgboost",
        "Decision Tree": "decision_tree",
        "SVM":           "svm",
    }

    try:
        import pymysql
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        for name, result in results.items():
            metrics = result["metrics"]
            algo    = algo_map.get(name, name.lower().replace(" ", "_"))
            f_path  = metrics.get("file_path", "")

            # Buat path relatif (relatif dari folder backend/)
            try:
                backend_dir = os.path.join(BASE_DIR, "../../../..")
                backend_dir = os.path.abspath(backend_dir)
                rel_path = os.path.relpath(f_path, backend_dir)
                rel_path = rel_path.replace("\\", "/")
            except Exception:
                rel_path = f_path

            is_active  = 1 if name == best_model_name else 0
            trained_at = time.strftime("%Y-%m-%d %H:%M:%S")

            # Cek apakah record sudah ada
            cursor.execute("SELECT id FROM ml_models WHERE algorithm = %s", (algo,))
            row = cursor.fetchone()

            if row:
                # Update record yang ada
                cursor.execute("""
                    UPDATE ml_models SET
                        accuracy        = %s,
                        precision_score = %s,
                        recall_score    = %s,
                        f1_score        = %s,
                        roc_auc         = %s,
                        training_time   = %s,
                        sample_count    = %s,
                        feature_count   = %s,
                        file_path       = %s,
                        is_active       = %s,
                        status          = 'ready',
                        trained_at      = %s
                    WHERE algorithm = %s
                """, (
                    round(metrics["accuracy"], 4),
                    round(metrics["precision"], 4),
                    round(metrics["recall"], 4),
                    round(metrics["f1"], 4),
                    round(metrics["roc_auc"], 4),
                    round(metrics["training_time"], 3),
                    total_samples,
                    len(FEATURE_COLS),
                    rel_path,
                    is_active,
                    trained_at,
                    algo,
                ))
                logger.info(f"  ✓ Updated: {name} (Acc={metrics['accuracy']:.4f} F1={metrics['f1']:.4f})")
            else:
                # Insert record baru
                version = "1.0"
                model_name = f"{name} v{version}"
                cursor.execute("""
                    INSERT INTO ml_models
                        (name, algorithm, version, accuracy, precision_score,
                         recall_score, f1_score, roc_auc, training_time,
                         sample_count, feature_count, file_path, is_active,
                         status, trained_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'ready', %s)
                """, (
                    model_name, algo, version,
                    round(metrics["accuracy"], 4),
                    round(metrics["precision"], 4),
                    round(metrics["recall"], 4),
                    round(metrics["f1"], 4),
                    round(metrics["roc_auc"], 4),
                    round(metrics["training_time"], 3),
                    total_samples,
                    len(FEATURE_COLS),
                    rel_path,
                    is_active,
                    trained_at,
                ))
                logger.info(f"  ✓ Inserted: {name}")

        conn.commit()
        cursor.close()
        conn.close()
        logger.info("  ✓ Database berhasil disinkronkan!")

    except ImportError:
        logger.warning("  ⚠ pymysql tidak terinstall. Jalankan: pip install pymysql")
        logger.warning("  ⚠ Update database secara manual via phpMyAdmin.")
        _print_manual_sql(results, best_model_name, algo_map)
    except Exception as e:
        logger.error(f"  ✗ Gagal sync ke database: {e}")
        logger.warning("  ⚠ Update database secara manual via phpMyAdmin:")
        _print_manual_sql(results, best_model_name, algo_map)


def _print_manual_sql(results: dict, best_model_name: str, algo_map: dict):
    """Print SQL UPDATE statements jika database sync gagal."""
    logger.info("\n  SQL untuk update manual di phpMyAdmin:")
    logger.info("  " + "-" * 50)
    for name, result in results.items():
        m    = result["metrics"]
        algo = algo_map.get(name, name.lower().replace(" ", "_"))
        active = 1 if name == best_model_name else 0
        sql = (
            f"  UPDATE ml_models SET "
            f"accuracy={m['accuracy']:.4f}, "
            f"precision_score={m['precision']:.4f}, "
            f"recall_score={m['recall']:.4f}, "
            f"f1_score={m['f1']:.4f}, "
            f"roc_auc={m['roc_auc']:.4f}, "
            f"is_active={active}, status='ready', "
            f"trained_at=NOW() "
            f"WHERE algorithm='{algo}';"
        )
        logger.info(sql)
    logger.info("  " + "-" * 50)


def train_all():
    """Main training pipeline."""
    logger.info("=" * 60)
    logger.info("Sentinel AI - Machine Learning Training Pipeline")
    logger.info("=" * 60)

    # Load data
    df = load_dataset()
    X, y, le, scaler = preprocess(df)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    models_config = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=15, min_samples_split=5,
            random_state=42, n_jobs=-1, class_weight="balanced"
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            random_state=42, eval_metric="mlogloss", verbosity=0,
            use_label_encoder=False
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, min_samples_split=5, random_state=42,
            class_weight="balanced"
        ),
        "SVM": SVC(
            kernel="rbf", C=10, gamma="scale", probability=True,
            random_state=42, class_weight="balanced"
        ),
    }

    results = {}
    best_model_name = None
    best_f1 = 0.0

    for name, clf in models_config.items():
        logger.info(f"\n── Training {name}...")
        t0 = time.time()
        clf.fit(X_train, y_train)
        training_time = time.time() - t0

        metrics = evaluate_model(clf, X_test, y_test, name, le)
        metrics["training_time"] = round(training_time, 3)
        results[name] = {"model": clf, "metrics": metrics}

        # Save model
        algo_slug = name.lower().replace(" ","_")
        path = os.path.join(MODEL_DIR, f"{algo_slug}.joblib")
        joblib.dump(clf, path)
        metrics["file_path"] = path
        logger.info(f"Saved → {path} ({training_time:.1f}s)")

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            best_model_name = name

    # Save best as active model
    if best_model_name:
        best_path = os.path.join(MODEL_DIR, "active_model.joblib")
        joblib.dump(results[best_model_name]["model"], best_path)
        logger.info(f"\n✓ Best model: {best_model_name} (F1={best_f1:.4f}) → active_model.joblib")

    # Save evaluation report
    report = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "best_model": best_model_name,
        "models": {
            name: {k: v for k, v in res["metrics"].items() if k != "model"}
            for name, res in results.items()
        }
    }
    with open(os.path.join(EVAL_DIR, "evaluation_report.json"), "w") as f:
        json.dump(report, f, indent=2)

    # ── Sync hasil training ke database ──────────────────────────
    sync_to_database(results, best_model_name, len(df))

    # Feature importance chart (Random Forest + XGBoost)
    for model_name in ["Random Forest", "XGBoost"]:
        if model_name in results:
            clf = results[model_name]["model"]
            if hasattr(clf, "feature_importances_"):
                fig, ax = plt.subplots(figsize=(8,5))
                importances = clf.feature_importances_
                indices = np.argsort(importances)[::-1]
                ax.bar(range(len(FEATURE_COLS)), importances[indices], color="#09090B")
                ax.set_xticks(range(len(FEATURE_COLS)))
                ax.set_xticklabels([FEATURE_COLS[i] for i in indices], rotation=45, ha="right", fontsize=7)
                ax.set_title(f"Feature Importance - {model_name}")
                plt.tight_layout()
                plt.savefig(os.path.join(EVAL_DIR, f"fi_{model_name.lower().replace(' ','_')}.png"), dpi=100)
                plt.close()

    logger.info("\n✓ Training selesai! Lihat evaluasi di models/evaluations/")
    logger.info("=" * 60)
    return results


if __name__ == "__main__":
    train_all()