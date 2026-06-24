#!/usr/bin/env python3
"""
Sentinel AI - Setup & Installation Script
Menginisialisasi project dari awal
"""
import os
import sys
import subprocess
import shutil


def run(cmd, cwd=None):
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=cwd)
    if result.returncode != 0:
        print(f"  [WARN] Command returned {result.returncode}")
    return result.returncode == 0


def check_requirements():
    print("\n[1] Memeriksa prasyarat...")
    checks = {
        "Python 3.12+": ("python --version", "Python 3"),
        "pip":          ("pip --version", "pip"),
        "MySQL":        ("mysql --version", "mysql"),
    }
    all_ok = True
    for name, (cmd, keyword) in checks.items():
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            ok = keyword.lower() in (result.stdout + result.stderr).lower()
            print(f"  {'✓' if ok else '✗'} {name}")
            if not ok:
                all_ok = False
        except FileNotFoundError:
            print(f"  ✗ {name} - NOT FOUND")
            all_ok = False
    return all_ok


def setup_env():
    print("\n[2] Menyiapkan file .env...")
    if not os.path.exists(".env"):
        shutil.copy(".env.example", ".env")
        print("  ✓ .env dibuat dari .env.example")
        print("  ⚠  PENTING: Edit .env dan isi kredensial database + API key!")
    else:
        print("  ✓ .env sudah ada")


def install_python_deps():
    print("\n[3] Menginstall Python dependencies...")
    run("pip install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt")


def create_directories():
    print("\n[4] Membuat direktori yang diperlukan...")
    dirs = [
        "reports/pdf", "reports/json", "reports/csv",
        "storage/uploads", "storage/screenshots", "storage/logs", "storage/temp",
        "models/saved", "models/evaluations",
        "datasets/raw", "datasets/processed", "datasets/verified",
        "datasets/train", "datasets/test",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"  ✓ {d}/")


def setup_database():
    print("\n[5] Inisialisasi database...")
    print("  Pastikan MySQL berjalan dan kredensial di .env sudah benar.")
    print("  Jalankan manual:")
    print("    mysql -u root -p < database/schema.sql")


def train_models():
    print("\n[6] Melatih model Machine Learning...")
    backend_dir = "backend"
    result = run("python app/ml/training/train.py", cwd=backend_dir)
    if result:
        print("  ✓ Model berhasil dilatih")
    else:
        print("  ⚠  Gagal melatih model, pastikan dependencies terinstall")


def print_summary():
    print("\n" + "="*60)
    print("  Sentinel AI - Setup Selesai!")
    print("="*60)
    print("""
  Langkah selanjutnya:
  
  1. Edit file .env dan isi:
     - MYSQL_PASSWORD   → password MySQL Anda
     - JWT_SECRET       → string rahasia (min. 32 karakter)
     - ANTHROPIC_API_KEY → API key Claude (untuk AI Chat)
  
  2. Inisialisasi database:
     $ mysql -u root -p < database/schema.sql
  
  3. Jalankan backend:
     $ cd backend && uvicorn main:app --reload
  
  4. Buka frontend:
     - Buka browser ke: http://localhost:8000/docs (Swagger)
     - Atau buka langsung: frontend/index.html
     - Atau gunakan Live Server di VS Code
  
  5. Login dengan:
     Email   : admin@sentinel.ai
     Password: Admin@123
  
  6. Untuk melatih ulang model ML:
     $ cd backend && python app/ml/training/train.py

  PENTING: Gunakan hanya pada website yang Anda miliki atau
  yang telah memberikan izin pengujian keamanan.
""")


def main():
    print("=" * 60)
    print("  Sentinel AI - Instalasi & Setup")
    print("  Autonomous Multi-Agent AI Security Auditor v1.0")
    print("=" * 60)

    if not check_requirements():
        print("\n⚠  Beberapa prasyarat tidak terpenuhi. Lanjutkan? (y/n): ", end="")
        if input().lower() != "y":
            sys.exit(1)

    setup_env()
    install_python_deps()
    create_directories()
    setup_database()
    train_models()
    print_summary()


if __name__ == "__main__":
    main()
