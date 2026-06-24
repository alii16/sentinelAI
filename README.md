# Sentinel AI 🛡️
## Autonomous Multi-Agent AI Security Auditor

Platform audit keamanan website berbasis **Artificial Intelligence** dan **Machine Learning** yang mampu melakukan crawling, discovery, fingerprinting teknologi, endpoint discovery, intelligent scan planning, active security testing, vulnerability classification, risk assessment, serta menghasilkan laporan keamanan secara otomatis berdasarkan standar **OWASP Top 10**.

---

## 🏗️ Arsitektur

```
Browser (Frontend)
      │
REST API (FastAPI)
      │
AI ORCHESTRATOR
      │
 ┌────┴────────────┬────────────┬────────────┐
 ▼                 ▼            ▼            ▼
Discovery       Technology  Endpoint    Attack Planner
 │                 │            │
 └─────────────────┴────────────┘
                   ▼
             Scanner Agent
                   ▼
          Verification Agent (ML)
                   ▼
         Risk Assessment Agent
                   ▼
       Recommendation Agent
                   ▼
            Report Agent
                   ▼
           AI Chat Agent
                   │
                MySQL
```

---

## 🚀 Fitur Utama

| Fitur | Deskripsi |
|-------|-----------|
| **Multi-Agent AI** | Setiap tahap audit dikontrol oleh AI Agent independen |
| **Active Scanner** | Pengujian keamanan aktif dengan observasi respons |
| **Technology Fingerprint** | Deteksi framework, CMS, server, library otomatis |
| **Endpoint Intelligence** | Prioritasi endpoint berdasarkan risiko keamanan |
| **ML Verification** | 4 model ML untuk klasifikasi kerentanan |
| **AI Security Chat** | Tanya jawab berbasis data audit menggunakan Claude API |
| **PDF Report** | Laporan profesional dengan Executive Summary |
| **OWASP Aligned** | Temuan dipetakan ke OWASP Top 10 & CWE |
| **AI Memory** | Riwayat audit untuk tracking perkembangan keamanan |

---

## 📋 Prasyarat

- Python 3.12+
- MySQL 8.0+
- pip
- (Opsional) Node.js untuk Live Server

---

## ⚡ Instalasi Cepat

```bash
# 1. Clone atau ekstrak project
cd sentinel-ai

# 2. Jalankan installer
python scripts/install.py

# 3. Edit konfigurasi
cp .env.example .env
# Edit .env: isi MYSQL_PASSWORD, JWT_SECRET, ANTHROPIC_API_KEY

# 4. Buat database
mysql -u root -p < database/schema.sql

# 5. Latih model ML
cd backend && python app/ml/training/train.py

# 6. Jalankan backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## 🐳 Docker (Rekomendasi)

```bash
cp .env.example .env
# Edit .env terlebih dahulu

docker-compose up -d
```

Akses:
- Frontend: http://localhost
- API Docs: http://localhost:8000/docs

---

## 📁 Struktur Project

```
sentinel-ai/
├── backend/
│   ├── main.py                    # FastAPI entry point
│   └── app/
│       ├── api/v1/                # REST API endpoints
│       ├── ai/                    # AI Agents
│       │   ├── orchestrator/      # AI Orchestrator
│       │   ├── discovery/         # Discovery Agent (Crawler)
│       │   ├── technology/        # Technology Fingerprint
│       │   ├── endpoint/          # Endpoint Intelligence
│       │   ├── attack_planner/    # Attack Planner
│       │   ├── scanner/           # Active Scanner
│       │   ├── verification/      # ML Verification
│       │   ├── risk/              # Risk Assessment
│       │   ├── recommendation/    # Recommendation Engine
│       │   ├── report/            # Report Generator
│       │   └── chat/              # AI Chat Agent
│       ├── core/                  # Config, DB, Security
│       ├── models/                # SQLAlchemy ORM models
│       ├── repositories/          # Database repositories
│       ├── middleware/            # HTTP middleware
│       ├── ml/training/           # ML training scripts
│       └── websocket/             # WebSocket handlers
├── frontend/
│   ├── index.html                 # Landing page
│   ├── assets/js/
│   │   ├── api.js                 # API client
│   │   └── layout.js              # Sidebar + navbar
│   └── pages/
│       ├── auth/                  # Login, Register
│       ├── dashboard/             # Dashboard
│       ├── websites/              # Website management
│       ├── scan/                  # Scan + History
│       ├── report/                # Reports
│       ├── ai-chat/               # AI Chat
│       ├── ai-models/             # ML Models
│       ├── dataset/               # Dataset
│       ├── settings/              # Settings
│       └── notifications/         # Notifications
├── database/
│   └── schema.sql                 # MySQL schema (24 tabel)
├── models/saved/                  # Trained ML models (.joblib)
├── reports/                       # Generated reports
├── docker/                        # Docker configs
├── scripts/                       # Setup scripts
├── .env.example                   # Environment template
├── docker-compose.yml
└── requirements.txt
```

---

## 🔐 Default Login

```
Email   : admin@sentinel.ai
Password: Admin@123
```

---

## 🤖 AI Agents

| Agent | Tanggung Jawab |
|-------|----------------|
| **Orchestrator** | Mengatur urutan & workflow semua agent |
| **Discovery** | Crawling halaman, form, endpoint, asset |
| **Technology** | Fingerprinting framework & server |
| **Endpoint** | Prioritasi endpoint berdasarkan risiko |
| **Attack Planner** | Menyusun strategi pengujian keamanan |
| **Scanner** | Menjalankan active security testing |
| **Verification** | Klasifikasi ML + confidence score |
| **Risk** | Menghitung Security Score & Grade |
| **Recommendation** | Rekomendasi perbaikan OWASP |
| **Report** | Generate PDF/JSON/CSV |
| **Chat** | AI Assistant berbasis data audit |

---

## 📊 Machine Learning

4 model tersedia, dipilih berdasarkan F1 Score terbaik:

| Model | Default Accuracy |
|-------|-----------------|
| Random Forest | 95.4% |
| XGBoost | 96.2% |
| Decision Tree | 91.2% |
| SVM | 93.5% |

Label klasifikasi: Authentication, Authorization, Configuration, Input Validation, Session, Header, Information, Safe

---

## 🔑 API Endpoints Utama

```
POST   /api/v1/auth/login
GET    /api/v1/dashboard/statistics
GET    /api/v1/websites
POST   /api/v1/scans
GET    /api/v1/scans/{id}/progress
GET    /api/v1/ai/summary/{scan_id}
GET    /api/v1/ai/recommendation/{scan_id}
POST   /api/v1/ai/chat
GET    /api/v1/reports/{id}/pdf
WS     /ws/scan/{scan_id}
```

Dokumentasi lengkap: `http://localhost:8000/docs`

---

## ⚙️ Konfigurasi .env

```env
MYSQL_PASSWORD=your_password
JWT_SECRET=your-secret-key-min-32-chars
ANTHROPIC_API_KEY=your-claude-api-key   # Untuk AI Chat
```

---

## ⚠️ Disclaimer

Sentinel AI dirancang untuk digunakan pada website yang **Anda miliki** atau yang telah memberikan **izin resmi** untuk pengujian keamanan. Penggunaan pada website tanpa izin merupakan pelanggaran hukum dan etika.

---

## 📄 Lisensi

Dibuat untuk tujuan penelitian dan pengembangan sistem audit keamanan berbasis AI.

---

**Sentinel AI** · Autonomous Multi-Agent AI Security Auditor · v1.0
