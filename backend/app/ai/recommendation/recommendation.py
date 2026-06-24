"""Sentinel AI - Recommendation Agent."""
import logging
from typing import List, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Recommendation

logger = logging.getLogger("sentinel.recommendation")

RECOMMENDATION_TEMPLATES = {
    "SQL Injection": {
        "title": "Perbaiki Kerentanan SQL Injection",
        "cause": "Input pengguna tidak divalidasi atau disanitasi sebelum digunakan dalam kueri SQL.",
        "impact": "Penyerang dapat membaca, memodifikasi, atau menghapus data sensitif dari database.",
        "solution": "Gunakan Prepared Statements / Parameterized Queries. Jangan pernah menggabungkan input pengguna langsung ke dalam kueri SQL. Gunakan ORM seperti Eloquent atau SQLAlchemy.",
        "owasp_ref": "A03:2021 - Injection",
        "cwe_ref": "CWE-89",
        "cvss": 9.8,
        "checklist": [
            "Ganti query dinamis dengan prepared statements",
            "Validasi tipe data input",
            "Batasi hak akses database (prinsip least privilege)",
            "Aktifkan WAF (Web Application Firewall)",
            "Log dan monitor query yang mencurigakan"
        ]
    },
    "Cross-Site Scripting (XSS)": {
        "title": "Perbaiki Kerentanan Cross-Site Scripting (XSS)",
        "cause": "Aplikasi menampilkan data yang dimasukkan pengguna tanpa encoding atau sanitasi yang tepat.",
        "impact": "Penyerang dapat menyuntikkan script berbahaya yang dieksekusi di browser korban, mencuri cookie sesi, atau melakukan phishing.",
        "solution": "Encode semua output HTML. Gunakan Content Security Policy (CSP). Validasi dan sanitasi semua input. Gunakan library seperti DOMPurify untuk sanitasi sisi klien.",
        "owasp_ref": "A03:2021 - Injection",
        "cwe_ref": "CWE-79",
        "cvss": 7.4,
        "checklist": [
            "Terapkan HTML entity encoding pada output",
            "Implementasikan Content Security Policy (CSP)",
            "Gunakan HTTPOnly flag pada cookie sesi",
            "Validasi input di sisi server",
            "Gunakan template engine dengan auto-escaping"
        ]
    },
    "Missing Security Headers": {
        "title": "Tambahkan Security Headers yang Wajib",
        "cause": "Web server tidak mengkonfigurasi HTTP security headers yang direkomendasikan.",
        "impact": "Rentan terhadap serangan clickjacking, MIME-type sniffing, dan cross-site scripting.",
        "solution": "Tambahkan security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Content-Security-Policy, Strict-Transport-Security, dan Referrer-Policy.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref": "CWE-693",
        "cvss": 5.4,
        "checklist": [
            "Tambahkan Strict-Transport-Security: max-age=31536000",
            "Tambahkan X-Frame-Options: DENY",
            "Tambahkan X-Content-Type-Options: nosniff",
            "Konfigurasi Content-Security-Policy",
            "Tambahkan Referrer-Policy: no-referrer"
        ]
    },
    "Critical Security Headers Missing": {
        "title": "Headers Keamanan Kritis Tidak Ditemukan",
        "cause": "Hampir semua HTTP security headers standar tidak dikonfigurasi pada server.",
        "impact": "Sangat rentan terhadap berbagai serangan browser-based. Meningkatkan attack surface secara signifikan.",
        "solution": "Segera konfigurasi semua security headers yang direkomendasikan OWASP. Gunakan tools seperti securityheaders.com untuk verifikasi.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref": "CWE-693",
        "cvss": 7.2,
        "checklist": [
            "Audit konfigurasi web server (Apache/Nginx)",
            "Implementasikan semua OWASP recommended headers",
            "Uji menggunakan https://securityheaders.com",
            "Aktifkan HTTPS dan HSTS",
            "Review konfigurasi setiap deployment"
        ]
    },
    "Insecure Cookie Configuration": {
        "title": "Amankan Konfigurasi Cookie Sesi",
        "cause": "Cookie sesi tidak memiliki flag keamanan yang diperlukan (HttpOnly, Secure, SameSite).",
        "impact": "Cookie dapat dicuri melalui JavaScript (tanpa HttpOnly) atau dikirim melalui HTTP biasa (tanpa Secure), memungkinkan session hijacking.",
        "solution": "Set atribut HttpOnly, Secure, dan SameSite=Strict pada semua session cookie.",
        "owasp_ref": "A07:2021 - Identification and Authentication Failures",
        "cwe_ref": "CWE-1004",
        "cvss": 6.5,
        "checklist": [
            "Tambahkan HttpOnly flag pada session cookie",
            "Tambahkan Secure flag pada semua cookie",
            "Set SameSite=Strict atau SameSite=Lax",
            "Gunakan cookie dengan masa berlaku yang wajar",
            "Regenerate session ID setelah login"
        ]
    },
    "Information Disclosure": {
        "title": "Cegah Kebocoran Informasi Sistem",
        "cause": "Aplikasi menampilkan informasi detail sistem, stack trace, atau pesan error yang sensitif.",
        "impact": "Penyerang mendapatkan informasi tentang infrastruktur yang dapat digunakan untuk serangan lebih lanjut.",
        "solution": "Pastikan aplikasi produksi tidak menampilkan informasi debug atau pesan kesalahan detail. Gunakan error handler yang menampilkan halaman kesalahan generik.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref": "CWE-200",
        "cvss": 5.3,
        "checklist": [
            "Nonaktifkan mode debug atau detailed error output di lingkungan produksi",
            "Gunakan halaman error generik untuk kesalahan 404 dan 500",
            "Jangan tampilkan versi framework atau detail server secara publik",
            "Hapus komentar debug dan informasi sensitif dari kode produksi",
            "Periksa apakah log aplikasi hanya dapat diakses oleh tim internal"
        ]
    },
    "Server Version Disclosure": {
        "title": "Sembunyikan Versi Server",
        "cause": "Header Server mengungkapkan versi web server yang digunakan.",
        "impact": "Penyerang dapat mencari kerentanan spesifik untuk versi server tersebut.",
        "solution": "Konfigurasi web server untuk menyembunyikan atau mengubah header Server. Di Nginx: server_tokens off; Di Apache: ServerTokens Prod.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref": "CWE-200",
        "cvss": 5.3,
        "checklist": [
            "Nginx: tambahkan 'server_tokens off;'",
            "Apache: set 'ServerTokens Prod'",
            "Hapus atau samarkan X-Powered-By header",
            "Perbarui server ke versi terbaru",
            "Pasang WAF untuk filtering header"
        ]
    },
    "Broken Access Control": {
        "title": "Perbaiki Kontrol Akses",
        "cause": "Halaman atau resource sensitif dapat diakses tanpa autentikasi yang memadai.",
        "impact": "Pengguna tidak sah dapat mengakses data atau fungsi yang seharusnya terbatas.",
        "solution": "Implementasikan autentikasi dan otorisasi yang tepat. Gunakan middleware auth pada semua route sensitif.",
        "owasp_ref": "A01:2021 - Broken Access Control",
        "cwe_ref": "CWE-284",
        "cvss": 9.1,
        "checklist": [
            "Tambahkan middleware autentikasi",
            "Terapkan role-based access control (RBAC)",
            "Validasi otorisasi di setiap endpoint",
            "Deny by default - tolak semua kecuali yang diizinkan",
            "Log akses yang tidak sah"
        ]
    },
    "File Upload Endpoint Detected": {
        "title": "Amankan Endpoint Upload File",
        "cause": "Endpoint upload file memerlukan validasi ketat untuk mencegah upload file berbahaya.",
        "impact": "Upload file berbahaya dapat menyebabkan Remote Code Execution atau penyimpanan konten berbahaya.",
        "solution": "Validasi tipe file (whitelist), batasi ukuran, simpan di luar web root, scan dengan antivirus, gunakan nama file acak.",
        "owasp_ref": "A04:2021 - Insecure Design",
        "cwe_ref": "CWE-434",
        "cvss": 8.8,
        "checklist": [
            "Validasi MIME type di sisi server",
            "Whitelist ekstensi file yang diizinkan",
            "Batasi ukuran file upload",
            "Simpan file di luar document root",
            "Rename file dengan nama acak"
        ]
    },
    "Technology Stack Disclosure": {
        "title": "Sembunyikan Informasi Teknologi",
        "cause": "Header X-Powered-By atau meta generator mengungkapkan teknologi yang digunakan.",
        "impact": "Memudahkan penyerang menemukan kerentanan spesifik framework/CMS yang digunakan.",
        "solution": "Hapus header X-Powered-By. Sembunyikan informasi versi CMS. Hapus meta generator tag.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref": "CWE-200",
        "cvss": 5.3,
        "checklist": [
            "Hapus X-Powered-By header",
            "Hapus atau ubah meta generator",
            "Sembunyikan versi CMS",
            "Nonaktifkan readme/changelog di root",
            "Gunakan WAF untuk menyaring response headers"
        ]
    },
    "Insecure Content Security Policy": {
        "title": "Perkuat Content Security Policy",
        "cause": "CSP mengizinkan 'unsafe-inline' yang melemahkan proteksi XSS.",
        "impact": "Inline scripts masih dapat dieksekusi, mengurangi efektivitas CSP sebagai pertahanan XSS.",
        "solution": "Hapus 'unsafe-inline' dari CSP. Gunakan nonce atau hash untuk script yang diperlukan. Terapkan CSP ketat.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref": "CWE-1021",
        "cvss": 5.4,
        "checklist": [
            "Hapus 'unsafe-inline' dari script-src",
            "Gunakan nonce-based CSP",
            "Pindahkan inline script ke file eksternal",
            "Uji CSP dengan CSP Evaluator",
            "Aktifkan CSP reporting endpoint"
        ]
    },
}


class RecommendationAgent:
    def __init__(self, db: AsyncSession, scan_id: int, predictions: List[Dict]):
        self.db = db
        self.scan_id = scan_id
        self.predictions = predictions

    async def run(self):
        seen_predictions = set()
        for pred in self.predictions:
            pred_name = pred.get("prediction", "")
            if pred_name in seen_predictions:
                continue
            seen_predictions.add(pred_name)

            template = RECOMMENDATION_TEMPLATES.get(pred_name)
            if not template:
                continue

            rec = Recommendation(
                scan_id=self.scan_id,
                title=template["title"],
                summary=f"{pred_name} terdeteksi dengan confidence {pred.get('confidence', 0):.0f}%",
                cause=template["cause"],
                impact=template["impact"],
                solution=template["solution"],
                priority=pred.get("severity", "medium"),
                owasp_ref=template["owasp_ref"],
                cwe_ref=template["cwe_ref"],
                cvss_score=template.get("cvss"),
                affected_url=pred.get("url", ""),
                checklist=template.get("checklist", [])
            )
            self.db.add(rec)
        
        await self.db.flush()
