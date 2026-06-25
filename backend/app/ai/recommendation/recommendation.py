"""
Sentinel AI - Recommendation Agent
Generates one actionable recommendation per unique finding type.
Each recommendation includes cause, impact, solution, OWASP/CWE ref,
CVSS score, and an actionable checklist.
"""
import logging
from typing import List, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Recommendation

logger = logging.getLogger("sentinel.recommendation")

# ── Recommendation templates ─────────────────────────────────────
TEMPLATES: Dict[str, dict] = {
    "SQL Injection": {
        "title":     "Perbaiki Kerentanan SQL Injection",
        "cause":     "Input pengguna dimasukkan langsung ke dalam kueri SQL tanpa validasi atau sanitasi, memungkinkan penyerang memanipulasi logika database.",
        "impact":    "Penyerang dapat membaca, mengubah, atau menghapus data sensitif dari database, bahkan mengambil alih server dalam kasus tertentu. Ini adalah kerentanan dengan dampak tertinggi.",
        "solution":  "Gunakan Prepared Statements atau Parameterized Queries di seluruh kode. Hindari string concatenation untuk membangun kueri SQL. Terapkan ORM (Eloquent, SQLAlchemy) sebagai lapisan abstraksi.",
        "owasp_ref": "A03:2021 - Injection",
        "cwe_ref":   "CWE-89",
        "cvss":       9.8,
        "priority":  "critical",
        "checklist": [
            "Ganti semua query dinamis dengan prepared statements / parameterized queries",
            "Gunakan ORM (Eloquent, SQLAlchemy, Hibernate) untuk akses database",
            "Terapkan validasi whitelist pada semua input pengguna",
            "Batasi hak akses akun database (prinsip least privilege)",
            "Aktifkan WAF (Web Application Firewall) dengan aturan SQLi",
            "Monitor dan catat semua query yang mencurigakan",
            "Lakukan code review menyeluruh pada semua titik yang menerima input",
        ]
    },
    "Cross-Site Scripting (XSS)": {
        "title":     "Perbaiki Kerentanan Cross-Site Scripting (XSS)",
        "cause":     "Aplikasi merender data dari pengguna tanpa melakukan encoding atau sanitasi yang tepat, memungkinkan skrip berbahaya dieksekusi di browser pengguna lain.",
        "impact":    "Penyerang dapat mencuri session cookie, melakukan phishing, mengalihkan pengguna ke situs berbahaya, atau mengeksekusi aksi atas nama korban.",
        "solution":  "Terapkan output encoding pada semua data yang ditampilkan ke HTML. Gunakan Content Security Policy (CSP) yang ketat. Validasi input di sisi server. Gunakan library sanitasi seperti DOMPurify di sisi klien.",
        "owasp_ref": "A03:2021 - Injection",
        "cwe_ref":   "CWE-79",
        "cvss":       7.4,
        "priority":  "high",
        "checklist": [
            "Terapkan HTML entity encoding pada semua output yang berasal dari pengguna",
            "Implementasikan Content Security Policy (CSP) yang ketat",
            "Gunakan template engine dengan auto-escaping aktif",
            "Set flag HttpOnly pada semua session cookie",
            "Gunakan DOMPurify atau library sanitasi serupa di sisi klien",
            "Validasi dan batasi karakter yang diterima pada setiap input field",
        ]
    },
    "Critical Security Headers Missing": {
        "title":     "Segera Tambahkan Security Headers Kritis",
        "cause":     "Web server tidak mengkonfigurasi HTTP security headers yang direkomendasikan oleh OWASP, membiarkan browser tanpa panduan keamanan yang jelas.",
        "impact":    "Rentan terhadap clickjacking, MIME-sniffing, XSS, dan berbagai serangan browser-based. Ini meningkatkan attack surface secara signifikan.",
        "solution":  "Tambahkan minimal 5 dari 7 security headers wajib: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, dan X-XSS-Protection.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref":   "CWE-693",
        "cvss":       7.2,
        "priority":  "high",
        "checklist": [
            "Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Tambahkan: X-Frame-Options: DENY",
            "Tambahkan: X-Content-Type-Options: nosniff",
            "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin",
            "Tambahkan: Permissions-Policy: geolocation=(), microphone=()",
            "Konfigurasi Content-Security-Policy yang sesuai dengan kebutuhan aplikasi",
            "Verifikasi dengan tool: https://securityheaders.com",
            "Terapkan pada seluruh respons, termasuk error page",
        ]
    },
    "Missing Security Headers": {
        "title":     "Tambahkan Security Headers yang Direkomendasikan",
        "cause":     "Beberapa HTTP security headers yang direkomendasikan belum dikonfigurasi pada web server.",
        "impact":    "Beberapa vektor serangan browser-based yang seharusnya bisa dicegah dengan header tidak terproteksi.",
        "solution":  "Tambahkan security headers yang belum ada. Untuk Nginx tambahkan di blok server{}, untuk Apache tambahkan di .htaccess atau httpd.conf.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref":   "CWE-693",
        "cvss":       5.4,
        "priority":  "medium",
        "checklist": [
            "Audit header yang ada dengan https://securityheaders.com",
            "Tambahkan X-Frame-Options: DENY atau SAMEORIGIN",
            "Tambahkan X-Content-Type-Options: nosniff",
            "Tambahkan Referrer-Policy: no-referrer-when-downgrade",
            "Aktifkan HTTPS dan tambahkan HSTS header",
            "Review dan update konfigurasi web server secara berkala",
        ]
    },
    "Insecure Cookie Configuration": {
        "title":     "Amankan Konfigurasi Cookie Sesi",
        "cause":     "Cookie sesi tidak memiliki atribut keamanan yang diperlukan (HttpOnly, Secure, atau SameSite), membuat cookie rentan terhadap pencurian.",
        "impact":    "Cookie dapat diakses melalui JavaScript (tanpa HttpOnly), dikirim melalui HTTP tidak terenkripsi (tanpa Secure), atau dieksploitasi melalui CSRF (tanpa SameSite).",
        "solution":  "Pastikan semua cookie sesi memiliki atribut HttpOnly, Secure, dan SameSite=Strict atau Lax. Regenerasi session ID setelah login.",
        "owasp_ref": "A07:2021 - Identification and Authentication Failures",
        "cwe_ref":   "CWE-1004",
        "cvss":       6.5,
        "priority":  "medium",
        "checklist": [
            "Set atribut HttpOnly pada semua session cookie",
            "Set atribut Secure agar cookie hanya dikirim via HTTPS",
            "Set SameSite=Strict atau SameSite=Lax untuk mencegah CSRF",
            "Regenerate session ID setelah login berhasil",
            "Set masa kadaluarsa cookie yang wajar (bukan session-only untuk semua)",
            "Hapus cookie yang tidak diperlukan",
        ]
    },
    "Missing SameSite Cookie Flag": {
        "title":     "Tambahkan Atribut SameSite pada Cookie",
        "cause":     "Cookie tidak memiliki atribut SameSite, membuat aplikasi berpotensi rentan terhadap serangan CSRF.",
        "impact":    "Penyerang dari situs lain dapat memicu aksi atas nama pengguna yang sedang login.",
        "solution":  "Tambahkan SameSite=Strict untuk cookie sesi sensitif, atau SameSite=Lax sebagai minimum.",
        "owasp_ref": "A07:2021 - Identification and Authentication Failures",
        "cwe_ref":   "CWE-1275",
        "cvss":       4.3,
        "priority":  "low",
        "checklist": [
            "Tambahkan SameSite=Strict pada cookie sesi utama",
            "Gunakan SameSite=Lax jika cross-site navigation diperlukan",
            "Terapkan CSRF token sebagai lapisan perlindungan tambahan",
            "Audit semua cookie yang dikirim aplikasi",
        ]
    },
    "Information Disclosure": {
        "title":     "Cegah Kebocoran Informasi Sistem",
        "cause":     "Aplikasi menampilkan pesan error detail, stack trace, atau informasi konfigurasi sistem yang seharusnya tidak terlihat publik.",
        "impact":    "Penyerang mendapat informasi berharga tentang teknologi, versi, dan struktur internal aplikasi untuk merencanakan serangan lebih lanjut.",
        "solution":  "Nonaktifkan debug mode di production. Konfigurasi custom error page. Jangan tampilkan stack trace atau pesan error detail kepada pengguna akhir.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref":   "CWE-200",
        "cvss":       5.3,
        "priority":  "medium",
        "checklist": [
            "Set DEBUG=False atau APP_ENV=production",
            "Buat halaman error kustom untuk 404, 500, dan error lainnya",
            "Jangan tampilkan stack trace, nama file, atau baris kode ke pengguna",
            "Hapus komentar debug dan informasi sensitif dari kode",
            "Pastikan log error hanya bisa diakses tim internal",
            "Review endpoint yang mungkin mengekspos informasi sistem",
        ]
    },
    "Server Version Disclosure": {
        "title":     "Sembunyikan Versi Web Server",
        "cause":     "Header Server mengungkapkan nama dan versi web server secara spesifik (contoh: nginx/1.18.0).",
        "impact":    "Penyerang dapat mencari dan mengeksploitasi kerentanan yang diketahui untuk versi server tersebut.",
        "solution":  "Konfigurasi server untuk menyembunyikan versi. Nginx: server_tokens off; Apache: ServerTokens Prod; IIS: removeServerHeader.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref":   "CWE-200",
        "cvss":       5.3,
        "priority":  "low",
        "checklist": [
            "Nginx: tambahkan 'server_tokens off;' di nginx.conf",
            "Apache: set 'ServerTokens Prod' dan 'ServerSignature Off'",
            "IIS: gunakan URLScan atau konfigurasi removeServerHeader",
            "Hapus atau ubah header X-Powered-By",
            "Selalu perbarui server ke versi terbaru yang tersedia",
        ]
    },
    "Technology Stack Disclosure": {
        "title":     "Sembunyikan Informasi Technology Stack",
        "cause":     "Header X-Powered-By atau respons lain mengungkapkan teknologi yang digunakan (PHP, ASP.NET, Express, dll).",
        "impact":    "Informasi ini memudahkan penyerang mencari kerentanan yang diketahui untuk teknologi tersebut.",
        "solution":  "Hapus atau ubah header X-Powered-By. Di PHP: expose_php = Off. Di Express: app.disable('x-powered-by'). Di Laravel: ubah konfigurasi middleware.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref":   "CWE-200",
        "cvss":       4.3,
        "priority":  "low",
        "checklist": [
            "PHP: set 'expose_php = Off' di php.ini",
            "Express.js: app.disable('x-powered-by') atau gunakan helmet.js",
            "Laravel: hapus atau modifikasi middleware yang menambahkan header",
            "ASP.NET: hapus X-Powered-By via web.config",
            "Pertimbangkan menggunakan WAF untuk menyaring response header",
        ]
    },
    "Broken Access Control": {
        "title":     "Perbaiki Kontrol Akses pada Halaman Sensitif",
        "cause":     "Halaman atau endpoint sensitif (admin, dashboard) dapat diakses tanpa autentikasi atau otorisasi yang memadai.",
        "impact":    "Pengguna tidak sah dapat mengakses data sensitif, mengubah konfigurasi, atau mengambil alih fungsi administratif.",
        "solution":  "Implementasikan middleware autentikasi dan otorisasi pada semua route sensitif. Terapkan prinsip deny-by-default.",
        "owasp_ref": "A01:2021 - Broken Access Control",
        "cwe_ref":   "CWE-284",
        "cvss":       9.1,
        "priority":  "critical",
        "checklist": [
            "Tambahkan middleware autentikasi pada semua route sensitif",
            "Terapkan Role-Based Access Control (RBAC)",
            "Gunakan prinsip deny-by-default: tolak semua kecuali yang eksplisit diizinkan",
            "Validasi otorisasi di sisi server, bukan hanya sisi klien",
            "Log semua upaya akses tidak sah",
            "Uji seluruh endpoint dengan pengguna tanpa hak akses",
        ]
    },
    "File Upload Endpoint Detected": {
        "title":     "Amankan Endpoint Upload File",
        "cause":     "Endpoint upload file ditemukan dan memerlukan validasi ketat untuk mencegah upload file berbahaya.",
        "impact":    "Tanpa validasi yang tepat, penyerang dapat mengupload file executable yang memungkinkan Remote Code Execution (RCE) pada server.",
        "solution":  "Validasi tipe file dengan whitelist MIME type, batasi ukuran, simpan di luar web root, rename dengan nama acak, dan scan dengan antivirus.",
        "owasp_ref": "A04:2021 - Insecure Design",
        "cwe_ref":   "CWE-434",
        "cvss":       8.8,
        "priority":  "high",
        "checklist": [
            "Validasi MIME type di sisi server (bukan hanya ekstensi)",
            "Whitelist hanya ekstensi file yang diperlukan (jpg, png, pdf, dll)",
            "Batasi ukuran file upload sesuai kebutuhan bisnis",
            "Simpan file upload di luar document root web server",
            "Rename file dengan nama acak (UUID) — jangan gunakan nama asli",
            "Scan file upload dengan antivirus sebelum diproses",
            "Jangan izinkan eksekusi file dari direktori upload",
        ]
    },
    "Insecure Content Security Policy": {
        "title":     "Perkuat Konfigurasi Content Security Policy",
        "cause":     "CSP yang ada mengizinkan 'unsafe-inline', yang secara signifikan mengurangi proteksi terhadap XSS.",
        "impact":    "Inline scripts dan styles tetap dapat dieksekusi meskipun CSP aktif, membuat CSP kurang efektif melawan XSS.",
        "solution":  "Hapus 'unsafe-inline' dari CSP. Gunakan nonce atau hash untuk script yang memang diperlukan. Pindahkan inline script ke file eksternal.",
        "owasp_ref": "A05:2021 - Security Misconfiguration",
        "cwe_ref":   "CWE-1021",
        "cvss":       5.4,
        "priority":  "medium",
        "checklist": [
            "Hapus 'unsafe-inline' dari directive script-src",
            "Pindahkan semua inline script ke file JavaScript eksternal",
            "Gunakan nonce-based CSP: script-src 'nonce-{random}'",
            "Uji CSP dengan https://csp-evaluator.withgoogle.com",
            "Aktifkan CSP reporting: report-uri /csp-report",
            "Terapkan CSP secara bertahap dimulai dari Content-Security-Policy-Report-Only",
        ]
    },
}


class RecommendationAgent:
    def __init__(self, db: AsyncSession, scan_id: int, predictions: List[Dict]):
        self.db          = db
        self.scan_id     = scan_id
        self.predictions = predictions

    async def run(self):
        seen: set = set()

        # Sort by severity so critical comes first
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_preds = sorted(
            self.predictions,
            key=lambda p: severity_order.get(p.get("severity", "info"), 5)
        )

        for pred in sorted_preds:
            pred_name = pred.get("prediction", "")
            if not pred_name or pred_name in seen:
                continue
            seen.add(pred_name)

            tmpl = TEMPLATES.get(pred_name)
            if not tmpl:
                # Generic fallback for unknown findings
                tmpl = {
                    "title":     f"Tinjau Temuan: {pred_name}",
                    "cause":     "Potensi masalah keamanan terdeteksi pada proses audit.",
                    "impact":    "Dampak tergantung pada konteks dan konfigurasi spesifik aplikasi.",
                    "solution":  "Tinjau temuan ini secara manual dan konsultasikan dengan tim keamanan.",
                    "owasp_ref": pred.get("owasp", "A05:2021"),
                    "cwe_ref":   pred.get("cwe", "CWE-200"),
                    "cvss":       5.0,
                    "priority":  pred.get("severity", "medium"),
                    "checklist": [
                        "Tinjau temuan ini secara manual",
                        "Konsultasikan dengan tim keamanan",
                        "Dokumentasikan langkah mitigasi yang diambil",
                    ]
                }

            confidence = pred.get("confidence", 0)
            affected   = pred.get("url", "")

            rec = Recommendation(
                scan_id      = self.scan_id,
                title        = tmpl["title"],
                summary      = (
                    f"{pred_name} terdeteksi dengan confidence {confidence:.0f}%. "
                    f"Prioritas perbaikan: {tmpl.get('priority','medium').upper()}."
                ),
                cause        = tmpl["cause"],
                impact       = tmpl["impact"],
                solution     = tmpl["solution"],
                priority     = tmpl.get("priority", pred.get("severity", "medium")),
                owasp_ref    = tmpl["owasp_ref"],
                cwe_ref      = tmpl["cwe_ref"],
                cvss_score   = tmpl.get("cvss"),
                affected_url = affected,
                checklist    = tmpl.get("checklist", []),
            )
            self.db.add(rec)

        try:
            await self.db.flush()
        except Exception as e:
            logger.warning(f"[Recommendation] flush error: {e}")

        logger.info(f"[Recommendation] {len(seen)} recommendations for scan {self.scan_id}")
