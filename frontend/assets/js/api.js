/**
 * Sentinel AI - API Client
 * All HTTP communication with the backend
 */

const API_BASE = "http://localhost:8000/api/v1";
const WS_BASE  = "ws://localhost:8000";

// ── Timezone: WIT (UTC+9) ────────────────────────────────────────
// Semua timestamp dari backend disimpan sebagai UTC.
// Konversi ke WIT (Waktu Indonesia Timur, UTC+9) untuk tampilan.
const USER_TIMEZONE = "Asia/Jayapura"; // WIT UTC+9

// ── Token Management ─────────────────────────────────────────────
const Auth = {
  getToken: () => localStorage.getItem("sentinel_token"),
  setToken: (t) => localStorage.setItem("sentinel_token", t),
  setUser:  (u) => localStorage.setItem("sentinel_user", JSON.stringify(u)),
  getUser:  () => { try { return JSON.parse(localStorage.getItem("sentinel_user")); } catch { return null; } },
  clear:    () => { localStorage.removeItem("sentinel_token"); localStorage.removeItem("sentinel_user"); },
  isLoggedIn: () => !!localStorage.getItem("sentinel_token"),
};

// ── HTTP Request Helper ──────────────────────────────────────────
async function request(method, path, body = null, options = {}) {
  const token = Auth.getToken();
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  Object.assign(headers, options.headers || {});

  const config = { method, headers };
  if (body) config.body = JSON.stringify(body);

  try {
    const res = await fetch(`${API_BASE}${path}`, config);
    // File download — return blob
    if (options.blob) {
      if (!res.ok) return { ok: false, status: res.status, data: { message: "Gagal mengunduh file" } };
      const blob = await res.blob();
      return { ok: true, status: res.status, data: blob };
    }
    const data = await res.json();
    if (res.status === 401) {
      Auth.clear();
      if (!window.location.pathname.includes("login")) {
        window.location.href = "/frontend/pages/auth/login.html";
      }
    }
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    console.error("API Error:", err);
    return { ok: false, status: 0, data: { success: false, message: "Gagal terhubung ke server" } };
  }
}

const api = {
  get:    (path, opts)       => request("GET",    path, null, opts || {}),
  post:   (path, body)       => request("POST",   path, body),
  put:    (path, body)       => request("PUT",    path, body),
  delete: (path)             => request("DELETE", path),
  blob:   (path)             => request("GET",    path, null, { blob: true }),
};

// ── API Methods ──────────────────────────────────────────────────
const API = {
  // Auth
  auth: {
    login:          (body) => api.post("/auth/login", body),
    register:       (body) => api.post("/auth/register", body),
    logout:         ()     => api.post("/auth/logout"),
    me:             ()     => api.get("/auth/me"),
    updateProfile:  (body) => api.put("/auth/profile", body),
    changePassword: (body) => api.put("/auth/password", body),
  },
  // Websites
  websites: {
    list:    (params = "") => api.get(`/websites${params}`),
    get:     (id)   => api.get(`/websites/${id}`),
    create:  (body) => api.post("/websites", body),
    update:  (id, body) => api.put(`/websites/${id}`, body),
    delete:  (id)   => api.delete(`/websites/${id}`),
  },
  // Scans
  scans: {
    create:   (body) => api.post("/scans", body),
    list:     ()     => api.get("/scans"),
    history:  ()     => api.get("/scans/history"),
    get:      (id)   => api.get(`/scans/${id}`),
    website:  (id)   => api.get(`/scans/${id}/website`),
    progress: (id)   => api.get(`/scans/${id}/progress`),
    logs:     (id)   => api.get(`/scans/${id}/logs`),
    cancel:   (id)   => api.post(`/scans/${id}/cancel`),
    delete:   (id)   => api.delete(`/scans/${id}`),
  },
  // Reports
  reports: {
    list:         ()         => api.get("/reports"),
    get:          (id)       => api.get(`/reports/${id}`),
    byScan:       (scanId)   => api.get(`/reports/by-scan/${scanId}`),
    technologies: (scanId)   => api.get(`/reports/technologies/${scanId}`),
    download:     (id, type) => api.blob(`/reports/${id}/${type}`),
    // URL helpers for direct links (used by frontend templates)
    pdfUrl:       (id)       => `${API_BASE}/reports/${id}/pdf`,
    jsonUrl:      (id)       => `${API_BASE}/reports/${id}/json`,
    csvUrl:       (id)       => `${API_BASE}/reports/${id}/csv`,
  },
  // AI
  ai: {
    summary:         (scanId) => api.get(`/ai/summary/${scanId}`),
    recommendations: (scanId) => api.get(`/ai/recommendation/${scanId}`),
    predictions:     (scanId) => api.get(`/ai/predictions/${scanId}`),
    chat:            (body)   => api.post("/ai/chat", body),
    memory:          (wid)    => api.get(`/ai/memory/${wid}`),
    models:          ()       => api.get("/ai/models"),
  },
  // Dashboard
  dashboard: {
    statistics:    () => api.get("/dashboard/statistics"),
    chartScore:    () => api.get("/dashboard/chart/security-score"),
    chartSeverity: () => api.get("/dashboard/chart/severity"),
    chartActivity: () => api.get("/dashboard/chart/activity"),
  },
  // Notifications
  notifications: {
    list:     ()   => api.get("/notifications"),
    markRead: (id) => api.put(`/notifications/read/${id}`),
    markAll:  ()   => api.put("/notifications/read-all"),
    delete:   (id) => api.delete(`/notifications/${id}`),
  },
  // Datasets
  datasets: {
    list: () => api.get("/datasets"),
  },
};

// ── WebSocket Helper ─────────────────────────────────────────────
function connectScanWS(scanId, handlers = {}) {
  const ws = new WebSocket(`${WS_BASE}/ws/scan/${scanId}`);
  ws.onopen    = () => handlers.onOpen?.();
  ws.onmessage = (e) => { try { handlers.onMessage?.(JSON.parse(e.data)); } catch {} };
  ws.onerror   = (e) => handlers.onError?.(e);
  ws.onclose   = () => handlers.onClose?.();
  return ws;
}

// ── UI Helpers ───────────────────────────────────────────────────
function toast(message, type = "success") {
  Swal.fire({
    toast: true, position: "top-end",
    icon: type, title: message,
    showConfirmButton: false, timer: 3500, timerProgressBar: true,
  });
}

function confirm(title, text, icon = "warning") {
  return Swal.fire({
    title, text, icon,
    showCancelButton: true,
    confirmButtonText: "Ya, lanjutkan",
    cancelButtonText: "Batal",
    confirmButtonColor: "#09090B",
    cancelButtonColor: "#71717A",
  });
}

function severityBadge(severity) {
  const map = {
    critical: "bg-red-100 text-red-700 border border-red-200",
    high:     "bg-orange-100 text-orange-700 border border-orange-200",
    medium:   "bg-yellow-100 text-yellow-700 border border-yellow-200",
    low:      "bg-green-100 text-green-700 border border-green-200",
    info:     "bg-blue-100 text-blue-700 border border-blue-200",
    safe:     "bg-emerald-100 text-emerald-700 border border-emerald-200",
  };
  const cls = map[severity?.toLowerCase()] || map.info;
  return `<span class="px-2 py-0.5 rounded-full text-xs font-semibold ${cls}">${(severity || "info").toUpperCase()}</span>`;
}

function gradeColor(grade) {
  const g = (grade || "").replace("+","");
  const map = { "A+": "text-emerald-500", A: "text-emerald-600", B: "text-green-600", C: "text-yellow-600", D: "text-orange-600", E: "text-red-600" };
  return map[grade] || map[g] || "text-slate-600";
}

function scoreColor(score) {
  if (score >= 90) return "text-emerald-600";
  if (score >= 80) return "text-green-600";
  if (score >= 70) return "text-yellow-600";
  if (score >= 60) return "text-orange-600";
  return "text-red-600";
}

/**
 * Format ISO timestamp ke zona waktu lokal browser pengguna.
 * Backend menyimpan UTC, browser akan otomatis konversi ke zona waktu OS.
 * Jika OS kamu sudah diset WIT (UTC+9), hasilnya sudah WIT.
 */
function formatDate(iso) {
  if (!iso) return "-";
  // Tambahkan "Z" jika tidak ada timezone info supaya dianggap UTC
  const isoFixed = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
  return new Date(isoFixed).toLocaleString("id-ID", {
    timeZone: USER_TIMEZONE,
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function formatDateShort(iso) {
  if (!iso) return "-";
  const isoFixed = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
  return new Date(isoFixed).toLocaleString("id-ID", {
    timeZone: USER_TIMEZONE,
    day: "2-digit", month: "short", year: "numeric",
  });
}

function formatTime(iso) {
  if (!iso) return "-";
  const isoFixed = iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z";
  return new Date(isoFixed).toLocaleString("id-ID", {
    timeZone: USER_TIMEZONE,
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function formatDuration(seconds) {
  if (!seconds && seconds !== 0) return "-";
  if (seconds < 60) return `${seconds} detik`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return s > 0 ? `${m} menit ${s} detik` : `${m} menit`;
}

function statusBadge(status) {
  const map = {
    pending:   "bg-slate-100 text-slate-600",
    running:   "bg-blue-100 text-blue-600 animate-pulse",
    completed: "bg-emerald-100 text-emerald-700",
    failed:    "bg-red-100 text-red-700",
    cancelled: "bg-slate-100 text-slate-500",
    paused:    "bg-yellow-100 text-yellow-700",
  };
  const labels = {
    pending: "Menunggu", running: "Berjalan", completed: "Selesai",
    failed: "Gagal", cancelled: "Dibatalkan", paused: "Dijeda"
  };
  return `<span class="px-2 py-0.5 rounded-full text-xs font-semibold ${map[status] || map.pending}">${labels[status] || status}</span>`;
}

// Skeleton loader
function skeleton(lines = 3) {
  return Array(lines).fill(0).map(() =>
    `<div class="h-4 bg-slate-200 rounded animate-pulse mb-2"></div>`
  ).join("");
}

// Helper download file
function downloadFile(reportId, type) {
  const token = Auth.getToken();
  const url = `${API_BASE}/reports/${reportId}/${type}?token=${token}`;
  // Browser buka URL, server kirim file dengan nama asli dari disk
  const a = document.createElement("a");
  a.href = url;
  a.target = "_blank";
  a.click();
}

// Redirect if not logged in
function requireAuth() {
  if (!Auth.isLoggedIn()) {
    window.location.href = "/frontend/pages/auth/login.html";
    return false;
  }
  return true;
}
function authGuard() { requireAuth(); }
