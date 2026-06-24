/**
 * Sentinel AI - API Client
 * All HTTP communication with the backend
 */

const API_BASE = "http://localhost:8000/api/v1";
const WS_BASE  = "ws://localhost:8000";

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
    const data = await res.json();
    if (res.status === 401) {
      Auth.clear();
      if (!window.location.pathname.includes("login")) {
        window.location.href = "/pages/auth/login.html";
      }
    }
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    console.error("API Error:", err);
    return { ok: false, status: 0, data: { success: false, message: "Gagal terhubung ke server" } };
  }
}

async function requestBlob(method, path, body = null, options = {}) {
  const token = Auth.getToken();
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  Object.assign(headers, options.headers || {});

  const config = { method, headers };
  if (body) config.body = JSON.stringify(body);

  try {
    const res = await fetch(`${API_BASE}${path}`, config);
    if (res.status === 401) {
      Auth.clear();
      if (!window.location.pathname.includes("login")) {
        window.location.href = "/pages/auth/login.html";
      }
    }
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      return { ok: false, status: res.status, data };
    }
    const blob = await res.blob();
    return { ok: true, status: res.status, data: blob, contentType: res.headers.get("content-type") };
  } catch (err) {
    console.error("API Error:", err);
    return { ok: false, status: 0, data: { success: false, message: "Gagal terhubung ke server" } };
  }
}

const api = {
  get:    (path) => request("GET", path),
  post:   (path, body) => request("POST", path, body),
  put:    (path, body) => request("PUT", path, body),
  delete: (path) => request("DELETE", path),
  download: (path) => requestBlob("GET", path),
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
    progress: (id)   => api.get(`/scans/${id}/progress`),
    logs:     (id)   => api.get(`/scans/${id}/logs`),
    cancel:   (id)   => api.post(`/scans/${id}/cancel`),
    delete:   (id)   => api.delete(`/scans/${id}`),
  },
  // Reports
  reports: {
    list:     ()                   => api.get("/reports"),
    get:      (id)                 => api.get(`/reports/${id}`),
    download: (id, type)           => api.download(`/reports/${id}/${type}`),
    pdfUrl:   (id)                 => `${API_BASE}/reports/${id}/pdf`,
    jsonUrl:  (id)                 => `${API_BASE}/reports/${id}/json`,
    csvUrl:   (id)                 => `${API_BASE}/reports/${id}/csv`,
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
    statistics: ()  => api.get("/dashboard/statistics"),
    chartScore: ()  => api.get("/dashboard/chart/security-score"),
    chartSeverity: () => api.get("/dashboard/chart/severity"),
    chartActivity: () => api.get("/dashboard/chart/activity"),
  },
  // Notifications
  notifications: {
    list:      ()   => api.get("/notifications"),
    markRead:  (id) => api.put(`/notifications/read/${id}`),
    markAll:   ()   => api.put("/notifications/read-all"),
    delete:    (id) => api.delete(`/notifications/${id}`),
  },
  // Datasets
  datasets: {
    list: () => api.get("/datasets"),
  },
};

// ── WebSocket Helper ─────────────────────────────────────────────
function connectScanWS(scanId, handlers = {}) {
  const token = Auth.getToken();
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
    showConfirmButton: false, timer: 3000, timerProgressBar: true,
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
  const map = { A: "text-emerald-600", B: "text-green-600", C: "text-yellow-600", D: "text-orange-600", E: "text-red-600" };
  return map[grade] || "text-slate-600";
}

function scoreColor(score) {
  if (score >= 90) return "text-emerald-600";
  if (score >= 80) return "text-green-600";
  if (score >= 70) return "text-yellow-600";
  if (score >= 60) return "text-orange-600";
  return "text-red-600";
}

function formatDate(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("id-ID", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatDuration(seconds) {
  if (!seconds) return "-";
  if (seconds < 60) return `${seconds} detik`;
  return `${Math.floor(seconds / 60)} menit ${seconds % 60} detik`;
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
  const cls = map[status] || "bg-slate-100 text-slate-600";
  const labels = {
    pending: "Menunggu", running: "Berjalan", completed: "Selesai",
    failed: "Gagal", cancelled: "Dibatalkan", paused: "Dijeda"
  };
  return `<span class="px-2 py-0.5 rounded-full text-xs font-semibold ${cls}">${labels[status] || status}</span>`;
}

// Skeleton loader
function skeleton(lines = 3) {
  return Array(lines).fill(0).map(() =>
    `<div class="h-4 bg-slate-200 rounded animate-pulse mb-2"></div>`
  ).join("");
}

// Redirect if not logged in
function requireAuth() {
  if (!Auth.isLoggedIn()) {
    window.location.href = "/pages/auth/login.html";
    return false;
  }
  return true;
}

// Guard for pages - run on page load
function authGuard() {
  if (!requireAuth()) return;
}
