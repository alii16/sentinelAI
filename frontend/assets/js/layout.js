/**
 * Sentinel AI - Layout (Sidebar + Navbar)
 */

function renderLayout(activePage = "") {
  const user = Auth.getUser();
  const name = user?.name || "Pengguna";
  const role = user?.role || "user";

  const navItems = [
    { id: "dashboard",      label: "Dashboard",      icon: "layout-dashboard", href: "../dashboard/index.html" },
    { id: "websites",       label: "Website",        icon: "globe",            href: "../websites/index.html" },
    { id: "scan",           label: "Scan",           icon: "radar",            href: "../scan/index.html" },
    { id: "history",        label: "Riwayat",        icon: "history",          href: "../scan/history.html" },
    { id: "reports",        label: "Laporan",        icon: "file-text",        href: "../report/index.html" },
    { id: "ai-chat",        label: "AI Chat",        icon: "bot",              href: "../ai-chat/index.html" },
    { id: "dataset",        label: "Dataset",        icon: "database",         href: "../dataset/index.html" },
    { id: "ai-models",      label: "AI Models",      icon: "brain",            href: "../ai-models/index.html" },
    { id: "notifications",  label: "Notifikasi",     icon: "bell",             href: "../notifications/index.html" },
    { id: "settings",       label: "Pengaturan",     icon: "settings",         href: "../settings/index.html" },
  ];
  if (role === "admin") {
    navItems.push({ id: "admin", label: "Admin", icon: "shield-user", href: "../admin/index.html" });
  }

  const sidebarItems = navItems.map(item => {
    const active = activePage === item.id ? "bg-slate-100 text-slate-900 font-semibold" : "text-slate-600 hover:bg-slate-50 hover:text-slate-900";
    return `
      <a href="${item.href}" class="flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 ${active} group">
        <i data-lucide="${item.icon}" class="w-4 h-4 shrink-0"></i>
        <span class="text-sm">${item.label}</span>
      </a>`;
  }).join("");

  document.getElementById("app-layout").innerHTML = `
    <!-- Sidebar -->
    <aside id="sidebar" class="fixed left-0 top-0 h-full w-60 bg-white border-r border-slate-200 z-40 flex flex-col transition-transform duration-300 lg:translate-x-0 -translate-x-full">
      <!-- Logo -->
      <div class="flex items-center gap-3 px-5 py-5 border-b border-slate-200">
        <div class="w-8 h-8 bg-slate-900 rounded-xl flex items-center justify-center">
          <i data-lucide="shield-check" class="w-4 h-4 text-white"></i>
        </div>
        <div>
          <p class="text-sm font-bold text-slate-900">Sentinel AI</p>
          <p class="text-xs text-slate-500">Security Auditor</p>
        </div>
      </div>

      <!-- Navigation -->
      <nav class="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        ${sidebarItems}
      </nav>

      <!-- User -->
      <div class="px-3 py-4 border-t border-slate-200">
        <div class="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-slate-50 cursor-pointer" onclick="handleLogout()">
          <div class="w-7 h-7 rounded-full bg-slate-900 flex items-center justify-center text-white text-xs font-bold shrink-0">
            ${name.charAt(0).toUpperCase()}
          </div>
          <div class="flex-1 min-w-0">
            <p class="text-sm font-medium text-slate-900 truncate">${name}</p>
            <p class="text-xs text-slate-500 capitalize">${role}</p>
          </div>
          <i data-lucide="log-out" class="w-4 h-4 text-slate-400"></i>
        </div>
      </div>
    </aside>

    <!-- Main -->
    <div class="lg:ml-60 flex flex-col min-h-screen">
      <!-- Navbar -->
      <header class="sticky top-0 z-30 bg-white border-b border-slate-200 h-14 flex items-center px-5 gap-4">
        <button onclick="toggleSidebar()" class="lg:hidden p-1.5 rounded-lg hover:bg-slate-100">
          <i data-lucide="menu" class="w-5 h-5 text-slate-600"></i>
        </button>

        <!-- Breadcrumb -->
        <div id="breadcrumb" class="flex items-center gap-1.5 text-sm text-slate-500 flex-1">
          <span class="text-slate-900 font-medium" id="breadcrumb-title">Dashboard</span>
        </div>

        <div class="flex items-center gap-2">
          <!-- Search (placeholder) -->
          <button class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500">
            <i data-lucide="search" class="w-4 h-4"></i>
          </button>

          <!-- Notifications -->
          <div class="relative">
            <button onclick="toggleNotifDropdown()" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 relative">
              <i data-lucide="bell" class="w-4 h-4"></i>
              <span id="notif-badge" class="absolute -top-0.5 -right-0.5 hidden w-4 h-4 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center"></span>
            </button>
            <!-- Dropdown -->
            <div id="notif-dropdown" class="hidden absolute right-0 top-10 w-80 bg-white border border-slate-200 rounded-2xl shadow-xl z-50 overflow-hidden">
              <div class="flex items-center justify-between px-4 py-3 border-b border-slate-100">
                <p class="text-sm font-semibold text-slate-900">Notifikasi</p>
                <button onclick="markAllNotif()" class="text-xs text-slate-500 hover:text-slate-900">Tandai semua</button>
              </div>
              <div id="notif-list" class="max-h-72 overflow-y-auto">
                <p class="text-xs text-slate-400 text-center py-6">Memuat...</p>
              </div>
            </div>
          </div>

          <!-- Profile -->
          <div class="w-7 h-7 rounded-full bg-slate-900 flex items-center justify-center text-white text-xs font-bold cursor-pointer"
               onclick="window.location.href='/frontend/pages/settings/index.html'">
            ${name.charAt(0).toUpperCase()}
          </div>
        </div>
      </header>

      <!-- Page Content -->
      <main class="flex-1 p-5 lg:p-6" id="page-content">
        <!-- Page inserts content here -->
      </main>
    </div>

    <!-- Overlay -->
    <div id="sidebar-overlay" onclick="toggleSidebar()" class="fixed inset-0 bg-black/40 z-30 hidden lg:hidden"></div>
  `;

  // Init lucide icons
  lucide.createIcons();

  // Load notifications count
  loadNotifCount();
}

function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebar-overlay");
  sidebar.classList.toggle("-translate-x-full");
  overlay.classList.toggle("hidden");
}

async function handleLogout() {
  const result = await confirm("Keluar?", "Anda akan keluar dari Sentinel AI.");
  if (result.isConfirmed) {
    await API.auth.logout();
    Auth.clear();
    window.location.href = "../../index.html";
  }
}

async function loadNotifCount() {
  const res = await API.notifications.list();
  if (!res.ok) return;
  const unread = (res.data.data || []).filter(n => !n.is_read).length;
  const badge = document.getElementById("notif-badge");
  if (badge && unread > 0) {
    badge.textContent = unread > 9 ? "9+" : unread;
    badge.classList.remove("hidden");
    badge.classList.add("flex");
  }
}

async function toggleNotifDropdown() {
  const dropdown = document.getElementById("notif-dropdown");
  dropdown.classList.toggle("hidden");
  if (!dropdown.classList.contains("hidden")) {
    await loadNotifications();
  }
}

async function loadNotifications() {
  const list = document.getElementById("notif-list");
  const res = await API.notifications.list();
  if (!res.ok || !res.data.data?.length) {
    list.innerHTML = `<p class="text-xs text-slate-400 text-center py-6">Tidak ada notifikasi</p>`;
    return;
  }
  list.innerHTML = res.data.data.slice(0, 8).map(n => `
    <div class="flex gap-3 px-4 py-3 hover:bg-slate-50 cursor-pointer border-b border-slate-50 ${n.is_read ? 'opacity-60' : ''}"
         onclick="markNotif(${n.id}, this)">
      <div class="w-8 h-8 rounded-xl bg-slate-100 flex items-center justify-center shrink-0">
        <i data-lucide="bell" class="w-3.5 h-3.5 text-slate-600"></i>
      </div>
      <div class="flex-1 min-w-0">
        <p class="text-xs font-semibold text-slate-900">${n.title}</p>
        <p class="text-xs text-slate-500 truncate">${n.body || ""}</p>
        <p class="text-[10px] text-slate-400 mt-0.5">${formatDate(n.created_at)}</p>
      </div>
      ${!n.is_read ? '<div class="w-2 h-2 bg-blue-500 rounded-full mt-1 shrink-0"></div>' : ''}
    </div>
  `).join("");
  lucide.createIcons();
}

async function markNotif(id, el) {
  await API.notifications.markRead(id);
  el.classList.add("opacity-60");
  const dot = el.querySelector(".bg-blue-500");
  if (dot) dot.remove();
  loadNotifCount();
}

async function markAllNotif() {
  await API.notifications.markAll();
  document.getElementById("notif-badge")?.classList.add("hidden");
  loadNotifications();
}

// Close notif dropdown on outside click
document.addEventListener("click", (e) => {
  const dropdown = document.getElementById("notif-dropdown");
  if (dropdown && !dropdown.closest("div")?.contains(e.target)) {
    // More precise check
  }
});
