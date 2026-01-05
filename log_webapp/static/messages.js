let currentLevel = null;

async function ensureAuthenticated() {
  const res = await fetch("/api/me");
  if (!res.ok) {
    window.location.href = "/login";
    return null;
  }
  const data = await res.json();
  if (!data.authenticated) {
    window.location.href = "/login";
    return null;
  }
  return data.user;
}

async function logout() {
  await fetch("/api/logout", { method: "POST" });
  window.location.href = "/login";
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

async function loadMessagesByLevel(level) {
  const res = await fetch(`/api/messages_by_level?level=${encodeURIComponent(level)}`);
  if (!res.ok) {
    if (res.status === 401) window.location.href = "/login";
    const err = await res.json().catch(() => ({}));
    document.getElementById("levelTitle").textContent = err.error || `Failed to load ${level}`;
    return;
  }
  const data = await res.json();
  currentLevel = data.level;
  document.getElementById("levelTitle").textContent = `${data.level} Messages (${data.messages.length})`;
  const tbody = document.getElementById("messagesBody");
  tbody.innerHTML = "";
  for (const item of data.messages) {
    const row = document.createElement("tr");
    const countCell = document.createElement("td");
    countCell.textContent = item.count;
    const msgCell = document.createElement("td");
    msgCell.textContent = item.message;
    msgCell.title = item.message;
    row.appendChild(countCell);
    row.appendChild(msgCell);
    tbody.appendChild(row);
  }
}

async function init() {
  const user = await ensureAuthenticated();
  if (!user) return;

  const userBadge = document.getElementById("userBadge");
  const logoutBtn = document.getElementById("logoutBtn");
  if (userBadge) {
    userBadge.textContent = user;
    userBadge.classList.remove("d-none");
  }
  if (logoutBtn) {
    logoutBtn.classList.remove("d-none");
    logoutBtn.addEventListener("click", logout);
  }

  const urlParams = new URLSearchParams(window.location.search);
  const level = (urlParams.get("level") || "").trim().toUpperCase();
  if (!level) {
    document.getElementById("levelTitle").textContent = "No level specified";
    return;
  }
  await loadMessagesByLevel(level);
}

init();
