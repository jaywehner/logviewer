const LEVELS = ["INFO", "WARNING", "DEBUG", "ERROR", "SEVERE"];
const LEVEL_COLORS = {
  INFO: "text-info",
  WARNING: "text-warning",
  DEBUG: "text-secondary",
  ERROR: "text-danger",
  SEVERE: "text-danger",
};

function isLogFileName(name) {
  const lower = name.toLowerCase();
  if (lower.endsWith(".log")) return true;
  return /\.log\.(?:[1-9]|[1-9]\d)$/.test(lower);
}

let selectedPath = null;
const enabledLevels = new Set(["INFO", "WARNING", "DEBUG", "ERROR", "SEVERE"]);

let fileTreeData = null;
let fileSearchQuery = "";
let lineSearchQuery = "";
let lastLoadedLines = [];

const STORAGE_KEYS = {
  expandedDirs: "log_webapp_expanded_dirs"
};

function loadExpandedDirs() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.expandedDirs);
    const arr = JSON.parse(raw || "[]");
    if (Array.isArray(arr)) return new Set(arr);
  } catch {
    // ignore
  }
  return new Set();
}

function saveExpandedDirs(set) {
  try {
    localStorage.setItem(STORAGE_KEYS.expandedDirs, JSON.stringify(Array.from(set)));
  } catch {
    // ignore
  }
}

let expandedDirs = loadExpandedDirs();

function setFileActionState() {
  const has = Boolean(selectedPath);
  const downloadBtn = document.getElementById("downloadBtn");
  const deleteBtn = document.getElementById("deleteBtn");
  if (downloadBtn) downloadBtn.disabled = !has;
  if (deleteBtn) deleteBtn.disabled = !has;
}

function filterTree(node, q) {
  const query = (q || "").trim().toLowerCase();
  if (!query) return node;

  if (node.type === "file") {
    return (node.name || "").toLowerCase().includes(query) ? node : null;
  }

  const children = [];
  for (const child of node.children || []) {
    const f = filterTree(child, query);
    if (f) children.push(f);
  }

  if (children.length > 0 || (node.name || "").toLowerCase().includes(query)) {
    return { ...node, children };
  }

  return null;
}

function renderTree() {
  const tree = document.getElementById("fileTree");
  tree.innerHTML = "";
  if (!fileTreeData) return;
  const filtered = filterTree(fileTreeData, fileSearchQuery);
  if (!filtered) return;
  // If filtering is active, auto-expand all dirs in the filtered result so matches are visible
  if ((fileSearchQuery || "").trim()) {
    function collectDirs(n) {
      if (!n) return;
      if (n.type === "dir") {
        expandedDirs.add(n.path || "");
        for (const c of n.children || []) collectDirs(c);
      }
    }
    collectDirs(filtered);
    saveExpandedDirs(expandedDirs);
  }

  renderTreeNode(filtered, tree);
}

function setChangePasswordAlert(kind, msg) {
  const err = document.getElementById("changePwError");
  const ok = document.getElementById("changePwSuccess");
  if (!err || !ok) return;

  err.classList.add("d-none");
  ok.classList.add("d-none");

  if (kind === "error") {
    err.textContent = msg;
    err.classList.remove("d-none");
  } else if (kind === "success") {
    ok.classList.remove("d-none");
  }
}

async function changePassword() {
  const currentPassword = document.getElementById("currentPassword").value;
  const newPassword = document.getElementById("newPassword").value;

  setChangePasswordAlert(null);
  const res = await fetch("/api/change_password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword, newPassword })
  });

  if (!res.ok) {
    if (res.status === 401) {
      setChangePasswordAlert("error", "Invalid current password (or session expired)");
      return;
    }
    const txt = await res.text().catch(() => "");
    setChangePasswordAlert("error", txt || `Failed (${res.status})`);
    return;
  }

  document.getElementById("currentPassword").value = "";
  document.getElementById("newPassword").value = "";
  setChangePasswordAlert("success");
}

function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

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

async function uploadFiles() {
  const input = document.getElementById("uploadFile");
  if (!input || !input.files || input.files.length === 0) return;

  const fd = new FormData();
  for (const f of input.files) fd.append("file", f, f.name);

  const res = await fetch("/api/upload", { method: "POST", body: fd });
  if (!res.ok) {
    if (res.status === 401) window.location.href = "/login";
    return;
  }

  const data = await res.json().catch(() => null);
  const meta = document.getElementById("selectedFileMeta");
  if (meta && data) {
    const z = (data.deletedZips || []).length;
    if (z > 0) meta.textContent = `Upload complete. Unzipped ${z} zip file(s).`;
    else meta.textContent = "Upload complete.";
  }

  input.value = "";
  await loadTree();
  await refreshSummary();
}

async function deleteAll() {
  if (!confirm("Delete ALL files in your folder?\n\nThis cannot be undone.")) return;
  const res = await fetch("/api/delete_all", { method: "DELETE" });
  if (!res.ok) {
    if (res.status === 401) window.location.href = "/login";
    return;
  }
  selectedPath = null;
  document.getElementById("selectedFile").textContent = "Select a log file…";
  document.getElementById("selectedFileMeta").textContent = "";
  document.getElementById("logOutput").textContent = "";
  setFileActionState();
  await loadTree();
  await refreshSummary();
}

function downloadSelected() {
  if (!selectedPath) return;
  const url = new URL("/api/raw", window.location.origin);
  url.searchParams.set("path", selectedPath);
  window.open(url.toString(), "_blank", "noopener,noreferrer");
}

function exportReport() {
  const url = new URL("/api/report.pdf", window.location.origin);
  window.open(url.toString(), "_blank", "noopener,noreferrer");
}

async function deleteSelected() {
  if (!selectedPath) return;
  if (!confirm(`Delete selected file?\n\n${selectedPath}`)) return;
  const url = new URL("/api/delete", window.location.origin);
  url.searchParams.set("path", selectedPath);
  const res = await fetch(url, { method: "DELETE" });
  if (!res.ok) {
    if (res.status === 401) window.location.href = "/login";
    return;
  }
  selectedPath = null;
  document.getElementById("selectedFile").textContent = "Select a log file…";
  document.getElementById("selectedFileMeta").textContent = "";
  document.getElementById("logOutput").textContent = "";
  setFileActionState();
  await loadTree();
  await refreshSummary();
}

function escapeHtml(s) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function buildLevelToggles() {
  const container = document.getElementById("levelToggles");
  container.innerHTML = "";

  for (const lvl of LEVELS) {
    const wrapper = el("div", "form-check form-switch");

    const input = el("input", "form-check-input");
    input.type = "checkbox";
    input.role = "switch";
    input.id = `lvl_${lvl}`;
    input.checked = true;
    input.addEventListener("change", async () => {
      if (input.checked) enabledLevels.add(lvl);
      else enabledLevels.delete(lvl);
      await refreshSelectedFile();
    });

    const label = el("label", "form-check-label", lvl);
    label.htmlFor = input.id;

    wrapper.appendChild(input);
    wrapper.appendChild(label);
    container.appendChild(wrapper);
  }
}

function renderTreeNode(node, parent) {
  if (node.type === "dir") {
    const dirRow = el("div", "node dir px-2 py-1 rounded d-flex align-items-center gap-2");
    const caret = el("span", "text-secondary", "▸");
    const name = el("span", "", node.name || "LogIngest");
    dirRow.appendChild(caret);
    dirRow.appendChild(name);

    const childrenWrap = el("div", "ms-3 mt-1");
    const dirPath = node.path || "";

    let open = expandedDirs.has(dirPath);
    childrenWrap.style.display = open ? "block" : "none";
    caret.textContent = open ? "▾" : "▸";

    dirRow.addEventListener("click", () => {
      open = !open;
      childrenWrap.style.display = open ? "block" : "none";
      caret.textContent = open ? "▾" : "▸";
      if (open) expandedDirs.add(dirPath);
      else expandedDirs.delete(dirPath);
      saveExpandedDirs(expandedDirs);
    });

    parent.appendChild(dirRow);
    parent.appendChild(childrenWrap);

    for (const child of node.children || []) {
      renderTreeNode(child, childrenWrap);
    }

    return;
  }

  const fileRow = el("div", "node file px-2 py-1 rounded");
  fileRow.textContent = node.name;
  fileRow.dataset.path = node.path;
  const lower = (node.name || "").toLowerCase();
  if (isLogFileName(node.name)) {
    fileRow.classList.add("log-file");
  } else if (lower.endsWith(".pdf")) {
    fileRow.classList.add("pdf-file");
  } else if (lower.endsWith(".txt")) {
    fileRow.classList.add("txt-file");
  } else if (lower.endsWith(".xml")) {
    fileRow.classList.add("xml-file");
  }
  fileRow.addEventListener("click", async (evt) => {
    evt.stopPropagation();
    if (lower.endsWith(".pdf")) {
      highlightSelected(fileRow);
      const url = new URL("/api/raw", window.location.origin);
      url.searchParams.set("path", node.path);
      window.open(url.toString(), "_blank", "noopener,noreferrer");
      return;
    }
    selectFile(node.path, fileRow);
  });
  parent.appendChild(fileRow);
}

function setTreeStatus(text, isError) {
  const s = document.getElementById("treeStatus");
  s.textContent = text;
  s.className = isError ? "small mt-1 text-danger" : "small mt-1 text-secondary";
}

async function loadTree() {
  setTreeStatus("Loading…", false);
  const tree = document.getElementById("fileTree");
  tree.innerHTML = "";

  const res = await fetch("/api/tree");
  if (!res.ok) {
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    const data = await res.json().catch(() => ({}));
    setTreeStatus(data.error || "Failed to load tree", true);
    return;
  }
  const data = await res.json();
  setTreeStatus("", false);
  fileTreeData = data.tree;
  renderTree();
}

function highlightSelected(row) {
  for (const n of document.querySelectorAll(".file-tree .file")) {
    n.classList.remove("active");
  }
  if (row) row.classList.add("active");
}

async function selectFile(path, row) {
  selectedPath = path;
  if (row) {
    highlightSelected(row);
  }
  document.getElementById("selectedFile").textContent = path;
  setFileActionState();
  await refreshSelectedFile();
}

async function refreshSelectedFile() {
  if (!selectedPath) return;

  const levels = Array.from(enabledLevels).join(",");
  const tail = document.getElementById("tailSwitch").checked;
  const maxLines = document.getElementById("maxLines").value;

  const url = new URL("/api/file", window.location.origin);
  url.searchParams.set("path", selectedPath);
  url.searchParams.set("levels", levels);
  url.searchParams.set("tail", String(tail));
  url.searchParams.set("maxLines", String(maxLines));

  const meta = document.getElementById("selectedFileMeta");
  const out = document.getElementById("logOutput");

  meta.textContent = "Loading…";
  out.textContent = "";

  const res = await fetch(url);
  if (!res.ok) {
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    meta.textContent = `Failed to load file (${res.status})`;
    return;
  }

  const data = await res.json();
  lastLoadedLines = data.lines || [];
  renderLogLines();
}

function renderLogLines() {
  const meta = document.getElementById("selectedFileMeta");
  const out = document.getElementById("logOutput");
  if (!meta || !out) return;

  const q = (lineSearchQuery || "").trim().toLowerCase();
  const filtered = q
    ? lastLoadedLines.filter((l) => (l.raw || "").toLowerCase().includes(q))
    : lastLoadedLines;

  // counts based on the loaded response (not the search-filtered subset)
  const counts = LEVELS.map((lvl) => {
    const c = lastLoadedLines.filter((x) => x.level === lvl).length;
    return `${lvl}:${c}`;
  }).join("  ");
  meta.textContent = `${counts} | showing ${filtered.length} line(s)`;

  out.innerHTML = filtered
    .map((l) => {
      const cls = `lvl-${l.level}`;
      return `<span class="${cls}">${escapeHtml(l.raw)}</span>`;
    })
    .join("\n");
}

function renderSummaryCounts(globalCounts) {
  const wrap = document.getElementById("summaryCounts");
  wrap.innerHTML = "";

  const row = el("div", "row g-2");
  for (const lvl of LEVELS) {
    const col = el("div", "col-6");
    const card = el("div", "p-2 border rounded bg-body-tertiary clickable-card");
    card.style.cursor = "pointer";
    const title = el("div", "small text-secondary", lvl);
    const value = el("div", "fs-5 fw-semibold", String(globalCounts[lvl] ?? 0));
    card.appendChild(title);
    card.appendChild(value);
    card.addEventListener("click", () => {
      window.location.href = `/messages?level=${encodeURIComponent(lvl)}`;
    });
    col.appendChild(card);
    row.appendChild(col);
  }
  wrap.appendChild(row);
}

function renderTopMessages(data) {
  const tbody = document.getElementById("topMessagesBody");
  tbody.innerHTML = "";
  for (const item of data) {
    const row = document.createElement("tr");
    row.style.cursor = "pointer";
    const countCell = document.createElement("td");
    countCell.textContent = item.count;
    const msgCell = document.createElement("td");
    msgCell.textContent = item.message;
    msgCell.title = item.message;
    row.appendChild(countCell);
    row.appendChild(msgCell);
    row.addEventListener("click", async () => {
      const res = await fetch("/api/first_occurrence?message=" + encodeURIComponent(item.message));
      if (!res.ok) return;
      const occ = await res.json();
      if (occ.path && occ.line) {
        await selectFile(occ.path);
        // Scroll to line after a short delay to ensure content is rendered
        setTimeout(() => scrollToLine(occ.line), 300);
      }
    });
    tbody.appendChild(row);
  }
}

function scrollToLine(lineNumber) {
  const out = document.getElementById("logOutput");
  if (!out) return;
  const lines = out.children;
  if (lineNumber > 0 && lineNumber <= lines.length) {
    const target = lines[lineNumber - 1];
    target.scrollIntoView({ block: "center" });
    // Optional: flash highlight
    target.style.backgroundColor = "rgba(255, 255, 0, 0.3)";
    setTimeout(() => {
      target.style.backgroundColor = "";
    }, 1500);
  }
}

async function searchAll() {
  const q = document.getElementById("lineSearch").value.trim();
  if (!q) return;
  const modalEl = document.getElementById("searchAllModal");
  const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
  const statusEl = document.getElementById("searchAllStatus");
  const tbody = document.getElementById("searchAllBody");
  statusEl.textContent = "Searching…";
  tbody.innerHTML = "";
  modal.show();
  const res = await fetch(`/api/search_all?q=${encodeURIComponent(q)}`);
  if (!res.ok) {
    statusEl.textContent = "Search failed.";
    return;
  }
  const data = await res.json();
  statusEl.textContent = `Found ${data.results.length} match${data.results.length === 1 ? "" : "es"} for "${data.query}"`;
  for (const item of data.results) {
    const row = document.createElement("tr");
    row.style.cursor = "pointer";
    const fileCell = document.createElement("td");
    fileCell.textContent = item.file;
    const lineCell = document.createElement("td");
    lineCell.textContent = item.line;
    const contentCell = document.createElement("td");
    contentCell.textContent = item.raw;
    row.appendChild(fileCell);
    row.appendChild(lineCell);
    row.appendChild(contentCell);
    row.addEventListener("click", () => {
      modal.hide();
      // Expand tree to the file and highlight it
      expandTreeToFile(item.file);
      // Load file and scroll to line after a short delay, using stored node if available
      setTimeout(() => {
        const node = window.__tempSelectedNode;
        selectFile(item.file, node);
        window.__tempSelectedNode = null;
        setTimeout(() => scrollToLine(item.line), 300);
      }, 200);
    });
    tbody.appendChild(row);
  }
}

function expandTreeToFile(targetPath) {
  if (!fileTreeData) return;
  const parts = targetPath.split("/");
  let current = fileTreeData;
  let accumulatedPath = "";
  for (const part of parts) {
    accumulatedPath = accumulatedPath ? `${accumulatedPath}/${part}` : part;
    if (!current.children) break;
    const found = current.children.find(child => child.name === part);
    if (!found) break;
    if (found.type === "dir") {
      expandedDirs.add(found.path || accumulatedPath);
      current = found;
    } else if (found.type === "file") {
      // Found the file; re-render tree then highlight after a delay
      saveExpandedDirs(expandedDirs);
      renderTree();
      setTimeout(() => {
        const fileNodes = document.querySelectorAll(".file-tree .file");
        for (const node of fileNodes) {
          if (node.dataset.path === targetPath) {
            // Manually apply active class and scroll into view
            for (const n of document.querySelectorAll(".file-tree .file")) {
              n.classList.remove("active");
            }
            node.classList.add("active");
            node.scrollIntoView({ block: "nearest" });
            // Store node reference to pass to selectFile
            window.__tempSelectedNode = node;
            break;
          }
        }
      }, 100);
      break;
    }
  }
}

async function refreshSummary() {
  const res = await fetch("/api/summary");
  if (!res.ok) {
    if (res.status === 401) window.location.href = "/login";
    return;
  }
  const data = await res.json();

  renderSummaryCounts(data.globalCounts || {});
  renderTopMessages(data.topMessages || []);
}

async function init() {
  const user = await ensureAuthenticated();
  if (!user) return;

  const userBadge = document.getElementById("userBadge");
  const logoutBtn = document.getElementById("logoutBtn");
  const changePasswordBtn = document.getElementById("changePasswordBtn");
  if (userBadge) {
    userBadge.textContent = user;
    userBadge.classList.remove("d-none");
  }
  if (logoutBtn) {
    logoutBtn.classList.remove("d-none");
    logoutBtn.addEventListener("click", logout);
  }
  if (changePasswordBtn) {
    changePasswordBtn.classList.remove("d-none");
    changePasswordBtn.addEventListener("click", () => {
      setChangePasswordAlert(null);
      const modalEl = document.getElementById("changePasswordModal");
      const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
      modal.show();
    });
  }

  buildLevelToggles();
  setFileActionState();
  await loadTree();
  await refreshSummary();

  document.getElementById("refreshBtn").addEventListener("click", async () => {
    await loadTree();
    await refreshSelectedFile();
  });

  document.getElementById("refreshSummaryBtn").addEventListener("click", refreshSummary);

  const exportReportBtn = document.getElementById("exportReportBtn");
  if (exportReportBtn) exportReportBtn.addEventListener("click", exportReport);
  document.getElementById("tailSwitch").addEventListener("change", refreshSelectedFile);
  document.getElementById("maxLines").addEventListener("change", refreshSelectedFile);

  const fileSearch = document.getElementById("fileSearch");
  if (fileSearch) {
    fileSearch.addEventListener("input", () => {
      fileSearchQuery = fileSearch.value || "";
      renderTree();
    });
  }

  const lineSearch = document.getElementById("lineSearch");
  if (lineSearch) {
    lineSearch.addEventListener("input", () => {
      lineSearchQuery = lineSearch.value || "";
      renderLogLines();
    });
  }

  const searchSelectedBtn = document.getElementById("searchSelectedBtn");
  if (searchSelectedBtn) {
    searchSelectedBtn.addEventListener("click", () => {
      // Trigger existing live filter behavior
      lineSearchQuery = lineSearch?.value || "";
      renderLogLines();
    });
  }

  const searchAllBtn = document.getElementById("searchAllBtn");
  if (searchAllBtn) {
    searchAllBtn.addEventListener("click", searchAll);
  }

  const uploadBtn = document.getElementById("uploadBtn");
  if (uploadBtn) uploadBtn.addEventListener("click", uploadFiles);
  const downloadBtn = document.getElementById("downloadBtn");
  if (downloadBtn) downloadBtn.addEventListener("click", downloadSelected);
  const deleteBtn = document.getElementById("deleteBtn");
  if (deleteBtn) deleteBtn.addEventListener("click", deleteSelected);

  const deleteAllBtn = document.getElementById("deleteAllBtn");
  if (deleteAllBtn) deleteAllBtn.addEventListener("click", deleteAll);

  const changePasswordSaveBtn = document.getElementById("changePasswordSaveBtn");
  if (changePasswordSaveBtn) changePasswordSaveBtn.addEventListener("click", changePassword);
}

init();
