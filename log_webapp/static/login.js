function showError(msg) {
  const el = document.getElementById("error");
  el.textContent = msg;
  el.classList.remove("d-none");
}

async function login() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) {
    if (res.status === 401) {
      showError("Invalid username or password");
      return;
    }
    showError(`Login failed (${res.status})`);
    return;
  }

  window.location.href = "/";
}

async function register() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  const res = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) {
    if (res.status === 409) {
      showError("User already exists");
      return;
    }
    if (res.status === 400) {
      const txt = await res.text().catch(() => "");
      showError(txt || "Invalid username or password");
      return;
    }
    showError(`Registration failed (${res.status})`);
    return;
  }

  window.location.href = "/";
}

document.getElementById("loginBtn").addEventListener("click", login);
document.getElementById("registerBtn").addEventListener("click", register);

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter") login();
});

(async () => {
  const res = await fetch("/api/me");
  if (res.ok) {
    const data = await res.json();
    if (data.authenticated) window.location.href = "/";
  }
  // Hide default credentials hint if admin has changed password
  const defaultRes = await fetch("/api/admin_default");
  if (defaultRes.ok) {
    const d = await defaultRes.json();
    if (!d.is_default) {
      const hints = document.querySelectorAll(".small.text-secondary");
      for (const hint of hints) {
        if (hint.textContent.includes("Default credentials")) {
          hint.style.display = "none";
        }
      }
    }
  }
})();
