document.getElementById("changePwForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const currentPassword = document.getElementById("currentPassword").value;
  const newPassword = document.getElementById("newPassword").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  const err = document.getElementById("changePwError");
  const ok = document.getElementById("changePwSuccess");
  err.classList.add("d-none");
  ok.classList.add("d-none");

  if (newPassword !== confirmPassword) {
    err.textContent = "New passwords do not match.";
    err.classList.remove("d-none");
    return;
  }

  const res = await fetch("/api/change_password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword, newPassword })
  });

  if (!res.ok) {
    if (res.status === 401) {
      err.textContent = "Invalid current password.";
    } else {
      const txt = await res.text().catch(() => "");
      err.textContent = txt || `Failed (${res.status})`;
    }
    err.classList.remove("d-none");
    return;
  }

  ok.classList.remove("d-none");
  setTimeout(() => {
    window.location.href = "/";
  }, 1000);
});
