import os
import re
import json
import zipfile
import io
from datetime import datetime
import shutil
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from functools import wraps
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Tuple

from flask import Flask, abort, jsonify, redirect, request, send_file, send_from_directory, session, render_template
from werkzeug.security import check_password_hash, generate_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


APP_ROOT = Path(__file__).resolve().parent
USER_LOGS_ROOT = (APP_ROOT.parent / "User_Storage").resolve()
USERS_FILE = (APP_ROOT / "users.json").resolve()


LEVEL_NORMALIZATION = {
    "INFO": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "DEBUG": "DEBUG",
    "ERROR": "ERROR",
    "SEVERE": "SEVERE",
}

LEVELS = ["INFO", "WARNING", "DEBUG", "ERROR", "SEVERE"]

SUMMARY_EXCLUDED_SUFFIXES = {".xml", ".txt", ".pdf", ".zip"}


LOG_ROTATION_RE = re.compile(r"\.log\.(?:[1-9]|[1-9]\d)$", re.IGNORECASE)


def is_log_file(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".log"):
        return True
    return bool(LOG_ROTATION_RE.search(name))

# Common GoAnywhere formats:
# 2024-03-01 19:46:56 INFO  message
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>[A-Z]+)\s+(?P<msg>.*)$"
)

# Common Tomcat/j.u.l formats:
# INFO: message
# SEVERE: message
LEVEL_COLON_RE = re.compile(r"^(?P<level>[A-Z]+)\s*:\s*(?P<msg>.*)$")


@dataclass(frozen=True)
class ParsedLine:
    level: Optional[str]
    raw: str
    message: str

def _normalize_level(level: str) -> Optional[str]:
    return LEVEL_NORMALIZATION.get(level.strip().upper())


def parse_line(line: str) -> ParsedLine:
    stripped = line.rstrip("\n")
    m = LINE_RE.match(stripped)
    if not m:
        m2 = LEVEL_COLON_RE.match(stripped)
        if not m2:
            return ParsedLine(level=None, raw=stripped, message=stripped)
        level2 = _normalize_level(m2.group("level"))
        msg2 = (m2.group("msg") or "").strip()
        return ParsedLine(level=level2, raw=stripped, message=msg2)
    level = _normalize_level(m.group("level"))
    msg = m.group("msg").strip()
    return ParsedLine(level=level, raw=stripped, message=msg)


def iter_log_lines(path: Path, tail: bool, max_lines: int) -> Iterable[ParsedLine]:
    if not tail:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                yield parse_line(line)
        return

    buf: Deque[ParsedLine] = deque(maxlen=max_lines)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            buf.append(parse_line(line))
    yield from buf


def iter_plain_text_lines(path: Path, tail: bool, max_lines: int) -> Iterable[str]:
    if not tail:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                yield line.rstrip("\n")
        return

    buf: Deque[str] = deque(maxlen=max_lines)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            buf.append(line.rstrip("\n"))
    yield from buf


def build_tree(root: Path) -> Dict:
    def _node(p: Path) -> Dict:
        if p.is_dir():
            children = sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
            return {
                "type": "dir",
                "name": p.name,
                "path": str(p.relative_to(root)).replace("\\", "/") if p != root else "",
                "children": [_node(c) for c in children],
            }
        return {
            "type": "file",
            "name": p.name,
            "path": str(p.relative_to(root)).replace("\\", "/"),
            "size": p.stat().st_size,
        }

    return _node(root)


def parse_levels_param(levels_param: Optional[str]) -> List[str]:
    if not levels_param:
        return LEVELS
    out: List[str] = []
    for raw in levels_param.split(","):
        norm = _normalize_level(raw)
        if norm and norm in LEVELS and norm not in out:
            out.append(norm)
    return out or LEVELS


app = Flask(__name__, static_folder=str(APP_ROOT / "static"), static_url_path="/static")
app.secret_key = os.environ.get("LOG_WEBAPP_SECRET", "dev-secret-change-me")


def _load_users() -> Dict[str, Dict[str, Any]]:
    if not USERS_FILE.exists():
        default = {"admin": {"password_hash": generate_password_hash("admin")}}
        USERS_FILE.write_text(json.dumps(default, indent=2), encoding="utf-8")
        return default
    try:
        content = USERS_FILE.read_text(encoding="utf-8").strip()
        if not content:
            # File exists but is empty
            default = {"admin": {"password_hash": generate_password_hash("admin")}}
            USERS_FILE.write_text(json.dumps(default, indent=2), encoding="utf-8")
            return default
        return json.loads(content)
    except (json.JSONDecodeError, OSError):
        # File is corrupted or unreadable, recreate with default
        default = {"admin": {"password_hash": generate_password_hash("admin")}}
        USERS_FILE.write_text(json.dumps(default, indent=2), encoding="utf-8")
        return default


def _save_users(users: Dict[str, Dict[str, Any]]) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")


def _get_current_user() -> Optional[str]:
    return session.get("user")


def _user_root(username: str) -> Path:
    root = (USER_LOGS_ROOT / username).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _is_valid_username(username: str) -> bool:
    # Keep it simple: filesystem-friendly and URL-friendly.
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username))


def _is_valid_password(password: str) -> bool:
    return len(password) >= 6


def _safe_extract_zip(zip_path: Path, dest_dir: Path) -> List[str]:
    extracted: List[str] = []
    with zipfile.ZipFile(zip_path) as z:
        for member in z.infolist():
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            target = (dest_dir / name).resolve()
            if not str(target).startswith(str(dest_dir)):
                raise ValueError("zip_slip")
        z.extractall(dest_dir)

        for member in z.infolist():
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            extracted.append(name)
    return extracted


def _unzip_recursively(root_dir: Path, max_passes: int = 50) -> Dict[str, Any]:
    deleted: List[str] = []
    extracted_from: List[str] = []
    extracted_files: List[str] = []

    for _ in range(max_passes):
        zips = sorted(root_dir.rglob("*.zip"), key=lambda p: str(p).lower())
        if not zips:
            break

        for zp in zips:
            if not zp.is_file():
                continue
            rel_zip = str(zp.relative_to(root_dir)).replace("\\", "/")
            try:
                extracted = _safe_extract_zip(zp, zp.parent)
            except (OSError, zipfile.BadZipFile, ValueError):
                continue

            extracted_from.append(rel_zip)
            parent_rel = str(zp.parent.relative_to(root_dir)).replace("\\", "/")
            extracted_files.extend([
                (f"{parent_rel}/{x}").lstrip("/") if parent_rel else x.lstrip("/") for x in extracted
            ])
            try:
                zp.unlink()
                deleted.append(rel_zip)
            except OSError:
                pass

    return {"deletedZips": deleted, "unzipped": extracted_from, "extractedFiles": extracted_files}


def _safe_join_user_root(user_root: Path, rel_path: str) -> Path:
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    candidate = (user_root / rel_path).resolve()
    if not str(candidate).startswith(str(user_root)):
        raise ValueError("path_outside_user_root")
    return candidate


def login_required(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        if not _get_current_user():
            if request.path.startswith("/api/"):
                abort(401, description="not authenticated")
            return redirect("/login")
        return fn(*args, **kwargs)

    return wrapper


@app.get("/")
@login_required
def index():
    if session.get("force_password_change"):
        return redirect("/force_change_password")
    return send_from_directory(app.static_folder, "index.html")


@app.get("/login")
def login_page():
    return send_from_directory(app.static_folder, "login.html")


@app.get("/force_change_password")
@login_required
def force_change_password_page():
    return render_template("force_change_password.html")


@app.get("/api/admin_default")
def api_admin_default():
    users = _load_users()
    admin = users.get("admin", {})
    changed = admin.get("password_changed", False)
    return jsonify({"is_default": not changed})


@app.post("/api/login")
def api_login():
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        abort(400, description="username and password required")
    users = _load_users()
    entry = users.get(username)
    if not entry or not check_password_hash(entry["password_hash"], password):
        abort(401, description="invalid credentials")
    session["user"] = username
    # If admin and hasn't changed default password, flag it
    if username == "admin" and not entry.get("password_changed", False):
        session["force_password_change"] = True
    return jsonify({"ok": True, "user": username})


@app.post("/api/register")
def api_register():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    if not _is_valid_username(username):
        abort(400, description="invalid username")
    if not _is_valid_password(password):
        abort(400, description="password too short")

    users = _load_users()
    if username in users:
        abort(409, description="user already exists")

    users[username] = {"password_hash": generate_password_hash(password)}
    _save_users(users)

    session["user"] = username
    _user_root(username)
    return jsonify({"ok": True, "user": username})


@app.post("/api/logout")
def api_logout():
    session.pop("user", None)
    return jsonify({"ok": True})


@app.post("/api/change_password")
@login_required
def api_change_password():
    username = _get_current_user()
    assert username is not None

    payload = request.get_json(silent=True) or {}
    current_password = payload.get("currentPassword") or ""
    new_password = payload.get("newPassword") or ""

    if not current_password or not new_password:
        abort(400, description="missing password")
    if not _is_valid_password(new_password):
        abort(400, description="password too short")

    users = _load_users()
    user = users.get(username)
    if not user or not check_password_hash(user.get("password_hash", ""), current_password):
        abort(401, description="invalid current password")

    users[username] = {"password_hash": generate_password_hash(new_password)}
    if username == "admin":
        users[username]["password_changed"] = True
        session.pop("force_password_change", None)
    _save_users(users)
    return jsonify({"ok": True})


@app.get("/api/me")
def api_me():
    u = _get_current_user()
    return jsonify({"authenticated": bool(u), "user": u})


@app.get("/api/root")
@login_required
def api_root():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)
    return jsonify({"user": username, "root": str(root)})


@app.get("/api/tree")
@login_required
def api_tree():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)
    return jsonify({"root": str(root), "tree": build_tree(root)})


@app.get("/api/file")
@login_required
def api_file():
    rel = request.args.get("path")
    if not rel:
        abort(400, description="missing path")

    username = _get_current_user()
    assert username is not None
    root = _user_root(username)

    try:
        p = _safe_join_user_root(root, rel)
    except ValueError:
        abort(400, description="invalid path")

    if not p.exists() or not p.is_file():
        abort(404, description="file not found")

    levels = set(parse_levels_param(request.args.get("levels")))
    tail = request.args.get("tail", "true").lower() in {"1", "true", "yes"}

    try:
        max_lines = int(request.args.get("maxLines", "2000"))
    except ValueError:
        max_lines = 2000
    max_lines = max(1, min(max_lines, 20000))

    filtered: List[Dict] = []
    counts = Counter()

    # Treat .xml/.txt as plain text config files: show in viewer, but they don't have log levels.
    if p.suffix.lower() in {".xml", ".txt"}:
        for line in iter_plain_text_lines(p, tail=tail, max_lines=max_lines):
            # Use INFO so the viewer can style/render consistently.
            if "INFO" in levels:
                filtered.append({"level": "INFO", "raw": line, "message": line})
        counts["INFO"] = len(filtered)
    else:
        for pl in iter_log_lines(p, tail=tail, max_lines=max_lines):
            if pl.level:
                counts[pl.level] += 1
            if pl.level is None:
                continue
            if pl.level not in levels:
                continue
            filtered.append({"level": pl.level, "raw": pl.raw, "message": pl.message})

    return jsonify(
        {
            "path": rel,
            "fullPath": str(p),
            "tail": tail,
            "maxLines": max_lines,
            "levels": sorted(levels),
            "counts": {lvl: counts.get(lvl, 0) for lvl in LEVELS},
            "lines": filtered,
        }
    )


@app.get("/api/raw")
@login_required
def api_raw():
    rel = request.args.get("path")
    if not rel:
        abort(400, description="missing path")

    username = _get_current_user()
    assert username is not None
    root = _user_root(username)

    try:
        p = _safe_join_user_root(root, rel)
    except ValueError:
        abort(400, description="invalid path")

    if not p.exists() or not p.is_file():
        abort(404, description="file not found")

    mimetype = None
    if p.suffix.lower() == ".pdf":
        mimetype = "application/pdf"

    return send_file(p, mimetype=mimetype, as_attachment=False, download_name=p.name)


def iter_log_files(root: Path) -> Iterable[Path]:
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            yield Path(dirpath) / fn


def _compute_summary(root: Path, levels_param: Optional[str]) -> Dict[str, Any]:
    levels = set(parse_levels_param(levels_param))
    if levels_param is None:
        levels = {"ERROR", "SEVERE"}

    max_per_file = 10000
    per_file_counts: Dict[str, Dict[str, int]] = {}
    global_counts = Counter()
    top_messages = Counter()

    for f in iter_log_files(root):
        if f.suffix.lower() in SUMMARY_EXCLUDED_SUFFIXES:
            continue
        if not is_log_file(f):
            continue
        rel = str(f.relative_to(root)).replace("\\", "/")
        counts = Counter()

        try:
            for pl in iter_log_lines(f, tail=False, max_lines=max_per_file):
                if not pl.level:
                    continue
                global_counts[pl.level] += 1
                counts[pl.level] += 1

                if pl.level in levels:
                    msg = re.sub(r"\b\d+\b", "{n}", pl.message)
                    msg = re.sub(r"\b[0-9a-f]{8,}\b", "{id}", msg, flags=re.IGNORECASE)
                    top_messages[msg] += 1
        except OSError:
            continue

        if sum(counts.values()) > 0:
            per_file_counts[rel] = {lvl: counts.get(lvl, 0) for lvl in LEVELS}

    top = [{"message": m, "count": c} for m, c in top_messages.most_common(50)]
    return {
        "root": str(root),
        "levels": sorted(levels),
        "globalCounts": {lvl: global_counts.get(lvl, 0) for lvl in LEVELS},
        "perFileCounts": per_file_counts,
        "topMessages": top,
    }


@app.get("/api/summary")
@login_required
def api_summary():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)
    summary = _compute_summary(root, request.args.get("levels"))
    return jsonify(summary)


def _wrap_text(text: str, max_chars: int) -> List[str]:
    words = (text or "").split()
    if not words:
        return [""]
    lines: List[str] = []
    cur = ""
    for w in words:
        if not cur:
            cur = w
            continue
        if len(cur) + 1 + len(w) <= max_chars:
            cur = f"{cur} {w}"
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


@app.get("/api/report.pdf")
@login_required
def api_report_pdf():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)
    summary = _compute_summary(root, request.args.get("levels"))

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    y = height - 54
    c.setFont("Helvetica-Bold", 16)
    c.drawString(54, y, "Log Summary Report")

    c.setFont("Helvetica", 10)
    y -= 18
    c.drawString(54, y, f"User: {username}")
    y -= 14
    c.drawString(54, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y -= 22
    c.setFont("Helvetica-Bold", 12)
    c.drawString(54, y, "Counts")

    y -= 16
    c.setFont("Helvetica", 10)
    counts = summary.get("globalCounts", {})
    for lvl in LEVELS:
        c.drawString(54, y, f"{lvl}: {counts.get(lvl, 0)}")
        y -= 12

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(54, y, "Top Messages")

    y -= 16
    c.setFont("Helvetica", 9)
    for item in summary.get("topMessages", [])[:50]:
        msg = item.get("message", "")
        cnt = item.get("count", 0)
        header = f"[{cnt}] "
        lines = _wrap_text(msg, 95)
        if y < 72:
            c.showPage()
            y = height - 54
            c.setFont("Helvetica", 9)
        c.drawString(54, y, header + (lines[0] if lines else ""))
        y -= 12
        for cont in lines[1:]:
            if y < 72:
                c.showPage()
                y = height - 54
                c.setFont("Helvetica", 9)
            c.drawString(70, y, cont)
            y -= 12

    c.showPage()
    c.save()
    buf.seek(0)

    filename = f"log_report_{username}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=False, download_name=filename)


@app.post("/api/upload")
@login_required
def api_upload():
    if "file" not in request.files and len(request.files) == 0:
        abort(400, description="missing file")

    username = _get_current_user()
    assert username is not None
    root = _user_root(username)

    target_dir = request.form.get("dir", "")
    try:
        dest_dir = _safe_join_user_root(root, target_dir)
    except ValueError:
        abort(400, description="invalid dir")
    dest_dir.mkdir(parents=True, exist_ok=True)

    saved: List[str] = []
    for _, f in request.files.items():
        if not f.filename:
            continue
        filename = Path(f.filename).name
        dest = (dest_dir / filename).resolve()
        if not str(dest).startswith(str(root)):
            abort(400, description="invalid filename")
        f.save(dest)
        saved.append(str(dest.relative_to(root)).replace("\\", "/"))

    unzip_info = _unzip_recursively(dest_dir)
    return jsonify({"ok": True, "saved": saved, **unzip_info})


@app.delete("/api/delete")
@login_required
def api_delete():
    rel = request.args.get("path")
    if not rel:
        abort(400, description="missing path")

    username = _get_current_user()
    assert username is not None
    root = _user_root(username)

    try:
        p = _safe_join_user_root(root, rel)
    except ValueError:
        abort(400, description="invalid path")

    if not p.exists() or not p.is_file():
        abort(404, description="file not found")

    p.unlink()
    return jsonify({"ok": True})


@app.delete("/api/delete_all")
@login_required
def api_delete_all():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)

    deleted_files = 0
    deleted_dirs = 0

    for child in list(root.iterdir()):
        try:
            if child.is_file() or child.is_symlink():
                child.unlink()
                deleted_files += 1
            elif child.is_dir():
                shutil.rmtree(child)
                deleted_dirs += 1
        except OSError:
            continue

    return jsonify({"ok": True, "deletedFiles": deleted_files, "deletedDirs": deleted_dirs})


@app.get("/api/first_occurrence")
@login_required
def api_first_occurrence():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)
    message = request.args.get("message", "").strip()
    if not message:
        abort(400, description="message required")

    max_per_file = 10000
    for f in iter_log_files(root):
        if f.suffix.lower() in SUMMARY_EXCLUDED_SUFFIXES:
            continue
        if not is_log_file(f):
            continue
        try:
            line_no = 0
            for pl in iter_log_lines(f, tail=False, max_lines=max_per_file):
                line_no += 1
                if not pl.level:
                    continue
                # Normalize the message the same way as in summary
                norm = re.sub(r"\b\d+\b", "{n}", pl.message)
                norm = re.sub(r"\b[0-9a-f]{8,}\b", "{id}", norm, flags=re.IGNORECASE)
                if norm == message:
                    rel_path = str(f.relative_to(root)).replace("\\", "/")
                    return jsonify({"path": rel_path, "line": line_no})
        except OSError:
            continue
    return jsonify({"path": None, "line": None})


@app.get("/api/messages_by_level")
@login_required
def api_messages_by_level():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)
    level_param = request.args.get("level", "").strip().upper()
    if level_param not in LEVELS:
        abort(400, description="invalid level")
    max_per_file = 10000
    counter = Counter()
    for f in iter_log_files(root):
        if f.suffix.lower() in SUMMARY_EXCLUDED_SUFFIXES:
            continue
        if not is_log_file(f):
            continue
        try:
            for pl in iter_log_lines(f, tail=False, max_lines=max_per_file):
                if pl.level != level_param:
                    continue
                norm = re.sub(r"\b\d+\b", "{n}", pl.message)
                norm = re.sub(r"\b[0-9a-f]{8,}\b", "{id}", norm, flags=re.IGNORECASE)
                counter[norm] += 1
        except OSError:
            continue
    result = [{"message": m, "count": c} for m, c in counter.most_common()]
    return jsonify({"level": level_param, "messages": result})


@app.get("/messages")
@login_required
def page_messages():
    return render_template("messages.html")


@app.get("/api/search_all")
@login_required
def api_search_all():
    username = _get_current_user()
    assert username is not None
    root = _user_root(username)
    q = request.args.get("q", "").strip()
    if not q:
        abort(400, description="query required")
    q_lower = q.lower()
    max_per_file = 10000
    results = []
    for f in iter_log_files(root):
        if f.suffix.lower() in SUMMARY_EXCLUDED_SUFFIXES:
            continue
        if not is_log_file(f):
            continue
        try:
            line_no = 0
            for pl in iter_log_lines(f, tail=False, max_lines=max_per_file):
                line_no += 1
                if q_lower in pl.raw.lower():
                    rel_path = str(f.relative_to(root)).replace("\\", "/")
                    results.append({
                        "file": rel_path,
                        "line": line_no,
                        "raw": pl.raw,
                        "level": pl.level
                    })
        except OSError:
            continue
    return jsonify({"query": q, "results": results})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5177, debug=True)
