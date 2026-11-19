import io
import os
import re
import sys
import ast
import json
import time
import uuid
import shlex
import shutil
import signal
import zipfile
import subprocess
import threading
import psutil
from collections import deque
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, session, send_file
from flask_socketio import SocketIO
import config

try:
    import pty
    import termios
    HAS_PTY = True
except ImportError:
    HAS_PTY = False

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

STATIC_DIR = os.path.join(config.BASE_DIR, "static")
os.makedirs(config.DATA_DIR, exist_ok=True)
os.makedirs(config.UPLOAD_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

START_TIME = time.time()

DB_FILES = {
    "database": os.path.join(config.DATA_DIR, "database.json"),
    "users": os.path.join(config.DATA_DIR, "users.json"),
    "performance": os.path.join(config.DATA_DIR, "performance.json"),
    "management": os.path.join(config.DATA_DIR, "management.json"),
}

DEFAULT_DATA = {
    "database": {"bots": {}},
    "users": {"users": {}},
    "performance": {
        "logs": [],
        "system_peaks": {"cpu": 0.0, "ram": 0.0, "max_concurrent_bots": 0}
    },
    "management": {
        "maintenance_mode": False,
        "max_bots_per_user": config.MAX_BOTS_PER_USER,
        "auto_install_deps": True,
        "ast_security_scan": True,
        "banned_user_ids": []
    }
}

db_lock = threading.RLock()
RUNNING_PROCS = {}
PROC_HANDLES = {}
BOT_TERMINALS = {}


# --- ATOMIC JSON DATABASE ENGINE ---
def init_json_dbs():
    with db_lock:
        for key, path in DB_FILES.items():
            if not os.path.exists(path):
                write_json(key, DEFAULT_DATA[key])


def read_json(key):
    with db_lock:
        path = DB_FILES[key]
        if not os.path.exists(path):
            write_json(key, DEFAULT_DATA[key])
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def write_json(key, data):
    with db_lock:
        path = DB_FILES[key]
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp_path, path)


init_json_dbs()


# --- AST SECURITY SCANNER (VPS & RDP PROTECTION) ---
BANNED_MODULES = {
    "subprocess", "ctypes", "pty", "fcntl", "resource",
    "posix", "nt", "winreg", "paramiko", "telnetlib", "ftplib"
}

BANNED_CALLS = {
    "os.system", "os.popen", "os.fork", "os.forkpty",
    "os.kill", "os.killpg", "os.chroot", "os.setuid", "os.setgid",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "shutil.rmtree"
}

BANNED_BUILTINS = {"eval", "exec", "compile", "__import__"}

DANGEROUS_STRINGS = (
    "../", "..\\", "/etc/passwd", "/etc/shadow", "/root/",
    "database.json", "users.json", "management.json", "performance.json",
    "rm -rf", ":(){ :|:& };:"
)


def scan_project_ast(bot_dir):
    mgmt = read_json("management")
    if not mgmt.get("ast_security_scan", True):
        return True, None

    for root, _, files in os.walk(bot_dir):
        for fname in files:
            if not fname.endswith(".py"):
                continue

            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, bot_dir)

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
                tree = ast.parse(source, filename=rel_path)
            except SyntaxError as e:
                return False, f"SyntaxError in {rel_path} (line {e.lineno}): {e.msg}"

            aliases = {}
            banned_names = {}

            for node in ast.walk(tree):
                line_no = getattr(node, "lineno", 0)

                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_mod = alias.name.split(".")[0]
                        if top_mod in BANNED_MODULES:
                            return False, f"{rel_path} (line {line_no}): Blocked module '{top_mod}'."
                        aliases[alias.asname or top_mod] = top_mod

                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    top_mod = node.module.split(".")[0]
                    if top_mod in BANNED_MODULES:
                        return False, f"{rel_path} (line {line_no}): Blocked module '{top_mod}'."
                    for alias in node.names:
                        full_target = f"{node.module}.{alias.name}"
                        if full_target in BANNED_CALLS:
                            banned_names[alias.asname or alias.name] = full_target

                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        fn = node.func.id
                        if fn in BANNED_BUILTINS:
                            return False, f"{rel_path} (line {line_no}): Blocked builtin '{fn}()'."
                        if fn in banned_names:
                            return False, f"{rel_path} (line {line_no}): Blocked call '{banned_names[fn]}()'."

                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        resolved_mod = aliases.get(node.func.value.id, node.func.value.id)
                        full_call = f"{resolved_mod}.{node.func.attr}"
                        if full_call in BANNED_CALLS:
                            return False, f"{rel_path} (line {line_no}): Blocked system call '{full_call}()'."

                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    lower_val = node.value.lower()
                    for pattern in DANGEROUS_STRINGS:
                        if pattern in lower_val:
                            return False, f"{rel_path} (line {line_no}): Blocked restricted path/pattern '{pattern}'."

    return True, None


# --- SAFE ZIP EXTRACTION & GITHUB FOLDER FLATTENING ---
def safe_extract_zip(zip_path, target_dir):
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            member_path = os.path.realpath(os.path.join(target_dir, member.filename))
            if not member_path.startswith(os.path.realpath(target_dir)):
                raise ValueError("Unsafe archive path blocked.")
        zf.extractall(target_dir)

    os.remove(zip_path)

    entries = [e for e in os.listdir(target_dir) if e != "__MACOSX"]
    if len(entries) == 1:
        nested_dir = os.path.join(target_dir, entries[0])
        if os.path.isdir(nested_dir):
            for item in os.listdir(nested_dir):
                shutil.move(os.path.join(nested_dir, item), os.path.join(target_dir, item))
            os.rmdir(nested_dir)


# --- AUTOMATIC MODULE & REQUIREMENT INSTALLER ---
STDLIB_MODULES = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
    "os", "sys", "re", "json", "time", "math", "random", "datetime", "asyncio",
    "logging", "threading", "subprocess", "shutil", "pathlib", "typing", "io",
    "base64", "hashlib", "urllib", "http", "collections", "itertools", "functools",
    "sqlite3", "glob", "signal", "inspect", "traceback", "uuid", "platform"
}

IMPORT_MAP = {
    "telethon": "telethon",
    "pyrogram": "pyrogram",
    "tgcrypto": "TgCrypto",
    "PIL": "Pillow",
    "cv2": "opencv-python-headless",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "yaml": "PyYAML",
    "motor": "motor",
    "pymongo": "pymongo",
    "aiohttp": "aiohttp",
    "requests": "requests",
    "yt_dlp": "yt-dlp",
    "gtts": "gTTS",
    "pytz": "pytz",
    "psutil": "psutil",
    "telegraph": "telegraph",
    "speedtest": "speedtest-cli",
    "uvloop": "uvloop",
    "aiofiles": "aiofiles",
    "httpx": "httpx"
}


def emit_log_line(bot_id, log_path, line):
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(line)
        log.flush()
    socketio.emit("bot_terminal", {"bot_id": bot_id, "chunk": line})


def auto_install_requirements(bot_id, bot_dir, log_path):
    mgmt = read_json("management")
    if not mgmt.get("auto_install_deps", True):
        return

    emit_log_line(bot_id, log_path, f"[{datetime.now().strftime('%H:%M:%S')}] Scanning userbot dependencies...\n")

    for root, _, files in os.walk(bot_dir):
        if "requirements.txt" in files:
            req_path = os.path.join(root, "requirements.txt")
            emit_log_line(bot_id, log_path, f"[PIP] Installing {os.path.relpath(req_path, bot_dir)}...\n")
            with open(log_path, "a", encoding="utf-8") as log:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", req_path, "--quiet"],
                    stdout=log, stderr=log
                )

    local_modules = set()
    detected_pkgs = set()

    for root, dirs, files in os.walk(bot_dir):
        for file in files:
            if file.endswith(".py"):
                local_modules.add(file[:-3])
        for d in dirs:
            local_modules.add(d)

    for root, _, files in os.walk(bot_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                source = ""
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        source = f.read()
                    tree = ast.parse(source, filename=file)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                top = alias.name.split(".")[0]
                                if top not in STDLIB_MODULES and top not in local_modules:
                                    detected_pkgs.add(IMPORT_MAP.get(top, top))
                        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                            top = node.module.split(".")[0]
                            if top not in STDLIB_MODULES and top not in local_modules:
                                detected_pkgs.add(IMPORT_MAP.get(top, top))
                except Exception:
                    matches = re.findall(r"^\s*(?:import|from)\s+([a-zA-Z0-9_]+)", source, re.MULTILINE)
                    for mod in matches:
                        if mod not in STDLIB_MODULES and mod not in local_modules:
                            detected_pkgs.add(IMPORT_MAP.get(mod, mod))

    for pkg in sorted(detected_pkgs):
        try:
            __import__(pkg.lower().replace("-", "_"))
        except ImportError:
            emit_log_line(bot_id, log_path, f"[AUTO-PIP] Installing missing module: {pkg}...\n")
            with open(log_path, "a", encoding="utf-8") as log:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                    stdout=log, stderr=log
                )

    emit_log_line(bot_id, log_path, "[SYSTEM] Dependencies verified. Starting interactive terminal...\n")


# --- REAL-TIME PTY / PIPE STREAM READER ---
def stream_pty_reader(bot_id, master_fd, log_path):
    try:
        with open(log_path, "a", encoding="utf-8", errors="replace") as log_fp:
            while True:
                try:
                    data = os.read(master_fd, 1024)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
                    log_fp.write(text)
                    log_fp.flush()
                    socketio.emit("bot_terminal", {"bot_id": bot_id, "chunk": text})
                except OSError:
                    break
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
        BOT_TERMINALS.pop(bot_id, None)


def stream_pipe_reader(bot_id, pipe_stream, log_path):
    try:
        with open(log_path, "a", encoding="utf-8", errors="replace") as log_fp:
            while True:
                data = pipe_stream.read(256)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
                log_fp.write(text)
                log_fp.flush()
                socketio.emit("bot_terminal", {"bot_id": bot_id, "chunk": text})
    finally:
        BOT_TERMINALS.pop(bot_id, None)


# --- MULTI-PROCESS LAUNCHER WITH AST CHECK & INTERACTIVE PTY ---
def launch_bot_process(bot_id):
    db = read_json("database")
    bot = db["bots"].get(bot_id)
    if not bot:
        return

    bot_dir = bot["dir"]
    log_path = bot["log_path"]
    run_target = bot["entry_file"]

    if not os.path.exists(bot_dir):
        bot["status"] = "ERROR: Files Missing"
        write_json("database", db)
        return

    is_safe, ast_err = scan_project_ast(bot_dir)
    if not is_safe:
        emit_log_line(bot_id, log_path, f"[AST BLOCKED] {ast_err}\n")
        bot["status"] = "BLOCKED (AST)"
        write_json("database", db)
        return

    auto_install_requirements(bot_id, bot_dir, log_path)

    proc_env = os.environ.copy()
    proc_env["PYTHONUNBUFFERED"] = "1"
    proc_env["TERM"] = "xterm"
    env_file = os.path.join(bot_dir, ".env")
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as ef:
            for line in ef:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    proc_env[k.strip()] = v.strip().strip('"').strip("'")

    if run_target.startswith("-m "):
        cmd = [sys.executable, "-u"] + shlex.split(run_target)
    else:
        cmd = [sys.executable, "-u", run_target]

    if HAS_PTY:
        master_fd, slave_fd = pty.openpty()
        try:
            attrs = termios.tcgetattr(slave_fd)
            attrs[3] = attrs[3] & ~termios.ECHO
            termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
        except Exception:
            pass

        proc = subprocess.Popen(
            cmd,
            cwd=bot_dir,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            start_new_session=True,
            env=proc_env
        )
        os.close(slave_fd)
        BOT_TERMINALS[bot_id] = {"type": "pty", "fd": master_fd, "proc": proc}
        threading.Thread(target=stream_pty_reader, args=(bot_id, master_fd, log_path), daemon=True).start()
    else:
        proc = subprocess.Popen(
            cmd,
            cwd=bot_dir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            env=proc_env
        )
        BOT_TERMINALS[bot_id] = {"type": "pipe", "fd": None, "proc": proc}
        threading.Thread(target=stream_pipe_reader, args=(bot_id, proc.stdout, log_path), daemon=True).start()

    RUNNING_PROCS[bot_id] = proc

    db = read_json("database")
    if bot_id in db["bots"]:
        db["bots"][bot_id]["pid"] = proc.pid
        db["bots"][bot_id]["status"] = "RUNNING"
        db["bots"][bot_id]["started_at"] = time.time()
        write_json("database", db)


def recover_running_bots():
    db = read_json("database")
    for bot_id, info in db["bots"].items():
        if info.get("status") in ("RUNNING", "INSTALLING") and os.path.exists(info.get("dir", "")):
            threading.Thread(target=launch_bot_process, args=(bot_id,), daemon=True).start()


# --- NON-BLOCKING REAL-TIME TELEMETRY WORKER ---
def telemetry_worker():
    psutil.cpu_percent(interval=None)
    perf = read_json("performance")
    history_buf = deque(perf.get("logs", [])[-40:], maxlen=40)
    peaks = perf.get("system_peaks", {"cpu": 0.0, "ram": 0.0, "max_concurrent_bots": 0})
    tick_counter = 0

    while True:
        try:
            sys_cpu = psutil.cpu_percent(interval=None)
            sys_ram = psutil.virtual_memory().percent

            db = read_json("database")
            bot_metrics = {}
            changed = False

            for bot_id, info in list(db["bots"].items()):
                pid = info.get("pid")
                if pid and psutil.pid_exists(pid):
                    try:
                        proc = PROC_HANDLES.get(pid)
                        if proc is None:
                            proc = psutil.Process(pid)
                            proc.cpu_percent(interval=None)
                            PROC_HANDLES[pid] = proc

                        if proc.status() == psutil.STATUS_ZOMBIE:
                            raise psutil.NoSuchProcess(pid)

                        cpu = round(proc.cpu_percent(interval=None), 1)
                        ram_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
                        info["cpu"] = cpu
                        info["ram_mb"] = ram_mb
                        info["status"] = "RUNNING"
                        bot_metrics[bot_id] = {
                            "owner_id": info["owner_id"],
                            "bot_name": info["bot_name"],
                            "cpu": cpu,
                            "ram_mb": ram_mb,
                            "status": "RUNNING"
                        }
                        changed = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        PROC_HANDLES.pop(pid, None)
                        if info["status"] == "RUNNING":
                            info["status"] = "STOPPED"
                            info["pid"] = None
                            info["cpu"] = 0.0
                            info["ram_mb"] = 0.0
                            changed = True
                else:
                    if pid:
                        PROC_HANDLES.pop(pid, None)
                    if info["status"] == "RUNNING":
                        info["status"] = "STOPPED"
                        info["pid"] = None
                        info["cpu"] = 0.0
                        info["ram_mb"] = 0.0
                        changed = True

            if changed:
                write_json("database", db)

            active_count = len(bot_metrics)
            if sys_cpu > peaks["cpu"]:
                peaks["cpu"] = sys_cpu
            if sys_ram > peaks["ram"]:
                peaks["ram"] = sys_ram
            if active_count > peaks.get("max_concurrent_bots", 0):
                peaks["max_concurrent_bots"] = active_count

            history_buf.append({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "sys_cpu": sys_cpu,
                "sys_ram": sys_ram,
                "active_bots": active_count
            })

            tick_counter += 1
            if tick_counter >= 15:
                write_json("performance", {"logs": list(history_buf), "system_peaks": peaks})
                tick_counter = 0

            socketio.emit("telemetry_update", {
                "sys_cpu": sys_cpu,
                "sys_ram": sys_ram,
                "peaks": peaks,
                "bots": bot_metrics,
                "history": list(history_buf)
            })
        except Exception as e:
            print("Telemetry worker error:", e)
        time.sleep(2)


# --- ROUTES: HEALTH, RANGE-ENABLED BGM STREAMING & USER-ID AUTH ---
@app.route("/health")
def health():
    return jsonify({"ok": True, "uptime": int(time.time() - START_TIME)})


AUDIO_EXTS = (".mp3", ".m4a", ".mp4", ".ogg", ".wav")


@app.route("/bgm")
def serve_bgm():
    for folder in (STATIC_DIR, config.BASE_DIR):
        if not os.path.isdir(folder):
            continue
        for ext in AUDIO_EXTS:
            preferred = os.path.join(folder, f"bgm{ext}")
            if os.path.exists(preferred):
                return send_file(preferred, conditional=True)
        for fname in sorted(os.listdir(folder)):
            if fname.lower().endswith(AUDIO_EXTS):
                return send_file(os.path.join(folder, fname), conditional=True)

    # Fallback: check if user uploaded an audio file into uploads/
    for root, _, files in os.walk(config.UPLOAD_DIR):
        for fname in sorted(files):
            if fname.lower().endswith(AUDIO_EXTS):
                return send_file(os.path.join(root, fname), conditional=True)

    return jsonify({"ok": False, "error": "No audio file found. Upload an MP3 via Hashira Panel or static/bgm.mp3."}), 404


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    user_id = str(data.get("user_id", "")).strip()
    owner_key = str(data.get("owner_key", "")).strip()

    if not user_id or not user_id.isdigit():
        return jsonify({"ok": False, "error": "Enter a valid numeric Telegram User ID."}), 400

    mgmt = read_json("management")
    if user_id in mgmt.get("banned_user_ids", []):
        return jsonify({"ok": False, "error": "This Telegram User ID is suspended."}), 403

    is_owner = (user_id == config.OWNER_USER_ID and owner_key == config.OWNER_SECRET_KEY)

    users_db = read_json("users")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if user_id not in users_db["users"]:
        users_db["users"][user_id] = {
            "user_id": user_id,
            "joined_at": now_str,
            "last_login": now_str,
            "role": "OWNER" if is_owner else "USER"
        }
    else:
        users_db["users"][user_id]["last_login"] = now_str
        if is_owner:
            users_db["users"][user_id]["role"] = "OWNER"

    write_json("users", users_db)
    os.makedirs(os.path.join(config.UPLOAD_DIR, user_id), exist_ok=True)

    session["user_id"] = user_id
    session["is_owner"] = is_owner
    return jsonify({"ok": True, "user_id": user_id, "is_owner": is_owner})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"authenticated": False})

    users_db = read_json("users")
    mgmt = read_json("management")
    user_info = users_db["users"].get(user_id, {})
    return jsonify({
        "authenticated": True,
        "user_id": user_id,
        "joined_at": user_info.get("joined_at", "N/A"),
        "max_bots": mgmt.get("max_bots_per_user", config.MAX_BOTS_PER_USER),
        "is_owner": session.get("is_owner", False)
    })


# --- ROUTES: DEPLOY (WITH AST SCAN), INTERACTIVE STDIN, LOGS & SETTINGS ---
@app.route("/api/deploy", methods=["POST"])
def deploy_bot():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Session expired. Please enter your User ID again."}), 401

    mgmt = read_json("management")
    if mgmt.get("maintenance_mode") and not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Platform is in maintenance mode."}), 503

    db = read_json("database")
    user_bots = [b for b in db["bots"].values() if b["owner_id"] == user_id]
    if len(user_bots) >= mgmt.get("max_bots_per_user", config.MAX_BOTS_PER_USER) and not session.get("is_owner"):
        return jsonify({"ok": False, "error": f"Maximum limit of {mgmt.get('max_bots_per_user')} userbots reached."}), 400

    bot_name = request.form.get("bot_name", "TelegramUserbot").strip()
    entry_file = request.form.get("entry_file", "main.py").strip()
    env_vars_raw = request.form.get("env_vars", "").strip()
    uploaded_files = request.files.getlist("files")

    if not uploaded_files or not any(f.filename for f in uploaded_files):
        return jsonify({"ok": False, "error": "Select at least one .py, .session, or .zip file."}), 400

    bot_id = f"ub_{uuid.uuid4().hex[:8]}"
    bot_dir = os.path.join(config.UPLOAD_DIR, user_id, bot_id)
    os.makedirs(bot_dir, exist_ok=True)

    for f in uploaded_files:
        if not f.filename:
            continue
        safe_name = secure_filename(os.path.basename(f.filename))
        if not safe_name:
            continue
        save_path = os.path.join(bot_dir, safe_name)
        f.save(save_path)
        if safe_name.lower().endswith(".zip"):
            try:
                safe_extract_zip(save_path, bot_dir)
            except Exception as e:
                shutil.rmtree(bot_dir, ignore_errors=True)
                return jsonify({"ok": False, "error": f"ZIP extraction failed: {e}"}), 400

    is_safe, ast_error = scan_project_ast(bot_dir)
    if not is_safe:
        shutil.rmtree(bot_dir, ignore_errors=True)
        return jsonify({"ok": False, "error": f"Security Scan Rejected Upload — {ast_error}"}), 400

    if not entry_file.startswith("-m "):
        if not os.path.exists(os.path.join(bot_dir, entry_file)):
            candidates = ["main.py", "bot.py", "run.py", "app.py", "start.py", "__main__.py"]
            found = next((c for c in candidates if os.path.exists(os.path.join(bot_dir, c))), None)
            if not found:
                py_files = [f for f in os.listdir(bot_dir) if f.endswith(".py")]
                found = py_files[0] if py_files else None
            if found:
                entry_file = found
            else:
                shutil.rmtree(bot_dir, ignore_errors=True)
                return jsonify({"ok": False, "error": "No executable .py file found inside upload."}), 400

    if env_vars_raw:
        with open(os.path.join(bot_dir, ".env"), "w", encoding="utf-8") as ef:
            ef.write(env_vars_raw)

    stored_files = []
    for root, _, files in os.walk(bot_dir):
        for fn in files:
            stored_files.append(os.path.relpath(os.path.join(root, fn), bot_dir))

    log_path = os.path.join(bot_dir, "runtime.log")
    db["bots"][bot_id] = {
        "bot_id": bot_id,
        "bot_name": bot_name,
        "owner_id": user_id,
        "entry_file": entry_file,
        "files": stored_files,
        "dir": bot_dir,
        "log_path": log_path,
        "status": "INSTALLING",
        "pid": None,
        "cpu": 0.0,
        "ram_mb": 0.0,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "started_at": time.time()
    }
    write_json("database", db)

    threading.Thread(target=launch_bot_process, args=(bot_id,), daemon=True).start()
    return jsonify({"ok": True, "bot_id": bot_id, "bot_name": bot_name})


@app.route("/api/bot/<bot_id>/stdin", methods=["POST"])
def send_bot_stdin(bot_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = read_json("database")
    bot = db["bots"].get(bot_id)
    if not bot or (bot["owner_id"] != user_id and not session.get("is_owner")):
        return jsonify({"ok": False, "error": "Access denied"}), 403

    term = BOT_TERMINALS.get(bot_id)
    if not term:
        return jsonify({"ok": False, "error": "Userbot terminal is not currently running. Start or Restart it first."}), 400

    data = request.json or {}
    if data.get("ctrl_c"):
        try:
            if term["type"] == "pty" and term["fd"] is not None:
                os.write(term["fd"], b"\x03")
            elif term.get("proc"):
                term["proc"].send_signal(signal.SIGINT)
            emit_log_line(bot_id, bot["log_path"], "\n^C\n")
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    user_input = str(data.get("input", ""))
    is_secret = bool(data.get("is_secret", False))
    payload = (user_input + "\n").encode("utf-8")

    try:
        if term["type"] == "pty" and term["fd"] is not None:
            os.write(term["fd"], payload)
        elif term.get("proc") and term["proc"].stdin:
            term["proc"].stdin.write(payload)
            term["proc"].stdin.flush()
        else:
            return jsonify({"ok": False, "error": "Stdin pipe closed."}), 400

        masked_echo = "••••••••" if is_secret else user_input
        emit_log_line(bot_id, bot["log_path"], f"\n> {masked_echo}\n")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to send input: {e}"}), 500


@app.route("/api/my-bots")
def my_bots():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = read_json("database")
    owned = [b for b in db["bots"].values() if b["owner_id"] == user_id]
    return jsonify({"ok": True, "bots": owned})


@app.route("/api/bot/<bot_id>/settings", methods=["GET", "POST"])
def bot_settings(bot_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = read_json("database")
    bot = db["bots"].get(bot_id)
    if not bot or (bot["owner_id"] != user_id and not session.get("is_owner")):
        return jsonify({"ok": False, "error": "Access denied"}), 403

    env_path = os.path.join(bot["dir"], ".env")
    if request.method == "GET":
        env_content = ""
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
                env_content = f.read()
        return jsonify({
            "ok": True,
            "bot_name": bot["bot_name"],
            "entry_file": bot["entry_file"],
            "env_vars": env_content
        })

    data = request.json or {}
    if data.get("bot_name"):
        bot["bot_name"] = data["bot_name"].strip()
    if data.get("entry_file"):
        bot["entry_file"] = data["entry_file"].strip()
    if "env_vars" in data:
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(data["env_vars"])

    write_json("database", db)
    return jsonify({"ok": True})


@app.route("/api/bot/<bot_id>/logs")
def get_bot_logs(bot_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = read_json("database")
    bot = db["bots"].get(bot_id)
    if not bot or (bot["owner_id"] != user_id and not session.get("is_owner")):
        return jsonify({"ok": False, "error": "Access denied"}), 403

    if os.path.exists(bot["log_path"]):
        with open(bot["log_path"], "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-180:]
        return jsonify({"ok": True, "logs": "".join(lines), "bot_name": bot["bot_name"]})
    return jsonify({"ok": True, "logs": "Terminal ready. Waiting for output...\n", "bot_name": bot["bot_name"]})


@app.route("/api/bot/<bot_id>/action", methods=["POST"])
def bot_action(bot_id):
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    action = (request.json or {}).get("action")
    db = read_json("database")
    bot = db["bots"].get(bot_id)

    if not bot or (bot["owner_id"] != user_id and not session.get("is_owner")):
        return jsonify({"ok": False, "error": "Access denied"}), 403

    pid = bot.get("pid")
    if action in ("stop", "restart", "terminate"):
        term = BOT_TERMINALS.pop(bot_id, None)
        if term and term.get("type") == "pty" and term.get("fd") is not None:
            try:
                os.close(term["fd"])
            except OSError:
                pass
        if pid and psutil.pid_exists(pid):
            try:
                parent = psutil.Process(pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except Exception:
                pass
        PROC_HANDLES.pop(pid, None)
        bot["pid"] = None
        bot["status"] = "STOPPED"
        bot["cpu"] = 0.0
        bot["ram_mb"] = 0.0
        write_json("database", db)

    if action in ("start", "restart"):
        bot["status"] = "INSTALLING"
        write_json("database", db)
        threading.Thread(target=launch_bot_process, args=(bot_id,), daemon=True).start()

    if action == "terminate":
        shutil.rmtree(bot["dir"], ignore_errors=True)
        del db["bots"][bot_id]
        write_json("database", db)

    return jsonify({"ok": True})


# --- ROUTES: OWNER MASTER CONTROL, BGM UPLOAD & JSON EXPORT ---
@app.route("/api/owner/upload-bgm", methods=["POST"])
def owner_upload_bgm():
    if not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Owner privileges required."}), 403

    f = request.files.get("bgm")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "Please select an .mp3 audio file."}), 400

    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in AUDIO_EXTS:
        return jsonify({"ok": False, "error": "Supported formats: .mp3, .m4a, .mp4, .ogg, .wav"}), 400

    for old in os.listdir(STATIC_DIR):
        if old.lower().startswith("bgm."):
            os.remove(os.path.join(STATIC_DIR, old))

    save_path = os.path.join(STATIC_DIR, f"bgm{ext}")
    f.save(save_path)
    return jsonify({"ok": True})


@app.route("/api/owner/overview")
def owner_overview():
    if not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Owner privileges required."}), 403

    db = read_json("database")
    users_db = read_json("users")
    perf = read_json("performance")
    mgmt = read_json("management")

    banned_set = set(mgmt.get("banned_user_ids", []))
    user_summary = []
    for uid, udata in users_db["users"].items():
        hosted_count = sum(1 for b in db["bots"].values() if b["owner_id"] == uid)
        running_count = sum(1 for b in db["bots"].values() if b["owner_id"] == uid and b["status"] == "RUNNING")
        user_summary.append({
            "user_id": uid,
            "hosted_count": hosted_count,
            "running_count": running_count,
            "last_login": udata.get("last_login", "N/A"),
            "banned": uid in banned_set
        })

    return jsonify({
        "ok": True,
        "users": user_summary,
        "all_bots": list(db["bots"].values()),
        "performance": perf,
        "management": mgmt
    })


@app.route("/api/owner/management", methods=["POST"])
def owner_update_management():
    if not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Owner privileges required."}), 403

    data = request.json or {}
    mgmt = read_json("management")

    if "maintenance_mode" in data:
        mgmt["maintenance_mode"] = bool(data["maintenance_mode"])
    if "auto_install_deps" in data:
        mgmt["auto_install_deps"] = bool(data["auto_install_deps"])
    if "ast_security_scan" in data:
        mgmt["ast_security_scan"] = bool(data["ast_security_scan"])
    if "max_bots_per_user" in data:
        mgmt["max_bots_per_user"] = max(1, int(data["max_bots_per_user"]))
    if "toggle_ban_user_id" in data:
        target_uid = str(data["toggle_ban_user_id"]).strip()
        banned = set(mgmt.get("banned_user_ids", []))
        if target_uid in banned:
            banned.remove(target_uid)
        else:
            banned.add(target_uid)
        mgmt["banned_user_ids"] = list(banned)

    write_json("management", mgmt)
    return jsonify({"ok": True, "management": mgmt})


@app.route("/api/owner/download-all")
def owner_download_all():
    if not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Owner privileges required."}), 403

    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for folder in (config.DATA_DIR, config.UPLOAD_DIR):
            for root, _, files in os.walk(folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, config.BASE_DIR)
                    zf.write(full_path, rel_path)
    mem_zip.seek(0)

    return send_file(
        mem_zip,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"siduser_full_backup_{int(time.time())}.zip"
    )


@app.route("/api/owner/download-json/<db_name>")
def owner_download_single_json(db_name):
    if not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Owner privileges required."}), 403
    if db_name not in DB_FILES:
        return jsonify({"ok": False, "error": "Invalid JSON database name."}), 404
    return send_file(DB_FILES[db_name], as_attachment=True, download_name=f"{db_name}.json")


threading.Thread(target=telemetry_worker, daemon=True).start()
threading.Thread(target=recover_running_bots, daemon=True).start()

if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=config.PORT,
        debug=False,
        allow_unsafe_werkzeug=True
    )
