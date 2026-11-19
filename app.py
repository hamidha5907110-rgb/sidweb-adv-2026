import os
import re
import sys
import json
import time
import uuid
import shutil
import zipfile
import subprocess
import threading
import psutil
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, send_file
from flask_socketio import SocketIO
import config

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

os.makedirs(config.DATA_DIR, exist_ok=True)
os.makedirs(config.UPLOAD_DIR, exist_ok=True)

# JSON File Paths
DB_FILES = {
    "database": os.path.join(config.DATA_DIR, "database.json"),
    "users": os.path.join(config.DATA_DIR, "users.json"),
    "performance": os.path.join(config.DATA_DIR, "performance.json"),
    "management": os.path.join(config.DATA_DIR, "management.json"),
}

DEFAULT_DATA = {
    "database": {"bots": {}},
    "users": {"users": {}},
    "performance": {"logs": [], "system_peaks": {"cpu": 0.0, "ram": 0.0}},
    "management": {
        "maintenance_mode": False,
        "max_bots_per_user": config.MAX_BOTS_PER_USER,
        "auto_install_deps": True,
        "banned_users": []
    }
}

db_lock = threading.Lock()
RUNNING_PROCS = {}  # bot_id -> subprocess.Popen


def init_json_dbs():
    for key, path in DB_FILES.items():
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_DATA[key], f, indent=4)


def read_json(key):
    with db_lock:
        with open(DB_FILES[key], "r", encoding="utf-8") as f:
            return json.load(f)


def write_json(key, data):
    with db_lock:
        with open(DB_FILES[key], "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)


init_json_dbs()


# --- AUTOMATIC MODULE & REQUIREMENT INSTALLER ---
STDLIB_MODULES = {
    "os", "sys", "re", "json", "time", "math", "random", "datetime", "asyncio",
    "logging", "threading", "subprocess", "shutil", "pathlib", "typing", "io",
    "base64", "hashlib", "urllib", "http", "collections", "itertools", "functools"
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
    "pytz": "pytz"
}


def auto_install_requirements(bot_dir, log_path):
    """Installs requirements.txt AND scans .py imports to auto-install missing packages."""
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"[{datetime.now().strftime('%H:%M:%S')}] 🔍 Scanning dependencies...\n")

        req_file = os.path.join(bot_dir, "requirements.txt")
        if os.path.exists(req_file):
            log.write("[SYSTEM] 📦 Found requirements.txt. Installing...\n")
            log.flush()
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", req_file, "--quiet"],
                stdout=log, stderr=log
            )

        # Scan all .py files for third-party imports
        detected_pkgs = set()
        for root, _, files in os.walk(bot_dir):
            for file in files:
                if file.endswith(".py"):
                    try:
                        with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        matches = re.findall(r"^\s*(?:import|from)\s+([a-zA-Z0-9_]+)", content, re.MULTILINE)
                        for mod in matches:
                            if mod not in STDLIB_MODULES and not os.path.exists(os.path.join(bot_dir, f"{mod}.py")):
                                pkg_name = IMPORT_MAP.get(mod, mod)
                                detected_pkgs.add(pkg_name)
                    except Exception:
                        pass

        for pkg in detected_pkgs:
            try:
                __import__(pkg.lower().replace("-", "_"))
            except ImportError:
                log.write(f"[AUTO-PIP] ⬇️ Installing missing module: {pkg}...\n")
                log.flush()
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                    stdout=log, stderr=log
                )
        log.write("[SYSTEM] ✅ All modules verified and ready.\n")


# --- REAL-TIME TELEMETRY BACKGROUND WORKER ---
def telemetry_worker():
    while True:
        try:
            db = read_json("database")
            perf = read_json("performance")
            sys_cpu = psutil.cpu_percent(interval=0.5)
            sys_ram = psutil.virtual_memory().percent

            if sys_cpu > perf["system_peaks"]["cpu"]:
                perf["system_peaks"]["cpu"] = sys_cpu
            if sys_ram > perf["system_peaks"]["ram"]:
                perf["system_peaks"]["ram"] = sys_ram

            bot_metrics = {}
            changed = False

            for bot_id, info in list(db["bots"].items()):
                pid = info.get("pid")
                if pid and psutil.pid_exists(pid):
                    try:
                        proc = psutil.Process(pid)
                        if proc.status() == psutil.STATUS_ZOMBIE:
                            raise psutil.NoSuchProcess(pid)
                        cpu = round(proc.cpu_percent(interval=0.1), 1)
                        ram_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
                        uptime_sec = int(time.time() - info.get("started_at", time.time()))
                        info["cpu"] = cpu
                        info["ram_mb"] = ram_mb
                        info["status"] = "RUNNING"
                        bot_metrics[bot_id] = {
                            "owner": info["owner"],
                            "cpu": cpu,
                            "ram_mb": ram_mb,
                            "uptime": uptime_sec,
                            "status": "RUNNING"
                        }
                        changed = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        if info["status"] == "RUNNING":
                            info["status"] = "STOPPED"
                            info["pid"] = None
                            info["cpu"] = 0.0
                            info["ram_mb"] = 0.0
                            changed = True
                else:
                    if info["status"] == "RUNNING":
                        info["status"] = "STOPPED"
                        info["pid"] = None
                        changed = True

            if changed:
                write_json("database", db)

            perf["logs"].append({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "sys_cpu": sys_cpu,
                "sys_ram": sys_ram,
                "active_bots": len(bot_metrics)
            })
            perf["logs"] = perf["logs"][-40:]  # Keep last 40 data points
            write_json("performance", perf)

            socketio.emit("telemetry_update", {
                "sys_cpu": sys_cpu,
                "sys_ram": sys_ram,
                "bots": bot_metrics,
                "history": perf["logs"]
            })
        except Exception as e:
            print("Telemetry error:", e)
        time.sleep(2)


threading.Thread(target=telemetry_worker, daemon=True).start()


# --- AUTHENTICATION ROUTES ---
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    tg_username = data.get("tg_username", "").strip().lstrip("@").lower()
    display_name = data.get("display_name", "").strip() or tg_username
    owner_key = data.get("owner_key", "").strip()

    if not tg_username:
        return jsonify({"ok": False, "error": "Telegram username is required."}), 400

    mgmt = read_json("management")
    if tg_username in mgmt.get("banned_users", []):
        return jsonify({"ok": False, "error": "This Telegram username is suspended."}), 403

    is_owner = (tg_username == config.OWNER_USERNAME.lower() and owner_key == config.OWNER_SECRET_KEY)

    users_db = read_json("users")
    if tg_username not in users_db["users"]:
        users_db["users"][tg_username] = {
            "username": tg_username,
            "display_name": display_name,
            "joined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "role": "OWNER" if is_owner else "USER"
        }
    else:
        users_db["users"][tg_username]["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if display_name:
            users_db["users"][tg_username]["display_name"] = display_name
        if is_owner:
            users_db["users"][tg_username]["role"] = "OWNER"

    write_json("users", users_db)

    session["tg_username"] = tg_username
    session["is_owner"] = is_owner
    return jsonify({"ok": True, "username": tg_username, "is_owner": is_owner})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    username = session.get("tg_username")
    if not username:
        return jsonify({"authenticated": False})
    users_db = read_json("users")
    user_info = users_db["users"].get(username, {})
    return jsonify({
        "authenticated": True,
        "username": username,
        "display_name": user_info.get("display_name", username),
        "is_owner": session.get("is_owner", False)
    })


# --- USERBOT DEPLOYMENT & ISOLATED DASHBOARD ---
@app.route("/api/deploy", methods=["POST"])
def deploy_bot():
    username = session.get("tg_username")
    if not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    mgmt = read_json("management")
    if mgmt.get("maintenance_mode") and not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Platform is in maintenance mode."}), 503

    db = read_json("database")
    user_bots = [b for b in db["bots"].values() if b["owner"] == username]
    if len(user_bots) >= mgmt.get("max_bots_per_user", 5) and not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Maximum hosted userbot limit reached."}), 400

    bot_name = request.form.get("bot_name", "MyUserbot").strip()
    entry_file = request.form.get("entry_file", "main.py").strip()
    env_vars_raw = request.form.get("env_vars", "").strip()
    uploaded_files = request.files.getlist("files")

    if not uploaded_files:
        return jsonify({"ok": False, "error": "Please upload at least one .py or .zip file."}), 400

    bot_id = f"bot_{uuid.uuid4().hex[:8]}"
    bot_dir = os.path.join(config.UPLOAD_DIR, username, bot_id)
    os.makedirs(bot_dir, exist_ok=True)

    for f in uploaded_files:
        filename = f.filename
        if not filename:
            continue
        save_path = os.path.join(bot_dir, os.path.basename(filename))
        f.save(save_path)
        if filename.endswith(".zip"):
            with zipfile.ZipFile(save_path, "r") as zip_ref:
                zip_ref.extractall(bot_dir)
            os.remove(save_path)

    # Auto-detect entry file if default main.py isn't present
    if not os.path.exists(os.path.join(bot_dir, entry_file)):
        py_files = [f for f in os.listdir(bot_dir) if f.endswith(".py")]
        if py_files:
            entry_file = py_files[0]
        else:
            shutil.rmtree(bot_dir, ignore_errors=True)
            return jsonify({"ok": False, "error": "No executable .py file found in upload."}), 400

    # Save custom .env variables if provided
    if env_vars_raw:
        with open(os.path.join(bot_dir, ".env"), "w", encoding="utf-8") as ef:
            ef.write(env_vars_raw)

    log_path = os.path.join(bot_dir, "runtime.log")
    db["bots"][bot_id] = {
        "bot_id": bot_id,
        "bot_name": bot_name,
        "owner": username,
        "entry_file": entry_file,
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

    # Launch background installer + process runner
    threading.Thread(target=launch_bot_process, args=(bot_id,), daemon=True).start()
    return jsonify({"ok": True, "bot_id": bot_id})


def launch_bot_process(bot_id):
    db = read_json("database")
    bot = db["bots"].get(bot_id)
    if not bot:
        return

    bot_dir = bot["dir"]
    log_path = bot["log_path"]
    entry_file = bot["entry_file"]

    auto_install_requirements(bot_dir, log_path)

    # Parse .env into subprocess environment
    proc_env = os.environ.copy()
    env_file = os.path.join(bot_dir, ".env")
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as ef:
            for line in ef:
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    proc_env[k.strip()] = v.strip().strip('"').strip("'")

    log_fp = open(log_path, "a", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-u", entry_file],
        cwd=bot_dir,
        stdout=log_fp,
        stderr=log_fp,
        env=proc_env
    )
    RUNNING_PROCS[bot_id] = proc

    db = read_json("database")
    if bot_id in db["bots"]:
        db["bots"][bot_id]["pid"] = proc.pid
        db["bots"][bot_id]["status"] = "RUNNING"
        db["bots"][bot_id]["started_at"] = time.time()
        write_json("database", db)


@app.route("/api/my-bots")
def my_bots():
    """STRICT ISOLATION: Returns ONLY bots owned by the logged-in user."""
    username = session.get("tg_username")
    if not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = read_json("database")
    owned = [b for b in db["bots"].values() if b["owner"] == username]
    return jsonify({"ok": True, "bots": owned})


@app.route("/api/bot/<bot_id>/logs")
def get_bot_logs(bot_id):
    username = session.get("tg_username")
    if not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = read_json("database")
    bot = db["bots"].get(bot_id)
    if not bot or (bot["owner"] != username and not session.get("is_owner")):
        return jsonify({"ok": False, "error": "Access denied"}), 403

    if os.path.exists(bot["log_path"]):
        with open(bot["log_path"], "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-100:]
        return jsonify({"ok": True, "logs": "".join(lines)})
    return jsonify({"ok": True, "logs": "No logs available yet."})


@app.route("/api/bot/<bot_id>/action", methods=["POST"])
def bot_action(bot_id):
    username = session.get("tg_username")
    if not username:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    action = (request.json or {}).get("action")
    db = read_json("database")
    bot = db["bots"].get(bot_id)

    if not bot or (bot["owner"] != username and not session.get("is_owner")):
        return jsonify({"ok": False, "error": "Access denied"}), 403

    pid = bot.get("pid")
    if action in ("stop", "restart", "terminate"):
        if pid and psutil.pid_exists(pid):
            try:
                parent = psutil.Process(pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except Exception:
                pass
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


# --- OWNER MASTER CONTROL ROUTES ---
@app.route("/api/owner/overview")
def owner_overview():
    if not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Owner privileges required."}), 403

    db = read_json("database")
    users_db = read_json("users")
    perf = read_json("performance")
    mgmt = read_json("management")

    # Aggregate user statistics (username, display name, hosted count)
    user_summary = []
    for uname, udata in users_db["users"].items():
        hosted_count = sum(1 for b in db["bots"].values() if b["owner"] == uname)
        running_count = sum(1 for b in db["bots"].values() if b["owner"] == uname and b["status"] == "RUNNING")
        user_summary.append({
            "username": uname,
            "display_name": udata.get("display_name", uname),
            "hosted_count": hosted_count,
            "running_count": running_count,
            "last_login": udata.get("last_login", "N/A")
        })

    return jsonify({
        "ok": True,
        "users": user_summary,
        "all_bots": list(db["bots"].values()),
        "performance": perf,
        "management": mgmt
    })


@app.route("/api/owner/download-all")
def owner_download_all():
    if not session.get("is_owner"):
        return jsonify({"ok": False, "error": "Owner privileges required."}), 403

    export_zip = os.path.join(config.BASE_DIR, f"siduser_full_backup_{int(time.time())}.zip")
    with zipfile.ZipFile(export_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for folder in (config.DATA_DIR, config.UPLOAD_DIR):
            for root, _, files in os.walk(folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, config.BASE_DIR)
                    zf.write(full_path, rel_path)

    return send_file(export_zip, as_attachment=True)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
