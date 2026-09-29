import os
import sys
from flask import Flask

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(PROJECT_ROOT, "uploads")
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Persisted rather than regenerated per-process so a debug-mode auto-reload
# (or a normal restart) doesn't invalidate every logged-in session.
_secret_key_path = os.path.join(PROJECT_ROOT, "instance", ".secret_key")
os.makedirs(os.path.dirname(_secret_key_path), exist_ok=True)
if not os.path.isfile(_secret_key_path):
    with open(_secret_key_path, "wb") as f:
        f.write(os.urandom(32))
with open(_secret_key_path, "rb") as f:
    app.secret_key = f.read()

from db.database import init_db
init_db()

from web.auth import register_auth
register_auth(app)

from web.routes import register_routes
register_routes(app)

from web.management_routes import register_management_routes
register_management_routes(app)

from web.help_routes import register_help_routes
register_help_routes(app)

from core.retention_scheduler import start_background_checker
start_background_checker(PROJECT_ROOT)

if __name__ == "__main__":
    print("="*60)
    print("[SERVER] IAI (Investigate with AI) Platform Server Starting...")
    print("[SERVER] Dashboard URL: http://127.0.0.1:5000/")
    print("="*60)
    app.run(host="0.0.0.0", port=5000, debug=True)
