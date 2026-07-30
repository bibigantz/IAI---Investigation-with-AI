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

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

from web.routes import register_routes
register_routes(app)

if __name__ == "__main__":
    print("="*60)
    print("[SERVER] IAI (Investigate with AI) Platform Server Starting...")
    print("[SERVER] Dashboard URL: http://127.0.0.1:5000/")
    print("="*60)
    app.run(host="0.0.0.0", port=5000, debug=True)
