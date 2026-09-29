import functools
from datetime import datetime, timezone
from flask import session, redirect, request, jsonify, render_template, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from db.database import get_session
from db.models import User

# Paths reachable with no session at all. Static assets are matched by the
# Flask endpoint name ("static"), not the URL path, so they're excluded in
# the before_request hook itself rather than listed here.
_PUBLIC_PATHS = {"/login", "/logout"}

# POST endpoints that generate a read-only download rather than mutating
# anything -- exempted from the viewer read-only gate below even though
# they're not GET requests.
_VIEWER_ALLOWED_POST_PATHS = {"/api/findings/export"}


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_session() as db_session:
        user = db_session.get(User, user_id)
        if not user:
            return None
        return {"id": user.id, "username": user.username, "role": user.role,
                "must_change_password": user.must_change_password}


def _unauthenticated_response():
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Authentication required"}), 401
    return redirect(f"/login?next={request.path}")


def _forbidden_response(message: str = "Admin access required"):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": message}), 403
    return render_template("forbidden.html", message=message), 403


def role_required(*roles):
    """Decorator for routes that need a role stricter than the global gate
    already enforces (the global gate only distinguishes logged-in vs. not,
    plus a blanket /management admin check -- this covers everything else,
    e.g. an admin-only action nested under a non-/management path)."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return _unauthenticated_response()
            if user["role"] not in roles:
                return _forbidden_response()
            return view(*args, **kwargs)
        return wrapped
    return decorator


def register_auth(app):
    @app.before_request
    def _global_auth_gate():
        if request.endpoint == "static" or request.path in _PUBLIC_PATHS:
            return None

        user = current_user()
        if not user:
            return _unauthenticated_response()

        if user["must_change_password"] and request.path not in ("/change-password",):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Password change required", "must_change_password": True}), 403
            return redirect("/change-password")

        if (request.path == "/management" or request.path.startswith("/management/")
                or request.path.startswith("/api/management/")):
            if user["role"] != "admin":
                return _forbidden_response()

        # 'viewer' is read-only, enforced globally rather than per-route:
        # any state-changing request is blocked except the account-management
        # flows every role needs (changing your own password, signing out).
        if user["role"] == "viewer" and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.path not in ("/logout", "/change-password") and request.path not in _VIEWER_ALLOWED_POST_PATHS:
                return _forbidden_response("Viewer accounts are read-only.")
        return None

    @app.context_processor
    def _inject_current_user():
        return {"current_user": current_user()}

    @app.route("/login", methods=["GET", "POST"])
    def login_page():
        if request.method == "GET":
            return render_template("login.html", error=None)

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        with get_session() as db_session:
            user = db_session.query(User).filter(User.username == username).first()
            if not user or not check_password_hash(user.password_hash, password):
                return render_template("login.html", error="Invalid username or password"), 401
            session["user_id"] = user.id

        next_path = request.args.get("next") or "/"
        return redirect(next_path)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect("/login")

    @app.route("/change-password", methods=["GET", "POST"])
    def change_password_page():
        user = current_user()
        if not user:
            return redirect("/login")
        if request.method == "GET":
            return render_template("change_password.html", error=None)

        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if len(new_password) < 8:
            return render_template("change_password.html", error="Password must be at least 8 characters."), 400
        if new_password != confirm_password:
            return render_template("change_password.html", error="Passwords do not match."), 400

        with get_session() as db_session:
            db_user = db_session.get(User, user["id"])
            db_user.password_hash = generate_password_hash(new_password)
            db_user.must_change_password = False

        return redirect("/")
