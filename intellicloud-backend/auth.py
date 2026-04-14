import os
from functools import wraps
from flask import request, jsonify, g
import firebase_admin
from firebase_admin import credentials, auth as fb_auth
from models.clients import get_client_by_api_key

_firebase_inited = False

def init_firebase_app(app=None):
    if os.getenv("DISABLE_FIREBASE") == "1":
        if app: app.logger.warning("Firebase disabled (DISABLE_FIREBASE=1)")
        return
    if firebase_admin._apps:
        return
    path = os.getenv("FIREBASE_CREDENTIALS_JSON")
    try:
        if path and os.path.exists(path):
            cred = credentials.Certificate(path)
        else:
            cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred)
        if app: app.logger.info("Firebase initialized")
    except Exception as e:
        if app: app.logger.error(f"Firebase init failed: {e}")
        raise

def _decode_bearer():
    """Return decoded Firebase token dict or None."""
    authz = request.headers.get("Authorization", "")
    if not authz.startswith("Bearer "):
        return None
    token = authz.split(" ", 1)[1].strip()
    try:
        init_firebase_app()
        
        return fb_auth.verify_id_token(token)
    except Exception as e:
        print("Firebase token verification failed:", e)
        return None

def require_auth(f):
    """Require a valid Firebase bearer token. Attaches request.user."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        else:
            return jsonify({"error": "unauthorized"}), 401
        
        try:
            decoded = fb_auth.verify_id_token(token)
            request.user = decoded
        except Exception:
            return jsonify({"error": "unauthorized"}), 401
        
        return f(*args, **kwargs)
    return wrapper

def require_role(required: str):
    """Require a specific role claim (defaulting to 'user' if absent)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            decoded = _decode_bearer()
            if not decoded:
                return jsonify({"error": "unauthorized"}), 401
            role = decoded.get("role", "user")
            if role != required:
                return jsonify({"error": "forbidden", "need": required, "have": role}), 403
            request.user = {
                "uid": decoded.get("uid"),
                "email": decoded.get("email"),
                "role": role,
            }
            return fn(*args, **kwargs)
        return wrapper
    return deco

def verify_api(fn):
    """
    Public API-key gate for client endpoints.
    Reads key from X-Client-Key / x-api-key header or ?api_key=.
    On success: sets g.client = {client_id, client_name, ...}
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = (
            request.headers.get("X-Client-Key")
            or request.headers.get("x-api-key")
            or request.args.get("api_key")
        )
        if not api_key:
            return jsonify({"error": "missing_api_key"}), 401

        client = get_client_by_api_key(api_key)
        if not client:
            return jsonify({"error": "invalid_api_key"}), 403

        g.client = {
            "client_id": client["client_id"],
            "client_name": client["client_name"],
            "domain": client.get("domain"),
            "created_at": client.get("created_at"),
        }
        return fn(*args, **kwargs)
    return wrapper
