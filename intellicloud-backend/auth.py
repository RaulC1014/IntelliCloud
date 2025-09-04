import os
import firebase_admin
from firebase_admin import credentials, auth
from functools import wraps
from models.db import get_db_connection
from flask import request, jsonify, g


cred = credentials.Certificate('serviceAccountKey.json')
firebase_admin.initialize_app(cred)

def init_firebase_app():
    if firebase_admin._apps:
        return
    cred_path = os.getenv("FIREBASE_CRED_PATH","serviceAccounts/firebase-admin.json")
    if not os.path.isabs(cred_path):
        base = os.path.dirname(os.path.abspath(__file__))
        cred_path = os.path.join(base, cred_path)
    if not os.path.exists(cred_path):
        raise RuntimeError(
            f"Firebase credential not found at: {cred_path}."
            "Set FIREBASE_CRED_PATH in your .env"
        )
    project_id = os.getenv("FIREBASE_PROJECT_ID")
    opts = {"project_Id": project_id} if project_id else None
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred, opts)

def verify_token(id_token):
    """
    Verifies the firebase ID token from client
    returns the decoded token if valid, none if invalid
    """
    try:
        decoded_token = auth.verify_id_token(id_token)
        role = decoded_token.get("role", "analyst")
        decoded_token["role"] = role
        return decoded_token
    except Exception as e:
        print("Token verification failed: ", e)
        return None
    
def verify_api(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = (
            request.headers.get("X-API-Key")
            or request.header.get("x-api-key")
            or request.args.get("apu_key")
        )
        if not api_key:
            return jsonify({"error": "Missing API key"}), 401
        
        conn = get_db_connection()
        if not conn:
            return {"error": "Database unavailable"}, 500
        
        try:
            cur = conn.cursor()
            cur.execute("SELECT client_id, client_name FROM clients WHERE api_key = %s", (api_key,),
            )
            client = cur.fetchone()
        finally:
            try:
                cur.close()
                conn.close()
            except Exception:
                pass

        if not client:
            return jsonify({"error": "Invalid API key"}), 403
        
        g.client = {"client_id": client[0], "client_name": client[1]}
        return f(*args, **kwargs)
    
    return decorated_function
    
def authenticate_request():
    """
    Authenticates incoming HTTP requests using Firebase ID tokens.
    Returns (user, None, 200) if authenticated,
    or (None, error_response, status_code) if not
    """

    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return None, jsonify({"error": "Missing or invalid Authorization header"}), 401
    
    id_token = auth_header.split("Bearer ", 1)[1].strip()
    decoded_token = verify_token(id_token)

    if not decoded_token:
        return None, jsonify({"error": "Invalid or expired token"}), 401
    
    user = {
        "user_id": decoded_token.get("uid"),
        "email": decoded_token.get("email"),
        "role": decoded_token.get("role", "analyst"),
    }

    return user, None, 200

def require_role(role_required):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user, error_response, status_code = authenticate_request()
            if error_response:
                return error_response, status_code
            if user.get("role") != role_required:
                return jsonify({"error": f"Forbidden: {role_required} access required"}), 403
            request.user = user
            return f(user, *args, **kwargs)
        return wrapper
    return decorator

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization header missing"}), 401
        
        id_token = auth_header.split(" ", 1)[1].strip()
        decoded_token = verify_token(id_token)
        if not decoded_token:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        user = {
            "user_id": decoded_token.get("uid"),
            "email": decoded_token.get("email"),
            "role": decoded_token.get("role", "user")
        }

        request.user = user
        return f(user, *args, **kwargs)
    return wrapper