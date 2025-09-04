import firebase_admin
from firebase_admin import credentials, auth
from functools import wraps
from models.db import get_clienty_by_api, get_db_connection
from flask import request, jsonify, g


cred = credentials.Certificate('serviceAccountKey.json')
firebase_admin.initialize_app(cred)

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
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            return jsonify({"error": "Missing API key"}), 401
        
        conn = get_db_connection()
        if not conn:
            return {"error": "Database unavailable"}, 500
        
        cur = conn.cursor()
        cur.execute("SELECT client_id, client_name FROM clients WHERE api_key = %s", (api_key,))

        client = cur.fetchone()
        cur.close()
        conn.close()

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
    
    id_token = auth_header.split("Bearer ")[1]
    decoded_token = verify_token(id_token)

    if not decoded_token:
        return None, jsonify({"error": "Invalid or expired token"}), 401
    
    return {
        "user_id": decoded_token.get('uid'),
        "role": decoded_token.get("role", "analyst") }, None, 200

def require_role(role_required):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user, error_response, status_code = authenticate_request()
            if error_response:
                return error_response, status_code
            if user.get("role") != role_required:
                return jsonify({"error": f"Forbidden: {role_required} access required"}), 403
            return f(user, *args, **kwargs)
        return wrapper
    return decorator

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0] != "Bearer":
            return jsonify({"error": "Invalid Authorizatino header format"}), 401
        
        id_token = parts[1]
        decoded_token = verify_token(id_token)
        if not decoded_token:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        user = {
            "user_id": decoded_token.get("uid"),
            "email": decoded_token.get("email"),
            "role": decoded_token.get("role", "user")
        }

        return f(user, *args, **kwargs)
    return wrapper