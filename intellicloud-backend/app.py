import os, logging
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

from extensions import limiter
from auth import init_firebase_app
from services.geo import load_readers
from routes.ai import ai_bp

CITY_DB = os.environ.get("GEOIP_CITY_DB", "/data/GeoLite2-City.mmdb")
ASN_DB  = os.environ.get("GEOIP_ASN_DB",  "/data/GeoLite2-ASN.mmdb")

logger = logging.getLogger(__name__)

def _load_secret_key() -> str | None:
    key = os.getenv("FLASK_SECRET_KEY")
    if key:
        return key
    path = os.getenv("FLASK_SECRET_KEY_FILE")
    if path and os.path.exists(path):
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except Exception as exc:
            logger.error("Failed to read FLASK_SECRET_KEY_FILE %s: %s", path, exc)
    return None

def create_app():
    load_dotenv()
    app = Flask(__name__)

    readers = load_readers()
    app.config["GEO_READERS"] = readers
    app.extensions["geo"] = readers

    @app.teardown_appcontext
    def _close_mmdb(exception):
        rs = app.extensions.get("geo") or app.config.get("GEO_READERS") or {}
        for r in (rs.get("city"), rs.get("asn")):
            try:
                if r:
                    r.close()
            except Exception:
                pass

    secret = _load_secret_key()
    if secret:
        app.config["SECRET_KEY"] = secret
    else:
        logger.warning("SECRET_KEY is not set. Provide FLASK_SECRET_KEY or FLASK_SECRET_KEY_FILE.")

    allowed = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if not allowed:
        allowed = [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",      
            "http://127.0.0.1:5174",
            "http://localhost:5175",
            "http://127.0.0.1:5175"
        ]

    CORS(app, resources={r"/api/*": {"origins": allowed, "supports_credentials": True}})

    try:
        init_firebase_app(app)
    except Exception as exc:
        logger.warning("Firebase init skipped/failed: %s", exc)
    try:
        limiter.init_app(app)
    except Exception as exc:
        logger.warning("Limiter init skipped/failed: %s", exc)

    from routes.threats import threats_bp
    from routes.tracker import track_bp
    from routes.collector import collector_bp
    from routes.clients import clients_bp
    from routes.traffic import bp as traffic_bp
    from routes.ops import bp as ops_bp
    from routes.audit import bp as audit_bp

    app.register_blueprint(ai_bp, url_prefix="/api")
    app.register_blueprint(threats_bp, url_prefix="/api")
    app.register_blueprint(track_bp, url_prefix="/api")
    app.register_blueprint(collector_bp, url_prefix="/api")
    app.register_blueprint(clients_bp, url_prefix="/api")
    app.register_blueprint(traffic_bp, url_prefix="/api")
    app.register_blueprint(ops_bp, url_prefix="/api")
    app.register_blueprint(audit_bp, url_prefix="/api")

    @app.route("/")
    def home():
        return {"message": "Backend is running!"}

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "bad_request", "detail": str(e)}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "unauthorized", "detail": str(e)}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "forbidden", "detail": str(e)}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(422)
    def unprocessable(e):
        return jsonify({"error": "unprocessable_entity", "detail": str(e)}), 422

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "server_error"}), 500

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
