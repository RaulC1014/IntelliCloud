from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os

from routes.threats import threats_bp
from routes.tracker import track_bp
from routes.collector import collector_bp
from routes.clients import clients_bp
from extensions import limiter

from auth import init_firebase_app

init_firebase_app()

def create_app():

    load_dotenv()

    app = Flask(__name__)
    CORS(app)

    init_firebase_app()

    limiter.init_app(app)

    allowed = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
    if not allowed:
        allowed = ["http://localhost:5173", "http://127.0.0.1:5173"]

    CORS(app, resources={r"/api/*": {"origins": allowed, "supports_credentials": True}})
    
 
    app.register_blueprint(threats_bp, url_prefix="/api/threats")
    app.register_blueprint(track_bp, url_prefix="/api/track")
    app.register_blueprint(collector_bp, url_prefix="/api/collect")
    app.register_blueprint(clients_bp, url_prefix="/api/clients")

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

if __name__  == "__main__":
    app = create_app()
    app.run(host = "0.0.0.0", port = 5000, debug = True)

