from flask import Flask
from flask_cors import CORS
from routes.threats import threats_bp
from routes.tracker import track_bp
from routes.collector import collector_bp
from routes.clients import clients_bp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)



app.register_blueprint(threats_bp, url_prefix="/api/threats")
app.register_blueprint(track_bp)
app. register_blueprint(collector_bp)
app.register_blueprint(clients_bp)

@app.route("/")

def home():
    return {"message": "Backend is running!"}


if __name__  == "__main__":
    app.run(debug=True)

