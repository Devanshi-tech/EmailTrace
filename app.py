from pathlib import Path

from flask import Flask, jsonify

from config import Config
from database.database import init_app as init_database
from database.results import recover_interrupted_analyses
from routes.analysis import analysis_bp
from routes.reports import reports_bp
from routes.upload import upload_bp


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    for folder in (app.config["UPLOAD_FOLDER"], app.config["REPORTS_FOLDER"]):
        Path(folder).mkdir(parents=True, exist_ok=True)

    init_database(app)
    with app.app_context():
        recovered = recover_interrupted_analyses()
    if recovered:
        app.logger.warning("Marked %d interrupted analysis run(s) as failed", recovered)

    app.register_blueprint(upload_bp, url_prefix="/api")
    app.register_blueprint(analysis_bp, url_prefix="/api")
    app.register_blueprint(reports_bp, url_prefix="/api")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=Config.DEBUG)