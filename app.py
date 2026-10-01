from pathlib import Path

from flask import Flask, jsonify

from config import Config
from config.logging_config import register_request_logging, setup_logging
from database.database import init_app as init_database
from database.results import recover_interrupted_analyses
from routes.analysis import analysis_bp
from routes.errors import register_error_handlers
from routes.reports import reports_bp
from routes.upload import upload_bp


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    setup_logging(app)
    register_request_logging(app)

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
    register_error_handlers(app)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    return app


if __name__ == "__main__":
    application = create_app()
    application.logger.info("Starting EmailTrace on http://127.0.0.1:5000")
    application.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)