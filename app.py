from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return {
        "message": "EmailTrace backend is running",
        "status": "success"
    }


if __name__ == "__main__":
    app.run(debug=True)