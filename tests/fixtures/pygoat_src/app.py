"""Simulated vulnerable Python application for testing."""
import requests
import flask
from flask import Flask, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/")
def index():
    """Home page."""
    response = requests.get("https://api.example.com/data")
    return render_template("index.html", data=response.json())


@app.route("/upload", methods=["POST"])
def upload():
    """File upload endpoint."""
    f = request.files["file"]
    filename = secure_filename(f.filename)
    f.save(f"/uploads/{filename}")
    return "Uploaded"


if __name__ == "__main__":
    app.run(debug=True)
