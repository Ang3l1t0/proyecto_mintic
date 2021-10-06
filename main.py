from flask import Flask
from flask import render_template

app = Flask(__name__)


@app.route('/')
def hola_mundo():
    return render_template("index.html")
