from flask import Flask
from flask import render_template

app = Flask(__name__)

@app.route("/")
def hello_world():
    title = 'Список постов'
    return render_template('app.html', title=title)
