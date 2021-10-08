from flask import Flask, render_template, jsonify, request
from personas import admin, teachers, students

app = Flask(__name__)


@app.route('/')
def index():
    """Function to render index page

    Returns:
        render: returns index.html
    """
    return 'Entro a pagina principal'


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Function to render the login page

    Returns:
        render: returns login.html
    """
    return "Login's page"


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Function to render the login page

    Returns:
        render: returns register.html
    """
    return "register's page"


@app.route('/teachers')
def get_teachers():
    """Function to display the list of teachers.

    Returns:
        Json: json list of teachers.
    """
    return jsonify({"teachers": teachers})


@app.route('/students')
def get_students():
    """Function to display the list of students.

    Returns:
        Json: json list of students.
    """
    return jsonify({"students": students})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
