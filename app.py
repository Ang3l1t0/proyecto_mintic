from flask import Flask, render_template, jsonify, request
from bd_personas import admin, students, teachers

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

# Teachers


@app.route('/teachers')
def get_teachers():
    """Function to display the list of teachers.

    Returns:
        Json: json list of teachers.
    """
    return jsonify({"teachers": teachers})


@app.route('/teachers/<int:id>')
def get_teacher(id):
    """Function to get a teacher by id.

    Args:
        id (int): number of id assigned to each teacher.

    Returns:
        json: json response with teacher data if exists. Otherwise give a string error message.
    """
    lst_teachers = [teacher for teacher in teachers if teacher['id'] == id]
    if len(lst_teachers) > 0:
        return jsonify({"teacher": lst_teachers})
    return jsonify({"message": "The teacher with id {} is not available".format(id)})


@app.route('/teachers', methods=['POST'])
def add_teacher():
    """Fuction to add a teacher

    Returns:
        json: returns a json with name of the teacher that was added and the list of all teachers
    """
    teacher = request.json
    teachers.append(teacher)
    return jsonify({"message": "The teacher {} {} was added successfully".format(teacher["name"], teacher["last_name"])}, {"teachers": teachers})


@app.route('/teachers/<int:id>', methods=['PUT'])
def update_teacher(id):
    """Function to update a teacher.

    Args:
        id (int): id number assigned to each teacher. 

    Returns:
        json: json response with teacher's name, last_name and id if it exists. Otherwise a message with not found response. 
    """
    lst_teachers = [teacher for teacher in teachers if teacher["id"] == id]
    if len(lst_teachers) > 0:
        teacher = lst_teachers[0]
        teacher["cc"] = request.json["cc"]
        teacher["user"] = request.json["user"]
        teacher["password"] = request.json["password"]
        teacher["name"] = request.json["name"]
        teacher["last_name"] = request.json["last_name"]
        teacher["age"] = request.json["age"]
        teacher["email"] = request.json["email"]
        teacher["subjects"] = request.json["subjects"]
        return jsonify({"message": "teacher {} {} with id {} was correctly updated.".format(teacher["name"], teacher["last_name"], teacher["id"])})
    return jsonify({"message": "teacher with id {} was not found"})


@app.route('/teachers/<int:id>', methods=['DELETE'])
def delete_teacher(id):
    lst_teachers = [teacher for teacher in teachers if teacher["id"] == id]
    if len(lst_teachers) > 0:
        teachers.remove(lst_teachers[0])
        return jsonify({"message": "Teacher with id {} was successfully deleted.".format(id)}, {"teachers": teachers})
    return jsonify({"message": "Teacher with id {} was not found.".format(id)})


@app.route('/students')
def get_students():
    """Function to display the list of students.

    Returns:
        Json: json list of students.
    """
    return jsonify({"students": students})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
