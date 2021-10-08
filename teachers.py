from flask import jsonify
from bd_personas import teachers


def get_teachers():
    """Function to display the list of teachers.

    Returns:
        Json: json list of teachers.
    """
    return jsonify({"teachers": teachers})
