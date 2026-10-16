from flask import Blueprint
from app.controllers.analyzer_controller import index_controller

main_bp = Blueprint('main', __name__)

@main_bp.route('/', methods=['GET', 'POST'])
def index():
    return index_controller()