from flask import Blueprint
from app.controllers.analyzer_controller import (
    index_controller,
    descargar_errores_json_controller,
    descargar_reporte_txt_controller
)

main_bp = Blueprint('main', __name__)


@main_bp.route('/', methods=['GET', 'POST'])
def index():
    return index_controller()


@main_bp.route('/descargar/errores-json', methods=['GET'])
def descargar_errores_json():
    return descargar_errores_json_controller()


@main_bp.route('/descargar/reporte-txt', methods=['GET'])
def descargar_reporte_txt():
    return descargar_reporte_txt_controller()