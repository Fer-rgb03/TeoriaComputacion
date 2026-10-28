from flask import Blueprint, render_template
from werkzeug.exceptions import RequestEntityTooLarge
from app.controllers.analyzer_controller import (
    index_controller,
    descargar_errores_json_controller,
    descargar_reporte_txt_controller,
    verificar_integridad_sesion_controller
)
from app.services.analyzer_service import analyze_logs_input

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


@main_bp.route('/verificar-integridad', methods=['GET'])
def verificar_integridad():
    return verificar_integridad_sesion_controller()


@main_bp.app_errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    """F-09: Rechaza solicitudes HTTP cuyo cuerpo supere MAX_CONTENT_LENGTH (1 MB) antes del análisis."""
    ctx = analyze_logs_input("", run_id=None, persist_reports=False, is_demo=False)
    ctx['upload_notice'] = "Solicitud HTTP rechazada (Código 413): El cuerpo de la petición supera el límite máximo de 1 MB."
    return render_template('index.html', **ctx), 413