import os
import re
import uuid
from flask import render_template, request, send_file, abort, session, jsonify, current_app
from app.config import Config
from app.services.analyzer_service import (
    analyze_logs_input,
    verify_persisted_session_records,
    DEFAULT_SAMPLE_LOGS
)

MAX_FILE_SIZE_BYTES = Config.MAX_CONTENT_LENGTH
ALLOWED_EXTENSIONS = {'.txt', '.log'}
SAFE_RUN_ID_REGEX = re.compile(r'^[a-f0-9]{16}$')


def _empty_error_context(error_message, raw_input=""):
    """F-07 y F-16: Cancela el análisis sin generar reportes ni cargar datos de muestra."""
    session.pop('soc_run_id', None)
    ctx = analyze_logs_input("", run_id=None, persist_reports=False, is_demo=False)
    ctx['log_input'] = raw_input
    ctx['upload_notice'] = error_message
    return ctx


def index_controller():
    if request.method == 'GET':
        # En GET inicial se presenta el modo demostración explícitamente identificado (F-16)
        context = analyze_logs_input(DEFAULT_SAMPLE_LOGS, run_id=None, persist_reports=False, is_demo=True)
        context['upload_notice'] = None
        return render_template('index.html', **context)

    # Solicitud POST: Distinguir entre botón explícito de Demostración y Análisis de Usuario (F-16)
    mode = request.form.get('mode', 'analyze')
    if mode == 'demo':
        session.pop('soc_run_id', None)
        context = analyze_logs_input(DEFAULT_SAMPLE_LOGS, run_id=None, persist_reports=False, is_demo=True)
        context['upload_notice'] = "Modo Demostración activado explícitamente: se muestran registros de ejemplo (sin generar reportes de usuario)."
        return render_template('index.html', **context)

    uploaded_file = request.files.get('txt_file') or request.files.get('log_file')
    if uploaded_file and uploaded_file.filename != '':
        try:
            _, ext = os.path.splitext(uploaded_file.filename.lower())
            if ext not in ALLOWED_EXTENSIONS:
                ctx = _empty_error_context(
                    f"Análisis cancelado: La extensión '{ext}' no está permitida. Solo se admiten archivos .txt o .log."
                )
                return render_template('index.html', **ctx)

            file_bytes = uploaded_file.read(MAX_FILE_SIZE_BYTES + 1)
            if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                ctx = _empty_error_context(
                    "Análisis cancelado: El archivo excede el tamaño máximo permitido de 1 MB."
                )
                return render_template('index.html', **ctx)

            # F-14: Decodificación UTF-8 estricta (sin sustitución silenciosa errors='replace')
            try:
                decoded_text = file_bytes.decode('utf-8', errors='strict').strip()
            except UnicodeDecodeError:
                ctx = _empty_error_context(
                    "Análisis cancelado: El archivo contiene secuencias de bytes que no son UTF-8 válidas."
                )
                return render_template('index.html', **ctx)

            if not decoded_text:
                ctx = _empty_error_context(
                    "Análisis cancelado: El archivo subido está vacío. Envíe un archivo con al menos un registro."
                )
                return render_template('index.html', **ctx)

            raw_input = decoded_text

        except Exception as exc:
            # F-18: Registrar detalle interno en el servidor y mostrar mensaje genérico controlado al cliente
            current_app.logger.error("Error interno al leer archivo subido: %s", exc)
            ctx = _empty_error_context(
                "Análisis cancelado: No fue posible procesar el archivo enviado debido a un error de lectura."
            )
            return render_template('index.html', **ctx)
    else:
        form_text = request.form.get('log_input', '').strip()
        if not form_text:
            ctx = _empty_error_context(
                "Análisis cancelado: La entrada de texto está vacía. Ingrese registros de log o use el botón 'Cargar Demostración'."
            )
            return render_template('index.html', **ctx)

        if len(form_text.encode('utf-8')) > MAX_FILE_SIZE_BYTES:
            ctx = _empty_error_context(
                "Análisis cancelado: El texto enviado excede el límite máximo de 1 MB."
            )
            return render_template('index.html', **ctx)

        raw_input = form_text

    run_id = uuid.uuid4().hex[:16]
    session['soc_run_id'] = run_id
    context = analyze_logs_input(raw_input, run_id=run_id, persist_reports=True, is_demo=False)
    context['upload_notice'] = None
    return render_template('index.html', **context)


def descargar_errores_json_controller():
    run_id = session.get('soc_run_id', '')
    if not run_id or not SAFE_RUN_ID_REGEX.match(run_id):
        abort(403, description="No existe un análisis activo en su sesión actual.")
    ruta = os.path.join(Config.SESSIONS_DIR, f'logs_erroneos_{run_id}.json')
    if not os.path.exists(ruta):
        abort(404, description="El reporte solicitado no existe o ha expirado según la política de retención.")
    return send_file(
        ruta,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'logs_erroneos_soc_{run_id}.json'
    )


def descargar_reporte_txt_controller():
    run_id = session.get('soc_run_id', '')
    if not run_id or not SAFE_RUN_ID_REGEX.match(run_id):
        abort(403, description="No existe un análisis activo en su sesión actual.")
    ruta = os.path.join(Config.SESSIONS_DIR, f'reporte_area_revision_{run_id}.txt')
    if not os.path.exists(ruta):
        abort(404, description="El reporte TXT solicitado no existe o ha expirado según la política de retención.")
    return send_file(
        ruta,
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'reporte_area_encargada_soc_{run_id}.txt'
    )


def verificar_integridad_sesion_controller():
    """F-02: Endpoint independiente que re-verifica desde disco los HMAC-SHA256 almacenados."""
    run_id = session.get('soc_run_id', '')
    if not run_id or not SAFE_RUN_ID_REGEX.match(run_id):
        return jsonify({"error": "Sin sesión de análisis activa."}), 403
    resultado = verify_persisted_session_records(run_id)
    return jsonify(resultado), 200