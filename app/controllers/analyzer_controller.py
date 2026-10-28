import os
import re
import uuid
from flask import render_template, request, send_file, abort, session
from app.services.analyzer_service import analyze_logs_input, DEFAULT_SAMPLE_LOGS

MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB
ALLOWED_EXTENSIONS = {'.txt', '.log'}
SAFE_RUN_ID_REGEX = re.compile(r'^[a-f0-9]{16}$')


def index_controller():
    raw_input = DEFAULT_SAMPLE_LOGS
    upload_notice = None
    has_analyzed = False
    run_id = session.get('soc_run_id')

    if request.method == 'POST':
        has_analyzed = True
        run_id = uuid.uuid4().hex[:16]
        session['soc_run_id'] = run_id

        uploaded_file = request.files.get('txt_file') or request.files.get('log_file')
        if uploaded_file and uploaded_file.filename != '':
            try:
                _, ext = os.path.splitext(uploaded_file.filename.lower())
                if ext not in ALLOWED_EXTENSIONS:
                    upload_notice = f"Archivo rechazado: Extensión '{ext}' no permitida. Solo se admiten .txt o .log."
                else:
                    file_bytes = uploaded_file.read(MAX_FILE_SIZE_BYTES + 1)
                    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                        upload_notice = "Archivo rechazado: Excede el tamaño máximo permitido de 1 MB."
                    else:
                        decoded_text = file_bytes.decode('utf-8', errors='replace').strip()
                        if not decoded_text:
                            upload_notice = "El archivo subido está vacío. Se procesó el lote de prueba por defecto."
                        else:
                            raw_input = decoded_text
            except Exception as exc:
                upload_notice = f"Error controlado al leer el archivo: {exc}"
        else:
            form_text = request.form.get('log_input', '').strip()
            if form_text:
                if len(form_text) > MAX_FILE_SIZE_BYTES:
                    upload_notice = "El texto ingresado excede el límite de 1 MB y fue acotado."
                    raw_input = form_text[:MAX_FILE_SIZE_BYTES]
                else:
                    raw_input = form_text
            else:
                upload_notice = "Entrada vacía. Se procesó el lote de demostración por defecto."

    context = analyze_logs_input(raw_input, run_id=run_id, persist_reports=has_analyzed)
    context['upload_notice'] = upload_notice
    return render_template('index.html', **context)


def descargar_errores_json_controller():
    """H-03: Solo descarga el archivo asociado al run_id de la sesión activa del usuario."""
    run_id = session.get('soc_run_id', '')
    if not run_id or not SAFE_RUN_ID_REGEX.match(run_id):
        abort(403, description="Debe ejecutar primero un análisis en su sesión actual antes de descargar reportes.")
    ruta = os.path.abspath(os.path.join(os.getcwd(), 'app', 'storage', 'sesiones', f'logs_erroneos_{run_id}.json'))
    if not os.path.exists(ruta):
        abort(404, description="El reporte de su sesión no se encuentra disponible. Ejecute el análisis nuevamente.")
    return send_file(
        ruta,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'logs_erroneos_soc_{run_id}.json'
    )


def descargar_reporte_txt_controller():
    """H-03: Solo descarga el reporte TXT asociado al run_id de la sesión activa del usuario."""
    run_id = session.get('soc_run_id', '')
    if not run_id or not SAFE_RUN_ID_REGEX.match(run_id):
        abort(403, description="Debe ejecutar primero un análisis en su sesión actual antes de descargar reportes.")
    ruta = os.path.abspath(os.path.join(os.getcwd(), 'app', 'storage', 'sesiones', f'reporte_area_revision_{run_id}.txt'))
    if not os.path.exists(ruta):
        abort(404, description="El reporte TXT de su sesión no se encuentra disponible. Ejecute el análisis nuevamente.")
    return send_file(
        ruta,
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'reporte_area_encargada_soc_{run_id}.txt'
    )