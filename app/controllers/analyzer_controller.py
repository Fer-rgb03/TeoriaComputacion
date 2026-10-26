import os
from flask import render_template, request, send_file, abort
from app.services.analyzer_service import analyze_logs_input, DEFAULT_SAMPLE_LOGS


def index_controller():
    raw_input = DEFAULT_SAMPLE_LOGS
    if request.method == 'POST':
        uploaded_file = request.files.get('log_file')
        if uploaded_file and uploaded_file.filename != '':
            raw_input = uploaded_file.read().decode('utf-8', errors='replace')
        else:
            raw_input = request.form.get('log_input', DEFAULT_SAMPLE_LOGS)

    context = analyze_logs_input(raw_input)
    return render_template('index.html', **context)


def descargar_errores_json_controller():
    ruta = os.path.join(os.getcwd(), 'app', 'storage', 'logs_erroneos.json')
    if not os.path.exists(ruta):
        analyze_logs_input(DEFAULT_SAMPLE_LOGS)
    if not os.path.exists(ruta):
        abort(404, description="Archivo JSON no encontrado.")
    return send_file(
        ruta,
        mimetype='application/json',
        as_attachment=True,
        download_name='logs_erroneos_soc.json'
    )


def descargar_reporte_txt_controller():
    ruta = os.path.join(os.getcwd(), 'app', 'storage', 'reporte_area_revision.txt')
    if not os.path.exists(ruta):
        analyze_logs_input(DEFAULT_SAMPLE_LOGS)
    if not os.path.exists(ruta):
        abort(404, description="Reporte TXT no encontrado.")
    return send_file(
        ruta,
        mimetype='text/plain',
        as_attachment=True,
        download_name='reporte_area_encargada_soc.txt'
    )