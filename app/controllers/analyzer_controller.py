import os
from flask import render_template, request, send_file, abort
from app.services.analyzer_service import analyze_logs_input, DEFAULT_SAMPLE_LOGS

MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # Límite de 1 MB (Punto 5)
ALLOWED_EXTENSIONS = {'.txt', '.log'}


def index_controller():
    raw_input = DEFAULT_SAMPLE_LOGS
    upload_Notice = None

    if request.method == 'POST':
        uploaded_file = request.files.get('txt_file') or request.files.get('log_file')
        if uploaded_file and uploaded_file.filename != '':
            try:
                _, ext = os.path.splitext(uploaded_file.filename.lower())
                if ext not in ALLOWED_EXTENSIONS:
                    upload_Notice = f"Archivo rechazado: Extensión '{ext}' no permitida. Solo se admiten archivos .txt o .log."
                else:
                    file_bytes = uploaded_file.read(MAX_FILE_SIZE_BYTES + 1)
                    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                        upload_Notice = "Archivo rechazado: Excede el tamaño máximo permitido de 1 MB."
                    else:
                        decoded_text = file_bytes.decode('utf-8', errors='replace').strip()
                        if not decoded_text:
                            upload_Notice = "El archivo subido está vacío. Se cargó el lote de prueba por defecto."
                        else:
                            raw_input = decoded_text
            except Exception as exc:
                upload_Notice = f"Error al procesar el archivo subido: {exc}"
        else:
            form_text = request.form.get('log_input', '').strip()
            if form_text:
                if len(form_text) > MAX_FILE_SIZE_BYTES:
                    upload_Notice = "El texto ingresado excede el límite permitido de 1 MB."
                    raw_input = form_text[:MAX_FILE_SIZE_BYTES]
                else:
                    raw_input = form_text
            else:
                upload_Notice = "Entrada vacía. Se cargaron los registros de demostración por defecto."

    context = analyze_logs_input(raw_input)
    context['upload_notice'] = upload_Notice
    return render_template('index.html', **context)


def descargar_errores_json_controller():
    try:
        ruta = os.path.abspath(os.path.join(os.getcwd(), 'app', 'storage', 'logs_erroneos.json'))
        if not os.path.exists(ruta):
            analyze_logs_input(DEFAULT_SAMPLE_LOGS)
        if not os.path.exists(ruta):
            abort(404, description="No se pudo generar ni localizar el archivo logs_erroneos.json.")
        return send_file(
            ruta,
            mimetype='application/json',
            as_attachment=True,
            download_name='logs_erroneos_soc.json'
        )
    except Exception as exc:
        abort(500, description=f"Error controlado al descargar el reporte JSON: {exc}")


def descargar_reporte_txt_controller():
    try:
        ruta = os.path.abspath(os.path.join(os.getcwd(), 'app', 'storage', 'reporte_area_revision.txt'))
        if not os.path.exists(ruta):
            analyze_logs_input(DEFAULT_SAMPLE_LOGS)
        if not os.path.exists(ruta):
            abort(404, description="No se pudo generar ni localizar el reporte TXT para el área de revisión.")
        return send_file(
            ruta,
            mimetype='text/plain',
            as_attachment=True,
            download_name='reporte_area_encargada_soc.txt'
        )
    except Exception as exc:
        abort(500, description=f"Error controlado al descargar el reporte TXT: {exc}")