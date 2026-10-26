import os
import re
import csv
import json
import hmac
import hashlib
import calendar
from datetime import datetime
from app.config import Config
from app.models.token_model import TokenModel
from app.patterns.singleton.grammar_singleton import GrammarSingleton
from app.services.jflap_service import build_jflap_models_for_token
from app.services.tree_service import build_token_real_trees, render_real_tree_svg, tree_to_parentheses

grammar = GrammarSingleton()

MAX_LINE_LENGTH = 2048
MAX_LINES_PER_BATCH = 200

DEFAULT_SAMPLE_LOGS = """2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3}
2026-10-12T08:15:30 10.0.0.5 CRITICAL PRIVILEGE_ESCALATION {"user":"root","ctx":{"port":22}}
2026-09-20T14:32:05 192.168.1.10 @ ERROR LOGIN_FAILED {"user":"admin"}
2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3"""

# Reglas heurísticas de apoyo para detección de entradas sospechosas (Punto 4)
SUSPICIOUS_INPUT_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b|--|;|\bOR\b\s+['\"\d]+=['\"\d]+|"
    r"\$ne|\$gt|\$lt|\$where|<script|javascript:|\.\./|\x00)",
    re.IGNORECASE
)

SAFE_KEY_IDENTIFIER = re.compile(r'^"[a-zA-Z0-9_\-\.]+"$')


def validate_timestamp_strict(ts_str):
    """Punto 3: Verifica formato ISO-8601 y validez real en calendario gregoriano y reloj de 24h."""
    if len(ts_str) != 19 or ts_str[4] != '-' or ts_str[7] != '-' or ts_str[10] != 'T' or ts_str[13] != ':' or ts_str[16] != ':':
        return False, "Formato TIMESTAMP inválido (se requiere AAAA-MM-DDTHH:MM:SS)."
    try:
        year = int(ts_str[0:4])
        month = int(ts_str[5:7])
        day = int(ts_str[8:10])
        hour = int(ts_str[11:13])
        minute = int(ts_str[14:16])
        second = int(ts_str[17:19])

        if not (1970 <= year <= 2100):
            return False, f"Año fuera de rango operativo ({year})."
        if not (1 <= month <= 12):
            return False, f"Mes inválido ({month}); debe estar entre 01 y 12."
        max_day = calendar.monthrange(year, month)[1]
        if not (1 <= day <= max_day):
            return False, f"Día inválido ({day}) para el mes {month:02d}/{year} (máx: {max_day})."
        if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
            return False, f"Hora inválida ({hour:02d}:{minute:02d}:{second:02d}); rango permitido 00:00:00 a 23:59:59."
        return True, f"Fecha/hora calendario válida ({ts_str})"
    except ValueError:
        return False, "Componentes numéricos corruptos en TIMESTAMP."


def validate_ipv4_strict(ip_str):
    """Punto 3: Verifica que cada uno de los 4 octetos IPv4 esté en el rango estricto 0 a 255."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False, "La dirección IPv4 debe tener exactamente 4 octetos."
    for idx, part in enumerate(parts, start=1):
        if not part.isdigit():
            return False, f"Octeto #{idx} ({part!r}) no es numérico."
        if len(part) > 1 and part.startswith('0'):
            return False, f"Octeto #{idx} ({part!r}) contiene ceros a la izquierda ambiguos."
        val = int(part)
        if not (0 <= val <= 255):
            return False, f"Octeto #{idx} ({val}) fuera del rango IPv4 permitido [0..255]."
    return True, "IPv4 válida (octetos en rango 0..255)"


def validate_string_security_and_type(str_lexeme, is_key=False):
    """Puntos 3 y 4: Validación específica por tipo de dato para cadenas JSON y detección de anomalías."""
    if len(str_lexeme) < 2 or not (str_lexeme.startswith('"') and str_lexeme.endswith('"')):
        return False, "Cadena mal delimitada por comillas."
    inner = str_lexeme[1:-1]
    if any(ord(ch) < 32 for ch in inner):
        return False, "La cadena contiene caracteres de control ASCII no permitidos."
    if len(inner) > 256:
        return False, "Longitud de cadena excede el límite de seguridad (256 caracteres)."
    if is_key and not SAFE_KEY_IDENTIFIER.match(str_lexeme):
        return False, f"La clave JSON {str_lexeme} contiene caracteres no permitidos para un identificador de atributo."
    match = SUSPICIOUS_INPUT_PATTERNS.search(inner)
    if match:
        return False, f"Entrada sospechosa detectada en cadena ({match.group(0)!r}): posible vector de inyección o comando."
    return True, "Cadena verificada"


def compute_record_hmac(raw_log):
    """
    Punto 7: Calcula un código HMAC-SHA256 completo (64 caracteres hexadecimales) sin truncamiento
    para verificar integridad interna de los registros procesados.
    """
    secret_key = os.environ.get('SOC_HMAC_SECRET_KEY', 'USIL_TCOM_SOC_INTEGRITY_KEY_2026').encode('utf-8')
    return hmac.new(secret_key, raw_log.strip().encode('utf-8'), hashlib.sha256).hexdigest()


def analyze_single_log(log_line, line_number=1):
    tokens = []
    lexical_errors = []

    if len(log_line) > MAX_LINE_LENGTH:
        return {
            'line_number': line_number,
            'raw': log_line[:200] + '... [TRUNCADO]',
            'valid_lexical': False,
            'valid_syntactic': False,
            'valid_semantic': False,
            'valid_security': False,
            'is_valid': False,
            'status': 'ERROR DE LÍMITE DE ENTRADA',
            'errors': [f"Línea {line_number}: Excede la longitud máxima permitida ({MAX_LINE_LENGTH} caracteres)."],
            'tokens': [],
            'pda_trace': [],
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None
        }

    for idx, mo in enumerate(re.finditer(grammar.TOK_REGEX, log_line)):
        kind = mo.lastgroup
        value = mo.group()
        col = mo.start() + 1

        if kind in ('SPACE', 'NEWLINE'):
            continue
        elif kind == 'MISMATCH':
            lexical_errors.append(
                f"Línea {line_number}, Col {col}: Símbolo ilegal {value!r} ∉ Σ. El AFD transita al Estado Trampa (qT)."
            )
            continue

        jflap_afd_svg, jflap_afnd_svg, jflap_runs = build_jflap_models_for_token(kind, value)
        syn_svg, sem_svg, paren_rep, sem_ok, sem_msg = build_token_real_trees(kind, value)

        # Punto 3 y 4: Reforzar validación semántica estricta en cada token
        if kind == 'TIMESTAMP':
            sem_ok, sem_msg = validate_timestamp_strict(value)
        elif kind == 'IP':
            sem_ok, sem_msg = validate_ipv4_strict(value)
        elif kind == 'STRING':
            sem_ok, sem_msg = validate_string_security_and_type(value, is_key=False)
        elif kind == 'NUMBER':
            try:
                num_val = int(value)
                if not (0 <= num_val <= 10**9):
                    sem_ok, sem_msg = False, f"Valor numérico ({num_val}) fuera de rango operativo."
            except ValueError:
                sem_ok, sem_msg = False, "Constante entera inválida."

        meta = grammar.TOKEN_METADATA.get(kind, {})

        tok_obj = TokenModel(
            index=len(tokens) + 1,
            type=kind,
            value=value,
            line=line_number,
            column=col,
            categoria=meta.get('categoria', ''),
            regex=meta.get('regex', ''),
            quintupla_afd=meta.get('quintupla_afd', {}),
            quintupla_afnd=meta.get('quintupla_afnd', {}),
            jflap_afd_svg=jflap_afd_svg,
            jflap_afnd_svg=jflap_afnd_svg,
            jflap_runs=jflap_runs,
            syn_tree_svg=syn_svg,
            sem_tree_svg=sem_svg,
            paren_rep=paren_rep,
            sem_ok=sem_ok,
            sem_msg=sem_msg
        )
        tokens.append(tok_obj.to_dict())

    if lexical_errors:
        return {
            'line_number': line_number,
            'raw': log_line,
            'valid_lexical': False,
            'valid_syntactic': False,
            'valid_semantic': False,
            'valid_security': False,
            'is_valid': False,
            'status': 'ERROR LÉXICO',
            'errors': lexical_errors,
            'tokens': tokens,
            'pda_trace': [],
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None
        }

    pos = 0
    pda_stack = ['Z0']
    pda_trace = ['(q0, w, Z0) ⊢ Configuración inicial del Autómata de Pila con fondo Z0']
    semantic_fields = []
    semantic_errors = [f"Token {t['type']} ({t['value']}): {t['sem_msg']}" for t in tokens if not t['sem_ok']]
    security_errors = []

    def match(expected_type):
        nonlocal pos
        if pos < len(tokens) and tokens[pos]['type'] == expected_type:
            tok = tokens[pos]
            pos += 1
            return tok, {'label': expected_type, 'sub': tok['value']}
        actual = tokens[pos]['type'] if pos < len(tokens) else "FIN_DE_CADENA"
        raise SyntaxError(f"Error Sintáctico en token #{pos+1}: Se esperaba '{expected_type}' pero se encontró '{actual}'.")

    def parse_payload():
        nonlocal pos
        _, n_lb = match('LBRACE')
        pda_stack.append('{')
        pda_trace.append(f"Lee '{{' → Apila '{{' (PUSH) | Pila: {''.join(pda_stack)}")

        children = [n_lb]
        seen_keys = set()
        if pos < len(tokens) and tokens[pos]['type'] != 'RBRACE':
            children.append(parse_fields(seen_keys))
        else:
            raise SyntaxError("Error Sintáctico: El objeto PAYLOAD no puede estar vacío; requiere al menos un FIELD.")

        _, n_rb = match('RBRACE')
        children.append(n_rb)
        if pda_stack and pda_stack[-1] == '{':
            pda_stack.pop()
            pda_trace.append(f"Lee '}}' → Desapila '{{' (POP) | Pila: {''.join(pda_stack)}")

        return {'label': 'PAYLOAD', 'children': children}

    def parse_fields(seen_keys):
        nonlocal pos
        first_f = parse_field(seen_keys)
        if pos < len(tokens) and tokens[pos]['type'] == 'COMMA':
            _, n_cm = match('COMMA')
            rest_f = parse_fields(seen_keys)
            return {'label': 'FIELDS', 'children': [first_f, n_cm, rest_f]}
        return {'label': 'FIELDS', 'children': [first_f]}

    def parse_field(seen_keys):
        nonlocal pos
        k_tok, n_str = match('STRING')
        key_val = k_tok['value']

        # Validar formato de clave y unicidad dentro del mismo objeto JSON (Punto 3 y 4)
        k_ok, k_msg = validate_string_security_and_type(key_val, is_key=True)
        if not k_ok and k_msg not in security_errors:
            security_errors.append(k_msg)
        if key_val in seen_keys:
            semantic_errors.append(f"Clave JSON duplicada ({key_val}) dentro del mismo objeto PAYLOAD.")
        seen_keys.add(key_val)

        _, n_col = match('COLON')
        v_type, n_val = parse_value()
        semantic_fields.append((key_val, v_type))
        return {'label': 'FIELD', 'children': [n_str, n_col, n_val]}

    def parse_value():
        nonlocal pos
        if pos >= len(tokens):
            raise SyntaxError("Error Sintáctico: Se esperaba un VALUE (STRING, NUMBER o PAYLOAD), pero terminó la cadena.")
        cur = tokens[pos]['type']
        if cur == 'STRING':
            t, n_s = match('STRING')
            return f"String({t['value']})", {'label': 'VALUE', 'children': [n_s]}
        elif cur == 'NUMBER':
            t, n_num = match('NUMBER')
            return f"Int({t['value']})", {'label': 'VALUE', 'children': [n_num]}
        elif cur == 'LBRACE':
            n_pay = parse_payload()
            return "ObjetoJSON({...})", {'label': 'VALUE', 'children': [n_pay]}
        else:
            raise SyntaxError(f"Error Sintáctico: Token '{cur}' no es un VALUE válido en la GLC.")

    try:
        ts_tok, n_ts = match('TIMESTAMP')
        ip_tok, n_ip = match('IP')
        sev_tok, n_sev = match('SEVERITY')
        evt_tok, n_evt = match('EVENT_TYPE')
        n_payload = parse_payload()

        if pos < len(tokens):
            raise SyntaxError(f"Error Sintáctico: Tokens adicionales fuera de la gramática a partir de {tokens[pos]['value']!r}.")

        pda_trace.append("(qF, λ, Z0) ⊢ Pila en Z0 y entrada consumida → SINTAXIS ACEPTADA")

        general_syn_dict = {
            'label': 'LOG (Raíz S)',
            'children': [n_ts, n_ip, n_sev, n_evt, n_payload]
        }

        all_post_errors = semantic_errors + security_errors
        sem_valid = len(semantic_errors) == 0
        sec_valid = len(security_errors) == 0 and not any("Entrada sospechosa" in e for e in semantic_errors)
        overall_valid = sem_valid and sec_valid

        if overall_valid:
            final_status = 'VÁLIDO (ACEPTADO)'
            record_hmac = compute_record_hmac(log_line)
        elif not sec_valid:
            final_status = 'RECHAZADO (ALERTA DE SEGURIDAD / ENTRADA SOSPECHOSA)'
            record_hmac = None
        else:
            final_status = 'ERROR SEMÁNTICO'
            record_hmac = None

        general_sem_dict = {
            'label': 'LOG.sem (Raíz AST)',
            'sub': 'VÁLIDO SOC' if overall_valid else 'RECHAZADO',
            'children': [
                {'label': 'Tiempo', 'sub': ts_tok['value'], 'children': [{'label': 'Calendario', 'sub': 'ISO-8601 OK' if ts_tok['sem_ok'] else 'Fecha/Hora Inválida'}]},
                {'label': 'Origen Red', 'sub': ip_tok['value'], 'children': [{'label': 'Octetos', 'sub': '0..255 OK' if ip_tok['sem_ok'] else 'IPv4 Inválida'}]},
                {'label': 'Severidad', 'sub': sev_tok['value'], 'children': [{'label': 'SLA', 'sub': sev_tok['sem_msg']}]},
                {'label': 'Evento', 'sub': evt_tok['value'], 'children': [{'label': 'Normativa', 'sub': 'SBS 504-2021'}]},
                {'label': 'Atributos JSON', 'children': [
                    {'label': k, 'sub': v} for k, v in semantic_fields
                ] or [{'label': 'Vacío', 'sub': '{}'}]}
            ]
        }

        return {
            'line_number': line_number,
            'raw': log_line,
            'valid_lexical': True,
            'valid_syntactic': True,
            'valid_semantic': sem_valid,
            'valid_security': sec_valid,
            'is_valid': overall_valid,
            'status': final_status,
            'errors': all_post_errors,
            'tokens': tokens,
            'pda_trace': pda_trace,
            'general_syn_svg': render_real_tree_svg(general_syn_dict, "syntactic"),
            'general_sem_svg': render_real_tree_svg(general_sem_dict, "semantic"),
            'general_paren': tree_to_parentheses(general_syn_dict),
            'integrity_hmac': record_hmac
        }

    except SyntaxError as e:
        pda_trace.append(f"❌ Rechazo en Autómata de Pila / Parser: {e}")
        return {
            'line_number': line_number,
            'raw': log_line,
            'valid_lexical': True,
            'valid_syntactic': False,
            'valid_semantic': False,
            'valid_security': False,
            'is_valid': False,
            'status': 'ERROR SINTÁCTICO',
            'errors': [str(e)] + semantic_errors,
            'tokens': tokens,
            'pda_trace': pda_trace,
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None
        }


def save_all_reports_and_history(results, storage_dir="app/storage"):
    """
    Puntos 6, 7 y 8:
    Guarda los resultados en app/storage/ (logs_erroneos.json, reporte_area_revision.txt,
    datos.json, reportes.csv) y conserva una copia con marca de tiempo en app/storage/historial/
    para evitar el sobrescrito accidental entre ejecuciones.
    """
    os.makedirs(storage_dir, exist_ok=True)
    history_dir = os.path.join(storage_dir, "historial")
    os.makedirs(history_dir, exist_ok=True)

    now = datetime.now()
    fecha_gen = now.strftime("%Y-%m-%d %H:%M:%S")
    run_stamp = now.strftime("%Y%m%d_%H%M%S")

    logs_erroneos = []
    logs_verificados = []
    export_data = []

    for r in results:
        export_data.append({
            'linea': r['line_number'],
            'log_crudo': r['raw'],
            'valido': r['is_valid'],
            'estado': r['status'],
            'total_tokens': len(r['tokens']),
            'hmac_sha256': r.get('integrity_hmac'),
            'errores': r['errors']
        })

        if not r['is_valid']:
            logs_erroneos.append({
                "linea": r['line_number'],
                "log_original": r['raw'],
                "estado_clasificacion": r['status'],
                "diagnostico_detallado": r['errors'] if r['errors'] else ["Incumplimiento de reglas formales"],
                "accion_recomendada": "Aislar registro y remitir al Área de Revisión SOC / TI"
            })
        else:
            logs_verificados.append({
                "linea": r['line_number'],
                "log_original": r['raw'],
                "hmac_sha256": r.get('integrity_hmac')
            })

    # 1. Archivo JSON de logs erróneos
    payload_erroneos = {
        "metadata": {
            "sistema": "SOC Analyzer & JFLAP Studio (Persistencia en Archivos JSON/CSV/TXT)",
            "fecha_generacion": fecha_gen,
            "id_ejecucion": run_stamp,
            "total_procesados": len(results),
            "total_aceptados": len(logs_verificados),
            "total_rechazados": len(logs_erroneos),
            "nota_seguridad": (
                "Validación léxica, sintáctica, semántica y filtrado heurístico de entradas. "
                "Para futuras integraciones con BD relacionales se requiere uso de consultas parametrizadas."
            )
        },
        "logs_erroneos": logs_erroneos
    }
    ruta_json_err = os.path.join(storage_dir, "logs_erroneos.json")
    with open(ruta_json_err, "w", encoding="utf-8") as fj:
        json.dump(payload_erroneos, fj, indent=4, ensure_ascii=False)

    # Copia histórica sin sobrescribir
    with open(os.path.join(history_dir, f"logs_erroneos_{run_stamp}.json"), "w", encoding="utf-8") as fjh:
        json.dump(payload_erroneos, fjh, indent=4, ensure_ascii=False)

    # 2. Archivo TXT para el área encargada de revisión
    lineas_txt = [
        "================================================================================",
        "         REPORTE OFICIAL DE AUDITORÍA Y REVISIÓN DE LOGS — ÁREA SOC / TI        ",
        "================================================================================",
        f"Fecha de emisión        : {fecha_gen} (ID Ejecución: {run_stamp})",
        f"Arquitectura Almacenam. : Archivos planos estructurados (JSON, CSV y TXT)",
        f"Total de logs procesados: {len(results)}",
        f"Logs Válidos (Aceptados): {len(logs_verificados)}",
        f"Logs con Error (Rechazo): {len(logs_erroneos)}",
        "--------------------------------------------------------------------------------",
        "SECCIÓN A: REGISTROS RECHAZADOS PARA REVISIÓN DEL ÁREA ENCARGADA",
        "--------------------------------------------------------------------------------"
    ]
    if not logs_erroneos:
        lineas_txt.append("No se registraron logs erróneos en esta ejecución.")
    else:
        for err in logs_erroneos:
            diag_str = " | ".join(err['diagnostico_detallado'])
            lineas_txt.append(
                f"[LÍNEA {err['linea']:02d}] ESTADO: {err['estado_clasificacion']}\n"
                f"  ├── Log Crudo   : {err['log_original']}\n"
                f"  ├── Diagnóstico : {diag_str}\n"
                f"  └── Acción Área : {err['accion_recomendada']}\n"
            )

    lineas_txt.extend([
        "--------------------------------------------------------------------------------",
        "SECCIÓN B: REGISTROS ACEPTADOS CON HUELLA DE INTEGRIDAD INTERNA (HMAC-SHA256)",
        "Nota: Huella HMAC-SHA256 de 64 caracteres para control de integridad de archivo.",
        "--------------------------------------------------------------------------------"
    ])
    if not logs_verificados:
        lineas_txt.append("No hay registros aceptados en esta ejecución.")
    else:
        for ok in logs_verificados:
            lineas_txt.append(
                f"[LÍNEA {ok['linea']:02d}] ACEPTADO\n"
                f"  ├── Registro    : {ok['log_original']}\n"
                f"  └── HMAC-SHA256 : {ok['hmac_sha256']}\n"
            )
    lineas_txt.append("================================================================================")

    ruta_txt = os.path.join(storage_dir, "reporte_area_revision.txt")
    with open(ruta_txt, "w", encoding="utf-8") as ft:
        ft.write("\n".join(lineas_txt))
    with open(os.path.join(history_dir, f"reporte_area_revision_{run_stamp}.txt"), "w", encoding="utf-8") as fth:
        fth.write("\n".join(lineas_txt))

    # 3. Archivos generales datos.json y reportes.csv
    json_path = os.path.join(storage_dir, 'datos.json')
    csv_path = os.path.join(storage_dir, 'reportes.csv')
    with open(json_path, 'w', encoding='utf-8') as jf:
        json.dump(export_data, jf, ensure_ascii=False, indent=2)
    with open(csv_path, 'w', newline='', encoding='utf-8') as cf:
        writer = csv.writer(cf)
        writer.writerow(['Linea', 'Estado', 'Valido', 'Total_Tokens', 'HMAC_SHA256', 'Log_Crudo'])
        for item in export_data:
            writer.writerow([
                item['linea'], item['estado'], item['valido'],
                item['total_tokens'], item['hmac_sha256'] or 'N/A', item['log_crudo']
            ])


def analyze_logs_input(raw_input):
    """
    Punto 6: Ejecuta el análisis completo de cada registro y calcula las estadísticas
    (accepted / rejected) DESPUÉS de finalizar todas las validaciones.
    """
    if not raw_input or not raw_input.strip():
        raw_input = DEFAULT_SAMPLE_LOGS

    all_lines = [line.strip() for line in raw_input.splitlines() if line.strip()]
    truncated_batch = False
    if len(all_lines) > MAX_LINES_PER_BATCH:
        all_lines = all_lines[:MAX_LINES_PER_BATCH]
        truncated_batch = True

    results = []
    for idx, line in enumerate(all_lines, start=1):
        res = analyze_single_log(line, line_number=idx)
        results.append(res)

    # Punto 6: Contabilizar aceptados y rechazados DESPUÉS de todas las validaciones
    accepted = sum(1 for r in results if r['is_valid'])
    rejected = sum(1 for r in results if not r['is_valid'])
    total_tokens = sum(len(r['tokens']) for r in results)

    save_all_reports_and_history(results)

    summary = {
        'total_lines': len(results),
        'total_tokens': total_tokens,
        'accepted': accepted,
        'rejected': rejected,
        'truncated_batch': truncated_batch
    }

    return {
        'log_input': raw_input,
        'results': results,
        'summary': summary
    }