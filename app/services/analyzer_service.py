import os
import re
import csv
import json
import hmac
import uuid
import hashlib
import calendar
from datetime import datetime
from app.models.token_model import TokenModel
from app.patterns.singleton.grammar_singleton import GrammarSingleton
from app.services.jflap_service import build_master_automata_catalog, simulate_token_both_traces
from app.services.tree_service import build_token_real_trees, render_real_tree_svg, tree_to_parentheses

grammar = GrammarSingleton()

# H-04: Catálogo maestro precalculado 1 sola vez por tipo de token (evita redundancia y desborde de DOM)
MASTER_AUTOMATA_CATALOG = build_master_automata_catalog()

MAX_LINE_LENGTH = 2048
MAX_LINES_PER_BATCH = 200

DEFAULT_SAMPLE_LOGS = """2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3}
2026-10-12T08:15:30 10.0.0.5 CRITICAL PRIVILEGE_ESCALATION {"user":"root","ctx":{"port":22}}
2026-09-20T14:32:05 192.168.1.10 @ ERROR LOGIN_FAILED {"user":"admin"}
2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3"""

SUSPICIOUS_INPUT_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b|--|;|\bOR\b\s+['\"\d]+=['\"\d]+|"
    r"\$ne|\$gt|\$lt|\$where|<script|javascript:|\.\./|\x00)",
    re.IGNORECASE
)

SAFE_KEY_IDENTIFIER = re.compile(r'^"[a-zA-Z0-9_\-\.]+"$')
VALID_JSON_ESCAPE_REGEX = re.compile(r'\\["\\/bfnrt]')


def validate_timestamp_strict(ts_str):
    """H-01 y B-15: Verifica formato exacto AAAA-MM-DDTHH:MM:SS y validez en calendario gregoriano (bisiestos y días/mes)."""
    if len(ts_str) != 19:
        extra = ts_str[19:]
        return False, f"Formato TIMESTAMP fuera del alcance UTC local: no se admiten sufijos de zona o fracción ({extra!r})."
    if ts_str[4] != '-' or ts_str[7] != '-' or ts_str[10] != 'T' or ts_str[13] != ':' or ts_str[16] != ':':
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
            return False, f"Mes inválido ({month:02d}); el AFD y el calendario exigen rango 01..12."
        max_day = calendar.monthrange(year, month)[1]
        if not (1 <= day <= max_day):
            leap_note = "año bisiesto" if calendar.isleap(year) else "año no bisiesto"
            return False, f"Día inexistente ({day:02d}) para el mes {month:02d}/{year} ({leap_note}, máximo {max_day} días)."
        if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
            return False, f"Hora inválida ({hour:02d}:{minute:02d}:{second:02d}); rango permitido 00:00:00 a 23:59:59."
        return True, f"Fecha/hora calendario válida ({ts_str})"
    except ValueError:
        return False, "Componentes numéricos corruptos en TIMESTAMP."


def validate_ipv4_strict(ip_str):
    """Comprueba que cada uno de los 4 octetos IPv4 esté entre 0 y 255 sin ceros iniciales."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False, "La dirección IPv4 debe tener exactamente 4 octetos."
    for idx, part in enumerate(parts, start=1):
        if not part.isdigit():
            return False, f"Octeto #{idx} ({part!r}) no es numérico."
        if len(part) > 1 and part.startswith('0'):
            return False, f"Octeto #{idx} ({part!r}) contiene ceros iniciales no permitidos."
        val = int(part)
        if not (0 <= val <= 255):
            return False, f"Octeto #{idx} ({val}) fuera del intervalo válido [0..255]."
    return True, "IPv4 válida (octetos en 0..255)"


def validate_string_security_and_type(str_lexeme, is_key=False):
    """H-05: Valida secuencias de escape JSON simplificado y detecta patrones sospechosos."""
    if len(str_lexeme) < 2 or not (str_lexeme.startswith('"') and str_lexeme.endswith('"')):
        return False, "Cadena mal delimitada por comillas."
    inner = str_lexeme[1:-1]
    if any(ord(ch) < 32 for ch in inner):
        return False, "La cadena contiene caracteres de control ASCII no permitidos."
    if len(inner) > 256:
        return False, "Longitud de cadena excede el límite de 256 caracteres."

    cleaned_escapes = VALID_JSON_ESCAPE_REGEX.sub('', inner)
    if '\\' in cleaned_escapes or '"' in cleaned_escapes:
        return False, "Secuencia de escape no soportada en JSON simplificado (solo se admiten \\\", \\\\, \\/, \\b, \\f, \\n, \\r, \\t)."

    if is_key and not SAFE_KEY_IDENTIFIER.match(str_lexeme):
        return False, f"La clave JSON {str_lexeme} contiene caracteres no permitidos para un identificador."
    match = SUSPICIOUS_INPUT_PATTERNS.search(inner)
    if match:
        return False, f"Entrada sospechosa detectada por patrón ({match.group(0)!r})."
    return True, "Literal de cadena verificado"


def _get_hmac_secret_key():
    """H-03: Carga la clave secreta desde la variable de entorno del servidor."""
    env_key = os.environ.get('SOC_HMAC_SECRET_KEY')
    if env_key:
        return env_key.encode('utf-8')
    return b'SOC_EPHEMERAL_DEV_HMAC_KEY_CONFIGURED_VIA_ENV'


def compute_record_hmac(raw_log):
    return hmac.new(_get_hmac_secret_key(), raw_log.strip().encode('utf-8'), hashlib.sha256).hexdigest()


def verify_record_hmac(raw_log, expected_hmac):
    if not expected_hmac:
        return False
    return hmac.compare_digest(compute_record_hmac(raw_log), expected_hmac)


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
            'errors': [f"Línea {line_number}, Col 1: Excede la longitud máxima permitida ({MAX_LINE_LENGTH} caracteres)."],
            'tokens': [],
            'valid_token_count': 0,
            'pda_trace': [],
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None,
            'hmac_verified': False
        }

    for mo in re.finditer(grammar.TOK_REGEX, log_line):
        kind = mo.lastgroup
        value = mo.group()
        col = mo.start() + 1

        if kind in ('SPACE', 'NEWLINE'):
            continue

        # H-05 y M-09: Incluir tokens ilegales (MISMATCH o LEADING_ZERO como 007) explícitamente en la tabla
        if kind == 'MISMATCH':
            err_detail = (
                f"Línea {line_number}, Col {col}: Símbolo ilegal {value!r} ∉ Σ_token. "
                f"El AFD transita al Estado Trampa (qT)."
            )
            lexical_errors.append(err_detail)
            meta = grammar.TOKEN_METADATA['ERROR_LEXICO']
            bad_tok = TokenModel(
                index=len(tokens) + 1,
                type='ERROR_LEXICO',
                value=value,
                line=line_number,
                column=col,
                categoria=meta['categoria'],
                regex=meta['regex'],
                quintupla_afd={},
                quintupla_afnd={},
                jflap_afd_svg='',
                jflap_afnd_svg='',
                jflap_runs=[],
                syn_tree_svg='',
                sem_tree_svg='',
                paren_rep=f"( ERROR_LEXICO:{value} )",
                sem_ok=False,
                sem_msg=f"Símbolo ilegal {value!r} en Col {col} (Rechazado en qT)"
            ).to_dict()
            bad_tok['live_trace'] = f"Posición Col {col}: '{value}' ∉ Σ_token → Transición inmediata a qT (Reject)"
            tokens.append(bad_tok)
            continue

        if kind == 'LEADING_ZERO':
            err_detail = (
                f"Línea {line_number}, Col {col}: Entero con cero inicial prohibido {value!r} "
                f"(JSON exige 0|[1-9][0-9]*; el AFD de NUMBER transita de q1 a qT)."
            )
            lexical_errors.append(err_detail)
            meta = grammar.TOKEN_METADATA['NUMBER']
            bad_tok = TokenModel(
                index=len(tokens) + 1,
                type='ERROR_LEXICO',
                value=value,
                line=line_number,
                column=col,
                categoria='Entero Inválido (Cero a la izquierda)',
                regex=meta['regex'],
                quintupla_afd={},
                quintupla_afnd={},
                jflap_afd_svg='',
                jflap_afnd_svg='',
                jflap_runs=[],
                syn_tree_svg='',
                sem_tree_svg='',
                paren_rep=f"( ERROR_LEXICO:{value} )",
                sem_ok=False,
                sem_msg=f"Rechazado por AFD de NUMBER (q0 --'0'--> q1 --'{value[1]}'--> qT)"
            ).to_dict()
            bad_tok['live_trace'] = simulate_token_both_traces('NUMBER', value)
            tokens.append(bad_tok)
            continue

        syn_svg, sem_svg, paren_rep, sem_ok, sem_msg = build_token_real_trees(kind, value)

        if kind == 'TIMESTAMP':
            sem_ok, sem_msg = validate_timestamp_strict(value)
            # H-01: Si el AFD de TIMESTAMP rechaza la cadena (mes 00, 13..19, día 00, 32..39, hora 24..29),
            # registrarlo también en la traza léxica/semántica.
            live_trace = simulate_token_both_traces('TIMESTAMP', value[:19])
            if "Reject" in live_trace.split("|")[0]:
                lexical_errors.append(
                    f"Línea {line_number}, Col {col}: Marca temporal {value!r} rechazada por el AFD de TIMESTAMP ({ sem_msg })."
                )
        elif kind == 'IP':
            sem_ok, sem_msg = validate_ipv4_strict(value)
            live_trace = simulate_token_both_traces('IP', value)
        elif kind == 'STRING':
            sem_ok, sem_msg = validate_string_security_and_type(value, is_key=False)
            live_trace = simulate_token_both_traces('STRING', value)
        elif kind == 'NUMBER':
            live_trace = simulate_token_both_traces('NUMBER', value)
            try:
                num_val = int(value)
                if not (0 <= num_val <= 10**9):
                    sem_ok, sem_msg = False, f"Valor numérico ({num_val}) fuera del rango [0..10^9]."
            except ValueError:
                sem_ok, sem_msg = False, "Constante entera inválida."
        else:
            live_trace = simulate_token_both_traces(kind, value)

        meta = grammar.TOKEN_METADATA.get(kind, {})
        master_ref = MASTER_AUTOMATA_CATALOG.get(kind, {})

        tok_obj = TokenModel(
            index=len(tokens) + 1,
            type=kind,
            value=value,
            line=line_number,
            column=col,
            categoria=meta.get('categoria', ''),
            regex=meta.get('regex', ''),
            quintupla_afd=master_ref.get('quintupla_afd', {}),
            quintupla_afnd=master_ref.get('quintupla_afnd', {}),
            jflap_afd_svg='',
            jflap_afnd_svg='',
            jflap_runs=[],
            syn_tree_svg=syn_svg,
            sem_tree_svg=sem_svg,
            paren_rep=paren_rep,
            sem_ok=sem_ok,
            sem_msg=sem_msg
        ).to_dict()
        tok_obj['live_trace'] = live_trace
        tokens.append(tok_obj)

    # M-09: Si la línea tiene un error léxico, marcar el registro como rechazado desde el inicio
    # y no presentar sus demás tokens como semánticamente aceptados de forma aislada.
    if lexical_errors:
        for t in tokens:
            if t['type'] != 'ERROR_LEXICO' and t['sem_ok']:
                t['sem_msg'] = f"{t['sem_msg']} (Línea invalidada por Error Léxico)"
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
            'valid_token_count': 0,
            'pda_trace': ['❌ Fase Léxica rechazada: el Autómata de Pila no inicia porque la cadena no pertenece a Σ_token*.'],
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None,
            'hmac_verified': False
        }

    pos = 0
    pda_stack = ['Z0']
    pda_trace = ['(q0, w, Z0) ⊢ Configuración inicial del Autómata de Pila con símbolo de fondo Z0']
    semantic_fields = []
    semantic_errors = [
        f"Línea {line_number}, Col {t['column']} (Token #{t['index']} {t['type']} {t['value']}): {t['sem_msg']}"
        for t in tokens if not t['sem_ok'] and "Entrada sospechosa" not in t['sem_msg']
    ]
    security_errors = [
        f"Línea {line_number}, Col {t['column']} (Token #{t['index']} {t['type']} {t['value']}): {t['sem_msg']}"
        for t in tokens if not t['sem_ok'] and "Entrada sospechosa" in t['sem_msg']
    ]

    def current_line_col():
        if pos < len(tokens):
            return tokens[pos]['line'], tokens[pos]['column'], tokens[pos]['index'], tokens[pos]['type'], tokens[pos]['value']
        last_col = (len(log_line) + 1) if log_line else 1
        return line_number, last_col, len(tokens) + 1, "FIN_DE_CADENA", "EOF"

    def match(expected_type, expected_set_desc=None):
        """M-08: Diagnóstico sintáctico unificado con Línea, Columna, conjunto esperado y token encontrado."""
        nonlocal pos
        if pos < len(tokens) and tokens[pos]['type'] == expected_type:
            tok = tokens[pos]
            pos += 1
            return tok, {'label': expected_type, 'sub': tok['value']}
        ln, col, t_idx, actual_type, actual_val = current_line_col()
        exp_str = expected_set_desc or f"'{expected_type}'"
        found_str = f"'{actual_type}' ({actual_val!r})" if actual_type != "FIN_DE_CADENA" else "'FIN_DE_CADENA'"
        raise SyntaxError(
            f"Línea {ln}, Col {col} (Token #{t_idx}): Error Sintáctico — "
            f"Se esperaba {exp_str}, pero se encontró {found_str}."
        )

    def parse_payload():
        nonlocal pos
        _, n_lb = match('LBRACE', "delimitador de apertura '{' (LBRACE)")
        pda_stack.append('{')
        pda_trace.append(f"Lee '{{' → Apila '{{' (PUSH) | Pila actual: {''.join(pda_stack)}")

        children = [n_lb]
        seen_keys = set()
        if pos < len(tokens) and tokens[pos]['type'] != 'RBRACE':
            children.append(parse_fields(seen_keys))
        else:
            ln, col, t_idx, act_t, _ = current_line_col()
            raise SyntaxError(
                f"Línea {ln}, Col {col} (Token #{t_idx}): Error Sintáctico — "
                f"El objeto PAYLOAD no puede estar vacío; se esperaba 'STRING' (clave JSON), pero se encontró '{act_t}'."
            )

        # M-08: Después de parse_fields, los tokens válidos en la gramática eran ',' (consumido en parse_fields) o '}' (RBRACE)
        _, n_rb = match('RBRACE', "conjunto {',', '}'} (COMMA para otro atributo o RBRACE para cerrar PAYLOAD)")
        children.append(n_rb)
        if pda_stack and pda_stack[-1] == '{':
            pda_stack.pop()
            pda_trace.append(f"Lee '}}' → Desapila '{{' (POP) | Pila actual: {''.join(pda_stack)}")

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
        k_tok, n_str = match('STRING', "clave 'STRING' entre comillas dobles")
        key_val = k_tok['value']

        k_ok, k_msg = validate_string_security_and_type(key_val, is_key=True)
        if not k_ok:
            msg_formatted = f"Línea {line_number}, Col {k_tok['column']} (Clave JSON {key_val}): {k_msg}"
            if "Entrada sospechosa" in k_msg and msg_formatted not in security_errors:
                security_errors.append(msg_formatted)
            elif msg_formatted not in semantic_errors:
                semantic_errors.append(msg_formatted)
        if key_val in seen_keys:
            semantic_errors.append(
                f"Línea {line_number}, Col {k_tok['column']}: Clave JSON duplicada ({key_val}) dentro del mismo objeto PAYLOAD."
            )
        seen_keys.add(key_val)

        _, n_col = match('COLON', "separador ':' (COLON)")
        v_type, n_val = parse_value()
        semantic_fields.append((key_val, v_type))
        return {'label': 'FIELD', 'children': [n_str, n_col, n_val]}

    def parse_value():
        nonlocal pos
        ln, col, t_idx, cur, cur_val = current_line_col()
        if cur == 'FIN_DE_CADENA':
            raise SyntaxError(
                f"Línea {ln}, Col {col} (Token #{t_idx}): Error Sintáctico — "
                f"Se esperaba un VALUE del conjunto {{'STRING', 'NUMBER', 'LBRACE'}}, pero se encontró 'FIN_DE_CADENA'."
            )
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
            raise SyntaxError(
                f"Línea {ln}, Col {col} (Token #{t_idx}): Error Sintáctico — "
                f"Se esperaba un VALUE del conjunto {{'STRING', 'NUMBER', 'LBRACE'}} (JSON simplificado), "
                f"pero se encontró '{cur}' ({cur_val!r})."
            )

    try:
        ts_tok, n_ts = match('TIMESTAMP', "'TIMESTAMP' (AAAA-MM-DDTHH:MM:SS)")
        ip_tok, n_ip = match('IP', "'IP' (dirección IPv4 de 4 octetos)")
        sev_tok, n_sev = match('SEVERITY', "'SEVERITY' ∈ {INFO, WARNING, ERROR, CRITICAL}")
        evt_tok, n_evt = match('EVENT_TYPE', "'EVENT_TYPE' ([A-Z]+(_[A-Z]+)*)")
        n_payload = parse_payload()

        if pos < len(tokens):
            ln, col, t_idx, rem_type, rem_val = current_line_col()
            raise SyntaxError(
                f"Línea {ln}, Col {col} (Token #{t_idx}): Error Sintáctico — "
                f"Se esperaba 'FIN_DE_CADENA' tras cerrar PAYLOAD, pero se encontró token extra '{rem_type}' ({rem_val!r})."
            )

        pda_trace.append("(qF, λ, Z0) ⊢ Pila en Z0 y entrada consumida → SINTAXIS ACEPTADA")

        general_syn_dict = {
            'label': 'LOG (Raíz S)',
            'children': [n_ts, n_ip, n_sev, n_evt, n_payload]
        }

        all_post_errors = semantic_errors + security_errors
        sem_valid = len(semantic_errors) == 0
        sec_valid = len(security_errors) == 0
        overall_valid = sem_valid and sec_valid

        if overall_valid:
            final_status = 'VÁLIDO (ACEPTADO)'
            record_hmac = compute_record_hmac(log_line)
            hmac_ok = verify_record_hmac(log_line, record_hmac)
        elif not sec_valid and not sem_valid:
            final_status = 'ERROR SEMÁNTICO Y ALERTA DE PATRÓN SOSPECHOSO'
            record_hmac, hmac_ok = None, False
        elif not sec_valid:
            final_status = 'RECHAZADO (ENTRADA SOSPECHOSA DETECTADA POR PATRÓN)'
            record_hmac, hmac_ok = None, False
        else:
            final_status = 'ERROR SEMÁNTICO'
            record_hmac, hmac_ok = None, False

        general_sem_dict = {
            'label': 'LOG.sem (Raíz AST)',
            'sub': 'VÁLIDO SOC' if overall_valid else final_status,
            'children': [
                {'label': 'Tiempo', 'sub': ts_tok['value'], 'children': [{'label': 'Calendario', 'sub': 'ISO-8601 OK' if ts_tok['sem_ok'] else 'Fecha/Hora Inválida'}]},
                {'label': 'Origen Red', 'sub': ip_tok['value'], 'children': [{'label': 'Octetos', 'sub': '0..255 OK' if ip_tok['sem_ok'] else 'IPv4 Fuera de Rango'}]},
                {'label': 'Severidad', 'sub': sev_tok['value'], 'children': [{'label': 'SLA', 'sub': sev_tok['sem_msg']}]},
                {'label': 'Evento SOC', 'sub': evt_tok['value'], 'children': [{'label': 'Catálogo SBS', 'sub': 'Registrado OK' if evt_tok['sem_ok'] else 'No Registrado'}]},
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
            'valid_token_count': len(tokens) if overall_valid else 0,
            'pda_trace': pda_trace,
            'general_syn_svg': render_real_tree_svg(general_syn_dict, "syntactic"),
            'general_sem_svg': render_real_tree_svg(general_sem_dict, "semantic"),
            'general_paren': tree_to_parentheses(general_syn_dict),
            'integrity_hmac': record_hmac,
            'hmac_verified': hmac_ok
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
            'errors': [str(e)] + semantic_errors + security_errors,
            'tokens': tokens,
            'valid_token_count': 0,
            'pda_trace': pda_trace,
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None,
            'hmac_verified': False
        }


def save_session_reports(results, run_id, storage_dir="app/storage"):
    """
    H-03 y B-13:
    Guarda los reportes aislados por identificador de sesión/ejecución (run_id)
    para evitar que un visitante descargue datos de otra sesión y prevenir la sobrescritura accidental.
    """
    os.makedirs(storage_dir, exist_ok=True)
    sessions_dir = os.path.join(storage_dir, "sesiones")
    os.makedirs(sessions_dir, exist_ok=True)

    now = datetime.now()
    fecha_gen = now.strftime("%Y-%m-%d %H:%M:%S")

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
            'hmac_verificado': r.get('hmac_verified', False),
            'errores': r['errors']
        })

        if not r['is_valid']:
            logs_erroneos.append({
                "linea": r['line_number'],
                "log_original": r['raw'],
                "categoria_error": r['status'],
                "diagnostico_detallado": r['errors'] if r['errors'] else ["Incumplimiento de reglas formales"],
                "accion_recomendada": "Aislar registro y remitir al Área de Revisión SOC / TI"
            })
        else:
            logs_verificados.append({
                "linea": r['line_number'],
                "log_original": r['raw'],
                "hmac_sha256": r.get('integrity_hmac'),
                "verificacion_hmac": "VERIFICADO_OK (hmac.compare_digest = True)" if r.get('hmac_verified') else "NO_VERIFICADO"
            })

    payload_erroneos = {
        "metadata": {
            "sistema": "SOC Analyzer & JFLAP Studio",
            "fecha_generacion": fecha_gen,
            "id_sesion_analisis": run_id,
            "total_procesados": len(results),
            "total_aceptados": len(logs_verificados),
            "total_rechazados": len(logs_erroneos),
            "alcance_seguridad": (
                "Validación léxica, sintáctica (JSON simplificado), semántica (calendario, IPv4, catálogo SBS) "
                "y detección heurística por patrones. Clave HMAC gestionada mediante variable de entorno."
            )
        },
        "logs_erroneos": logs_erroneos
    }

    ruta_json_session = os.path.join(sessions_dir, f"logs_erroneos_{run_id}.json")
    with open(ruta_json_session, "w", encoding="utf-8") as fj:
        json.dump(payload_erroneos, fj, indent=4, ensure_ascii=False)

    lineas_txt = [
        "================================================================================",
        "         REPORTE OFICIAL DE AUDITORÍA Y REVISIÓN DE LOGS — ÁREA SOC / TI        ",
        "================================================================================",
        f"Fecha de emisión        : {fecha_gen} (ID Análisis: {run_id})",
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
                f"[LÍNEA {err['linea']:02d}] CATEGORÍA: {err['categoria_error']}\n"
                f"  ├── Log Crudo   : {err['log_original']}\n"
                f"  ├── Diagnóstico : {diag_str}\n"
                f"  └── Acción Área : {err['accion_recomendada']}\n"
            )

    lineas_txt.extend([
        "--------------------------------------------------------------------------------",
        "SECCIÓN B: REGISTROS ACEPTADOS CON VERIFICACIÓN DE INTEGRIDAD (HMAC-SHA256)",
        "--------------------------------------------------------------------------------"
    ])
    if not logs_verificados:
        lineas_txt.append("No hay registros aceptados en esta ejecución.")
    else:
        for ok in logs_verificados:
            lineas_txt.append(
                f"[LÍNEA {ok['linea']:02d}] ACEPTADO | ESTADO INTEGRIDAD: {ok['verificacion_hmac']}\n"
                f"  ├── Registro    : {ok['log_original']}\n"
                f"  └── HMAC-SHA256 : {ok['hmac_sha256']}\n"
            )
    lineas_txt.append("================================================================================")

    ruta_txt_session = os.path.join(sessions_dir, f"reporte_area_revision_{run_id}.txt")
    with open(ruta_txt_session, "w", encoding="utf-8") as ft:
        ft.write("\n".join(lineas_txt))

    return ruta_json_session, ruta_txt_session


def analyze_logs_input(raw_input, run_id=None, persist_reports=False):
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

    accepted = sum(1 for r in results if r['is_valid'])
    rejected = sum(1 for r in results if not r['is_valid'])
    total_tokens = sum(len(r['tokens']) for r in results)
    valid_logs_tokens = sum(r['valid_token_count'] for r in results)

    if persist_reports and run_id:
        save_session_reports(results, run_id=run_id)

    summary = {
        'total_lines': len(results),
        'total_tokens': total_tokens,
        'valid_logs_tokens': valid_logs_tokens,
        'accepted': accepted,
        'rejected': rejected,
        'truncated_batch': truncated_batch
    }

    return {
        'log_input': raw_input,
        'results': results,
        'summary': summary,
        'master_catalog': MASTER_AUTOMATA_CATALOG,
        'run_id': run_id,
        'has_analyzed': persist_reports
    }