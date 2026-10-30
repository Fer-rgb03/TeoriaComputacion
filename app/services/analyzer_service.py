import os
import re
import csv
import json
import hmac
import time
import hashlib
import calendar
from datetime import datetime
from app.config import Config
from app.models.token_model import TokenModel
from app.patterns.singleton.grammar_singleton import GrammarSingleton
from app.services.jflap_service import (
    build_master_automata_catalog,
    simulate_token_both_traces,
    build_dynamic_lexeme_simulation_payload,
    SIGMA_ASCII
)
from app.services.tree_service import build_token_real_trees, render_real_tree_svg, tree_to_parentheses

grammar = GrammarSingleton()

# Catálogo maestro precalculado con la fuente única formal (FormalAutomatonModel)
MASTER_AUTOMATA_CATALOG = build_master_automata_catalog()

MAX_LINE_LENGTH = 2048
MAX_LINES_PER_BATCH = 200

DEFAULT_SAMPLE_LOGS = """2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3}
2024-02-29T23:59:59 10.0.0.5 CRITICAL PRIVILEGE_ESCALATION {"user":"root","ctx":{"port":22}}
2026-09-20T14:32:05 192.168.1.10 @ ERROR LOGIN_FAILED {"user":"admin"}
2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3"""

SUSPICIOUS_INPUT_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b|--|;|\bOR\b\s+['\"\d]+=['\"\d]+|"
    r"\$ne|\$gt|\$lt|\$where|<script|javascript:|\.\./|\x00)",
    re.IGNORECASE
)

SAFE_KEY_IDENTIFIER = re.compile(r'^"[a-zA-Z0-9_\-\.]+"$', re.ASCII)
VALID_JSON_ESCAPE_REGEX = re.compile(r'\\["\\/bfnrt]', re.ASCII)


def _is_ascii_digits(s):
    """Verifica que todos los caracteres sean dígitos ASCII '0'..'9'."""
    return bool(s) and all('0' <= ch <= '9' for ch in s)


def validate_timestamp_strict(ts_str):
    """Verifica formato ISO-8601 y validez real en calendario gregoriano."""
    if len(ts_str) != 19:
        extra = ts_str[19:]
        return False, f"Formato TIMESTAMP fuera del alcance UTC local: sufijo no admitido ({extra!r})."
    if ts_str[4] != '-' or ts_str[7] != '-' or ts_str[10] != 'T' or ts_str[13] != ':' or ts_str[16] != ':':
        return False, "Formato TIMESTAMP inválido (se requiere AAAA-MM-DDTHH:MM:SS)."
    parts_digits = ts_str[0:4] + ts_str[5:7] + ts_str[8:10] + ts_str[11:13] + ts_str[14:16] + ts_str[17:19]
    if not _is_ascii_digits(parts_digits):
        return False, "TIMESTAMP contiene caracteres no pertenecientes a dígitos ASCII [0-9]."

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
            return False, f"Mes inválido ({month:02d}); rango permitido 01..12."
        max_day = calendar.monthrange(year, month)[1]
        if not (1 <= day <= max_day):
            leap_note = "año bisiesto" if calendar.isleap(year) else "año no bisiesto"
            return False, f"Día inexistente ({day:02d}) para el mes {month:02d}/{year} ({leap_note}, máx {max_day} días)."
        if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
            return False, f"Hora inválida ({hour:02d}:{minute:02d}:{second:02d}); rango permitido 00:00:00 a 23:59:59."
        return True, f"Fecha/hora calendario válida ({ts_str})"
    except ValueError:
        return False, "Componentes numéricos corruptos en TIMESTAMP."


def validate_ipv4_strict(ip_str):
    """Verifica que cada octeto IPv4 esté en el intervalo 0..255 sin ceros iniciales."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False, "La dirección IPv4 debe tener exactamente 4 octetos."
    for idx, part in enumerate(parts, start=1):
        if not _is_ascii_digits(part):
            return False, f"Octeto #{idx} ({part!r}) no es numérico ASCII."
        if len(part) > 1 and part.startswith('0'):
            return False, f"Octeto #{idx} ({part!r}) contiene ceros iniciales no permitidos."
        val = int(part)
        if not (0 <= val <= 255):
            return False, f"Octeto #{idx} ({val}) fuera del intervalo IPv4 permitido [0..255]."
    return True, "IPv4 válida (octetos en 0..255)"


# Alfabeto ASCII imprimible completo (códigos 32..126, incluyendo el espacio ' ')
# permitido en el interior de literales JSON STRING.
SIGMA_ASCII_PRINTABLE = frozenset(SIGMA_ASCII) | {' '}


def validate_string_security_and_type(str_lexeme, is_key=False):
    """Valida cadenas JSON simplificadas y detecta patrones heurísticos sospechosos."""
    if len(str_lexeme) < 2 or not (str_lexeme.startswith('"') and str_lexeme.endswith('"')):
        return False, "Cadena mal delimitada por comillas."
    inner = str_lexeme[1:-1]
    for ch in inner:
        if ch not in SIGMA_ASCII_PRINTABLE:
            return False, f"Carácter {ch!r} fuera del alfabeto Σ_ASCII (32..126)."
    if len(inner) > 256:
        return False, "Longitud de cadena excede el límite de seguridad (256 caracteres)."

    cleaned_escapes = VALID_JSON_ESCAPE_REGEX.sub('', inner)
    if '\\' in cleaned_escapes or '"' in cleaned_escapes:
        return False, "Secuencia de escape JSON no soportada."

    if is_key and not SAFE_KEY_IDENTIFIER.match(str_lexeme):
        return False, f"La clave JSON {str_lexeme} contiene caracteres no permitidos."
    match = SUSPICIOUS_INPUT_PATTERNS.search(inner)
    if match:
        return False, f"Entrada sospechosa detectada por patrón ({match.group(0)!r})."
    return True, "Literal ASCII verificado"


def normalize_record_for_hmac(raw_log):
    return raw_log.strip().encode('utf-8')


def compute_record_hmac(raw_log):
    key_bytes = Config.SOC_HMAC_SECRET_KEY.encode('utf-8')
    return hmac.new(key_bytes, normalize_record_for_hmac(raw_log), hashlib.sha256).hexdigest()


def verify_record_hmac(raw_log, stored_hmac):
    if not stored_hmac or not isinstance(stored_hmac, str):
        return False
    return hmac.compare_digest(compute_record_hmac(raw_log), stored_hmac)


def cleanup_expired_reports():
    os.makedirs(Config.SESSIONS_DIR, exist_ok=True)
    now_ts = time.time()
    retention = Config.REPORT_RETENTION_SECONDS
    files_info = []

    for fname in os.listdir(Config.SESSIONS_DIR):
        fpath = os.path.join(Config.SESSIONS_DIR, fname)
        if os.path.isfile(fpath):
            try:
                mtime = os.path.getmtime(fpath)
                if now_ts - mtime > retention:
                    os.remove(fpath)
                else:
                    files_info.append((mtime, fpath))
            except OSError:
                pass

    max_files = Config.MAX_STORED_SESSIONS * 3
    if len(files_info) > max_files:
        files_info.sort(key=lambda x: x[0])
        for _, old_path in files_info[:len(files_info) - max_files]:
            try:
                os.remove(old_path)
            except OSError:
                pass


def _infer_expected_category_by_position(token_position_1based):
    """
    Para un símbolo ilegal (MISMATCH) en la posición k de la gramática
    LOG -> TIMESTAMP IP SEVERITY EVENT_TYPE PAYLOAD, determina el autómata
    de la categoría esperada donde ocurre el rechazo hacia qT / ∅.
    """
    pos_map = {
        1: 'TIMESTAMP',
        2: 'IP',
        3: 'SEVERITY',
        4: 'EVENT_TYPE',
        5: 'LBRACE'
    }
    return pos_map.get(token_position_1based, 'STRING')


def _attach_global_log_verdict(res_dict):
    """
    Garantiza que TODOS los tokens de un registro (sea válido o rechazado por
    error léxico, sintáctico, semántico o de seguridad) posean 'dynamic_simulation'
    con los 6 campos del veredicto global sincronizados con el resultado del log.
    """
    line_num = res_dict.get('line_number', 1)
    valid_lex = bool(res_dict.get('valid_lexical', False))
    valid_syn = bool(res_dict.get('valid_syntactic', False))
    valid_sem = bool(res_dict.get('valid_semantic', False))
    valid_sec = bool(res_dict.get('valid_security', False))
    is_val = bool(res_dict.get('is_valid', False))
    status_str = res_dict.get('status', '')
    errs = list(res_dict.get('errors', []))

    for t in res_dict.get('tokens', []):
        if 'dynamic_simulation' not in t or not t['dynamic_simulation']:
            cat_override = (
                _infer_expected_category_by_position(t.get('index', 1))
                if t.get('type') == 'ERROR_LEXICO' else None
            )
            t['dynamic_simulation'] = build_dynamic_lexeme_simulation_payload(
                tok_type=t.get('type', 'ERROR_LEXICO'),
                lexeme=t.get('value', ''),
                line_number=t.get('line', line_num),
                column=t.get('column', 1),
                token_index=t.get('index', 1),
                sem_ok=bool(t.get('sem_ok', False)),
                sem_msg=t.get('sem_msg', ''),
                valid_lexical_line=valid_lex,
                target_category_override=cat_override
            )

        dyn = t['dynamic_simulation']
        dyn['valid_lexical_line'] = valid_lex
        dyn['log_status'] = status_str
        dyn['log_is_valid'] = is_val
        dyn['log_valid_lexical'] = valid_lex
        dyn['log_valid_syntactic'] = valid_syn
        dyn['log_valid_semantic'] = valid_sem
        dyn['log_valid_security'] = valid_sec
        dyn['log_errors'] = errs

    return res_dict


def analyze_single_log(log_line, line_number=1):
    tokens = []
    lexical_errors = []

    if len(log_line) > MAX_LINE_LENGTH:
        return _attach_global_log_verdict({
            'line_number': line_number,
            'raw': log_line[:160] + f'... [VISTA ACOTADA: longitud recibida={len(log_line)} chars]',
            'valid_lexical': False,
            'valid_syntactic': False,
            'valid_semantic': False,
            'valid_security': False,
            'is_valid': False,
            'status': 'ERROR DE LÍMITE DE LONGITUD POR LÍNEA',
            'errors': [
                f"Línea {line_number}, Col 1: Longitud recibida ({len(log_line)} caracteres) "
                f"excede el límite máximo permitido por línea ({MAX_LINE_LENGTH} caracteres)."
            ],
            'tokens': [],
            'valid_token_count': 0,
            'pda_trace': [],
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None,
            'hmac_verified': False
        })

    for mo in grammar.TOK_REGEX.finditer(log_line):
        kind = mo.lastgroup
        value = mo.group()
        col = mo.start() + 1

        if kind in ('SPACE', 'NEWLINE'):
            continue

        if kind == 'MISMATCH':
            next_idx = len(tokens) + 1
            expected_cat = _infer_expected_category_by_position(next_idx)
            sim_mismatch = simulate_token_both_traces(expected_cat, value)
            err_detail = (
                f"Línea {line_number}, Col {col}: Símbolo ilegal {value!r} ∉ Σ_token (ASCII imprimible). "
                f"El AFD transita al Estado Trampa (qT)."
            )
            lexical_errors.append(err_detail)
            meta = grammar.TOKEN_METADATA['ERROR_LEXICO']
            bad_tok = TokenModel(
                index=next_idx,
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
            bad_tok['live_trace'] = sim_mismatch['combined_trace']
            bad_tok['dynamic_simulation'] = build_dynamic_lexeme_simulation_payload(
                tok_type='ERROR_LEXICO',
                lexeme=value,
                line_number=line_number,
                column=col,
                token_index=next_idx,
                sem_ok=False,
                sem_msg=bad_tok['sem_msg'],
                valid_lexical_line=False,
                target_category_override=expected_cat
            )
            tokens.append(bad_tok)
            continue

        if kind == 'MALFORMED_TIMESTAMP':
            next_idx = len(tokens) + 1
            sim_ts = simulate_token_both_traces('TIMESTAMP', value)
            err_detail = (
                f"Línea {line_number}, Col {col}: Marca temporal {value!r} rechazada en Fase Léxica por el AFD de TIMESTAMP "
                f"(mes fuera de 01..12, día fuera de 01..31, hora fuera de 00..23 o sufijo de zona no admitido). "
                f"{sim_ts['afd_trace']}"
            )
            lexical_errors.append(err_detail)
            bad_tok = TokenModel(
                index=next_idx,
                type='ERROR_LEXICO',
                value=value,
                line=line_number,
                column=col,
                categoria='Marca Temporal Fuera del Lenguaje Regular',
                regex=grammar.TOKEN_METADATA['TIMESTAMP']['regex'],
                quintupla_afd={},
                quintupla_afnd={},
                jflap_afd_svg='',
                jflap_afnd_svg='',
                jflap_runs=[],
                syn_tree_svg='',
                sem_tree_svg='',
                paren_rep=f"( ERROR_LEXICO:{value} )",
                sem_ok=False,
                sem_msg="Rechazado en el AFD de TIMESTAMP (transita a qT)"
            ).to_dict()
            bad_tok['live_trace'] = sim_ts['combined_trace']
            bad_tok['dynamic_simulation'] = build_dynamic_lexeme_simulation_payload(
                tok_type='ERROR_LEXICO',
                lexeme=value,
                line_number=line_number,
                column=col,
                token_index=next_idx,
                sem_ok=False,
                sem_msg=bad_tok['sem_msg'],
                valid_lexical_line=False,
                target_category_override='TIMESTAMP'
            )
            tokens.append(bad_tok)
            continue

        if kind == 'LEADING_ZERO':
            next_idx = len(tokens) + 1
            sim_num = simulate_token_both_traces('NUMBER', value)
            err_detail = (
                f"Línea {line_number}, Col {col}: Entero con cero inicial prohibido {value!r} "
                f"(JSON exige 0|[1-9][0-9]*; el AFD de NUMBER transita de q1 a qT)."
            )
            lexical_errors.append(err_detail)
            bad_tok = TokenModel(
                index=next_idx,
                type='ERROR_LEXICO',
                value=value,
                line=line_number,
                column=col,
                categoria='Entero Inválido (Cero inicial)',
                regex=grammar.TOKEN_METADATA['NUMBER']['regex'],
                quintupla_afd={},
                quintupla_afnd={},
                jflap_afd_svg='',
                jflap_afnd_svg='',
                jflap_runs=[],
                syn_tree_svg='',
                sem_tree_svg='',
                paren_rep=f"( ERROR_LEXICO:{value} )",
                sem_ok=False,
                sem_msg="Rechazado por AFD de NUMBER (q1 -> qT)"
            ).to_dict()
            bad_tok['live_trace'] = sim_num['combined_trace']
            bad_tok['dynamic_simulation'] = build_dynamic_lexeme_simulation_payload(
                tok_type='ERROR_LEXICO',
                lexeme=value,
                line_number=line_number,
                column=col,
                token_index=next_idx,
                sem_ok=False,
                sem_msg=bad_tok['sem_msg'],
                valid_lexical_line=False,
                target_category_override='NUMBER'
            )
            tokens.append(bad_tok)
            continue

        sim_info = simulate_token_both_traces(kind, value)
        live_trace = sim_info['combined_trace']

        if not sim_info['afd_accepted']:
            lexical_errors.append(
                f"Línea {line_number}, Col {col}: El lexema {value!r} fue rechazado por el AFD de {kind}. {sim_info['afd_trace']}"
            )

        syn_svg, sem_svg, paren_rep, sem_ok, sem_msg = build_token_real_trees(kind, value)

        if kind == 'TIMESTAMP':
            sem_ok, sem_msg = validate_timestamp_strict(value)
        elif kind == 'IP':
            sem_ok, sem_msg = validate_ipv4_strict(value)
        elif kind == 'STRING':
            sem_ok, sem_msg = validate_string_security_and_type(value, is_key=False)
        elif kind == 'NUMBER':
            if not _is_ascii_digits(value):
                sem_ok, sem_msg = False, "El número contiene caracteres no ASCII."
            else:
                num_val = int(value)
                if not (0 <= num_val <= 10**9):
                    sem_ok, sem_msg = False, f"Valor numérico ({num_val}) fuera del rango permitido [0..10^9]."

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
        tok_obj['dynamic_simulation'] = build_dynamic_lexeme_simulation_payload(
            tok_type=kind,
            lexeme=value,
            line_number=line_number,
            column=col,
            token_index=tok_obj['index'],
            sem_ok=sem_ok,
            sem_msg=sem_msg,
            valid_lexical_line=True
        )
        tokens.append(tok_obj)

    if lexical_errors:
        for t in tokens:
            if t['type'] != 'ERROR_LEXICO' and t['sem_ok']:
                t['sem_msg'] = f"{t['sem_msg']} (Registro anulado por Error Léxico)"
        return _attach_global_log_verdict({
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
            'pda_trace': ['❌ Fase Léxica rechazada: el Autómata de Pila no inicia porque existen tokens rechazados en qT.'],
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': '',
            'integrity_hmac': None,
            'hmac_verified': False
        })

    pos = 0
    pda_stack = ['Z0']
    pda_trace = ['(q0, w, Z0) ⊢ Configuración inicial del Autómata de Pila con símbolo de fondo Z0']
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

        syn_children = [n_lb]
        seen_keys = set()
        if pos < len(tokens) and tokens[pos]['type'] != 'RBRACE':
            syn_fields_node, sem_field_nodes = parse_fields(seen_keys)
            syn_children.append(syn_fields_node)
        else:
            ln, col, t_idx, act_t, _ = current_line_col()
            raise SyntaxError(
                f"Línea {ln}, Col {col} (Token #{t_idx}): Error Sintáctico — "
                f"El objeto PAYLOAD no puede estar vacío; se esperaba 'STRING' (clave JSON), pero se encontró '{act_t}'."
            )

        _, n_rb = match('RBRACE', "conjunto {',', '}'} (COMMA para otro atributo o RBRACE para cerrar PAYLOAD)")
        syn_children.append(n_rb)
        if pda_stack and pda_stack[-1] == '{':
            pda_stack.pop()
            pda_trace.append(f"Lee '}}' → Desapila '{{' (POP) | Pila actual: {''.join(pda_stack)}")

        return {'label': 'PAYLOAD', 'children': syn_children}, sem_field_nodes

    def parse_fields(seen_keys):
        nonlocal pos
        first_syn, first_sem = parse_field(seen_keys)
        if pos < len(tokens) and tokens[pos]['type'] == 'COMMA':
            _, n_cm = match('COMMA')
            rest_syn, rest_sem_list = parse_fields(seen_keys)
            return {'label': 'FIELDS', 'children': [first_syn, n_cm, rest_syn]}, [first_sem] + rest_sem_list
        return {'label': 'FIELDS', 'children': [first_syn]}, [first_sem]

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
        v_sem_desc, n_val_syn, nested_sem_children = parse_value()

        if nested_sem_children is not None:
            sem_node = {'label': key_val, 'sub': 'ObjetoJSON', 'children': nested_sem_children}
        else:
            sem_node = {'label': key_val, 'sub': v_sem_desc}

        return {'label': 'FIELD', 'children': [n_str, n_col, n_val_syn]}, sem_node

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
            return f"String({t['value']})", {'label': 'VALUE', 'children': [n_s]}, None
        elif cur == 'NUMBER':
            t, n_num = match('NUMBER')
            return f"Int({t['value']})", {'label': 'VALUE', 'children': [n_num]}, None
        elif cur == 'LBRACE':
            n_pay_syn, nested_sem_nodes = parse_payload()
            return "ObjetoJSON({...})", {'label': 'VALUE', 'children': [n_pay_syn]}, nested_sem_nodes
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
        n_payload_syn, sem_payload_tree = parse_payload()

        if pos < len(tokens):
            ln, col, t_idx, rem_type, rem_val = current_line_col()
            raise SyntaxError(
                f"Línea {ln}, Col {col} (Token #{t_idx}): Error Sintáctico — "
                f"Se esperaba 'FIN_DE_CADENA' tras cerrar PAYLOAD, pero se encontró token extra '{rem_type}' ({rem_val!r})."
            )

        pda_trace.append("(qF, λ, Z0) ⊢ Pila en Z0 y entrada consumida → SINTAXIS ACEPTADA")

        general_syn_dict = {
            'label': 'LOG (Raíz S)',
            'children': [n_ts, n_ip, n_sev, n_evt, n_payload_syn]
        }

        all_post_errors = semantic_errors + security_errors
        sem_valid = len(semantic_errors) == 0
        sec_valid = len(security_errors) == 0
        overall_valid = sem_valid and sec_valid

        if overall_valid:
            final_status = 'VÁLIDO (ACEPTADO)'
            record_hmac = compute_record_hmac(log_line)
        elif not sec_valid and not sem_valid:
            final_status = 'ERROR SEMÁNTICO Y ALERTA DE PATRÓN SOSPECHOSO'
            record_hmac = None
        elif not sec_valid:
            final_status = 'RECHAZADO (ENTRADA SOSPECHOSA DETECTADA POR PATRÓN)'
            record_hmac = None
        else:
            final_status = 'ERROR SEMÁNTICO'
            record_hmac = None

        general_sem_dict = {
            'label': 'LOG.sem (Raíz AST)',
            'sub': 'VÁLIDO SOC' if overall_valid else final_status,
            'children': [
                {'label': 'Tiempo', 'sub': ts_tok['value'], 'children': [{'label': 'Calendario', 'sub': 'ISO-8601 OK' if ts_tok['sem_ok'] else 'Fecha/Hora Inválida'}]},
                {'label': 'Origen Red', 'sub': ip_tok['value'], 'children': [{'label': 'Octetos', 'sub': '0..255 OK' if ip_tok['sem_ok'] else 'IPv4 Fuera de Rango'}]},
                {'label': 'Severidad', 'sub': sev_tok['value'], 'children': [{'label': 'SLA', 'sub': sev_tok['sem_msg']}]},
                {'label': 'Evento SOC', 'sub': evt_tok['value'], 'children': [{'label': 'Catálogo SBS', 'sub': 'Registrado OK' if evt_tok['sem_ok'] else 'No Registrado'}]},
                {'label': 'Atributos JSON', 'children': sem_payload_tree or [{'label': 'Vacío', 'sub': '{}'}]}
            ]
        }

        return _attach_global_log_verdict({
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
            'hmac_verified': False
        })

    except SyntaxError as e:
        pda_trace.append(f"❌ Rechazo en Autómata de Pila / Parser: {e}")
        return _attach_global_log_verdict({
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
        })


def save_session_reports(results, run_id, truncation_info=None):
    cleanup_expired_reports()
    os.makedirs(Config.SESSIONS_DIR, exist_ok=True)

    now = datetime.now()
    fecha_gen = now.strftime("%Y-%m-%d %H:%M:%S")

    logs_erroneos = []
    logs_verificados = []
    persisted_records = []

    for r in results:
        persisted_records.append({
            'linea': r['line_number'],
            'log_original': r['raw'],
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
                "categoria_error": r['status'],
                "diagnostico_detallado": r['errors'] if r['errors'] else ["Incumplimiento de reglas formales"],
                "accion_recomendada": "Aislar registro y remitir al Área de Revisión SOC / TI"
            })
        else:
            logs_verificados.append({
                "linea": r['line_number'],
                "log_original": r['raw'],
                "hmac_sha256": r.get('integrity_hmac')
            })

    ruta_store_session = os.path.join(Config.SESSIONS_DIR, f"registros_firmados_{run_id}.json")
    with open(ruta_store_session, "w", encoding="utf-8") as fs:
        json.dump({
            "id_sesion": run_id,
            "fecha_almacenamiento": fecha_gen,
            "registros": logs_verificados
        }, fs, indent=4, ensure_ascii=False)

    audit_check = verify_persisted_session_records(run_id)
    verified_map = {item['linea']: item['integro'] for item in audit_check['detalles']}
    for r in results:
        if r['is_valid']:
            r['hmac_verified'] = verified_map.get(r['line_number'], False)

    payload_erroneos = {
        "metadata": {
            "sistema": "SOC Analyzer & JFLAP Studio",
            "fecha_generacion": fecha_gen,
            "id_sesion_analisis": run_id,
            "total_recibidos": truncation_info['received'] if truncation_info else len(results),
            "total_procesados": len(results),
            "total_descartados_por_lote": truncation_info['discarded'] if truncation_info else 0,
            "lote_truncado": bool(truncation_info and truncation_info['truncated']),
            "total_aceptados": len(logs_verificados),
            "total_rechazados": len(logs_erroneos),
            "nota_deteccion_heuristica": (
                "La detección de patrones sospechosos es heurística (puede presentar falsos positivos o "
                "falsos negativos ante cargas ofuscadas) y no sustituye consultas parametrizadas ni un WAF."
            )
        },
        "logs_erroneos": logs_erroneos
    }

    ruta_json_session = os.path.join(Config.SESSIONS_DIR, f"logs_erroneos_{run_id}.json")
    with open(ruta_json_session, "w", encoding="utf-8") as fj:
        json.dump(payload_erroneos, fj, indent=4, ensure_ascii=False)

    lineas_txt = [
        "================================================================================",
        "         REPORTE OFICIAL DE AUDITORÍA Y REVISIÓN DE LOGS — ÁREA SOC / TI        ",
        "================================================================================",
        f"Fecha de emisión        : {fecha_gen} (ID Sesión: {run_id})",
        f"Total recibidos / proc. : {payload_erroneos['metadata']['total_recibidos']} recibidos | {len(results)} procesados",
        f"Logs Válidos (Aceptados): {len(logs_verificados)}",
        f"Logs con Error (Rechazo): {len(logs_erroneos)}",
    ]
    if truncation_info and truncation_info['truncated']:
        lineas_txt.append(
            f"ADVERTENCIA DE LOTE     : Se descartaron {truncation_info['discarded']} líneas por exceder el máximo de {MAX_LINES_PER_BATCH}."
        )
    lineas_txt.extend([
        "--------------------------------------------------------------------------------",
        "SECCIÓN A: REGISTROS RECHAZADOS PARA REVISIÓN DEL ÁREA ENCARGADA",
        "--------------------------------------------------------------------------------"
    ])
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
        "SECCIÓN B: AUDITORÍA DE INTEGRIDAD POST-ALMACENAMIENTO (DESDE DISCO)",
        "--------------------------------------------------------------------------------"
    ])
    if not logs_verificados:
        lineas_txt.append("No hay registros aceptados en esta ejecución.")
    else:
        for ok in logs_verificados:
            ver_ok = verified_map.get(ok['linea'], False)
            estado_str = "VERIFICADO_DESDE_DISCO_OK" if ver_ok else "FALLO_INTEGRIDAD_ALTERADO"
            lineas_txt.append(
                f"[LÍNEA {ok['linea']:02d}] ACEPTADO | AUDITORÍA DISCO: {estado_str}\n"
                f"  ├── Registro    : {ok['log_original']}\n"
                f"  └── HMAC-SHA256 : {ok['hmac_sha256']}\n"
            )
    lineas_txt.append("================================================================================")

    ruta_txt_session = os.path.join(Config.SESSIONS_DIR, f"reporte_area_revision_{run_id}.txt")
    with open(ruta_txt_session, "w", encoding="utf-8") as ft:
        ft.write("\n".join(lineas_txt))

    return ruta_json_session, ruta_txt_session


def verify_persisted_session_records(run_id, storage_path=None):
    ruta = storage_path or os.path.join(Config.SESSIONS_DIR, f"registros_firmados_{run_id}.json")
    if not os.path.exists(ruta):
        return {"verificado": False, "total": 0, "integros": 0, "alterados": 0, "detalles": []}

    with open(ruta, "r", encoding="utf-8") as f:
        data = json.load(f)

    detalles = []
    integros = 0
    alterados = 0
    for rec in data.get("registros", []):
        raw_stored = rec.get("log_original", "")
        hmac_stored = rec.get("hmac_sha256", "")
        es_integro = verify_record_hmac(raw_stored, hmac_stored)
        if es_integro:
            integros += 1
        else:
            alterados += 1
        detalles.append({
            "linea": rec.get("linea"),
            "log_recuperado": raw_stored,
            "hmac_almacenado": hmac_stored,
            "hmac_recalculado": compute_record_hmac(raw_stored),
            "integro": es_integro
        })

    return {
        "verificado": (alterados == 0),
        "total": len(detalles),
        "integros": integros,
        "alterados": alterados,
        "detalles": detalles
    }


def analyze_logs_input(raw_input, run_id=None, persist_reports=False, is_demo=False):
    if is_demo and (not raw_input or not raw_input.strip()):
        raw_input = DEFAULT_SAMPLE_LOGS

    if not raw_input or not raw_input.strip():
        return {
            'log_input': '',
            'results': [],
            'summary': {
                'total_received': 0,
                'total_lines': 0,
                'discarded_lines': 0,
                'total_tokens': 0,
                'valid_logs_tokens': 0,
                'accepted': 0,
                'rejected': 0,
                'truncated_batch': False
            },
            'master_catalog': MASTER_AUTOMATA_CATALOG,
            'run_id': None,
            'has_analyzed': False,
            'is_demo': False,
            'dynamic_lexemes_by_type': {tok_t: [] for tok_t in MASTER_AUTOMATA_CATALOG},
            'all_dynamic_tokens': []
        }

    all_lines = [line.strip() for line in raw_input.splitlines() if line.strip()]
    total_received = len(all_lines)
    truncated_batch = False
    discarded_lines = 0

    if total_received > MAX_LINES_PER_BATCH:
        all_lines = all_lines[:MAX_LINES_PER_BATCH]
        truncated_batch = True
        discarded_lines = total_received - MAX_LINES_PER_BATCH

    results = []
    for idx, line in enumerate(all_lines, start=1):
        res = analyze_single_log(line, line_number=idx)
        results.append(res)

    accepted = sum(1 for r in results if r['is_valid'])
    rejected = sum(1 for r in results if not r['is_valid'])
    total_tokens = sum(len(r['tokens']) for r in results)
    valid_logs_tokens = sum(r['valid_token_count'] for r in results)

    trunc_info = {
        'received': total_received,
        'processed': len(results),
        'discarded': discarded_lines,
        'truncated': truncated_batch
    }

    audit_summary = None
    if persist_reports and run_id and not is_demo:
        save_session_reports(results, run_id=run_id, truncation_info=trunc_info)
        audit_summary = verify_persisted_session_records(run_id)

    dynamic_lexemes_by_type = {tok_t: [] for tok_t in MASTER_AUTOMATA_CATALOG}
    all_dynamic_tokens = []
    for r in results:
        for t in r['tokens']:
            dyn = t.get('dynamic_simulation')
            if dyn:
                all_dynamic_tokens.append(dyn)
                cat_key = dyn.get('automaton_category', t['type'])
                if cat_key in dynamic_lexemes_by_type:
                    dynamic_lexemes_by_type[cat_key].append(dyn)

    summary = {
        'total_received': total_received,
        'total_lines': len(results),
        'discarded_lines': discarded_lines,
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
        'run_id': run_id if (persist_reports and not is_demo) else None,
        'has_analyzed': bool(persist_reports and not is_demo),
        'is_demo': is_demo,
        'audit_summary': audit_summary,
        'dynamic_lexemes_by_type': dynamic_lexemes_by_type,
        'all_dynamic_tokens': all_dynamic_tokens
    }