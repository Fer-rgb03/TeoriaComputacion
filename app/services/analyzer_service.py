import os
import re
import json
import csv
from app.config import Config
from app.models.token_model import TokenModel
from app.patterns.singleton.grammar_singleton import GrammarSingleton
from app.services.jflap_service import build_jflap_models_for_token
from app.services.tree_service import build_token_real_trees, render_real_tree_svg, tree_to_parentheses
DEFAULT_SAMPLE_LOGS = """2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3}
2026-10-12T08:15:30 10.0.0.5 CRITICAL PRIVILEGE_ESCALATION {"user":"root","ctx":{"port":22}}
2026-09-20T14:32:05 192.168.1.10 @ ERROR LOGIN_FAILED {"user":"admin"}
2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3"""
grammar = GrammarSingleton()

def analyze_single_log(log_line, line_number=1):
    tokens = []
    lexical_errors = []

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
            'status': 'ERROR LÉXICO',
            'errors': lexical_errors,
            'tokens': tokens,
            'pda_trace': [],
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': ''
        }

    pos = 0
    pda_stack = ['Z0']
    pda_trace = ['(q0, w, Z0) ⊢ Estado inicial del Autómata de Pila con fondo Z0']
    semantic_fields = []
    semantic_errors = [f"Token {t['type']} ({t['value']}): {t['sem_msg']}" for t in tokens if not t['sem_ok']]

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
        if pos < len(tokens) and tokens[pos]['type'] != 'RBRACE':
            children.append(parse_fields())

        _, n_rb = match('RBRACE')
        children.append(n_rb)
        if pda_stack and pda_stack[-1] == '{':
            pda_stack.pop()
            pda_trace.append(f"Lee '}}' → Desapila '{{' (POP) | Pila: {''.join(pda_stack)}")

        return {'label': 'PAYLOAD', 'children': children}

    def parse_fields():
        nonlocal pos
        first_f = parse_field()
        if pos < len(tokens) and tokens[pos]['type'] == 'COMMA':
            _, n_cm = match('COMMA')
            rest_f = parse_fields()
            return {'label': 'FIELDS', 'children': [first_f, n_cm, rest_f]}
        return {'label': 'FIELDS', 'children': [first_f]}

    def parse_field():
        nonlocal pos
        k_tok, n_str = match('STRING')
        _, n_col = match('COLON')
        v_type, n_val = parse_value()
        semantic_fields.append((k_tok['value'], v_type))
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

        pda_trace.append("(qF, λ, Z0) ⊢ Pila vacía en Z0 y entrada consumida → CADENA ACEPTADA")

        general_syn_dict = {
            'label': 'LOG (Raíz S)',
            'children': [n_ts, n_ip, n_sev, n_evt, n_payload]
        }

        sem_valid = len(semantic_errors) == 0
        general_sem_dict = {
            'label': 'LOG.sem (Raíz AST)',
            'sub': 'VÁLIDO SOC' if sem_valid else 'ERROR DOMINIO',
            'children': [
                {'label': 'Tiempo', 'sub': ts_tok['value'], 'children': [{'label': 'Formato', 'sub': 'ISO-8601 OK' if ts_tok['sem_ok'] else 'Rango Inválido'}]},
                {'label': 'Origen Red', 'sub': ip_tok['value'], 'children': [{'label': 'Octetos', 'sub': '0..255 OK' if ip_tok['sem_ok'] else 'Octeto > 255'}]},
                {'label': 'Severidad', 'sub': sev_tok['value'], 'children': [{'label': 'SLA', 'sub': sev_tok['sem_msg']}]},
                {'label': 'Evento', 'sub': evt_tok['value'], 'children': [{'label': 'Regla', 'sub': 'SBS 504-2021'}]},
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
            'status': 'VÁLIDO (ACEPTADO)' if sem_valid else 'ERROR SEMÁNTICO',
            'errors': semantic_errors,
            'tokens': tokens,
            'pda_trace': pda_trace,
            'general_syn_svg': render_real_tree_svg(general_syn_dict, "syntactic"),
            'general_sem_svg': render_real_tree_svg(general_sem_dict, "semantic"),
            'general_paren': tree_to_parentheses(general_syn_dict)
        }

    except SyntaxError as e:
        pda_trace.append(f"❌ Rechazo en Autómata de Pila: {e}")
        return {
            'line_number': line_number,
            'raw': log_line,
            'valid_lexical': True,
            'valid_syntactic': False,
            'valid_semantic': False,
            'status': 'ERROR SINTÁCTICO',
            'errors': [str(e)],
            'tokens': tokens,
            'pda_trace': pda_trace,
            'general_syn_svg': '',
            'general_sem_svg': '',
            'general_paren': ''
        }


def save_results_to_storage(results):
    """Guarda los resultados en app/storage/ (datos.json y reportes.csv) reemplazando cualquier BD."""
    os.makedirs(Config.STORAGE_DIR, exist_ok=True)
    json_path = os.path.join(Config.STORAGE_DIR, 'datos.json')
    csv_path = os.path.join(Config.STORAGE_DIR, 'reportes.csv')

    export_data = []
    for r in results:
        export_data.append({
            'linea': r['line_number'],
            'log_crudo': r['raw'],
            'estado': r['status'],
            'total_tokens': len(r['tokens']),
            'errores': r['errors']
        })

    with open(json_path, 'w', encoding='utf-8') as jf:
        json.dump(export_data, jf, ensure_ascii=False, indent=2)

    with open(csv_path, 'w', newline='', encoding='utf-8') as cf:
        writer = csv.writer(cf)
        writer.writerow(['Linea', 'Estado', 'Total_Tokens', 'Log_Crudo'])
        for item in export_data:
            writer.writerow([item['linea'], item['estado'], item['total_tokens'], item['log_crudo']])
import hashlib
from datetime import datetime

# Patrón formal de defensa contra ataques de corrupción de Base de Datos (SQLi / NoSQLi / XSS)
DB_INJECTION_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b|--|;|\bOR\b\s+['\"\d]+=['\"\d]+|\$ne|\$gt|\$where|<script)",
    re.IGNORECASE
)

def verificar_defensa_bd(raw_line):
    """Método de defensa: detecta intentos de inyección para evitar corrupción en la BD."""
    match = DB_INJECTION_PATTERNS.search(raw_line)
    if match:
        return False, f"ATAQUE BLOQUEADO (Escudo BD): Patrón malicioso detectado '{match.group(0)}'."
    return True, "OK"

def generar_archivos_retroalimentacion(results, storage_dir="app/storage"):
    """Genera logs_erroneos.json y reporte_area_revision.txt exigidos por la retroalimentación."""
    os.makedirs(storage_dir, exist_ok=True)
    fecha_gen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    logs_erroneos = []
    logs_verificados = []

    for r in results:
        raw_log = r.get('raw', '')
        # Es válido solo si pasó léxico, sintáctico y semántico
        is_valid = r.get('valid_lexical', False) and r.get('valid_syntactic', False) and r.get('valid_semantic', False)
        
        # Aplicar escudo defensivo de Base de Datos
        seguro_bd, alerta_bd = verificar_defensa_bd(raw_log)
        if not seguro_bd:
            is_valid = False
            r['status'] = 'ATAQUE BLOQUEADO / ERROR'
            r.setdefault('errors', []).append(alerta_bd)

        if not is_valid:
            logs_erroneos.append({
                "linea": r.get('line_number'),
                "log_original": raw_log,
                "estado": "RECHAZADO_EN_CUARENTENA",
                "diagnostico": "; ".join(r.get('errors', ['Estructura inválida'])) if r.get('errors') else alerta_bd,
                "accion": "Revisión obligatoria por el Área de SOC / TI"
            })
        else:
            sello = hashlib.sha256(f"{raw_log.strip()}|USIL_SOC_2026".encode('utf-8')).hexdigest()[:16]
            r['db_seal'] = sello
            logs_verificados.append({
                "linea": r.get('line_number'),
                "log_original": raw_log,
                "sello_bd": f"SHA256-{sello}"
            })

    # 1. Guardar JSON exclusivo de erróneos
    ruta_json = os.path.join(storage_dir, "logs_erroneos.json")
    with open(ruta_json, "w", encoding="utf-8") as fj:
        json.dump({
            "metadata": {
                "proyecto": "Analizador Léxico-Sintáctico SOC con Escudo Anti-Inyección",
                "fecha_generacion": fecha_gen,
                "total_procesados": len(results),
                "total_erroneos": len(logs_erroneos)
            },
            "logs_erroneos": logs_erroneos
        }, fj, indent=4, ensure_ascii=False)

    # 2. Guardar archivo .TXT formal para el área encargada
    ruta_txt = os.path.join(storage_dir, "reporte_area_revision.txt")
    lineas_txt = [
        "================================================================================",
        "         REPORTE OFICIAL DE AUDITORÍA Y REVISIÓN DE LOGS — ÁREA SOC / TI        ",
        "================================================================================",
        f"Fecha de emisión        : {fecha_gen}",
        f"Total de logs procesados: {len(results)}",
        f"Logs Válidos (Aptos BD) : {len(logs_verificados)}",
        f"Logs Erróneos (Revisión): {len(logs_erroneos)}",
        "--------------------------------------------------------------------------------",
        "SECCIÓN A: LOGS ERRÓNEOS EN CUARENTENA (PARA REVISIÓN DEL ÁREA ENCARGADA)",
        "--------------------------------------------------------------------------------"
    ]

    if not logs_erroneos:
        lineas_txt.append("No se registraron logs erróneos en este lote.")
    else:
        for err in logs_erroneos:
            lineas_txt.append(
                f"[LÍNEA {err['linea']:02d}] ESTADO: {err['estado']}\n"
                f"  ├── Log Crudo   : {err['log_original']}\n"
                f"  ├── Diagnóstico : {err['diagnostico']}\n"
                f"  └── Acción Área : {err['accion']}\n"
            )

    lineas_txt.extend([
        "--------------------------------------------------------------------------------",
        "SECCIÓN B: LOGS VERIFICADOS CON SELLO CRIPTOGRÁFICO (APTOS PARA BASE DE DATOS)",
        "--------------------------------------------------------------------------------"
    ])

    if not logs_verificados:
        lineas_txt.append("No hay logs verificados en este lote.")
    else:
        for ok in logs_verificados:
            lineas_txt.append(
                f"[LÍNEA {ok['linea']:02d}] VERIFICADO_OK | SELLO_BD: {ok['sello_bd']}...\n"
                f"  └── Registro Limpio: {ok['log_original']}\n"
            )

    lineas_txt.append("================================================================================")
    with open(ruta_txt, "w", encoding="utf-8") as ft:
        ft.write("\n".join(lineas_txt))

def analyze_logs_input(raw_input):
    """Procesa el bloque de texto completo línea por línea y dispara las salidas del profesor."""
    lines = [line.strip() for line in raw_input.split('\n') if line.strip()]
    results = []
    accepted = 0
    rejected = 0
    total_tokens = 0

    for idx, line in enumerate(lines, start=1):
        res = analyze_single_log(line, line_number=idx)
        results.append(res)
        
        if res.get('valid_lexical') and res.get('valid_syntactic') and res.get('valid_semantic'):
            accepted += 1
        else:
            rejected += 1
        total_tokens += len(res.get('tokens', []))

    # Disparar la generación automática de los archivos solicitados
    generar_archivos_retroalimentacion(results)
    # Guardar en almacenamiento general (datos.json y reportes.csv) como ya tenías
    save_results_to_storage(results)

    summary = {
        'total_lines': len(lines),
        'total_tokens': total_tokens,
        'accepted': accepted,
        'rejected': rejected
    }

    return {
        'log_input': raw_input,
        'results': results,
        'summary': summary
    }