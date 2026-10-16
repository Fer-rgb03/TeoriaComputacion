import os
import re
import json
import csv
from app.config import Config
from app.models.token_model import TokenModel
from app.patterns.singleton.grammar_singleton import GrammarSingleton
from app.services.jflap_service import build_jflap_models_for_token
from app.services.tree_service import build_token_real_trees, render_real_tree_svg, tree_to_parentheses

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