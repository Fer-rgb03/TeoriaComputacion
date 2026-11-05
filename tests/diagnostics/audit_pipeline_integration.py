#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría de Integración del Pipeline (Solo Lectura — Import Corregido).
Ubicación: tests/diagnostics/audit_pipeline_integration.py
Restricción: 100% solo lectura. No modifica archivos de producción, ni .jff, ni las 61 pruebas.
"""

import os
import sys
import types
import traceback
import unittest
import xml.etree.ElementTree as ET


def _resolve_project_root():
    """
    Localiza la raíz real del proyecto buscando hacia arriba el directorio que contiene
    'app/services/analyzer_service.py', preservando también el cálculo original '../..'
    para diagnóstico.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    legacy_root = os.path.abspath(os.path.join(script_dir, "..", ".."))

    candidates = [legacy_root, os.getcwd(), script_dir]
    curr = script_dir
    for _ in range(5):
        curr = os.path.dirname(curr)
        if curr not in candidates:
            candidates.append(curr)

    for cand in candidates:
        marker = os.path.join(cand, "app", "services", "analyzer_service.py")
        if os.path.isfile(marker):
            return cand, legacy_root

    return legacy_root, legacy_root


PROJECT_ROOT, LEGACY_PROJECT_ROOT = _resolve_project_root()
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

JFF_DIR = os.path.join(PROJECT_ROOT, "app", "storage", "jff")

# Registro detallado de excepciones de importación y tracebacks completos
IMPORT_EXCEPTIONS_LOG = []
UNVERIFIED_COMPONENTS = []
FALLBACK_NAMESPACE_USED = False

analyze_single_log = None
get_formal_automaton_pair = None

try:
    from app.services.analyzer_service import analyze_single_log
except Exception as exc:
    IMPORT_EXCEPTIONS_LOG.append({
        "component": "app.services.analyzer_service.analyze_single_log (importación directa)",
        "exc_type": type(exc).__name__,
        "exc_msg": str(exc),
        "traceback": traceback.format_exc(),
    })

# CORRECCIÓN INSTRUCCIÓN 2: get_formal_automaton_pair está definida en app.services.jflap_service
try:
    from app.services.jflap_service import get_formal_automaton_pair
except Exception as exc:
    IMPORT_EXCEPTIONS_LOG.append({
        "component": "app.services.jflap_service.get_formal_automaton_pair (importación directa)",
        "exc_type": type(exc).__name__,
        "exc_msg": str(exc),
        "traceback": traceback.format_exc(),
    })

if analyze_single_log is None or get_formal_automaton_pair is None:
    app_pkg_dir = os.path.join(PROJECT_ROOT, "app")
    if os.path.isdir(app_pkg_dir):
        try:
            if "app" not in sys.modules:
                app_stub = types.ModuleType("app")
                app_stub.__path__ = [app_pkg_dir]
                sys.modules["app"] = app_stub
                FALLBACK_NAMESPACE_USED = True

            if analyze_single_log is None:
                from app.services.analyzer_service import analyze_single_log
            if get_formal_automaton_pair is None:
                from app.services.jflap_service import get_formal_automaton_pair
        except Exception as exc_retry:
            IMPORT_EXCEPTIONS_LOG.append({
                "component": "Reintento con namespace 'app' sin app/__init__.py",
                "exc_type": type(exc_retry).__name__,
                "exc_msg": str(exc_retry),
                "traceback": traceback.format_exc(),
            })

if analyze_single_log is None:
    UNVERIFIED_COMPONENTS.append("analyzer_service.analyze_single_log")
if get_formal_automaton_pair is None:
    UNVERIFIED_COMPONENTS.append("jflap_service.get_formal_automaton_pair")


def _read_required_bool(mapping, key, missing_list):
    """
    Lee una clave booleana obligatoria verificando primero que exista en el diccionario
    y que su valor sea realmente de tipo bool. Jamás utiliza bool(mapping.get(...)).
    """
    if not isinstance(mapping, dict):
        missing_list.append(f"{key} (contenedor no es dict)")
        return None
    if key not in mapping:
        missing_list.append(f"{key} (clave ausente)")
        return None
    val = mapping[key]
    if not isinstance(val, bool):
        missing_list.append(f"{key} (tipo {type(val).__name__}, se esperaba bool)")
        return None
    return val


def _read_required_type(mapping, key, expected_type, missing_list):
    """Verifica existencia y tipo de una clave obligatoria no booleana ('tokens', 'status')."""
    if not isinstance(mapping, dict):
        missing_list.append(f"{key} (contenedor no es dict)")
        return None
    if key not in mapping:
        missing_list.append(f"{key} (clave ausente)")
        return None
    val = mapping[key]
    if not isinstance(val, expected_type):
        missing_list.append(f"{key} (tipo {type(val).__name__}, se esperaba {expected_type.__name__})")
        return None
    return val


def format_phase_value(val):
    """Formatea un booleano de fase sin interpretar None como False: True->'OK', False->'ERR', None->'N/D'."""
    if val is True:
        return "OK"
    if val is False:
        return "ERR"
    return "N/D"


def format_automaton_value(val):
    """Formatea un resultado de autómata sin interpretar None como False: True->'Acc', False->'Rej', None->'N/D'."""
    if val is True:
        return "Acc"
    if val is False:
        return "Rej"
    return "N/D"


def simulate_jff_xml_strict(jff_path, word):
    """
    Simulador XML JFLAP autónomo (preserva ' ' ASCII 32 sin usar .strip() en <read>).
    Retorna siempre {'verified': bool, 'accepted': bool|None, 'error': str|None}.
    """
    if not os.path.isfile(jff_path):
        return {"verified": False, "accepted": None, "error": f"Archivo no encontrado: {jff_path}"}

    try:
        root = ET.parse(jff_path).getroot()
        automaton = root.find("automaton")
        if automaton is None:
            return {"verified": False, "accepted": None, "error": "Sin nodo <automaton>"}

        initials = []
        finals = set()
        transitions = []

        for st in automaton.findall("state"):
            sid = st.attrib.get("id")
            if st.find("initial") is not None:
                initials.append(sid)
            if st.find("final") is not None:
                finals.add(sid)

        for tr in automaton.findall("transition"):
            u = (tr.findtext("from") or "").strip()
            v = (tr.findtext("to") or "").strip()
            read_el = tr.find("read")
            if read_el is None or read_el.text is None or read_el.text == "":
                sym = ""
            else:
                sym = read_el.text
            transitions.append((u, v, sym))

        if len(initials) != 1:
            return {
                "verified": False,
                "accepted": None,
                "error": f"Cantidad inválida de estados iniciales: {len(initials)}"
            }

        def eps_closure(state_set):
            closure = set(state_set)
            stack = list(state_set)
            while stack:
                curr = stack.pop()
                for orig, dest, s in transitions:
                    if orig == curr and s == "" and dest not in closure:
                        closure.add(dest)
                        stack.append(dest)
            return frozenset(closure)

        current = eps_closure([initials[0]])
        for ch in word:
            next_set = {dest for orig, dest, s in transitions if orig in current and s == ch}
            current = eps_closure(next_set)
            if not current:
                break

        return {"verified": True, "accepted": bool(current & finals), "error": None}
    except Exception as exc:
        return {"verified": False, "accepted": None, "error": f"{type(exc).__name__}: {exc}"}


def build_log_with_target(target_category, target_lexeme):
    """Construye un log completo colocando el lexema objetivo en su posición gramatical."""
    base_ts = "2026-10-17T08:43:29"
    base_ip = "192.168.1.10"
    base_sev = "ERROR"
    base_evt = "LOGIN_FAILED"
    base_str = '"admin"'
    base_num = "5"

    if target_category == "TIMESTAMP":
        base_ts = target_lexeme
    elif target_category == "IP":
        base_ip = target_lexeme
    elif target_category == "SEVERITY":
        base_sev = target_lexeme
    elif target_category == "EVENT_TYPE":
        base_evt = target_lexeme
    elif target_category == "STRING":
        base_str = target_lexeme
    elif target_category == "NUMBER":
        base_num = target_lexeme

    return f'{base_ts} {base_ip} {base_sev} {base_evt} {{"user":{base_str},"attempts":{base_num}}}'


def make_empty_case_record(case_id, category, lexeme, description):
    """
    Crea un diccionario con el esquema completo de claves inicializadas en None
    para que ninguna función consumidora sufra KeyError cuando un componente no esté verificado.
    """
    return {
        "id": case_id,
        "category": category,
        "lexeme": lexeme,
        "description": description,
        "valid_lexical": None,
        "valid_syntactic": None,
        "valid_semantic": None,
        "valid_security": None,
        "is_valid": None,
        "log_status": None,
        "observed_log_keys": [],
        "missing_log_keys": [],
        "lexer_token_type": None,
        "lexer_accepts_as_cat": None,
        "embedded_afd_accepted": None,
        "afd_has_simulate": False,
        "afnd_has_simulate": False,
        "afd_mem": None,
        "afnd_mem": None,
        "afd_jff": None,
        "afnd_jff": None,
        "jff_afd_verified": False,
        "jff_afnd_verified": False,
        "jff_afd_error": None,
        "jff_afnd_error": None,
        "afd_error_pos": None,
        "afd_error_sym": None,
        "unverified_reasons": [],
        "classification": "NO_VERIFICADO",
        "explanation": "",
    }


def evaluate_integration_case(
    case_id,
    category,
    lexeme,
    description,
    analyzer_fn=None,
    automaton_pair_fn=None,
    jff_sim_fn=None,
    jff_dir_override=None,
):
    """
    Evalúa un caso de integración de forma defensiva:
      - Jamás lanza KeyError si un componente falla o no puede verificarse.
      - No usa bool(log_res.get(...)) para campos obligatorios.
      - Comprueba que afd_model y afnd_model tengan el método simulate() y que devuelvan 'accepted' booleano.
      - Verifica 'verified' y 'error' de ambos simuladores JFF antes de comparar.
    """
    rec = make_empty_case_record(case_id, category, lexeme, description)

    fn_analyze = analyze_single_log if analyzer_fn is None else analyzer_fn
    fn_pair = get_formal_automaton_pair if automaton_pair_fn is None else automaton_pair_fn
    fn_jff = simulate_jff_xml_strict if jff_sim_fn is None else jff_sim_fn
    target_jff_dir = JFF_DIR if jff_dir_override is None else jff_dir_override

    # 1. Evaluar Analizador Principal (analyze_single_log)
    if fn_analyze is None:
        rec["unverified_reasons"].append("analyze_single_log no disponible")
    else:
        try:
            full_log = build_log_with_target(category, lexeme)
            log_res = fn_analyze(full_log, 1)
            if not isinstance(log_res, dict):
                rec["unverified_reasons"].append(
                    f"analyze_single_log devolvió {type(log_res).__name__} en vez de dict"
                )
            else:
                rec["observed_log_keys"] = sorted(log_res.keys())
                missing = []
                rec["valid_lexical"] = _read_required_bool(log_res, "valid_lexical", missing)
                rec["valid_syntactic"] = _read_required_bool(log_res, "valid_syntactic", missing)
                rec["valid_semantic"] = _read_required_bool(log_res, "valid_semantic", missing)
                if "valid_security" in log_res and isinstance(log_res["valid_security"], bool):
                    rec["valid_security"] = log_res["valid_security"]
                if "is_valid" in log_res and isinstance(log_res["is_valid"], bool):
                    rec["is_valid"] = log_res["is_valid"]

                rec["log_status"] = _read_required_type(log_res, "status", str, missing)
                tokens = _read_required_type(log_res, "tokens", list, missing)
                rec["missing_log_keys"] = missing

                if missing:
                    rec["unverified_reasons"].append(
                        f"Claves obligatorias ausentes/inválidas en analyze_single_log: {missing}"
                    )

                if isinstance(tokens, list):
                    matched_token = None
                    for t in tokens:
                        if isinstance(t, dict) and t.get("value") == lexeme and t.get("type") == category:
                            matched_token = t
                            break
                    if matched_token is None:
                        for t in tokens:
                            if isinstance(t, dict) and t.get("value") == lexeme:
                                matched_token = t
                                break

                    if matched_token is not None:
                        rec["lexer_token_type"] = matched_token.get("type", "SIN_TIPO")
                        dyn = matched_token.get("dynamic_simulation")
                        if isinstance(dyn, dict):
                            afd_dyn = dyn.get("afd")
                            if isinstance(afd_dyn, dict) and "accepted" in afd_dyn and isinstance(afd_dyn["accepted"], bool):
                                rec["embedded_afd_accepted"] = afd_dyn["accepted"]
                    else:
                        rec["lexer_token_type"] = "FRAGMENTADO/MISMATCH"

                    if rec["valid_lexical"] is not None:
                        rec["lexer_accepts_as_cat"] = (
                            matched_token is not None
                            and matched_token.get("type") == category
                            and rec["valid_lexical"] is True
                        )
        except Exception as exc:
            rec["unverified_reasons"].append(f"Excepción en analyze_single_log: {type(exc).__name__}: {exc}")

    # 2. Evaluar Modelos Formales en Memoria (AFD y AFND) — Instrucción 3
    if fn_pair is None:
        rec["unverified_reasons"].append("get_formal_automaton_pair no disponible")
    else:
        try:
            afd_model, afnd_model, _ = fn_pair(category)
            rec["afd_has_simulate"] = callable(getattr(afd_model, "simulate", None))
            rec["afnd_has_simulate"] = callable(getattr(afnd_model, "simulate", None))

            if not rec["afd_has_simulate"] or not rec["afnd_has_simulate"]:
                rec["unverified_reasons"].append(
                    f"Modelo sin método simulate(): AFD={rec['afd_has_simulate']}, AFND={rec['afnd_has_simulate']}"
                )
            else:
                afd_mem_res = afd_model.simulate(lexeme)
                afnd_mem_res = afnd_model.simulate(lexeme)

                missing_mem = []
                rec["afd_mem"] = _read_required_bool(afd_mem_res, "accepted", missing_mem)
                rec["afnd_mem"] = _read_required_bool(afnd_mem_res, "accepted", missing_mem)
                if isinstance(afd_mem_res, dict):
                    rec["afd_error_pos"] = afd_mem_res.get("error_position")
                    rec["afd_error_sym"] = afd_mem_res.get("error_symbol")
                if missing_mem:
                    rec["unverified_reasons"].append(f"Claves inválidas en simulate() en memoria: {missing_mem}")
        except Exception as exc:
            rec["unverified_reasons"].append(f"Excepción en autómatas en memoria: {type(exc).__name__}: {exc}")

    # 3. Evaluar Archivos .jff en Disco verificando 'verified' y 'error'
    p_afd_jff = os.path.join(target_jff_dir, f"AFD_{category}.jff")
    p_afnd_jff = os.path.join(target_jff_dir, f"AFND_{category}.jff")

    jff_afd_res = fn_jff(p_afd_jff, lexeme)
    jff_afnd_res = fn_jff(p_afnd_jff, lexeme)

    if (
        isinstance(jff_afd_res, dict)
        and jff_afd_res.get("verified") is True
        and jff_afd_res.get("error") is None
        and isinstance(jff_afd_res.get("accepted"), bool)
    ):
        rec["jff_afd_verified"] = True
        rec["afd_jff"] = jff_afd_res["accepted"]
    else:
        err_msg = jff_afd_res.get("error") if isinstance(jff_afd_res, dict) else "Respuesta JFF inválida"
        rec["jff_afd_error"] = err_msg or "Simulador JFF AFD retornó verified=False"
        rec["unverified_reasons"].append(f"AFD_{category}.jff no verificado: {rec['jff_afd_error']}")

    if (
        isinstance(jff_afnd_res, dict)
        and jff_afnd_res.get("verified") is True
        and jff_afnd_res.get("error") is None
        and isinstance(jff_afnd_res.get("accepted"), bool)
    ):
        rec["jff_afnd_verified"] = True
        rec["afnd_jff"] = jff_afnd_res["accepted"]
    else:
        err_msg = jff_afnd_res.get("error") if isinstance(jff_afnd_res, dict) else "Respuesta JFF inválida"
        rec["jff_afnd_error"] = err_msg or "Simulador JFF AFND retornó verified=False"
        rec["unverified_reasons"].append(f"AFND_{category}.jff no verificado: {rec['jff_afnd_error']}")

    # 4. Si algún componente obligatorio no pudo verificarse, devolver NO_VERIFICADO con N/D en columnas faltantes
    required_verdicts = (
        rec["valid_lexical"],
        rec["valid_syntactic"],
        rec["valid_semantic"],
        rec["afd_mem"],
        rec["afnd_mem"],
        rec["afd_jff"],
        rec["afnd_jff"],
    )
    if rec["unverified_reasons"] or any(v is None for v in required_verdicts):
        rec["classification"] = "NO_VERIFICADO"
        rec["explanation"] = "; ".join(rec["unverified_reasons"])
        return rec

    # 5. Clasificación rigurosa basada en resultados observados y reglas documentadas
    valid_lex = rec["valid_lexical"]
    valid_syn = rec["valid_syntactic"]
    valid_sem = rec["valid_semantic"]
    valid_sec = True if rec["valid_security"] is None else rec["valid_security"]
    afd_mem_acc = rec["afd_mem"]
    afnd_mem_acc = rec["afnd_mem"]
    afd_jff_acc = rec["afd_jff"]
    afnd_jff_acc = rec["afnd_jff"]
    status = rec["log_status"]
    actual_token_type = rec["lexer_token_type"]
    lexer_recognized_as_expected = rec["lexer_accepts_as_cat"]

    automata_all_agree = (afd_mem_acc == afnd_mem_acc == afd_jff_acc == afnd_jff_acc)
    log_globally_accepted = (valid_lex and valid_syn and valid_sem and valid_sec)

    if not automata_all_agree:
        rec["classification"] = "DISCREPANCIA: MEMORIA_VS_JFF"
        rec["explanation"] = (
            f"Los motores formales difieren entre sí: AFD_Mem={afd_mem_acc}, "
            f"AFND_Mem={afnd_mem_acc}, AFD_JFF={afd_jff_acc}, AFND_JFF={afnd_jff_acc}."
        )
    elif lexer_recognized_as_expected and not afd_mem_acc and log_globally_accepted:
        rec["classification"] = "DISCREPANCIA: DEFECTO_REAL_INTEGRACION_LEXICA"
        rec["explanation"] = (
            f"Defecto real comprobado: el analizador acepta globalmente el log con {lexeme!r} "
            f"(LEX=OK, SIN=OK, SEM=OK, status='{status}'), pero el autómata formal de {category} "
            f"(en memoria y .jff) RECHAZA el lexema en pos={rec['afd_error_pos']} "
            f"(símbolo={rec['afd_error_sym']!r}, embedded_afd_accepted={rec['embedded_afd_accepted']}). "
            f"El veredicto del AFD en dynamic_simulation es ignorado por analyze_single_log()."
        )
    elif lexer_recognized_as_expected and not afd_mem_acc and not log_globally_accepted:
        rec["classification"] = "DIFERENCIA_FASE: RECHAZO_LEXICO_AFD_VS_RECHAZO_SEMANTICO"
        rec["explanation"] = (
            f"Ambos rechazan el registro globalmente, pero en distinta fase: el AFD/AFND/JFF de {category} "
            f"rechaza {lexeme!r} en fase léxica (pos={rec['afd_error_pos']}, sym={rec['afd_error_sym']!r}), "
            f"mientras el lexer Python acepta el patrón superficial (LEX=OK) y delega el rechazo a '{status}'."
        )
    elif not lexer_recognized_as_expected and afd_mem_acc:
        rec["classification"] = "DISCREPANCIA: LEXER_RECHAZA_Y_AFD_ACEPTA"
        rec["explanation"] = (
            f"El autómata {category} acepta {lexeme!r}, pero el lexer Python dio "
            f"valid_lexical={valid_lex} (tipo={actual_token_type}, status='{status}')."
        )
    elif valid_lex and not afd_mem_acc and actual_token_type != category:
        rec["classification"] = "DIFERENCIA_DISEÑO: TOKENIZACION_POR_PATRON_Y_RECHAZO_SINTACTICO"
        rec["explanation"] = (
            f"Regla documentada: AFD_{category} rechaza {lexeme!r} (Rej). Como el escáner léxico tokeniza sin "
            f"contexto posicional, clasifica {lexeme!r} como {actual_token_type} (LEX=OK) y el parser PDA "
            f"rechaza la secuencia en Fase Sintáctica (SIN=ERR, status='{status}')."
        )
    elif lexer_recognized_as_expected and afd_mem_acc and not log_globally_accepted:
        rec["classification"] = "COINCIDENCIA_LEXICA (RECHAZO_SEMANTICO_DOCUMENTADO)"
        rec["explanation"] = (
            f"Regla documentada: acuerdo léxico 100% (LEX=OK y AFD/AFND/JFF=Acc). El rechazo posterior "
            f"en '{status}' (SEM={'OK' if valid_sem else 'ERR'}) corresponde a validación semántica de dominio."
        )
    else:
        rec["classification"] = "COINCIDENCIA_TOTAL"
        rec["explanation"] = (
            f"Acuerdo total entre Analizador Python (LEX={format_phase_value(valid_lex)}, "
            f"SIN={format_phase_value(valid_syn)}, SEM={format_phase_value(valid_sem)}, "
            f"tipo={actual_token_type}, status='{status}') y los 4 motores formales "
            f"(AFD_M={format_automaton_value(afd_mem_acc)}, AFND_M={format_automaton_value(afnd_mem_acc)}, "
            f"AFD_J={format_automaton_value(afd_jff_acc)}, AFND_J={format_automaton_value(afnd_jff_acc)})."
        )

    return rec


INTEGRATION_CASES = [
    # 1. TIMESTAMP
    ("CP-I01", "TIMESTAMP", "2026-10-17T08:43:29", "TIMESTAMP válido estándar"),
    ("CP-I02", "TIMESTAMP", "2026-13-01T14:32:05", "Frontera: Mes 13 (fuera de 01..12)"),
    ("CP-I03", "TIMESTAMP", "2026-10-12T24:00:00", "Frontera: Hora 24 (fuera de 00..23)"),
    ("CP-I04", "TIMESTAMP", "2027-02-29T12:35:42", "Frontera: Año no bisiesto (semántico)"),
    ("CP-I05", "TIMESTAMP", "2026/10/17T08:43:29", "TIMESTAMP inválido con barras '/'"),
    # 2. IP
    ("CP-I06", "IP", "192.168.1.10", "IP válida estándar"),
    ("CP-I07", "IP", "192.168.1.256", "Frontera: IP con octeto 256 (> 255)"),
    ("CP-I08", "IP", "192.168.001.10", "Frontera: IP con cero inicial (001)"),
    ("CP-I09", "IP", "192.168.1", "IP inválida incompleta (3 octetos)"),
    # 3. SEVERITY
    ("CP-I10", "SEVERITY", "ERROR", "SEVERITY válida (ERROR)"),
    ("CP-I11", "SEVERITY", "DEBUG", "Frontera: Severidad no admitida (DEBUG)"),
    ("CP-I12", "SEVERITY", "ERR", "SEVERITY truncada inválida (ERR)"),
    # 4. EVENT_TYPE
    ("CP-I13", "EVENT_TYPE", "LOGIN_FAILED", "EVENT_TYPE válido con guion bajo"),
    ("CP-I14", "EVENT_TYPE", "_LOGIN", "EVENT_TYPE inválido con '_' inicial"),
    # 5. STRING
    ("CP-I15", "STRING", '"admin"', "STRING válido alfabético"),
    ("CP-I16", "STRING", '"hola mundo"', "Frontera: STRING con espacio interno"),
    ("CP-I17", "STRING", '"conexión"', "Frontera: STRING con carácter Unicode ('ó')"),
    ("CP-I18", "STRING", r'"Alerta en \"servidor\""', "Frontera: STRING con comillas escapadas"),
    # 6. NUMBER
    ("CP-I19", "NUMBER", "5", "NUMBER entero no negativo válido"),
    ("CP-I20", "NUMBER", "007", "Frontera: NUMBER con ceros iniciales (007)"),
    ("CP-I21", "NUMBER", "-15", "NUMBER negativo inválido (-15)"),
]


def format_table_row(r):
    """Formatea una fila de la tabla usando 'N/D' para cualquier valor None."""
    b_lex = format_phase_value(r.get("valid_lexical"))
    b_syn = format_phase_value(r.get("valid_syntactic"))
    b_sem = format_phase_value(r.get("valid_semantic"))
    b_dm = format_automaton_value(r.get("afd_mem"))
    b_nm = format_automaton_value(r.get("afnd_mem"))
    b_dj = format_automaton_value(r.get("afd_jff"))
    b_nj = format_automaton_value(r.get("afnd_jff"))
    lex_disp = r["lexeme"] if len(r["lexeme"]) <= 24 else r["lexeme"][:21] + "..."
    return (
        f"{r['id']:<6} | {r['category']:<10} | {lex_disp:<24} | {b_lex:<4} | {b_syn:<4} | "
        f"{b_sem:<4} | {b_dm:<5} | {b_nm:<6} | {b_dj:<5} | {b_nj:<6} | {r['classification']}"
    )


class TestPipelineIntegrationDiagnostic(unittest.TestCase):
    """
    Pruebas automatizadas del propio diagnóstico de integración que comprueban:
      - Manejo seguro de NO_VERIFICADO mostrando 'N/D' sin KeyError ni coerción a False.
      - Inspección estricta de claves reales de analyze_single_log() y del método simulate() con 'accepted'.
      - Comprobación de 'verified' y 'error' en ambos simuladores JFF.
      - No clasificación de separaciones léxico/semánticas documentadas como defectos.
      - Detección con evidencia de discrepancias reales.
    """

    @classmethod
    def setUpClass(cls):
        cls.results = {c[0]: evaluate_integration_case(*c) for c in INTEGRATION_CASES}

    def test_diag_01_unverified_components_show_nd_and_never_coerce_to_false(self):
        """
        Si analyze_single_log o get_formal_automaton_pair no están disponibles, o si falta una
        clave obligatoria, debe devolverse NO_VERIFICADO y mostrarse 'N/D' en las columnas
        afectadas sin lanzar KeyError y sin interpretar None como False ('ERR'/'Rej').
        """
        res_no_analyzer = evaluate_integration_case(
            "CP-TEST1", "TIMESTAMP", "2026-10-17T08:43:29", "Sin analizador",
            analyzer_fn=lambda line, idx: {}
        )
        self.assertEqual(res_no_analyzer["classification"], "NO_VERIFICADO")
        self.assertIsNone(res_no_analyzer["valid_lexical"])
        self.assertIsNone(res_no_analyzer["valid_syntactic"])
        self.assertIsNone(res_no_analyzer["valid_semantic"])
        row_str = format_table_row(res_no_analyzer)
        self.assertIn("| N/D  | N/D  | N/D  |", row_str)

    def test_diag_02_jff_simulator_checks_verified_and_error_before_comparison(self):
        """
        Si cualquiera de los dos simuladores JFF devuelve verified=False o error!=None,
        su columna debe ser None ('N/D') y el caso debe marcarse como NO_VERIFICADO.
        """
        def broken_jff_sim(path, word):
            return {"verified": False, "accepted": None, "error": "Error simulado de lectura XML"}

        res_bad_jff = evaluate_integration_case(
            "CP-TEST2", "IP", "192.168.1.10", "JFF no verificado",
            jff_sim_fn=broken_jff_sim
        )
        self.assertEqual(res_bad_jff["classification"], "NO_VERIFICADO")
        self.assertFalse(res_bad_jff["jff_afd_verified"])
        self.assertFalse(res_bad_jff["jff_afnd_verified"])
        self.assertIsNone(res_bad_jff["afd_jff"])
        self.assertIsNone(res_bad_jff["afnd_jff"])
        row_str = format_table_row(res_bad_jff)
        self.assertIn("| N/D   | N/D    | NO_VERIFICADO", row_str)

    def test_diag_03_analyze_single_log_and_automata_simulate_contract_verified(self):
        """
        Instrucción 3 y 5: Verifica que las claves obligatorias reales ('valid_lexical',
        'valid_syntactic', 'valid_semantic', 'tokens', 'status') existan y que los modelos
        AFD y AFND obtenidos de jflap_service tengan simulate() y devuelvan 'accepted' booleano
        (mostrando 'Acc' o 'Rej' en lugar de 'N/D' en los 21 casos).
        """
        r = self.results["CP-I01"]
        self.assertEqual(r["missing_log_keys"], [], f"Claves faltantes: {r['missing_log_keys']}")
        for required_key in ("valid_lexical", "valid_syntactic", "valid_semantic", "tokens", "status"):
            self.assertIn(required_key, r["observed_log_keys"])
        self.assertTrue(r["afd_has_simulate"])
        self.assertTrue(r["afnd_has_simulate"])
        self.assertIs(r["valid_lexical"], True)
        self.assertIs(r["valid_syntactic"], True)
        self.assertIs(r["valid_semantic"], True)
        self.assertEqual(r["classification"], "COINCIDENCIA_TOTAL")

        # Confirmar que ninguno de los 21 casos tenga None ('N/D') en AFD_M o AFND_M
        for cid, rec in self.results.items():
            self.assertIn(rec["afd_mem"], (True, False), f"{cid}: AFD_M quedó en N/D")
            self.assertIn(rec["afnd_mem"], (True, False), f"{cid}: AFND_M quedó en N/D")

    def test_diag_04_documented_semantic_rejections_are_not_classified_as_defects(self):
        """
        Verifica que 2027-02-29T12:35:42 (CP-I04), 192.168.1.256 (CP-I07) y
        192.168.001.10 (CP-I08) sean aceptados léxicamente por el analizador y los 4 autómatas,
        rechazados en fase semántica, y clasificados como separación documentada (no defecto).
        """
        for cid in ("CP-I04", "CP-I07", "CP-I08"):
            r = self.results[cid]
            self.assertIs(r["valid_lexical"], True)
            self.assertIs(r["valid_semantic"], False)
            self.assertIs(r["afd_mem"], True)
            self.assertIs(r["afnd_mem"], True)
            self.assertIs(r["afd_jff"], True)
            self.assertIs(r["afnd_jff"], True)
            self.assertEqual(
                r["classification"],
                "COINCIDENCIA_LEXICA (RECHAZO_SEMANTICO_DOCUMENTADO)",
                f"Falso positivo en {cid}: {r['classification']}"
            )

    def test_diag_05_debug_and_err_tokenized_as_event_type_and_rejected_syntactically(self):
        """
        Verifica que DEBUG (CP-I11) y ERR (CP-I12) sean rechazados por AFD_SEVERITY,
        tokenizados como EVENT_TYPE por el escáner y rechazados en Fase Sintáctica por el PDA.
        """
        for cid in ("CP-I11", "CP-I12"):
            r = self.results[cid]
            self.assertIs(r["afd_mem"], False)
            self.assertIs(r["afnd_mem"], False)
            self.assertIs(r["afd_jff"], False)
            self.assertIs(r["afnd_jff"], False)
            self.assertIs(r["valid_lexical"], True)
            self.assertIs(r["valid_syntactic"], False)
            self.assertEqual(r["lexer_token_type"], "EVENT_TYPE")
            self.assertEqual(
                r["classification"],
                "DIFERENCIA_DISEÑO: TOKENIZACION_POR_PATRON_Y_RECHAZO_SINTACTICO"
            )

    def test_diag_06_month_13_hour_24_unicode_and_escaped_quotes_observed_rules(self):
        """
        Verifica los resultados observados en los casos frontera CP-I02 (mes 13),
        CP-I03 (hora 24), CP-I17 (Unicode) y CP-I18 (comillas escapadas).
        """
        for cid in ("CP-I02", "CP-I03", "CP-I17"):
            r = self.results[cid]
            self.assertIs(r["afd_mem"], False)
            self.assertIs(r["afnd_mem"], False)
            self.assertIs(r["afd_jff"], False)
            self.assertIs(r["afnd_jff"], False)
            self.assertIn(
                r["classification"],
                ("COINCIDENCIA_TOTAL", "DIFERENCIA_FASE: RECHAZO_LEXICO_AFD_VS_RECHAZO_SEMANTICO")
            )

        r18 = self.results["CP-I18"]
        self.assertIs(r18["valid_lexical"], True)
        self.assertIs(r18["valid_syntactic"], True)
        self.assertIs(r18["valid_semantic"], True)
        if r18["afd_mem"] is False:
            self.assertEqual(r18["classification"], "DISCREPANCIA: DEFECTO_REAL_INTEGRACION_LEXICA")
            self.assertIs(r18["embedded_afd_accepted"], False)
        else:
            self.assertEqual(r18["classification"], "COINCIDENCIA_TOTAL")


def main():
    print("=" * 148)
    print(" DIAGNÓSTICO DE IMPORTACIÓN Y ENTORNO DE EJECUCIÓN")
    print("=" * 148)
    print(f"Intérprete Python         : {sys.executable}")
    print(f"PROJECT_ROOT ('../..')    : {LEGACY_PROJECT_ROOT}")
    print(f"PROJECT_ROOT resuelto     : {PROJECT_ROOT}")
    print(f"Directorio JFF            : {JFF_DIR} (Existe={os.path.isdir(JFF_DIR)})")

    if IMPORT_EXCEPTIONS_LOG:
        print("\n[!] EXCEPCIÓN CAPTURADA DURANTE LA IMPORTACIÓN:")
        for idx, item in enumerate(IMPORT_EXCEPTIONS_LOG, start=1):
            print(f"  {idx}. Componente : {item['component']}")
            print(f"     Excepción  : {item['exc_type']}: {item['exc_msg']}")
            print("     Traceback completo:")
            for line in item["traceback"].strip().splitlines():
                print(f"       {line}")
    else:
        print("Estado de importación     : OK (analyze_single_log y get_formal_automaton_pair importados sin errores)")

    print("\n" + "=" * 148)
    print(" TABLA DE LOS 21 CASOS DE INTEGRACIÓN: ANALIZADOR PYTHON vs. AFD/AFND EN MEMORIA vs. ARCHIVOS JFF")
    print("=" * 148)
    header = (
        f"{'ID':<6} | {'CAT':<10} | {'ENTRADA (LEXEMA)':<24} | {'LEX':<4} | {'SIN':<4} | "
        f"{'SEM':<4} | {'AFD_M':<5} | {'AFND_M':<6} | {'AFD_J':<5} | {'AFND_J':<6} | {'CLASIFICACIÓN'}"
    )
    print(header)
    print("-" * 148)

    results = []
    for case in INTEGRATION_CASES:
        r = evaluate_integration_case(*case)
        results.append(r)
        print(format_table_row(r))

    print("=" * 148)
    print("\nEVIDENCIA DETALLADA DE DISCREPANCIAS Y SEPARACIONES DE FASE DOCUMENTADAS:")
    print("-" * 148)
    for r in results:
        if r["classification"] != "COINCIDENCIA_TOTAL":
            print(f"* [{r['id']}] {r['category']} ({r['lexeme']!r}) -> {r['classification']}")
            print(f"  Explicación: {r['explanation']}")

    print("\n" + "=" * 148)
    print(" EJECUTANDO PRUEBAS AUTOMATIZADAS DEL DIAGNÓSTICO (6 PRUEBAS)")
    print("=" * 148)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestPipelineIntegrationDiagnostic)
    runner = unittest.TextTestRunner(verbosity=2)
    test_res = runner.run(suite)
    if not test_res.wasSuccessful():
        sys.exit(1)


if __name__ == "__main__":
    main()