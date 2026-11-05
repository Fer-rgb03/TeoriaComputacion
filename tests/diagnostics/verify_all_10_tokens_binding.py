#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría de Solo Lectura: Coherencia de los 10 Tokens y Verificación Explícita de Vinculación
sobre valid_lexical=False.
Ubicación: tests/diagnostics/verify_all_10_tokens_binding.py
Restricciones:
  - No modifica archivos de producción, ni los 20 .jff, ni el JAR de JFLAP, ni las 61 pruebas.
  - Compara la gramática EVENT_TYPE por comportamiento, no por igualdad literal de regex.
  - T04-L comprueba aceptación léxica y deja constancia del rechazo semántico observado.
  - Verifica explícitamente en test_03 que los 10 rechazos forzados provoquen valid_lexical=False.
"""

import inspect
import os
import sys
import types
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch


def _resolve_project_root():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for cand in (
        os.path.abspath(os.path.join(script_dir, "..", "..")),
        os.getcwd(),
        script_dir,
    ):
        if os.path.isfile(os.path.join(cand, "app", "services", "analyzer_service.py")):
            return cand
    return os.path.abspath(os.path.join(script_dir, "..", ".."))


PROJECT_ROOT = _resolve_project_root()
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from app.services.analyzer_service import analyze_single_log
    import app.services.jflap_service as jflap_service
    from app.services.jflap_service import get_formal_automaton_pair
    from app.services.automata_engine import (
        TOKEN_FORMAL_REGEX_AST_SPECS,
        FormalAutomatonModel,
        build_thompson_afnd,
        subset_construction_afnd_to_afd,
        simulate_loaded_jff_directly,
    )
    from app.patterns.singleton.grammar_singleton import GrammarSingleton
except Exception:
    app_pkg_dir = os.path.join(PROJECT_ROOT, "app")
    if "app" not in sys.modules and os.path.isdir(app_pkg_dir):
        app_stub = types.ModuleType("app")
        app_stub.__path__ = [app_pkg_dir]
        sys.modules["app"] = app_stub
    from app.services.analyzer_service import analyze_single_log
    import app.services.jflap_service as jflap_service
    from app.services.jflap_service import get_formal_automaton_pair
    from app.services.automata_engine import (
        TOKEN_FORMAL_REGEX_AST_SPECS,
        FormalAutomatonModel,
        build_thompson_afnd,
        subset_construction_afnd_to_afd,
        simulate_loaded_jff_directly,
    )
    try:
        from app.patterns.singleton.grammar_singleton import GrammarSingleton
    except Exception:
        from app.patterns.singleton.grammar_singleton import GrammarSingleton

JFF_DIR = os.path.join(PROJECT_ROOT, "app", "storage", "jff")

ALL_10_TOKENS = [
    "TIMESTAMP", "IP", "SEVERITY", "EVENT_TYPE", "STRING",
    "NUMBER", "LBRACE", "RBRACE", "COLON", "COMMA"
]


def inspect_event_type_definitions():
    """
    Tarea 1: Inspecciona la expresión regular formal de EVENT_TYPE, la expresión del lexer
    Python y las transiciones de AFD_EVENT_TYPE.jff y AFND_EVENT_TYPE.jff.
    """
    grammar = GrammarSingleton()
    formal_regex = TOKEN_FORMAL_REGEX_AST_SPECS.get("EVENT_TYPE", "N/D")
    meta_regex = grammar.TOKEN_METADATA.get("EVENT_TYPE", {}).get("regex", "N/D")

    lexer_spec_regex = "N/D"
    for name, pattern in getattr(grammar, "TOKEN_SPECS", []):
        if name == "EVENT_TYPE":
            lexer_spec_regex = pattern
            break

    def summarize_jff(path):
        root = ET.parse(path).getroot()
        aut = root.find("automaton")
        states = {st.attrib["id"]: st.attrib.get("name", st.attrib["id"]) for st in aut.findall("state")}
        finals = [
            st.attrib.get("name", st.attrib["id"])
            for st in aut.findall("state")
            if st.find("final") is not None
        ]
        non_trap_Transitions = {}
        eps_count = 0
        total_tr = 0
        for tr in aut.findall("transition"):
            total_tr += 1
            u = states.get(tr.findtext("from"), tr.findtext("from"))
            v = states.get(tr.findtext("to"), tr.findtext("to"))
            read_el = tr.find("read")
            sym = "" if (read_el is None or read_el.text is None) else read_el.text
            if sym == "":
                eps_count += 1
            if v != "qT" and u != "qT":
                non_trap_Transitions.setdefault((u, v), set()).add(sym if sym != "" else "ε")
        return {
            "states_count": len(states),
            "finals": finals,
            "total_transitions": total_tr,
            "epsilon_count": eps_count,
            "active_edges": {
                f"{u}->{v}": (
                    f"[A..Z] (26)" if syms == {chr(c) for c in range(ord("A"), ord("Z") + 1)}
                    else sorted(syms)
                )
                for (u, v), syms in sorted(non_trap_Transitions.items())
            },
        }

    p_afd = os.path.join(JFF_DIR, "AFD_EVENT_TYPE.jff")
    p_afnd = os.path.join(JFF_DIR, "AFND_EVENT_TYPE.jff")
    return {
        "formal_regex_automata_engine": formal_regex,
        "lexer_spec_regex_python": lexer_spec_regex,
        "metadata_regex_python": meta_regex,
        "afd_jff_summary": summarize_jff(p_afd),
        "afnd_jff_summary": summarize_jff(p_afnd),
    }


# 30 Casos (Válido, Límite e Inválido para los 10 tipos de tokens).
# T04-L corregido según la gramática real de EVENT_TYPE: [A..Z][A..Z]*(_[A..Z][A..Z]*)* (sin dígitos).
CASES_30_ALL_TOKENS = [
    # 1. TIMESTAMP
    ("T01-V", "TIMESTAMP", "Válido estándar", "2026-10-17T08:43:29", "2026-10-17T08:43:29", "TIMESTAMP",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T01-L", "TIMESTAMP", "Límite (Año no bisiesto)", "2027-02-29T12:35:42", "2027-02-29T12:35:42", "TIMESTAMP",
     '2027-02-29T12:35:42 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, False),
    ("T01-I", "TIMESTAMP", "Inválido (Mes 13)", "2026-13-01T14:32:05", "2026-13-01T14:32:05", "ERROR_LEXICO",
     '2026-13-01T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     False, False, False, False, False),

    # 2. IP
    ("T02-V", "IP", "Válido estándar", "192.168.1.10", "192.168.1.10", "IP",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T02-L", "IP", "Límite (Octeto 256 > 255)", "192.168.1.256", "192.168.1.256", "IP",
     '2026-10-17T08:43:29 192.168.1.256 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, False),
    ("T02-I", "IP", "Inválido (3 octetos: 192.168.1)", "192.168.1", ".", "ERROR_LEXICO",
     '2026-10-17T08:43:29 192.168.1 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     False, False, False, False, False),

    # 3. SEVERITY
    ("T03-V", "SEVERITY", "Válido (ERROR)", "ERROR", "ERROR", "SEVERITY",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T03-L", "SEVERITY", "Límite (CRITICAL 8 chars)", "CRITICAL", "CRITICAL", "SEVERITY",
     '2026-10-17T08:43:29 192.168.1.10 CRITICAL LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T03-I", "SEVERITY", "Inválido (DEBUG -> EVENT_TYPE)", "DEBUG", "DEBUG", "EVENT_TYPE",
     '2026-10-17T08:43:29 192.168.1.10 DEBUG LOGIN_FAILED {"user":"admin","attempts":5}',
     False, True, True, False, False),

    # 4. EVENT_TYPE (T04-L: patrón léxico válido; el analizador reportó rechazo semántico)
    ("T04-V", "EVENT_TYPE", "Válido (LOGIN_FAILED)", "LOGIN_FAILED", "LOGIN_FAILED", "EVENT_TYPE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T04-L", "EVENT_TYPE", "Límite léxico (rechazo semántico observado)", "PRIVILEGE_ESCALATION_ATTEMPT", "PRIVILEGE_ESCALATION_ATTEMPT", "EVENT_TYPE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR PRIVILEGE_ESCALATION_ATTEMPT {"user":"admin","attempts":5}',
     True, True, True, True, False),
    ("T04-I", "EVENT_TYPE", "Inválido ('_' inicial: _LOGIN)", "_LOGIN", "_LOGIN", None,
     '2026-10-17T08:43:29 192.168.1.10 ERROR _LOGIN {"user":"admin","attempts":5}',
     False, False, False, False, False),

    # 5. STRING
    ("T05-V", "STRING", "Válido (\"admin\")", '"admin"', '"admin"', "STRING",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T05-L", "STRING", "Límite (Cadena vacía \"\")", '""', '""', "STRING",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"","attempts":5}',
     True, True, True, True, True),
    ("T05-I", "STRING", "Inválido (Unicode \"conexión\")", '"conexión"', '"conexión"', None,
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"conexión","attempts":5}',
     False, False, False, False, False),

    # 6. NUMBER
    ("T06-V", "NUMBER", "Válido (5)", "5", "5", "NUMBER",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T06-L", "NUMBER", "Límite (>10^9 semántico)", "1000000001", "1000000001", "NUMBER",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":1000000001}',
     True, True, True, True, False),
    ("T06-I", "NUMBER", "Inválido (Cero inicial 007)", "007", "007", "ERROR_LEXICO",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":007}',
     False, False, False, False, False),

    # 7. LBRACE '{'
    ("T07-V", "LBRACE", "Válido ('{')", "{", "{", "LBRACE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T07-L", "LBRACE", "Límite (JSON anidado 2 niveles)", "{", "{", "LBRACE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","meta":{"port":22}}',
     True, True, True, True, True),
    ("T07-I", "LBRACE", "Puntuación repetida ('{{' -> 2x'{' + SIN=ERR)", "{{", "{", "LBRACE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {{"user":"admin","attempts":5}',
     False, True, True, False, False),

    # 8. RBRACE '}'
    ("T08-V", "RBRACE", "Válido ('}')", "}", "}", "RBRACE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T08-L", "RBRACE", "Límite (Cierre JSON anidado 2 niveles)", "}", "}", "RBRACE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","meta":{"port":22}}',
     True, True, True, True, True),
    ("T08-I", "RBRACE", "Puntuación repetida ('}}' -> 2x'}' + SIN=ERR)", "}}", "}", "RBRACE",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}}',
     False, True, True, False, False),

    # 9. COLON ':'
    ("T09-V", "COLON", "Válido (':')", ":", ":", "COLON",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T09-L", "COLON", "Límite (Múltiples ':' en JSON anidado)", ":", ":", "COLON",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5,"src":"db"}',
     True, True, True, True, True),
    ("T09-I", "COLON", "Puntuación repetida ('::' -> 2x':' + SIN=ERR)", "::", ":", "COLON",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user"::"admin","attempts":5}',
     False, True, True, False, False),

    # 10. COMMA ','
    ("T10-V", "COMMA", "Válido (',')", ",", ",", "COMMA",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}',
     True, True, True, True, True),
    ("T10-L", "COMMA", "Límite (3 comas en JSON multicampo/anidado)", ",", ",", "COMMA",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5,"meta":{"ip":"10.0.0.1","port":22}}',
     True, True, True, True, True),
    ("T10-I", "COMMA", "Puntuación repetida (',,' -> 2x',' + SIN=ERR)", ",,", ",", "COMMA",
     '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin",,"attempts":5}',
     False, True, True, False, False),
]


def probe_token_binding_in_memory(tok_type):
    """
    Tarea 5:
    Reutiliza los modelos reales (afd_model, afnd_model) construidos por get_formal_automaton_pair(tok_type)
    y fuerza el rechazo exclusivamente en memoria interceptando afd_model.simulate y afnd_model.simulate.
    Comprueba tanto la ejecución real del método como si el rechazo provoca valid_lexical=False.
    """
    valid_log = '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}'
    afd_model, afnd_model, _ = get_formal_automaton_pair(tok_type)

    orig_afd_simulate = afd_model.simulate
    orig_afnd_simulate = afnd_model.simulate

    afd_intercepted_calls = []
    afnd_intercepted_calls = []

    def forced_reject_afd(lexeme):
        afd_intercepted_calls.append(lexeme)
        real_reject = dict(orig_afd_simulate("~"))
        real_reject["accepted"] = False
        real_reject["result"] = "Reject"
        real_reject["final_states"] = []
        real_reject["error_position"] = 1
        real_reject["error_symbol"] = lexeme[0] if lexeme else "~"
        return real_reject

    def forced_reject_afnd(lexeme):
        afnd_intercepted_calls.append(lexeme)
        real_reject = dict(orig_afnd_simulate("~"))
        real_reject["accepted"] = False
        real_reject["result"] = "Reject"
        real_reject["final_states"] = []
        real_reject["error_position"] = 1
        real_reject["error_symbol"] = lexeme[0] if lexeme else "~"
        return real_reject

    with patch.object(afd_model, "simulate", side_effect=forced_reject_afd), \
         patch.object(afnd_model, "simulate", side_effect=forced_reject_afnd):
        res = analyze_single_log(valid_log, 1)

    matching_tokens = [tk for tk in res.get("tokens", []) if tk.get("type") == tok_type]
    target_tok = matching_tokens[0] if matching_tokens else None

    dyn = target_tok.get("dynamic_simulation", {}) if target_tok else {}
    dyn_afd_acc = dyn.get("afd", {}).get("accepted")
    dyn_afnd_acc = dyn.get("afnd", {}).get("accepted")
    dyn_lex_acc = dyn.get("lexical_accepted")

    injection_executed = (
        len(afd_intercepted_calls) > 0
        and len(afnd_intercepted_calls) > 0
        and target_tok is not None
        and dyn_afd_acc is False
        and dyn_afnd_acc is False
    )

    is_binding = bool(injection_executed and (res.get("valid_lexical") is False))
    if not injection_executed:
        verdict = "ERROR_DIAGNOSTICO: INYECCION_NO_EJECUTADA"
    elif is_binding:
        verdict = "VINCULANTE (valid_lexical=False)"
    else:
        verdict = "NO VINCULANTE (valid_lexical=True)"

    return {
        "tok_type": tok_type,
        "token_found": target_tok is not None,
        "occurrences_in_log": len(matching_tokens),
        "sample_lexeme": target_tok.get("value", "") if target_tok else "",
        "afd_calls_count": len(afd_intercepted_calls),
        "afnd_calls_count": len(afnd_intercepted_calls),
        "injection_executed": injection_executed,
        "dyn_afd_accepted": dyn_afd_acc,
        "dyn_afnd_accepted": dyn_afnd_acc,
        "dyn_lexical_accepted": dyn_lex_acc,
        "log_valid_lexical": res.get("valid_lexical"),
        "log_valid_syntactic": res.get("valid_syntactic"),
        "log_valid_semantic": res.get("valid_semantic"),
        "log_is_valid": res.get("is_valid"),
        "log_status": res.get("status"),
        "is_binding": is_binding,
        "verdict": verdict,
    }


class TestAll10TokensDiagnosticSuite(unittest.TestCase):
    """Suite automatizada del diagnóstico de los 10 tokens (30 casos + 10 sondas de vinculación)."""

    def test_01_event_type_grammar_and_rejection_of_auth_stage_2_verified(self):
        """
        Tareas 1 y 2: Comprueba que EVENT_TYPE está definido como [A..Z][A..Z]*(_[A..Z][A..Z]*)*
        (solo letras mayúsculas y guiones bajos simples) y que por ello rechaza 'AUTH_STAGE_2',
        '_LOGIN' y 'LOGIN__', mientras acepta 'LOGIN_FAILED' y 'PRIVILEGE_ESCALATION_ATTEMPT'.
        """
        info = inspect_event_type_definitions()
        # Dos ER sintácticamente distintas pueden representar el mismo lenguaje.
        # La prueba debe verificar reconocimiento real, no identidad textual de la ER.
        self.assertIsInstance(info["formal_regex_automata_engine"], str)
        self.assertNotEqual(info["formal_regex_automata_engine"], "N/D")

        afd_m, afnd_m, _ = get_formal_automaton_pair("EVENT_TYPE")
        p_afd = os.path.join(JFF_DIR, "AFD_EVENT_TYPE.jff")
        p_afnd = os.path.join(JFF_DIR, "AFND_EVENT_TYPE.jff")

        for valid_evt in ("LOGIN_FAILED", "PRIVILEGE_ESCALATION", "PRIVILEGE_ESCALATION_ATTEMPT"):
            self.assertTrue(afd_m.simulate(valid_evt)["accepted"], f"AFD debe aceptar {valid_evt}")
            self.assertTrue(afnd_m.simulate(valid_evt)["accepted"], f"AFND debe aceptar {valid_evt}")
            self.assertTrue(simulate_loaded_jff_directly(p_afd, valid_evt))
            self.assertTrue(simulate_loaded_jff_directly(p_afnd, valid_evt))

        for invalid_evt in ("AUTH_STAGE_2", "_LOGIN", "LOGIN__", "LOGIN_"):
            self.assertFalse(afd_m.simulate(invalid_evt)["accepted"], f"AFD debe rechazar {invalid_evt}")
            self.assertFalse(afnd_m.simulate(invalid_evt)["accepted"], f"AFND debe rechazar {invalid_evt}")
            self.assertFalse(simulate_loaded_jff_directly(p_afd, invalid_evt))
            self.assertFalse(simulate_loaded_jff_directly(p_afnd, invalid_evt))

    def test_02_all_30_cases_find_target_token_and_match_coherence(self):
        """Verifica la coherencia de los 30 casos (válidos, límites e inválidos) en los 10 tokens."""
        for (
            cid, tok_type, kind_label, isolated_lexeme, expected_tok_val, expected_tok_type,
            log_line, exp_iso_aut, exp_tok_aut, exp_lex, exp_syn, exp_sem
        ) in CASES_30_ALL_TOKENS:
            afd_m, afnd_m, _ = get_formal_automaton_pair(tok_type)
            afd_iso = afd_m.simulate(isolated_lexeme)["accepted"]
            afnd_iso = afnd_m.simulate(isolated_lexeme)["accepted"]
            p_afd = os.path.join(JFF_DIR, f"AFD_{tok_type}.jff")
            p_afnd = os.path.join(JFF_DIR, f"AFND_{tok_type}.jff")
            jff_afd_iso = simulate_loaded_jff_directly(p_afd, isolated_lexeme)
            jff_afnd_iso = simulate_loaded_jff_directly(p_afnd, isolated_lexeme)

            self.assertEqual(afd_iso, exp_iso_aut, f"{cid}: AFD_M falló en cadena aislada {isolated_lexeme!r}")
            self.assertEqual(afnd_iso, exp_iso_aut, f"{cid}: AFND_M falló en cadena aislada {isolated_lexeme!r}")
            self.assertEqual(jff_afd_iso, exp_iso_aut, f"{cid}: AFD_JFF falló en {isolated_lexeme!r}")
            self.assertEqual(jff_afnd_iso, exp_iso_aut, f"{cid}: AFND_JFF falló en {isolated_lexeme!r}")

            res = analyze_single_log(log_line, 1)
            tokens = res.get("tokens", [])
            self.assertGreater(len(tokens), 0, f"{cid}: analyze_single_log no produjo tokens")

            if expected_tok_type is not None:
                found = [
                    t for t in tokens
                    if t.get("value") == expected_tok_val and t.get("type") == expected_tok_type
                ]
            else:
                found = [
                    t for t in tokens
                    if expected_tok_val in t.get("value", "") or t.get("type") == "ERROR_LEXICO"
                ]

            self.assertGreater(
                len(found), 0,
                f"{cid}: No se encontró el token esperado ({expected_tok_type}, {expected_tok_val!r}) en {tokens}"
            )

            tok_dyn = found[0].get("dynamic_simulation", {})
            self.assertIsNotNone(tok_dyn, f"{cid}: El token no contiene dynamic_simulation")
            self.assertEqual(
                tok_dyn.get("afd", {}).get("accepted"),
                exp_tok_aut,
                f"{cid}: Resultado inesperado en dynamic_simulation['afd']['accepted'] del token en el log"
            )

            if cid == "T10-L":
                comma_tokens = [t for t in tokens if t.get("type") == "COMMA" and t.get("value") == ","]
                self.assertEqual(len(comma_tokens), 3, "T10-L debe contener exactamente 3 tokens COMMA")

            if cid in ("T07-I", "T08-I", "T09-I", "T10-I"):
                self.assertFalse(afd_iso, f"{cid}: El autómata debe rechazar la secuencia doble {isolated_lexeme!r}")
                self.assertTrue(
                    tok_dyn.get("afd", {}).get("accepted"),
                    f"{cid}: Cada signo individual {expected_tok_val!r} debe ser aceptado por su AFD"
                )
                self.assertGreaterEqual(len(found), 2)
                self.assertTrue(res["valid_lexical"])
                self.assertFalse(res["valid_syntactic"])

            self.assertEqual(res["valid_lexical"], exp_lex, f"{cid}: valid_lexical discrepó")
            self.assertEqual(res["valid_syntactic"], exp_syn, f"{cid}: valid_syntactic discrepó")
            self.assertEqual(res["valid_semantic"], exp_sem, f"{cid}: valid_semantic discrepó")
            if cid == "T04-L":
                # Evidencia reportada en el entorno del usuario: el patrón es aceptado
                # léxica y sintácticamente, pero rechazado semánticamente.
                # Esto NO confirma la causa: debe inspeccionarse la regla de dominio.
                self.assertTrue(res["valid_lexical"])
                self.assertTrue(res["valid_syntactic"])
                self.assertFalse(res["valid_semantic"])
                self.assertEqual(res["status"], "ERROR SEMÁNTICO")

    def test_03_all_10_binding_probes_explicitly_provoke_valid_lexical_false(self):
        """
        Tarea 5:
        Verifica explícitamente que en los 10 tipos de tokens:
          1) Se intercepten y ejecuten realmente afd_model.simulate y afnd_model.simulate.
          2) El rechazo forzado de cada uno de los 10 tokens provoque explícitamente
             valid_lexical == False en el resultado de analyze_single_log().
        """
        non_binding_failures = []
        for tok in ALL_10_TOKENS:
            probe = probe_token_binding_in_memory(tok)
            self.assertTrue(probe["token_found"], f"No se encontró el token {tok} en el log de prueba")
            self.assertGreater(
                probe["afd_calls_count"], 0,
                f"El parche de AFD NO interceptó ninguna llamada en analyze_single_log() para {tok}"
            )
            self.assertGreater(
                probe["afnd_calls_count"], 0,
                f"El parche de AFND NO interceptó ninguna llamada en analyze_single_log() para {tok}"
            )
            self.assertTrue(probe["injection_executed"], f"Inyección no ejecutada en {tok}")
            self.assertIs(probe["dyn_afd_accepted"], False)
            self.assertIs(probe["dyn_afnd_accepted"], False)
            self.assertIs(probe["dyn_lexical_accepted"], False)

            if probe["log_valid_lexical"] is not False or not probe["is_binding"]:
                non_binding_failures.append(
                    f"{tok} (lexema={probe['sample_lexeme']!r}, llamadas={probe['afd_calls_count']}/{probe['afnd_calls_count']}, "
                    f"AFD={probe['dyn_afd_accepted']}, AFND={probe['dyn_afnd_accepted']}, "
                    f"valid_lexical={probe['log_valid_lexical']}, status={probe['log_status']!r})"
                )

        self.assertEqual(
            non_binding_failures,
            [],
            "Discrepancia real de vinculación: los siguientes rechazos forzados de AFD/AFND "
            "NO provocaron valid_lexical=False en analyze_single_log(): "
            + "; ".join(non_binding_failures)
        )

    def test_04_models_restored_intact_after_memory_probes(self):
        """Verifica que al salir del contexto de parche en memoria los 10 autómatas quedan intactos."""
        samples = {
            "TIMESTAMP": "2026-10-17T08:43:29",
            "IP": "192.168.1.10",
            "SEVERITY": "ERROR",
            "EVENT_TYPE": "LOGIN_FAILED",
            "STRING": '"admin"',
            "NUMBER": "5",
            "LBRACE": "{",
            "RBRACE": "}",
            "COLON": ":",
            "COMMA": ",",
        }
        for tok, lex in samples.items():
            afd_m, afnd_m, _ = get_formal_automaton_pair(tok)
            self.assertTrue(afd_m.simulate(lex)["accepted"], f"El AFD {tok} quedó alterado")
            self.assertTrue(afnd_m.simulate(lex)["accepted"], f"El AFND {tok} quedó alterado")


def main():
    print("=" * 150)
    print(" 0. INSPECCIÓN DE EVENT_TYPE (EXPRESIÓN FORMAL, LEXER PYTHON Y TRANSICIONES JFF — TAREAS 1 A 4)")
    print("=" * 150)
    evt_info = inspect_event_type_definitions()
    print(f"  - ER Formal (automata_engine.py) : {evt_info['formal_regex_automata_engine']}")
    print(f"  - ER Lexer Python (TOKEN_SPECS)  : {evt_info['lexer_spec_regex_python']}")
    print(f"  - ER Metadatos (TOKEN_METADATA)  : {evt_info['metadata_regex_python']}")
    print(f"  - Resumen AFD_EVENT_TYPE.jff     : {evt_info['afd_jff_summary']}")
    print(f"  - Resumen AFND_EVENT_TYPE.jff    : {evt_info['afnd_jff_summary']}")

    print("\n" + "=" * 150)
    print(" 1. TABLA DE LOS 30 CASOS EN LOS 10 TOKENS (T04-L: DISTINCIÓN LÉXICO / SEMÁNTICO)")
    print("=" * 150)
    header = (
        f"{'ID':<5} | {'TOKEN':<10} | {'DESCRIPCIÓN DEL CASO':<48} | {'CADENA':<19} | "
        f"{'AUT_AISLADO':<11} | {'AUT_TOKEN_LOG':<13} | {'LEX':<3} | {'SIN':<3} | {'SEM':<3} | {'ESTADO GLOBAL'}"
    )
    print(header)
    print("-" * 150)

    for (
        cid, tok_type, kind_label, isolated_lexeme, expected_tok_val, expected_tok_type,
        log_line, exp_iso_aut, exp_tok_aut, exp_lex, exp_syn, exp_sem
    ) in CASES_30_ALL_TOKENS:
        afd_m, afnd_m, _ = get_formal_automaton_pair(tok_type)
        iso_acc = afd_m.simulate(isolated_lexeme)["accepted"] and afnd_m.simulate(isolated_lexeme)["accepted"]
        res = analyze_single_log(log_line, 1)
        tokens = res.get("tokens", [])
        if expected_tok_type is not None:
            found = [t for t in tokens if t.get("value") == expected_tok_val and t.get("type") == expected_tok_type]
        else:
            found = [t for t in tokens if expected_tok_val in t.get("value", "") or t.get("type") == "ERROR_LEXICO"]

        tok_acc = found[0]["dynamic_simulation"]["afd"]["accepted"] if found else None
        b_iso = "Acc / Acc" if iso_acc else "Rej / Rej"
        b_tok = "Acc / Acc" if tok_acc is True else ("Rej / Rej" if tok_acc is False else "N/D")
        b_lex = "OK" if res["valid_lexical"] else "ERR"
        b_syn = "OK" if res["valid_syntactic"] else "ERR"
        b_sem = "OK" if res["valid_semantic"] else "ERR"
        cad_disp = isolated_lexeme if len(isolated_lexeme) <= 19 else isolated_lexeme[:16] + "..."
        print(
            f"{cid:<5} | {tok_type:<10} | {kind_label:<48} | {cad_disp:<19} | "
            f"{b_iso:<11} | {b_tok:<13} | {b_lex:<3} | {b_syn:<3} | {b_sem:<3} | {res['status']}"
        )

    print("=" * 150)
    print("NOTA T04-L: el rechazo semántico es el resultado observado en la captura;")
    print("su justificación como regla de negocio sigue pendiente de inspeccionar.")
    print("\n" + "=" * 150)
    print(" 2. RESULTADOS DE LAS 10 SONDAS DE VINCULACIÓN FORZADA (VERIFICANDO valid_lexical=False — TAREA 5)")
    print("=" * 150)
    b_header = (
        f"{'TOKEN':<10} | {'LEXEMA':<19} | {'LLAMADAS (AFD/AFND)':<19} | "
        f"{'AFD':<5} | {'AFND':<5} | {'dyn.lex_acc':<11} | {'valid_lexical':<13} | "
        f"{'ESTADO GLOBAL':<19} | {'VEREDICTO'}"
    )
    print(b_header)
    print("-" * 150)

    for tok in ALL_10_TOKENS:
        p = probe_token_binding_in_memory(tok)
        calls_str = f"{p['afd_calls_count']} / {p['afnd_calls_count']} (Ejecutado)"
        print(
            f"{p['tok_type']:<10} | {p['sample_lexeme']:<19} | {calls_str:<19} | "
            f"{str(p['dyn_afd_accepted']):<5} | {str(p['dyn_afnd_accepted']):<5} | "
            f"{str(p['dyn_lexical_accepted']):<11} | {str(p['log_valid_lexical']):<13} | "
            f"{p['log_status']:<19} | {p['verdict']}"
        )
    print("=" * 150)

    print("\n" + "=" * 150)
    print(" 3. EJECUTANDO SUITE AUTOMATIZADA DEL DIAGNÓSTICO (4 PRUEBAS)")
    print("=" * 150)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestAll10TokensDiagnosticSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    res_test = runner.run(suite)
    if not res_test.wasSuccessful():
        sys.exit(1)


if __name__ == "__main__":
    main()