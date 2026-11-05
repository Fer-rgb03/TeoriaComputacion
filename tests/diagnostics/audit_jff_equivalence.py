#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditor Formal de Estructura XML y Equivalencia Matemática (AFD vs AFND) para JFLAP (.jff).
Ubicación: tests/diagnostics/audit_jff_equivalence.py
Modo: 100% Solo Lectura sobre app/storage/jff/ + Suite de Pruebas Negativas en memoria/copias temporales.
"""

import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from collections import deque

TOKENS = [
    "TIMESTAMP", "IP", "SEVERITY", "EVENT_TYPE", "STRING",
    "NUMBER", "LBRACE", "RBRACE", "COLON", "COMMA"
]

JFF_DIR = os.path.join("app", "storage", "jff")
IMPLICIT_SINK = "__IMPLICIT_SINK__"


def inspect_and_validate_jff(filepath, expected_kind="AFD"):
    """
    Tareas 1, 2, 3 y 4:
    Analiza un archivo .jff y valida su integridad estructural según su tipo ('AFD' o 'AFND'):
      1. XML válido, nodo <type>fa</type> y <automaton>.
      2. Estados con IDs únicos y nombres únicos (al menos 1 estado).
      3. Exactamente 1 estado inicial (<initial/>).
      4. Todas las transiciones referencian estados <from> y <to> existentes en Q.
      5. Ninguna transición consumidora tiene etiquetas multi-carácter (len(sym) == 1).
      6. Si expected_kind == 'AFD':
         - Prohibidas las transiciones épsilon (<read/> vacío).
         - Prohibido el no determinismo (dos destinos distintos o aristas repetidas para el mismo (estado, símbolo)).
         - Admite AFD parciales (registrando si es Total o Parcial sobre Σ_ASCII).
    """
    report = {
        "filepath": filepath,
        "kind": expected_kind,
        "exists": False,
        "structural_valid": False,
        "structural_errors": [],
        "error_codes": set(),
        "states": {},            # id -> name
        "initial_states": [],    # lista de ids con <initial/>
        "final_states": set(),   # conjunto de ids con <final/>
        "transitions": [],       # lista de (u, v, sym)
        "dfa_delta": {},         # (u, sym) -> v (solo para AFD válido)
        "epsilon_count": 0,
        "alphabet": set(),
        "is_partial_afd": False,
        "missing_transitions_count": 0,
    }

    if not os.path.isfile(filepath):
        report["structural_errors"].append(f"Archivo no encontrado: {filepath}")
        report["error_codes"].add("ARCHIVO_INEXISTENTE")
        return report

    report["exists"] = True

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except Exception as exc:
        report["structural_errors"].append(f"XML mal formado: {exc}")
        report["error_codes"].add("XML_MALFORMADO")
        return report

    type_text = (root.findtext("type") or "").strip()
    if type_text != "fa":
        report["structural_errors"].append(f"Tipo JFLAP inválido: se esperaba 'fa', se encontró {type_text!r}")
        report["error_codes"].add("TIPO_JFLAP_INVALIDO")

    automaton = root.find("automaton")
    if automaton is None:
        report["structural_errors"].append("El archivo no contiene el nodo <automaton>.")
        report["error_codes"].add("SIN_NODO_AUTOMATON")
        return report

    seen_ids = set()
    seen_names = set()

    for st in automaton.findall("state"):
        sid = st.attrib.get("id")
        sname = st.attrib.get("name")

        if sid is None or sid.strip() == "":
            report["structural_errors"].append("Estado sin atributo 'id'.")
            report["error_codes"].add("ID_ESTADO_VACIO")
            continue

        if sid in seen_ids:
            report["structural_errors"].append(f"ID de estado duplicado: id={sid!r}.")
            report["error_codes"].add("ID_ESTADO_DUPLICADO")
        seen_ids.add(sid)

        if sname is None or sname.strip() == "":
            sname = f"q{sid}"
        elif sname in seen_names:
            report["structural_errors"].append(f"Nombre de estado duplicado: name={sname!r}.")
            report["error_codes"].add("NOMBRE_ESTADO_DUPLICADO")
        seen_names.add(sname)

        report["states"][sid] = sname

        if st.find("initial") is not None:
            report["initial_states"].append(sid)
        if st.find("final") is not None:
            report["final_states"].add(sid)

    if len(report["states"]) == 0:
        report["structural_errors"].append("El autómata no declara ningún estado (Q = ∅).")
        report["error_codes"].add("CONJUNTO_ESTADOS_VACIO")

    if len(report["initial_states"]) == 0:
        report["structural_errors"].append("El autómata no tiene estado inicial (0 estados con <initial/>).")
        report["error_codes"].add("SIN_ESTADO_INICIAL")
    elif len(report["initial_states"]) > 1:
        names = [report["states"].get(i, i) for i in report["initial_states"]]
        report["structural_errors"].append(
            f"Múltiples estados iniciales ({len(report['initial_states'])}): {names}."
        )
        report["error_codes"].add("DOBLE_ESTADO_INICIAL")

    seen_exact_edges = set()
    state_symbol_targets = {}  # (u, sym) -> set of destination ids

    for idx, tr in enumerate(automaton.findall("transition"), start=1):
        from_el = tr.find("from")
        to_el = tr.find("to")
        read_el = tr.find("read")

        u = from_el.text.strip() if (from_el is not None and from_el.text is not None) else ""
        v = to_el.text.strip() if (to_el is not None and to_el.text is not None) else ""

        # IMPORTANTE: NO usar .strip() en <read> para preservar el espacio ' ' (ASCII 32)
        if read_el is None or read_el.text is None or read_el.text == "":
            sym = ""
            report["epsilon_count"] += 1
        else:
            sym = read_el.text
            report["alphabet"].add(sym)

        # Validar referencias de origen y destino
        if u not in report["states"] or v not in report["states"]:
            report["structural_errors"].append(
                f"Transición #{idx} referencia estado inexistente: from={u!r} -> to={v!r} (read={sym!r})."
            )
            report["error_codes"].add("ESTADO_INEXISTENTE")

        # Validar longitud atómica de símbolo
        if sym != "" and len(sym) != 1:
            report["structural_errors"].append(
                f"Transición #{idx} ({u}->{v}) contiene etiqueta multi-carácter o rango sin expandir: {sym!r}."
            )
            report["error_codes"].add("ETIQUETA_MULTICARACTER")

        edge_key = (u, v, sym)
        if edge_key in seen_exact_edges:
            report["structural_errors"].append(
                f"Transición duplicada exacta detectada: from={u!r}, to={v!r}, read={sym!r}."
            )
            report["error_codes"].add("TRANSICION_DUPLICADA")
        seen_exact_edges.add(edge_key)

        report["transitions"].append((u, v, sym))

        if expected_kind == "AFD":
            if sym == "":
                u_name = report["states"].get(u, u)
                v_name = report["states"].get(v, v)
                report["structural_errors"].append(
                    f"El AFD contiene una transición épsilon prohibida: {u_name} (id={u}) -> {v_name} (id={v})."
                )
                report["error_codes"].add("AFD_CON_EPSILON")
            else:
                pair = (u, sym)
                if pair not in state_symbol_targets:
                    state_symbol_targets[pair] = set()
                state_symbol_targets[pair].add(v)
                report["dfa_delta"][pair] = v

    if expected_kind == "AFD":
        for (u, sym), targets in state_symbol_targets.items():
            if len(targets) > 1:
                u_name = report["states"].get(u, u)
                t_names = [f"{report['states'].get(t, t)}(id={t})" for t in sorted(targets)]
                report["structural_errors"].append(
                    f"No determinismo en AFD: el estado {u_name} (id={u}) con símbolo {sym!r} "
                    f"transita a múltiples destinos: {', '.join(t_names)}."
                )
                report["error_codes"].add("AFD_NO_DETERMINISTA")

        # Comprobar si el AFD es total o parcial respecto a Σ_ASCII (95 símbolos imprimibles)
        sigma_ascii = {chr(c) for c in range(32, 127)}
        missing = 0
        for sid in report["states"]:
            for ch in sigma_ascii:
                if (sid, ch) not in report["dfa_delta"]:
                    missing += 1
        report["missing_transitions_count"] = missing
        report["is_partial_afd"] = (missing > 0)

    report["structural_valid"] = (len(report["structural_errors"]) == 0)
    return report


def epsilon_closure(state_set, transitions):
    """
    Tarea 4: Calcula la ε-clausura exacta de un conjunto de estados en un AFND,
    manejando cadenas transitivas y ciclos ε sin bucles infinitos.
    """
    closure = set(state_set)
    stack = list(state_set)
    while stack:
        u = stack.pop()
        for orig, dest, sym in transitions:
            if orig == u and sym == "" and dest not in closure:
                closure.add(dest)
                stack.append(dest)
    return frozenset(closure)


def move_afnd_subset(state_set, symbol, transitions):
    """Calcula move(S, a) para un subconjunto de estados S del AFND y un símbolo a."""
    reached = set()
    for orig, dest, sym in transitions:
        if orig in state_set and sym == symbol:
            reached.add(dest)
    return frozenset(reached)


def audit_pair_structure_and_equivalence(afd_filepath, afnd_filepath):
    """
    Tareas 1 a 5:
    1) Ejecuta primero la validación estructural estricta de AFD y AFND.
    2) Si alguno tiene errores estructurales, retorna estado estructural INVÁLIDO y
       equivalencia 'NO EVALUADO (ERROR ESTRUCTURAL)' (sin confundirlo con diferencia de lenguaje).
    3) Si ambos son estructuralmente válidos, ejecuta determinización por subconjuntos del AFND
       y búsqueda en anchura (BFS) sobre el autómata producto AFD × D(AFND), admitiendo
       AFD parciales mediante el estado sumidero implícito IMPLICIT_SINK.
    """
    afd_rep = inspect_and_validate_jff(afd_filepath, expected_kind="AFD")
    afnd_rep = inspect_and_validate_jff(afnd_filepath, expected_kind="AFND")

    if not afd_rep["structural_valid"] or not afnd_rep["structural_valid"]:
        combined_errors = (
            [f"[AFD] {e}" for e in afd_rep["structural_errors"]] +
            [f"[AFND] {e}" for e in afnd_rep["structural_errors"]]
        )
        return {
            "structural_status": "ERROR ESTRUCTURAL",
            "equivalence_status": "NO EVALUADO (ERROR ESTRUCTURAL)",
            "afd_report": afd_rep,
            "afnd_report": afnd_rep,
            "structural_errors": combined_errors,
            "error_codes": afd_rep["error_codes"] | afnd_rep["error_codes"],
            "witness": None,
            "discrepancy_side": None,
            "explored_pairs": 0,
        }

    # Alfabeto unificado: unión de alfabetos de ambos archivos + ASCII imprimible (32..126)
    sigma_ascii = {chr(c) for c in range(32, 127)}
    alphabet = sorted(afd_rep["alphabet"] | afnd_rep["alphabet"] | sigma_ascii)

    q0_afd = afd_rep["initial_states"][0]
    q0_afnd = afnd_rep["initial_states"][0]
    start_afnd_subset = epsilon_closure([q0_afnd], afnd_rep["transitions"])

    finals_afd = afd_rep["final_states"]
    finals_afnd = afnd_rep["final_states"]
    dfa_delta = afd_rep["dfa_delta"]
    afnd_transitions = afnd_rep["transitions"]

    # Cola BFS sobre el autómata producto: (estado_afd_o_IMPLICIT_SINK, subconjunto_afnd, palabra_actual)
    queue = deque([(q0_afd, start_afnd_subset, "")])
    visited = {(q0_afd, start_afnd_subset)}

    while queue:
        curr_afd, curr_afnd_sub, word = queue.popleft()

        acc_afd = (curr_afd != IMPLICIT_SINK) and (curr_afd in finals_afd)
        acc_afnd = bool(curr_afnd_sub & finals_afnd)

        # Diferencia simétrica: L(AFD) Δ L(AFND) != ∅
        if acc_afd != acc_afnd:
            side = (
                "Aceptada por AFD y Rechazada por AFND"
                if acc_afd else
                "Rechazada por AFD y Aceptada por AFND"
            )
            afd_state_label = (
                "q_sink (Sumidero Implícito)"
                if curr_afd == IMPLICIT_SINK
                else afd_rep["states"].get(curr_afd, curr_afd)
            )
            afnd_subset_labels = [afnd_rep["states"].get(s, s) for s in sorted(curr_afnd_sub)]
            return {
                "structural_status": "VÁLIDO",
                "equivalence_status": "NO EQUIVALENTE",
                "afd_report": afd_rep,
                "afnd_report": afnd_rep,
                "structural_errors": [],
                "error_codes": set(),
                "witness": word,
                "discrepancy_side": side,
                "afd_state_reached": afd_state_label,
                "afnd_subset_reached": afnd_subset_labels,
                "explored_pairs": len(visited),
            }

        for sym in alphabet:
            if curr_afd == IMPLICIT_SINK:
                next_afd = IMPLICIT_SINK
            else:
                # Si la transición (curr_afd, sym) no existe en el AFD parcial, va a IMPLICIT_SINK
                next_afd = dfa_delta.get((curr_afd, sym), IMPLICIT_SINK)

            next_afnd_sub = epsilon_closure(
                move_afnd_subset(curr_afnd_sub, sym, afnd_transitions),
                afnd_transitions
            )

            pair_state = (next_afd, next_afnd_sub)
            if pair_state not in visited:
                visited.add(pair_state)
                queue.append((next_afd, next_afnd_sub, word + sym))

    return {
        "structural_status": "VÁLIDO",
        "equivalence_status": "EQUIVALENTE",
        "afd_report": afd_rep,
        "afnd_report": afnd_rep,
        "structural_errors": [],
        "error_codes": set(),
        "witness": None,
        "discrepancy_side": None,
        "explored_pairs": len(visited),
    }


class TestNegativeAuditorCapabilities(unittest.TestCase):
    """
    Tareas 6 y 7:
    Suite de pruebas negativas sobre copias temporales aisladas (sin tocar app/storage/jff/).
    Verifica que el auditor:
      1. Detecte un estado inexistente en una transición.
      2. Detecte doble estado inicial.
      3. Detecte una transición no determinista en un AFD.
      4. Detecte una transición épsilon en un AFD.
      5. Detecte una diferencia intencional de lenguaje y entregue el contraejemplo mínimo.
      6. Admita un AFD parcial válido (sin estado trampa explícito) usando el sumidero implícito.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="audit_neg_test_")
        self.orig_afd_colon = os.path.join(JFF_DIR, "AFD_COLON.jff")
        self.orig_afnd_colon = os.path.join(JFF_DIR, "AFND_COLON.jff")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_temp_xml(self, filename, root):
        path = os.path.join(self.temp_dir.name, filename)
        tree = ET.ElementTree(root)
        tree.write(path, encoding="utf-8", xml_declaration=True)
        return path

    def test_neg_01_nonexistent_state_in_transition(self):
        """Caso 1: Transición que apunta a un estado inexistente (id='999')."""
        root = ET.parse(self.orig_afd_colon).getroot()
        aut = root.find("automaton")
        bad_tr = ET.SubElement(aut, "transition")
        ET.SubElement(bad_tr, "from").text = "0"
        ET.SubElement(bad_tr, "to").text = "999"
        ET.SubElement(bad_tr, "read").text = ";"

        mut_afd = self._write_temp_xml("AFD_COLON_bad_state.jff", root)
        res = audit_pair_structure_and_equivalence(mut_afd, self.orig_afnd_colon)

        self.assertEqual(res["structural_status"], "ERROR ESTRUCTURAL")
        self.assertEqual(res["equivalence_status"], "NO EVALUADO (ERROR ESTRUCTURAL)")
        self.assertIn("ESTADO_INEXISTENTE", res["error_codes"])
        self.assertIsNone(res["witness"])

    def test_neg_02_double_initial_state(self):
        """Caso 2: Doble estado inicial (<initial/> en q0 y en q1)."""
        root = ET.parse(self.orig_afd_colon).getroot()
        aut = root.find("automaton")
        for st in aut.findall("state"):
            if st.attrib.get("id") == "1":
                ET.SubElement(st, "initial")

        mut_afd = self._write_temp_xml("AFD_COLON_double_init.jff", root)
        res = audit_pair_structure_and_equivalence(mut_afd, self.orig_afnd_colon)

        self.assertEqual(res["structural_status"], "ERROR ESTRUCTURAL")
        self.assertEqual(res["equivalence_status"], "NO EVALUADO (ERROR ESTRUCTURAL)")
        self.assertIn("DOBLE_ESTADO_INICIAL", res["error_codes"])
        self.assertIsNone(res["witness"])

    def test_neg_03_nondeterministic_transition_in_afd(self):
        """Caso 3: Transición no determinista en un AFD (dos destinos para (q0, ':'))."""
        root = ET.parse(self.orig_afd_colon).getroot()
        aut = root.find("automaton")
        nd_tr = ET.SubElement(aut, "transition")
        ET.SubElement(nd_tr, "from").text = "0"
        ET.SubElement(nd_tr, "to").text = "2"
        ET.SubElement(nd_tr, "read").text = ":"

        mut_afd = self._write_temp_xml("AFD_COLON_nondet.jff", root)
        res = audit_pair_structure_and_equivalence(mut_afd, self.orig_afnd_colon)

        self.assertEqual(res["structural_status"], "ERROR ESTRUCTURAL")
        self.assertEqual(res["equivalence_status"], "NO EVALUADO (ERROR ESTRUCTURAL)")
        self.assertIn("AFD_NO_DETERMINISTA", res["error_codes"])
        self.assertIsNone(res["witness"])

    def test_neg_04_epsilon_transition_in_afd(self):
        """Caso 4: Transición épsilon (<read/> vacío) dentro de un archivo AFD."""
        root = ET.parse(self.orig_afd_colon).getroot()
        aut = root.find("automaton")
        eps_tr = ET.SubElement(aut, "transition")
        ET.SubElement(eps_tr, "from").text = "0"
        ET.SubElement(eps_tr, "to").text = "1"
        ET.SubElement(eps_tr, "read")  # <read/> vacío = épsilon

        mut_afd = self._write_temp_xml("AFD_COLON_epsilon.jff", root)
        res = audit_pair_structure_and_equivalence(mut_afd, self.orig_afnd_colon)

        self.assertEqual(res["structural_status"], "ERROR ESTRUCTURAL")
        self.assertEqual(res["equivalence_status"], "NO EVALUADO (ERROR ESTRUCTURAL)")
        self.assertIn("AFD_CON_EPSILON", res["error_codes"])
        self.assertIsNone(res["witness"])

    
    def test_neg_05_intentional_language_difference_with_counterexample(self):
        """
        Caso 5: Crear una diferencia de lenguaje manteniendo
        la estructura válida del AFD.

        El AFD modificado deja de aceptar ':'.
        El AFND original continúa aceptándolo.
        """
        root = ET.parse(self.orig_afd_colon).getroot()
        aut = root.find("automaton")

        # Eliminar la condición de aceptación de los estados.
        # No se eliminan estados ni transiciones.
        for st in aut.findall("state"):
            for final_el in list(st.findall("final")):
                st.remove(final_el)

        mut_afd = self._write_temp_xml(
            "AFD_COLON_lang_diff.jff",
            root
        )

        res = audit_pair_structure_and_equivalence(
            mut_afd,
            self.orig_afnd_colon
        )

        self.assertEqual(res["structural_status"], "VÁLIDO")
        self.assertEqual(res["equivalence_status"], "NO EQUIVALENTE")
        self.assertEqual(res["witness"], ":")
        self.assertEqual(
            res["discrepancy_side"],
            "Rechazada por AFD y Aceptada por AFND"
        )

    def test_neg_06_partial_afd_supported_via_implicit_sink(self):
        """
        Tarea 3: Verifica que un AFD parcial (sin estado trampa qT ni transiciones de rechazo)
        sea admitido como estructuralmente VÁLIDO (Parcial) y demostrado EQUIVALENTE al AFND
        mediante el estado sumidero implícito.
        """
        root = ET.parse(self.orig_afd_colon).getroot()
        aut = root.find("automaton")
        # Eliminar el estado trampa id='2' y todas las transiciones que salgan o entren a '2'
        for st in list(aut.findall("state")):
            if st.attrib.get("id") == "2":
                aut.remove(st)
        for tr in list(aut.findall("transition")):
            if tr.findtext("from") == "2" or tr.findtext("to") == "2":
                aut.remove(tr)

        partial_afd = self._write_temp_xml("AFD_COLON_partial.jff", root)
        res = audit_pair_structure_and_equivalence(partial_afd, self.orig_afnd_colon)

        self.assertEqual(res["structural_status"], "VÁLIDO")
        self.assertTrue(res["afd_report"]["is_partial_afd"])
        self.assertEqual(res["equivalence_status"], "EQUIVALENTE")
        self.assertIsNone(res["witness"])


def run_full_audit_and_negative_suite():
    print("=" * 120)
    print(" 1. AUDITORÍA ESTRUCTURAL Y EQUIVALENCIA FORMAL DE LOS 10 PARES ORIGINALES (app/storage/jff/)")
    print("=" * 120)
    header = (
        f"{'TOKEN':<11} | {'AFD (Q, F, T, Tipo)':<25} | {'AFND (Q, F, T, ε)':<22} | "
        f"{'VALIDACIÓN ESTRUCTURAL':<22} | {'EQUIVALENCIA FORMAL':<19} | {'PARES':<5} | {'CONTRAEJEMPLO'}"
    )
    print(header)
    print("-" * 120)

    all_originals_ok = True
    for tok in TOKENS:
        p_afd = os.path.join(JFF_DIR, f"AFD_{tok}.jff")
        p_afnd = os.path.join(JFF_DIR, f"AFND_{tok}.jff")
        res = audit_pair_structure_and_equivalence(p_afd, p_afnd)

        r_d = res["afd_report"]
        r_n = res["afnd_report"]

        dfa_Completeness = "Parcial" if r_d["is_partial_afd"] else "Total"
        afd_summary = f"Q={len(r_d['states'])},F={len(r_d['final_states'])},T={len(r_d['transitions'])},{dfa_Completeness}"
        afnd_summary = f"Q={len(r_n['states'])},F={len(r_n['final_states'])},T={len(r_n['transitions'])},ε={r_n['epsilon_count']}"
        witness_str = "Ninguno (∅)" if res["witness"] is None else repr(res["witness"])

        print(
            f"{tok:<11} | {afd_summary:<25} | {afnd_summary:<22} | "
            f"{res['structural_status']:<22} | {res['equivalence_status']:<19} | "
            f"{str(res['explored_pairs']):<5} | {witness_str}"
        )

        if res["structural_status"] != "VÁLIDO" or res["equivalence_status"] != "EQUIVALENTE":
            all_originals_ok = False
            for err in res["structural_errors"]:
                print(f"   -> DEFECTO ESTRUCTURAL: {err}")
            if res["witness"] is not None:
                print(f"   -> CONTRAEJEMPLO: {res['witness']!r} ({res['discrepancy_side']})")

    print("=" * 120)
    print("\n" + "=" * 120)
    print(" 2. EJECUCIÓN DE PRUEBAS NEGATIVAS EN COPIAS TEMPORALES AISLADAS (Tareas 6 y 7)")
    print("=" * 120)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestNegativeAuditorCapabilities)
    runner = unittest.TextTestRunner(verbosity=2)
    neg_result = runner.run(suite)

    if not all_originals_ok or not neg_result.wasSuccessful():
        sys.exit(1)


if __name__ == "__main__":
    run_full_audit_and_negative_suite()