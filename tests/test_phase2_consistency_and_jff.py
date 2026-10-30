import os
import re
import base64
import random
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from app.services.automata_engine import (
    SIGMA_ASCII,
    TOKEN_FORMAL_REGEX_AST_SPECS,
    validate_jff_xml_ten_requirements,
    parse_jff_xml_to_automaton,
    simulate_loaded_jff_directly
)
from app.services.jflap_service import (
    get_formal_automaton_pair,
    build_jflap_models_for_token,
    build_master_automata_catalog,
    regenerate_all_ten_jff_pairs
)
from app.services.analyzer_service import analyze_single_log


class TestPhase2ConsistencyAndJFF(unittest.TestCase):
    """Pruebas de la Fase 2: Consistencia entre Simulador, Quíntupla, SVG, Tabla y Archivo .JFF."""

    temp_dir = None
    generated_files = None

    @classmethod
    def setUpClass(cls):
        """
        Corrección 1 (Aislamiento de pruebas):
        Genera y utiliza exclusivamente archivos dentro del directorio temporal aislado cls.temp_dir,
        sin tocar ni regenerar archivos en app/storage/jff.
        """
        cls.temp_dir = tempfile.mkdtemp(prefix="soc_jff_phase2_")
        cls.generated_files = regenerate_all_ten_jff_pairs(output_dir=cls.temp_dir)

    @classmethod
    def tearDownClass(cls):
        if cls.temp_dir and os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_all_20_jff_files_pass_ten_formal_requirements(self):
        """Sección 6.2: Verifica los 10 requisitos formales en los 20 archivos .jff temporales."""
        for tok, (path_afd, path_afnd) in self.generated_files.items():
            with open(path_afd, "r", encoding="utf-8") as f1:
                xml_afd = f1.read()
            with open(path_afnd, "r", encoding="utf-8") as f2:
                xml_afnd = f2.read()

            val_afd = validate_jff_xml_ten_requirements(xml_afd, is_afnd=False)
            val_afnd = validate_jff_xml_ten_requirements(xml_afnd, is_afnd=True)

            self.assertTrue(val_afd['valid'], f"AFD_{tok}.jff incumple requisitos: {val_afd['errors']}")
            self.assertTrue(val_afnd['valid'], f"AFND_{tok}.jff incumple requisitos: {val_afnd['errors']}")

    def test_02_single_source_of_truth_between_quintuple_svg_table_and_jff(self):
        """Comprueba coherencia entre Quíntupla, SVG y Tabla (AFD completo) y archivo .jff (AFD ligero)."""
        for tok, (path_afd, path_afnd) in self.generated_files.items():
            afd_model, afnd_model, _ = get_formal_automaton_pair(tok)
            afd_html, afnd_html, _, q_afd, q_afnd = build_jflap_models_for_token(tok)

            svg_nodes_afd = re.findall(r'data-state-node="([^"]+)"', afd_html)
            table_rows_afd = re.findall(r'data-state-row="([^"]+)"', afd_html)
            svg_nodes_afnd = re.findall(r'data-state-node="([^"]+)"', afnd_html)
            table_rows_afnd = re.findall(r'data-state-row="([^"]+)"', afnd_html)

            with open(path_afd, "r", encoding="utf-8") as f1:
                jff_states_afd, _ = parse_jff_xml_to_automaton(f1.read())
            with open(path_afnd, "r", encoding="utf-8") as f2:
                jff_states_afnd, _ = parse_jff_xml_to_automaton(f2.read())

            jff_ids_afd = [s['id'] for s in jff_states_afd]
            jff_ids_afnd = [s['id'] for s in jff_states_afnd]

            # Modelo interno completo en SVG, Tabla y Quíntupla
            self.assertEqual(afd_model.state_ids, svg_nodes_afd)
            self.assertEqual(afd_model.state_ids, table_rows_afd)
            self.assertEqual(q_afd['Q'], "{" + ", ".join(afd_model.state_ids) + "}")
            # Modelo ligero sin qT en el archivo .jff exportado
            self.assertEqual(afd_model.lightweight_state_ids, jff_ids_afd)

            self.assertEqual(afnd_model.state_ids, svg_nodes_afnd)
            self.assertEqual(afnd_model.state_ids, table_rows_afnd)
            self.assertEqual(afnd_model.state_ids, jff_ids_afnd)
            self.assertEqual(q_afnd['Q'], "{" + ", ".join(jff_ids_afnd) + "}")

    def test_03_embedded_base64_download_uri_matches_exported_jff_file_byte_for_byte(self):
        """Verifica que el URI Base64 del botón de descarga coincida byte a byte con el archivo .jff."""
        for tok, (path_afd, path_afnd) in self.generated_files.items():
            afd_html, afnd_html, *_ = build_jflap_models_for_token(tok)

            m_afd = re.search(r'href="data:application/xml;base64,([^"]+)"', afd_html)
            m_afnd = re.search(r'href="data:application/xml;base64,([^"]+)"', afnd_html)
            self.assertIsNotNone(m_afd)
            self.assertIsNotNone(m_afnd)

            decoded_afd_xml = base64.b64decode(m_afd.group(1)).decode('utf-8')
            decoded_afnd_xml = base64.b64decode(m_afnd.group(1)).decode('utf-8')

            with open(path_afd, "r", encoding="utf-8") as f1:
                disk_afd_xml = f1.read()
            with open(path_afnd, "r", encoding="utf-8") as f2:
                disk_afnd_xml = f2.read()

            self.assertEqual(decoded_afd_xml, disk_afd_xml)
            self.assertEqual(decoded_afnd_xml, disk_afnd_xml)

    def test_04_structured_simulation_matches_loaded_jff_on_random_valid_and_invalid_corpus(self):
        """Compara resultados sobre un corpus aleatorio reproducible entre el simulador y el .jff."""
        rng = random.Random(20261028)

        def gen_random_candidates(tok):
            cands = []
            if tok == 'TIMESTAMP':
                for _ in range(15):
                    y = rng.randint(1970, 2099)
                    m = rng.randint(1, 12)
                    d = rng.randint(1, 31)
                    hh = rng.randint(0, 23)
                    mm = rng.randint(0, 59)
                    ss = rng.randint(0, 59)
                    valid_ts = f"{y:04d}-{m:02d}-{d:02d}T{hh:02d}:{mm:02d}:{ss:02d}"
                    cands.append(valid_ts)
                    cands.append(valid_ts[:rng.randint(1, 18)])
                    bad_m = f"{y:04d}-{rng.choice([0, 13, 19, 99]):02d}-{d:02d}T{hh:02d}:{mm:02d}:{ss:02d}"
                    cands.append(bad_m)
            elif tok == 'IP':
                for _ in range(15):
                    ip = ".".join(str(rng.randint(0, 999)) for _ in range(4))
                    cands.append(ip)
                    cands.append(".".join(str(rng.randint(0, 255)) for _ in range(rng.choice([2, 3, 5]))))
            elif tok == 'SEVERITY':
                cands.extend(['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'INF', 'WARN', 'ERROR1', 'info', ''])
            elif tok == 'EVENT_TYPE':
                for _ in range(15):
                    w = "_".join("".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=rng.randint(1, 5))) for _ in range(rng.randint(1, 3)))
                    cands.append(w)
                    cands.append("_" + w)
                    cands.append(w + "_")
                    cands.append(w + "1")
            elif tok == 'STRING':
                cands.extend(['""', '"a"', '"admin"', '"usr\\"admin\\""', '"\\\\"', '"\\n\\t"', '"', '"abc', 'abc"', '"\\a"'])
            elif tok == 'NUMBER':
                for _ in range(15):
                    n_str = str(rng.randint(0, 10**6))
                    cands.append(n_str)
                    cands.append("0" + n_str)
                    cands.append(n_str + "a")
            else:
                sym = {'LBRACE': '{', 'RBRACE': '}', 'COLON': ':', 'COMMA': ','}[tok]
                cands.extend([sym, sym + sym, "", " ", "a", "0"])
            return cands

        for tok, (path_afd, path_afnd) in self.generated_files.items():
            afd_model, afnd_model, _ = get_formal_automaton_pair(tok)
            for word in gen_random_candidates(tok):
                r_afd = afd_model.simulate(word)['accepted']
                r_afnd = afnd_model.simulate(word)['accepted']
                jff_afd = simulate_loaded_jff_directly(path_afd, word)
                jff_afnd = simulate_loaded_jff_directly(path_afnd, word)

                self.assertEqual(r_afd, r_afnd, f"Discrepancia interna AFD vs AFND en {tok} para {word!r}")
                self.assertEqual(r_afd, jff_afd, f"Discrepancia Simulador vs AFD_{tok}.jff para {word!r}")
                self.assertEqual(r_afnd, jff_afnd, f"Discrepancia Simulador vs AFND_{tok}.jff para {word!r}")

    def test_05_non_existent_transitions_and_out_of_alphabet_symbols_handled_consistently(self):
        for tok in TOKEN_FORMAL_REGEX_AST_SPECS:
            afd_model, afnd_model, _ = get_formal_automaton_pair(tok)
            empty_afd = afd_model.simulate("")
            empty_afnd = afnd_model.simulate("")
            self.assertFalse(empty_afd['accepted'])
            self.assertFalse(empty_afnd['accepted'])
            self.assertIsNotNone(empty_afd['error_reason'])

            bad_afd = afd_model.simulate("🔥")
            bad_afnd = afnd_model.simulate("🔥")
            self.assertFalse(bad_afd['accepted'])
            self.assertFalse(bad_afnd['accepted'])
            self.assertEqual(bad_afd['error_position'], 1)
            self.assertEqual(bad_afnd['error_position'], 1)

    def test_06_formal_automaton_atomic_transitions_match_jff_transitions_1_to_1(self):
        for tok, (path_afd, path_afnd) in self.generated_files.items():
            afd_model, afnd_model, _ = get_formal_automaton_pair(tok)
            with open(path_afd, "r", encoding="utf-8") as f1:
                _, jff_trans_afd = parse_jff_xml_to_automaton(f1.read())
            with open(path_afnd, "r", encoding="utf-8") as f2:
                _, jff_trans_afnd = parse_jff_xml_to_automaton(f2.read())

            # El modelo interno completo conserva |Q| * |Σ_ASCII| transiciones
            self.assertEqual(len(afd_model.atomic_transitions), len(afd_model.states) * len(SIGMA_ASCII))

            # El archivo .jff ligero coincide 1:1 en origen, destino y símbolo con lightweight_atomic_transitions
            expected_afd_tuples = [
                (e['from'], e['to'], 'ε' if e['read'] == '' else e['read'])
                for e in afd_model.lightweight_atomic_transitions
            ]
            actual_afd_tuples = [(t['from'], t['to'], t['label']) for t in jff_trans_afd]

            expected_afnd_tuples = [
                (e['from'], e['to'], 'ε' if e['read'] == '' else e['read'])
                for e in afnd_model.atomic_transitions
            ]
            actual_afnd_tuples = [(t['from'], t['to'], t['label']) for t in jff_trans_afnd]

            self.assertEqual(expected_afd_tuples, actual_afd_tuples)
            self.assertEqual(set(expected_afd_tuples), set(actual_afd_tuples))
            self.assertEqual(expected_afnd_tuples, actual_afnd_tuples)
            self.assertEqual(set(expected_afnd_tuples), set(actual_afnd_tuples))

    def test_07_master_catalog_consistency_with_formal_models(self):
        catalog = build_master_automata_catalog()
        self.assertEqual(len(catalog), 10)
        for tok, entry in catalog.items():
            afd_model, afnd_model, _ = get_formal_automaton_pair(tok)
            self.assertEqual(entry['quintupla_afd'], afd_model.quintuple)
            self.assertEqual(entry['quintupla_afnd'], afnd_model.quintuple)

    def test_08_mandatory_regression_logs_and_2027_02_29_preserved(self):
        c1 = analyze_single_log(
            '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}'
        )
        self.assertTrue(c1['is_valid'])
        self.assertEqual(len(c1['tokens']), 13)

        c2 = analyze_single_log(
            '2028-07-14T19:26:08 10.45.8.230 INFO PRIVILEGE_ESCALATION {"user":"operator","attempts":1}'
        )
        self.assertTrue(c2['is_valid'])
        self.assertEqual(len(c2['tokens']), 13)

        c3 = analyze_single_log(
            '2027-02-29T12:35:42 192.168.50.12 ERROR LOGIN_FAILED {"user":"admin","attempts":3}'
        )
        self.assertTrue(c3['valid_lexical'])
        self.assertFalse(c3['valid_semantic'])
        self.assertFalse(c3['is_valid'])
        self.assertEqual(c3['status'], 'ERROR SEMÁNTICO')

    def test_09_test_isolation_does_not_modify_permanent_storage(self):
        """
        Prueba específica para la Corrección 1:
        Verifica que todas las rutas de self.generated_files apunten exclusivamente al
        directorio temporal del sistema y que una regeneración de prueba no escriba en app/storage/jff.
        """
        perm_dir = os.path.abspath("app/storage/jff")
        temp_abs = os.path.abspath(self.temp_dir)
        self.assertNotEqual(perm_dir, temp_abs)
        self.assertFalse(temp_abs.startswith(perm_dir))

        for tok, (p_afd, p_afnd) in self.generated_files.items():
            self.assertTrue(os.path.abspath(p_afd).startswith(temp_abs))
            self.assertTrue(os.path.abspath(p_afnd).startswith(temp_abs))

        # Verificar que un archivo centinela en app/storage/jff no se vea afectado al regenerar en otro dir
        isolated_sub = tempfile.mkdtemp(prefix="soc_isolated_check_")
        try:
            before_snapshot = {}
            if os.path.exists(perm_dir):
                for fn in os.listdir(perm_dir):
                    fp = os.path.join(perm_dir, fn)
                    if os.path.isfile(fp):
                        before_snapshot[fn] = os.path.getmtime(fp)

            regenerate_all_ten_jff_pairs(output_dir=isolated_sub)

            after_snapshot = {}
            if os.path.exists(perm_dir):
                for fn in os.listdir(perm_dir):
                    fp = os.path.join(perm_dir, fn)
                    if os.path.isfile(fp):
                        after_snapshot[fn] = os.path.getmtime(fp)

            self.assertEqual(before_snapshot, after_snapshot)
        finally:
            shutil.rmtree(isolated_sub, ignore_errors=True)

    def test_10_exact_transition_comparison_detects_single_symbol_or_target_mutation(self):
        afd_model, _, _ = get_formal_automaton_pair('LBRACE')
        expected_tuples = [
            (e['from'], e['to'], 'ε' if e['read'] == '' else e['read'])
            for e in afd_model.lightweight_atomic_transitions
        ]
        mutated_xml = afd_model.to_jff_xml().replace(
            "<read>{</read>",
            "<read>}</read>",
            1
        )
        _, mutated_trans = parse_jff_xml_to_automaton(mutated_xml)
        mutated_tuples = [(t['from'], t['to'], t['label']) for t in mutated_trans]
        self.assertEqual(len(expected_tuples), len(mutated_tuples))
        self.assertNotEqual(expected_tuples, mutated_tuples)

    def test_11_validator_enforces_95_ascii_completeness_and_rejects_incomplete_or_duplicate_dfa(self):
        afd_model, _, _ = get_formal_automaton_pair('COLON')
        valid_complete_xml = afd_model.to_jff_xml(include_trap=True)

        res_ok = validate_jff_xml_ten_requirements(valid_complete_xml, is_afnd=False, require_complete_dfa=True)
        self.assertTrue(res_ok['valid'])
        self.assertEqual(res_ok['transition_count'], len(afd_model.states) * len(SIGMA_ASCII))

        root_missing = ET.fromstring(valid_complete_xml)
        aut_missing = root_missing.find('automaton')
        aut_missing.remove(aut_missing.find('transition'))
        incomplete_xml = ET.tostring(root_missing, encoding='unicode')
        res_incomplete = validate_jff_xml_ten_requirements(incomplete_xml, is_afnd=False, require_complete_dfa=True)
        self.assertFalse(res_incomplete['valid'])

        root_dup = ET.fromstring(valid_complete_xml)
        aut_dup = root_dup.find('automaton')
        dup_tr = ET.SubElement(aut_dup, 'transition')
        ET.SubElement(dup_tr, 'from').text = '0'
        ET.SubElement(dup_tr, 'to').text = '2'
        ET.SubElement(dup_tr, 'read').text = ':'
        duplicate_xml = ET.tostring(root_dup, encoding='unicode')
        res_dup = validate_jff_xml_ten_requirements(duplicate_xml, is_afnd=False, require_complete_dfa=True)
        self.assertFalse(res_dup['valid'])


if __name__ == '__main__':
    unittest.main()