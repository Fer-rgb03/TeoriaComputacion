import os
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from app.services.automata_engine import (
    SIGMA_ASCII,
    TOKEN_FORMAL_REGEX_AST_SPECS,
    validate_jff_xml_ten_requirements,
    parse_jff_xml_to_automaton,
    simulate_loaded_jff_directly,
    prove_jff_files_equivalence,
    prove_three_way_equivalence
)
from app.services.jflap_service import (
    get_formal_automaton_pair,
    export_lightweight_dfa_jff_xml,
    regenerate_all_ten_jff_pairs
)
from app.services.analyzer_service import (
    analyze_single_log,
    validate_ipv4_strict,
    validate_timestamp_strict
)


class TestPhase4JFLAPExportAndConsistency(unittest.TestCase):
    """
    Fase 4 (Corrección Definitiva JFLAP 7.1):
    Verifica la separación entre el AFD Completo Interno (con qT) y el AFD Ligero Exportable
    para JFLAP 7.1 (sin qT), la generación de los 20 archivos .jff (10 AFD ligeros + 10 AFND),
    la equivalencia formal triple por producto y los casos obligatorios de TIMESTAMP e IP.
    """

    temp_dir = None
    generated_files = None

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="soc_jff_phase4_")
        cls.generated_files = regenerate_all_ten_jff_pairs(output_dir=cls.temp_dir)

    @classmethod
    def tearDownClass(cls):
        if cls.temp_dir and os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_twenty_functional_jff_files_generated_with_valid_xml(self):
        """Sección 2 y 5: Verifica que se generen exactamente 10 AFD ligeros y 10 AFND con XML bien formado."""
        self.assertEqual(len(self.generated_files), 10)
        jff_files_in_dir = [f for f in os.listdir(self.temp_dir) if f.endswith('.jff')]
        self.assertEqual(len(jff_files_in_dir), 20)

        for tok, (path_afd, path_afnd) in self.generated_files.items():
            self.assertTrue(os.path.isfile(path_afd))
            self.assertTrue(os.path.isfile(path_afnd))
            for p in (path_afd, path_afnd):
                root = ET.parse(p).getroot()
                self.assertEqual(root.tag, 'structure')
                self.assertEqual(root.find('type').text.strip(), 'fa')
                self.assertIsNotNone(root.find('automaton'))

    def test_02_internal_complete_dfa_retains_qt_while_exported_lightweight_dfa_omits_qt(self):
        """
        Sección 1 (A y B):
        Verifica que el modelo formal interno conserve qT y la función total, mientras que el
        AFD ligero exportado omita qT y todas las transiciones hacia qT.
        Comprueba además los números exactos de TIMESTAMP (29 estados/2726 transiciones internas
        vs 28 estados/137 transiciones en el AFD ligero exportado).
        """
        for tok, (path_afd, _) in self.generated_files.items():
            afd_model, _, _ = get_formal_automaton_pair(tok)
            # A. Modelo interno completo conserva qT y función total
            self.assertIn('qT', afd_model.state_ids)
            self.assertEqual(len(afd_model.atomic_transitions), len(afd_model.states) * len(SIGMA_ASCII))

            # B. Modelo exportado ligero omite qT y aristas hacia qT
            with open(path_afd, "r", encoding="utf-8") as f:
                jff_states, jff_trans = parse_jff_xml_to_automaton(f.read())
            jff_state_ids = [s['id'] for s in jff_states]
            self.assertNotIn('qT', jff_state_ids)
            self.assertEqual(len(jff_states), len(afd_model.states) - 1)
            self.assertTrue(all(t['from'] != 'qT' and t['to'] != 'qT' for t in jff_trans))

        # Verificación exacta del caso documentado para TIMESTAMP
        ts_afd_model, _, _ = get_formal_automaton_pair('TIMESTAMP')
        self.assertEqual(len(ts_afd_model.states), 29)
        self.assertEqual(len(ts_afd_model.atomic_transitions), 2726)
        trap_edges_count = sum(1 for e in ts_afd_model.atomic_transitions if e['to'] == 'qT')
        self.assertEqual(trap_edges_count, 2589)

        ts_path_afd, _ = self.generated_files['TIMESTAMP']
        with open(ts_path_afd, "r", encoding="utf-8") as f_ts:
            ts_jff_states, ts_jff_trans = parse_jff_xml_to_automaton(f_ts.read())
        self.assertEqual(len(ts_jff_states), 28)
        self.assertEqual(len(ts_jff_trans), 137)

    def test_03_exported_lightweight_dfas_have_only_single_real_chars_and_no_duplicates_or_epsilons(self):
        """
        Sección 1.B y 3:
        Verifica que cada transición del AFD ligero use un único carácter real (no '0..9' ni 'Σ ∖ ...'),
        sin transiciones ε artificiales y sin múltiples destinos para un mismo (estado, símbolo).
        """
        for tok, (path_afd, path_afnd) in self.generated_files.items():
            with open(path_afd, "r", encoding="utf-8") as f1:
                xml_afd = f1.read()
            val_afd = validate_jff_xml_ten_requirements(xml_afd, is_afnd=False, require_complete_dfa=False)
            self.assertTrue(val_afd['valid'], f"AFD_{tok}.jff falló validación: {val_afd['errors']}")
            self.assertFalse(val_afd['has_trap_state'])

            with open(path_afnd, "r", encoding="utf-8") as f2:
                xml_afnd = f2.read()
            val_afnd = validate_jff_xml_ten_requirements(xml_afnd, is_afnd=True)
            self.assertTrue(val_afnd['valid'], f"AFND_{tok}.jff falló validación: {val_afnd['errors']}")

    def test_04_three_way_formal_equivalence_complete_dfa_lightweight_dfa_and_thompson_afnd(self):
        """
        Sección 4:
        Demostración formal de equivalencia mediante producto de autómatas y búsqueda BFS de
        contraejemplos entre:
          1. El AFD completo interno (con qT).
          2. El AFD ligero exportado (interpretando transiciones ausentes como trampa implícita).
          3. El AFND de Thompson exportado.
        """
        for tok, (path_afd, path_afnd) in self.generated_files.items():
            afd_model, _, _ = get_formal_automaton_pair(tok)
            proof = prove_three_way_equivalence(afd_model, path_afd, path_afnd)
            self.assertTrue(
                proof['equivalent'],
                f"Fallo de equivalencia triple en {tok}: testigo={proof['shortest_witness']!r} ({proof})"
            )

    def test_05_mandatory_timestamp_cases_in_jff_and_analyzer(self):
        """
        Sección 5 (Casos obligatorios de TIMESTAMP):
          - 2026-10-17T08:43:29 -> Accept léxico y semántico
          - 2026-13-17T08:43:29 -> Reject léxico
          - 2027-02-29T12:35:42 -> Accept léxico; rechazado posteriormente en validación semántica
        """
        path_afd, path_afnd = self.generated_files['TIMESTAMP']
        afd_model, afnd_model, _ = get_formal_automaton_pair('TIMESTAMP')

        # 1) 2026-10-17T08:43:29 -> Accept
        ts_ok = "2026-10-17T08:43:29"
        self.assertTrue(afd_model.simulate(ts_ok)['accepted'])
        self.assertTrue(afnd_model.simulate(ts_ok)['accepted'])
        self.assertTrue(simulate_loaded_jff_directly(path_afd, ts_ok))
        self.assertTrue(simulate_loaded_jff_directly(path_afnd, ts_ok))
        self.assertTrue(validate_timestamp_strict(ts_ok)[0])

        # 2) 2026-13-17T08:43:29 -> Reject
        ts_bad_month = "2026-13-17T08:43:29"
        self.assertFalse(afd_model.simulate(ts_bad_month)['accepted'])
        self.assertFalse(afnd_model.simulate(ts_bad_month)['accepted'])
        self.assertFalse(simulate_loaded_jff_directly(path_afd, ts_bad_month))
        self.assertFalse(simulate_loaded_jff_directly(path_afnd, ts_bad_month))

        # 3) 2027-02-29T12:35:42 -> Accept léxico, rechazo semántico
        ts_non_leap = "2027-02-29T12:35:42"
        self.assertTrue(afd_model.simulate(ts_non_leap)['accepted'])
        self.assertTrue(afnd_model.simulate(ts_non_leap)['accepted'])
        self.assertTrue(simulate_loaded_jff_directly(path_afd, ts_non_leap))
        self.assertTrue(simulate_loaded_jff_directly(path_afnd, ts_non_leap))
        sem_ok, _ = validate_timestamp_strict(ts_non_leap)
        self.assertFalse(sem_ok)

        res_log = analyze_single_log(f'{ts_non_leap} 192.168.1.10 ERROR LOGIN_FAILED {{"user":"admin","attempts":1}}')
        self.assertTrue(res_log['valid_lexical'])
        self.assertFalse(res_log['valid_semantic'])
        self.assertEqual(res_log['status'], 'ERROR SEMÁNTICO')

    def test_06_ip_192_168_1_10_accepted_lexically_and_semantically(self):
        """Caso obligatorio IP: 192.168.1.10 -> Accept léxico y semántico."""
        ip = "192.168.1.10"
        path_afd, path_afnd = self.generated_files['IP']
        afd_model, afnd_model, _ = get_formal_automaton_pair('IP')

        self.assertTrue(afd_model.simulate(ip)['accepted'])
        self.assertTrue(afnd_model.simulate(ip)['accepted'])
        self.assertTrue(simulate_loaded_jff_directly(path_afd, ip))
        self.assertTrue(simulate_loaded_jff_directly(path_afnd, ip))
        self.assertTrue(validate_ipv4_strict(ip)[0])

    def test_07_ip_192_168_001_10_accepted_lexically_but_rejected_semantically(self):
        """Caso obligatorio IP: 192.168.001.10 -> Accept léxico, rechazo semántico."""
        ip = "192.168.001.10"
        path_afd, path_afnd = self.generated_files['IP']
        afd_model, afnd_model, _ = get_formal_automaton_pair('IP')

        self.assertTrue(afd_model.simulate(ip)['accepted'])
        self.assertTrue(afnd_model.simulate(ip)['accepted'])
        self.assertTrue(simulate_loaded_jff_directly(path_afd, ip))
        self.assertTrue(simulate_loaded_jff_directly(path_afnd, ip))

        sem_ok, sem_msg = validate_ipv4_strict(ip)
        self.assertFalse(sem_ok)
        self.assertIn("ceros iniciales", sem_msg)

        res = analyze_single_log(f'2026-10-17T08:43:29 {ip} ERROR LOGIN_FAILED {{"user":"admin","attempts":1}}')
        self.assertTrue(res['valid_lexical'])
        self.assertFalse(res['valid_semantic'])
        self.assertEqual(res['status'], 'ERROR SEMÁNTICO')

    def test_08_ip_192_168_256_10_and_256_168_1_10_accepted_lexically_but_rejected_semantically(self):
        """Caso obligatorio IP: 192.168.256.10 y 256.168.1.10 -> Accept léxico, rechazo semántico."""
        path_afd, path_afnd = self.generated_files['IP']
        afd_model, afnd_model, _ = get_formal_automaton_pair('IP')

        for ip in ("192.168.256.10", "256.168.1.10"):
            self.assertTrue(afd_model.simulate(ip)['accepted'])
            self.assertTrue(afnd_model.simulate(ip)['accepted'])
            self.assertTrue(simulate_loaded_jff_directly(path_afd, ip))
            self.assertTrue(simulate_loaded_jff_directly(path_afnd, ip))

            sem_ok, sem_msg = validate_ipv4_strict(ip)
            self.assertFalse(sem_ok)
            self.assertIn("256", sem_msg)

            res = analyze_single_log(f'2026-10-17T08:43:29 {ip} ERROR LOGIN_FAILED {{"user":"admin","attempts":1}}')
            self.assertTrue(res['valid_lexical'])
            self.assertFalse(res['valid_semantic'])
            self.assertEqual(res['status'], 'ERROR SEMÁNTICO')

    def test_09_ip_192_168_1_rejected_lexically(self):
        """Caso obligatorio IP: 192.168.1 -> Reject léxico."""
        ip = "192.168.1"
        path_afd, path_afnd = self.generated_files['IP']
        afd_model, afnd_model, _ = get_formal_automaton_pair('IP')

        self.assertFalse(afd_model.simulate(ip)['accepted'])
        self.assertFalse(afnd_model.simulate(ip)['accepted'])
        self.assertFalse(simulate_loaded_jff_directly(path_afd, ip))
        self.assertFalse(simulate_loaded_jff_directly(path_afnd, ip))

    def test_10_ip_192_168_1_10_5_rejected_lexically(self):
        """Caso obligatorio IP: 192.168.1.10.5 -> Reject léxico."""
        ip = "192.168.1.10.5"
        path_afd, path_afnd = self.generated_files['IP']
        afd_model, afnd_model, _ = get_formal_automaton_pair('IP')

        sim_d = afd_model.simulate(ip)
        self.assertFalse(sim_d['accepted'])
        self.assertEqual(sim_d['final_states'], ['qT'])
        self.assertFalse(simulate_loaded_jff_directly(path_afd, ip))
        self.assertFalse(simulate_loaded_jff_directly(path_afnd, ip))

    def test_11_reject_lexically_invalid_strings_across_all_categories(self):
        invalid_samples = {
            'TIMESTAMP': ['2026-13-17T08:43:29', '2026-10-17', '2026-10-12T24:00:00'],
            'IP': ['192.168.1', '192.168.1.10.5', '192.168..1', '1234.1.1.1'],
            'SEVERITY': ['ERR', 'INFOO', 'WARN', 'critical'],
            'EVENT_TYPE': ['_LOGIN', 'LOGIN__', 'LOGIN_1', 'login'],
            'STRING': ['"unclosed', 'noquotes"', '"bad\\escape"'],
            'NUMBER': ['007', '01', '12a', '-5'],
            'LBRACE': ['{{', '}', 'a'],
            'RBRACE': ['}}', '{', 'a'],
            'COLON': ['::', ';', 'a'],
            'COMMA': [',,', '.', 'a'],
        }
        for tok, bad_list in invalid_samples.items():
            path_afd, path_afnd = self.generated_files[tok]
            afd_model, afnd_model, _ = get_formal_automaton_pair(tok)
            for bad_str in bad_list:
                self.assertFalse(afd_model.simulate(bad_str)['accepted'])
                self.assertFalse(afnd_model.simulate(bad_str)['accepted'])
                self.assertFalse(simulate_loaded_jff_directly(path_afd, bad_str))
                self.assertFalse(simulate_loaded_jff_directly(path_afnd, bad_str))

    def test_12_security_string_with_spaces_still_detected_correctly(self):
        sqli_log = '2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin\'); DROP TABLE logs;--","attempts":3}'
        res = analyze_single_log(sqli_log)
        self.assertTrue(res['valid_lexical'])
        self.assertTrue(res['valid_syntactic'])
        self.assertFalse(res['valid_security'])
        self.assertFalse(res['is_valid'])
        self.assertIn('SOSPECHOSA', res['status'])

    def test_13_permanent_storage_contains_exact_20_functional_jff_files(self):
        """
        Sección 2: Verifica que app/storage/jff/ contenga los 20 archivos .jff funcionales
        (10 AFD ligeros sin qT y 10 AFND de Thompson) con equivalencia triple comprobada.
        """
        perm_dir = "app/storage/jff"
        jff_files = sorted(f for f in os.listdir(perm_dir) if f.endswith('.jff'))
        self.assertEqual(len(jff_files), 20)

        for tok in TOKEN_FORMAL_REGEX_AST_SPECS:
            p_afd = os.path.join(perm_dir, f"AFD_{tok}.jff")
            p_afnd = os.path.join(perm_dir, f"AFND_{tok}.jff")
            self.assertTrue(os.path.isfile(p_afd))
            self.assertTrue(os.path.isfile(p_afnd))

            afd_model, _, _ = get_formal_automaton_pair(tok)
            proof = prove_three_way_equivalence(afd_model, p_afd, p_afnd)
            self.assertTrue(proof['equivalent'], f"Discrepancia en archivo permanente de {tok}: {proof}")

    def test_14_reusable_export_lightweight_dfa_function_consistency(self):
        """Sección 3: Verifica que export_lightweight_dfa_jff_xml genere el mismo XML ligero para las 10 categorías."""
        for tok, (path_afd, _) in self.generated_files.items():
            xml_fn = export_lightweight_dfa_jff_xml(tok)
            with open(path_afd, "r", encoding="utf-8") as f:
                xml_disk = f.read()
            self.assertEqual(xml_fn, xml_disk)

    def test_15_afd_string_jff_q1_transitions_and_complete_step_by_step_walk_for_admin(self):
        """
        Requisitos 1, 2, 3 y 7 (Corrección Urgente AFD_STRING.jff):
        1) Inspecciona las transiciones que salen de q1 en AFD_STRING.jff y comprueba que
           existen transiciones individuales <read>a</read>, <read>d</read>, <read>m</read>,
           <read>i</read>, <read>n</read>, <read> </read>, <read>\\</read> y <read>"</read>.
        2) Comprueba paso a paso que existe un recorrido completo y válido para '"admin"'
           en AFD_STRING.jff desde q0 hasta el estado final q3 (q0 -> q1 -> q1 -> ... -> q3).
        """
        path_afd, path_afnd = self.generated_files['STRING']
        with open(path_afd, "r", encoding="utf-8") as f:
            xml_str = f.read()

        states, transitions = parse_jff_xml_to_automaton(xml_str)
        state_map = {s['id']: s for s in states}
        self.assertIn('q0', state_map)
        self.assertIn('q1', state_map)
        self.assertTrue(state_map['q0']['initial'])

        # 1. Inspeccionar transiciones salientes de q1
        q1_out = {(t['label'], t['to']) for t in transitions if t['from'] == 'q1'}
        q1_labels = {t['label'] for t in transitions if t['from'] == 'q1'}
        for required_char in ('a', 'd', 'm', 'i', 'n', 'u', '1', '2', '3', ' ', '\\', '"'):
            self.assertIn(
                required_char, q1_labels,
                f"Falta la transición con el símbolo {required_char!r} saliendo de q1 en AFD_STRING.jff"
            )

        # Verificar que desde q1 con 'a' avanza determinísticamente a q1
        a_targets = [t['to'] for t in transitions if t['from'] == 'q1' and t['label'] == 'a']
        self.assertEqual(a_targets, ['q1'])

        # 2. Recorrido paso a paso completo de '"admin"' sobre las transiciones del XML de AFD_STRING.jff
        delta_jff = {(t['from'], t['label']): t['to'] for t in transitions}
        curr = 'q0'
        walk_states = [curr]
        for ch in '"admin"':
            self.assertIn((curr, ch), delta_jff, f"AFD_STRING.jff se detuvo en {curr} al leer {ch!r}")
            curr = delta_jff[(curr, ch)]
            walk_states.append(curr)

        self.assertEqual(walk_states, ['q0', 'q1', 'q1', 'q1', 'q1', 'q1', 'q1', 'q3'])
        self.assertTrue(state_map[curr]['final'], f"El estado final alcanzado ({curr}) no está marcado como <final/>")

    def test_16_string_jff_mandatory_cases_and_admin_path(self):
        """
        Objetivo principal (Fase 4 - Corrección urgente AFD_STRING.jff):
        Comprueba que JFLAP pueda ejecutar 'admin' desde q0 hasta un estado final,
        mostrando Accept en Multiple Run para los 5 casos obligatorios:
          - "admin" -> Accept
          - "usuario123" -> Accept
          - "hola mundo" -> Accept
          - "" -> Accept
          - "texto con espacios" -> Accept
        y validando su equivalencia formal con AFND_STRING.jff.
        """
        perm_dir = "app/storage/jff"
        p_afd_str = os.path.join(perm_dir, "AFD_STRING.jff")
        p_afnd_str = os.path.join(perm_dir, "AFND_STRING.jff")
        afd_model, afnd_model, _ = get_formal_automaton_pair('STRING')

        mandatory_strings = [
            '"admin"',
            '"usuario123"',
            '"hola mundo"',
            '""',
            '"texto con espacios"'
        ]

        for s_word in mandatory_strings:
            # 1. Simulador interno AFD
            self.assertTrue(
                afd_model.simulate(s_word)['accepted'],
                f"El simulador AFD interno rechazó la cadena válida {s_word!r}"
            )
            # 2. Simulador interno AFND
            self.assertTrue(
                afnd_model.simulate(s_word)['accepted'],
                f"El simulador AFND interno rechazó la cadena válida {s_word!r}"
            )
            # 3. Archivo AFD_STRING.jff cargado desde disco
            self.assertTrue(
                simulate_loaded_jff_directly(p_afd_str, s_word),
                f"AFD_STRING.jff falló en JFLAP Multiple Run para {s_word!r}"
            )
            # 4. Archivo AFND_STRING.jff cargado desde disco
            self.assertTrue(
                simulate_loaded_jff_directly(p_afnd_str, s_word),
                f"AFND_STRING.jff falló en JFLAP Multiple Run para {s_word!r}"
            )

        # Verificación formal de equivalencia por producto para STRING
        proof_str = prove_three_way_equivalence(afd_model, p_afd_str, p_afnd_str)
        self.assertTrue(proof_str['equivalent'], f"Discrepancia formal en STRING: {proof_str}")

if __name__ == '__main__':
    unittest.main()