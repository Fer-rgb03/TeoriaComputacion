import os
import shutil
import tempfile
import unittest
from app.services.automata_engine import (
    SIGMA_ASCII,
    TOKEN_FORMAL_REGEX_AST_SPECS,
    build_thompson_afnd,
    compute_epsilon_closure,
    subset_construction_afnd_to_afd,
    simulate_afd_structured,
    simulate_afnd_structured,
    prove_dfa_equivalence_by_product,
    parse_jff_xml_to_automaton,
    simulate_loaded_jff_directly,
    prove_jff_files_equivalence
)
from app.services.jflap_service import (
    get_token_automata_spec,
    regenerate_all_ten_jff_pairs
)
from app.services.analyzer_service import analyze_single_log


class TestPhase1FormalAutomata(unittest.TestCase):
    """Pruebas formales de la Fase 1 con directorio temporal aislado para los archivos JFF."""

    temp_dir = None
    generated_files = None

    @classmethod
    def setUpClass(cls):
        """
        Crea un directorio temporal aislado, limpia cualquier caché previa y genera desde cero
        los 10 pares de archivos .jff (20 archivos) exclusivamente dentro de cls.temp_dir,
        sin alterar archivos permanentes del proyecto.
        """
        cls.temp_dir = tempfile.mkdtemp(prefix="soc_jff_phase1_")
        cls.generated_files = regenerate_all_ten_jff_pairs(output_dir=cls.temp_dir)

    @classmethod
    def tearDownClass(cls):
        """Instrucción 7: Limpia y elimina el directorio temporal aislado al finalizar las pruebas."""
        if cls.temp_dir and os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        """Instrucciones 3 y 5: Verifica antes de cada test que generated_files exista en el dir temporal."""
        if not self.__class__.generated_files:
            self.__class__.setUpClass()
        self.assertIsInstance(self.generated_files, dict)
        self.assertEqual(len(self.generated_files), 10)
        for tok, (p_afd, p_afnd) in self.generated_files.items():
            self.assertTrue(os.path.isfile(p_afd), f"No existe el archivo temporal AFD para {tok}: {p_afd}")
            self.assertTrue(os.path.isfile(p_afnd), f"No existe el archivo temporal AFND para {tok}: {p_afnd}")
            self.assertGreater(os.path.getsize(p_afd), 0)
            self.assertGreater(os.path.getsize(p_afnd), 0)
            self.assertTrue(p_afd.startswith(self.temp_dir))
            self.assertTrue(p_afnd.startswith(self.temp_dir))

    def test_01_thompson_afnd_has_genuine_epsilon_transitions_for_complex_tokens(self):
        for tok in ('TIMESTAMP', 'IP', 'SEVERITY', 'EVENT_TYPE', 'STRING', 'NUMBER'):
            states_nfa, trans_nfa = build_thompson_afnd(tok)
            eps_count = sum(1 for t in trans_nfa if t['label'] == 'ε')
            self.assertGreater(eps_count, 0, f"El AFND de {tok} debe tener transiciones ε de Thompson.")
            initials = [s for s in states_nfa if s.get('initial')]
            finals = [s for s in states_nfa if s.get('final')]
            self.assertEqual(len(initials), 1)
            self.assertEqual(len(finals), 1)

    def test_02_base_tokens_have_no_artificial_epsilon_transitions(self):
        for tok in ('LBRACE', 'RBRACE', 'COLON', 'COMMA'):
            states_nfa, trans_nfa = build_thompson_afnd(tok)
            eps_count = sum(1 for t in trans_nfa if t['label'] == 'ε')
            self.assertEqual(eps_count, 0, f"{tok} es caso base de Thompson y no debe tener ε artificial.")
            self.assertEqual(len(states_nfa), 2)

    def test_03_timestamp_afd_and_afnd_exact_state_and_final_counts(self):
        path_afd, path_afnd = self.generated_files['TIMESTAMP']
        with open(path_afd, "r", encoding="utf-8") as f1:
            jff_afd_states, jff_afd_trans = parse_jff_xml_to_automaton(f1.read())
        with open(path_afnd, "r", encoding="utf-8") as f2:
            afnd_states, afnd_trans = parse_jff_xml_to_automaton(f2.read())

        states_afd_internal, *_ = get_token_automata_spec('TIMESTAMP')

        # AFND Thompson: 40 estados, 1 final (q39), 16 transiciones ε
        self.assertEqual(len(afnd_states), 40)
        self.assertEqual(len([s for s in afnd_states if s['final']]), 1)
        self.assertEqual(sum(1 for t in afnd_trans if t['label'] == 'ε'), 16)

        # AFD Completo Interno: 29 estados (28 activos + qT) y 1 estado final (q27)
        self.assertEqual(len(states_afd_internal), 29)
        # AFD Ligero Exportado a JFLAP: 28 estados (sin qT), 137 transiciones y 1 estado final (q27)
        self.assertEqual(len(jff_afd_states), 28)
        self.assertEqual(len(jff_afd_trans), 137)
        afd_finals = [s['id'] for s in jff_afd_states if s['final']]
        self.assertEqual(afd_finals, ['q27'])

    def test_04_timestamp_and_string_jff_regression_table_cases(self):
        path_afd, path_afnd = self.generated_files['TIMESTAMP']
        states_afd, trans_afd, states_afnd, trans_afnd, *_ = get_token_automata_spec('TIMESTAMP')

        audit_cases = [
            ("0", False),
            ("2026", False),
            ("2026-10-17", False),
            ("2026-13-01T14:32:05", False),
            ("2026-10-12T24:00:00", False),
            ("2026-10-17T08:43:29", True),
        ]

        for word, expected_accept in audit_cases:
            jff_afd_res = simulate_loaded_jff_directly(path_afd, word)
            jff_afnd_res = simulate_loaded_jff_directly(path_afnd, word)
            sim_afd_res = simulate_afd_structured(states_afd, trans_afd, word)['accepted']
            sim_afnd_res = simulate_afnd_structured(states_afnd, trans_afnd, word)['accepted']

            self.assertEqual(jff_afd_res, expected_accept, f"Fallo en AFD_TIMESTAMP.jff para {word!r}")
            self.assertEqual(jff_afnd_res, expected_accept, f"Fallo en AFND_TIMESTAMP.jff para {word!r}")
            self.assertEqual(sim_afd_res, expected_accept)
            self.assertEqual(sim_afnd_res, expected_accept)

        str_afd_path, str_afnd_path = self.generated_files['STRING']
        string_cases = [
            ("", False),
            ('"', False),
            ('""', True),
            ('"admin"', True),
            ('"usr\\"admin"', True),
            ('"unclosed', False),
            ('admin"', False),
        ]
        for s_word, s_expected in string_cases:
            self.assertEqual(
                simulate_loaded_jff_directly(str_afd_path, s_word), s_expected,
                f"Fallo en AFD_STRING.jff para {s_word!r}"
            )
            self.assertEqual(
                simulate_loaded_jff_directly(str_afnd_path, s_word), s_expected,
                f"Fallo en AFND_STRING.jff para {s_word!r}"
            )

    def test_05_formal_equivalence_of_exported_jff_files_with_shortest_witness(self):
        for tok, (path_afd, path_afnd) in self.generated_files.items():
            with open(path_afd, "r", encoding="utf-8") as f_xml:
                afd_states, afd_trans = parse_jff_xml_to_automaton(f_xml.read())
            self.assertNotIn('qT', [s['id'] for s in afd_states])
            self.assertTrue(all(t['to'] != 'qT' and t['from'] != 'qT' for t in afd_trans))

            proof = prove_jff_files_equivalence(path_afd, path_afnd)
            if not proof['equivalent']:
                self.fail(
                    f"Fallo de equivalencia formal entre {os.path.basename(path_afd)} y "
                    f"{os.path.basename(path_afnd)}. Detalle: {proof.get('error_detail')} | "
                    f"Cadena testigo más corta: {proof['shortest_witness']!r} "
                    f"(AFD={proof['afd_accepts']}, AFND={proof['afnd_accepts']})"
                )

    def test_06_three_mandatory_functional_cases_preserved(self):
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


if __name__ == '__main__':
    unittest.main()