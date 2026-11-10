"""Pruebas de la presentación académica; no cambian los autómatas."""
import unittest

from app import create_app
from app.patterns.singleton.grammar_singleton import GrammarSingleton
from app.services.analyzer_service import (
    ACADEMIC_LEXICAL_TABLE_SPECS, analyze_logs_input, analyze_single_log,
)
from app.services.automata_engine import TOKEN_FORMAL_REGEX_AST_SPECS
from app.services.jflap_service import get_formal_automaton_pair


GOOD = '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}'


class TestAcademicView(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True

    def test_01_catalog_has_ten_categories_and_no_fake_lexemes(self):
        data = analyze_logs_input('')
        rows = data['academic_lexical_table']
        self.assertEqual([r['token'] for r in rows], [
            'TIMESTAMP', 'IP', 'SEVERITY', 'EVENT_TYPE', 'STRING',
            'NUMBER', 'LBRACE', 'RBRACE', 'COLON', 'COMMA'
        ])
        self.assertEqual(len(ACADEMIC_LEXICAL_TABLE_SPECS), 10)
        self.assertTrue(all(not r['has_dynamic_lexemes'] for r in rows))

    def test_02_lexemes_change_with_the_actual_input(self):
        data = analyze_logs_input(GOOD)
        rows = {r['token']: r for r in data['academic_lexical_table']}
        self.assertEqual(rows['TIMESTAMP']['lexemes_list'], ['2026-10-17T08:43:29'])
        self.assertEqual(rows['IP']['lexemes_list'], ['192.168.1.10'])
        self.assertEqual(rows['SEVERITY']['lexemes_list'], ['ERROR'])
        self.assertEqual(rows['EVENT_TYPE']['lexemes_list'], ['LOGIN_FAILED'])
        self.assertEqual(rows['STRING']['lexemes_list'], ['"user"', '"admin"', '"attempts"'])
        self.assertEqual(rows['NUMBER']['lexemes_list'], ['5'])
        self.assertEqual(rows['COMMA']['occurrences_count'], 1)
        data2 = analyze_logs_input('2028-07-14T19:26:08 10.0.0.5 INFO PRIVILEGE_ESCALATION {"host":"srv01"}')
        rows2 = {r['token']: r for r in data2['academic_lexical_table']}
        self.assertEqual(rows2['SEVERITY']['lexemes_list'], ['INFO'])
        self.assertFalse(rows2['NUMBER']['has_dynamic_lexemes'])
        self.assertFalse(rows2['COMMA']['has_dynamic_lexemes'])

    def test_03_single_source_of_truth_for_regexes(self):
        metadata = GrammarSingleton().TOKEN_METADATA
        rows = analyze_logs_input('')['academic_lexical_table']
        for row in rows:
            self.assertEqual(row['regex_notation'], metadata[row['token']]['regex'])
            self.assertEqual(row['formal_engine_regex'], TOKEN_FORMAL_REGEX_AST_SPECS[row['token']])

    def test_04_number_formal_models_reject_leading_zeros(self):
        afd, afnd, _ = get_formal_automaton_pair('NUMBER')
        for v in ('0', '5', '2026'):
            self.assertTrue(afd.simulate(v)['accepted'])
            self.assertTrue(afnd.simulate(v)['accepted'])
        for v in ('007', '00', '-15'):
            self.assertFalse(afd.simulate(v)['accepted'])
            self.assertFalse(afnd.simulate(v)['accepted'])

    def test_05_valid_quoted_strings_remain_accepted(self):
        record = '2026-10-17T08:43:29 10.0.0.1 INFO LOGIN_FAILED {"user":"O\'Neil"}'
        self.assertTrue(analyze_single_log(record)['is_valid'])
        row = next(r for r in analyze_logs_input(record)['academic_lexical_table'] if r['token'] == 'STRING')
        self.assertIn('"O\'Neil"', row['lexemes_list'])
        self.assertIn('32..126', row['set_notation'])

    def test_06_lexical_syntactic_semantic_and_valid_cases(self):
        variants = [
            (GOOD, 'VÁLIDO (ACEPTADO)'),
            ('2026-10-17T08:43:29 192.168.1.10 @ ERROR LOGIN_FAILED {"user":"admin"}', 'ERROR LÉXICO'),
            ('2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5', 'ERROR SINTÁCTICO'),
            ('2027-02-29T12:35:42 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}', 'ERROR SEMÁNTICO'),
        ]
        for log, expected in variants:
            with self.subTest(expected=expected):
                self.assertEqual(analyze_single_log(log)['status'], expected)

    def test_07_sections_and_no_visible_position_column(self):
        with self.app.test_client() as client:
            response = client.post('/', data={'log_input': GOOD})
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        for label in ('A) CASO', 'B) PROCESO INTERNO', '2.1 Análisis Léxico',
                      '2.2 Máquinas Abstractas', '2.3 Tablas de Transiciones y Catálogo de Autómatas',
                      'data-academic-token="NUMBER"'):
            self.assertTrue(label in page, f"No se encontro en el HTML: {label}")
        self.assertTrue(
            '>Posición</th>' not in page,
            "La columna Posicion todavia aparece en el HTML"
        )

    def test_08_automata_downloads_and_error_positions_retained(self):
        data = analyze_logs_input(GOOD)
        tok = data['results'][0]['tokens'][0]
        self.assertIsInstance(tok['line'], int)
        self.assertIsInstance(tok['column'], int)
        self.assertIn('error_position', tok['dynamic_simulation']['afd'])
        with self.app.test_client() as client:
            response = client.get('/')
        html = response.get_data(as_text=True)
        self.assertIn('AFD_NUMBER.jff', html)
        self.assertIn('AFND_NUMBER.jff', html)
        self.assertIn('sim-afd-verdict-text', html)
        self.assertIn('sim-afnd-verdict-text', html)


if __name__ == '__main__':
    unittest.main()
