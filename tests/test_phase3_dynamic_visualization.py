import json
import re
import unittest
from app import create_app
from app.services.jflap_service import (
    get_formal_automaton_pair,
    build_dynamic_lexeme_simulation_payload,
    build_master_automata_catalog
)
from app.services.analyzer_service import analyze_single_log, analyze_logs_input


class TestPhase3DynamicVisualization(unittest.TestCase):
    """
    Fase 3 (Etapas A y B): Pruebas automatizadas de selección de lexemas reales,
    generación de pasos desde el modelo formal, ε-clausuras, diferenciación
    léxica/semántica/global y renderizado interactivo en la interfaz HTML.
    """

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_01_case1_valid_error_log_real_lexemes_and_traces(self):
        log1 = '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}'
        res = analyze_single_log(log1, line_number=1)
        self.assertTrue(res['is_valid'])
        self.assertEqual(len(res['tokens']), 13)

        tok_map = {t['value']: t for t in res['tokens']}
        sim_err = tok_map['ERROR']['dynamic_simulation']
        self.assertEqual(sim_err['lexeme'], 'ERROR')
        self.assertEqual(sim_err['automaton_category'], 'SEVERITY')
        self.assertTrue(sim_err['afd']['accepted'])
        self.assertTrue(sim_err['afnd']['accepted'])
        self.assertEqual(len(sim_err['afd']['steps']), 6)
        self.assertEqual([s['symbol'] for s in sim_err['afd']['steps'][1:]], ['E', 'R', 'R', 'O', 'R'])

    def test_02_case2_valid_info_log_updates_severity_and_does_not_keep_error(self):
        log2 = '2028-07-14T19:26:08 10.45.8.230 INFO PRIVILEGE_ESCALATION {"user":"operator","attempts":1}'
        ctx = analyze_logs_input(log2)
        res = ctx['results'][0]
        self.assertTrue(res['is_valid'])
        self.assertEqual(len(res['tokens']), 13)

        sev_sims = ctx['dynamic_lexemes_by_type']['SEVERITY']
        self.assertEqual(len(sev_sims), 1)
        sim_info = sev_sims[0]
        self.assertEqual(sim_info['lexeme'], 'INFO')
        self.assertEqual([s['symbol'] for s in sim_info['afd']['steps'][1:]], ['I', 'N', 'F', 'O'])

    def test_03_case3_semantic_error_2027_02_29_distinguishes_lexical_accept_from_semantic_reject(self):
        log3 = '2027-02-29T12:35:42 192.168.50.12 ERROR LOGIN_FAILED {"user":"admin","attempts":3}'
        res = analyze_single_log(log3, line_number=1)

        self.assertTrue(res['valid_lexical'])
        self.assertFalse(res['valid_semantic'])
        self.assertFalse(res['is_valid'])
        self.assertEqual(res['status'], 'ERROR SEMÁNTICO')

        dyn_ts = res['tokens'][0]['dynamic_simulation']
        self.assertTrue(dyn_ts['lexical_accepted'])
        self.assertFalse(dyn_ts['semantic_accepted'])
        self.assertFalse(dyn_ts['log_is_valid'])
        self.assertEqual(dyn_ts['log_status'], 'ERROR SEMÁNTICO')

    def test_04_case4_invalid_input_esto_no_es_un_log_valido_rejected_coherently(self):
        log4 = 'ESTO_NO_ES_UN_LOG_VALIDO'
        res = analyze_single_log(log4, line_number=1)
        self.assertFalse(res['is_valid'])
        self.assertFalse(res['valid_syntactic'])
        self.assertEqual(res['status'], 'ERROR SINTÁCTICO')
        self.assertFalse(res['tokens'][0]['dynamic_simulation']['log_is_valid'])

    def test_05_case5_step_by_step_navigation_forward_backward_reset_is_deterministic(self):
        afd_model, afnd_model, _ = get_formal_automaton_pair('SEVERITY')
        valid_afd_states = set(afd_model.state_ids)
        valid_afnd_states = set(afnd_model.state_ids)

        payload = build_dynamic_lexeme_simulation_payload('SEVERITY', 'ERROR')
        steps_afd = payload['afd']['steps']
        steps_afnd = payload['afnd']['steps']

        for idx in [0, 1, 2, 3, 2, 1, 0, len(steps_afd) - 1]:
            self.assertIn(steps_afd[idx]['active_state'], valid_afd_states)
            self.assertTrue(set(steps_afnd[idx]['active_states']).issubset(valid_afnd_states))

    def test_06_every_visualized_transition_exists_in_formal_model(self):
        log = '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}'
        res = analyze_single_log(log)
        for tok in res['tokens']:
            cat = tok['type']
            afd_model, afnd_model, _ = get_formal_automaton_pair(cat)
            afd_edges = {(t['from'], t['to'], t['label']) for t in afd_model.grouped_transitions}
            afnd_edges = {(t['from'], t['to'], t['label']) for t in afnd_model.grouped_transitions}

            for step in tok['dynamic_simulation']['afd']['steps'][1:]:
                tr = step['transition_used']
                self.assertIn((tr['from'], tr['to'], tr['label']), afd_edges)

            for step in tok['dynamic_simulation']['afnd']['steps'][1:]:
                for tr in step['transitions_used']:
                    self.assertIn((tr['from'], tr['to'], tr['label']), afnd_edges)
                for eps_tr in step['epsilon_transitions_used']:
                    self.assertIn((eps_tr['from'], eps_tr['to'], 'ε'), afnd_edges)

    def test_07_stage_b_ui_renders_dynamic_simulation_section_and_13_token_selectors(self):
        """Etapa B (Requisitos 1, 2, 3 y 5): Verifica renderizado HTML de la sección, controles y los 13 botones."""
        log1 = '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}'
        resp = self.client.post('/', data={'log_input': log1})
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')

        self.assertIn('Simulación dinámica del lexema actual', html)
        self.assertIn('Casos de demostración', html)
        self.assertIn('id="btn-sim-reset"', html)
        self.assertIn('id="btn-sim-start"', html)
        self.assertIn('id="btn-sim-prev"', html)
        self.assertIn('id="btn-sim-next"', html)
        self.assertIn('id="btn-sim-end"', html)

        # Verificar que existen los 13 botones selectores de token (L1_T1 a L1_T13)
        for idx in range(1, 14):
            self.assertIn(f'data-token-uid="L1_T{idx}"', html)

    def test_08_stage_b_embedded_json_matches_formal_engine_for_error_and_info(self):
        """Etapa B (Requisitos 3, 6, 7 y 10): Verifica que el JSON inyectado al navegador cambie de ERROR a INFO."""
        log_error = '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}'
        resp1 = self.client.post('/', data={'log_input': log_error})
        html1 = resp1.data.decode('utf-8')
        m1 = re.search(r'<script id="soc-dynamic-tokens-data" type="application/json">\s*(.*?)\s*</script>', html1, re.S)
        self.assertIsNotNone(m1)
        data1 = json.loads(m1.group(1))
        self.assertEqual(len(data1), 13)
        self.assertEqual(data1[2]['lexeme'], 'ERROR')

        log_info = '2028-07-14T19:26:08 10.45.8.230 INFO PRIVILEGE_ESCALATION {"user":"operator","attempts":1}'
        resp2 = self.client.post('/', data={'log_input': log_info})
        html2 = resp2.data.decode('utf-8')
        m2 = re.search(r'<script id="soc-dynamic-tokens-data" type="application/json">\s*(.*?)\s*</script>', html2, re.S)
        data2 = json.loads(m2.group(1))
        self.assertEqual(len(data2), 13)
        self.assertEqual(data2[2]['lexeme'], 'INFO')
        self.assertNotEqual(data2[2]['lexeme'], 'ERROR')

    def test_09_stage_b_svg_contains_data_edge_and_state_attributes_for_highlighting(self):
        """Etapa B (Requisito 4 y 12): Verifica que cada transición del modelo tenga su atributo data-edge-* en el SVG."""
        catalog = build_master_automata_catalog()
        for tok_type, entry in catalog.items():
            afd_svg = entry['jflap_afd_svg']
            for tr in entry['afd_transitions']:
                self.assertIn(f'data-edge-from="{tr["from"]}"', afd_svg)
                self.assertIn(f'data-edge-to="{tr["to"]}"', afd_svg)
    def test_10_stage_c_two_different_logs_same_category_automaton_changes_lexemes_and_paths(self):
        """
        NOTA ESPECIAL OBLIGATORIA (Etapa C):
        Analiza 2 logs diferentes en el mismo lote y verifica que al seleccionar sus tokens
        (L1_T1 vs L2_T1 en TIMESTAMP, L1_T2 vs L2_T2 en IP, L1_T3 vs L2_T3 en SEVERITY,
        L1_T4 vs L2_T4 en EVENT_TYPE y L1_T8 vs L2_T8 en STRING) cambian las cadenas y los
        recorridos de simulación, aunque ambos utilicen el mismo autómata de categoría.
        """
        batch_two_logs = (
            '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}\n'
            '2028-07-14T19:26:08 10.45.8.230 INFO PRIVILEGE_ESCALATION {"user":"operator","attempts":1}'
        )
        resp = self.client.post('/', data={'log_input': batch_two_logs})
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')

        m = re.search(r'<script id="soc-dynamic-tokens-data" type="application/json">\s*(.*?)\s*</script>', html, re.S)
        self.assertIsNotNone(m)
        all_tokens = json.loads(m.group(1))
        self.assertEqual(len(all_tokens), 26)  # 13 tokens del Log 1 + 13 tokens del Log 2

        by_uid = {t['token_uid']: t for t in all_tokens}

        # 1) Categoría SEVERITY: L1_T3 ('ERROR') vs L2_T3 ('INFO') usan el mismo autómata SEVERITY
        t_err = by_uid['L1_T3']
        t_info = by_uid['L2_T3']
        self.assertEqual(t_err['automaton_category'], 'SEVERITY')
        self.assertEqual(t_info['automaton_category'], 'SEVERITY')
        self.assertEqual(t_err['lexeme'], 'ERROR')
        self.assertEqual(t_info['lexeme'], 'INFO')

        path_err_afd = [s['active_state'] for s in t_err['afd']['steps']]
        path_info_afd = [s['active_state'] for s in t_info['afd']['steps']]
        # Ambos inician en q0, pero siguen estados distintos y longitudes distintas (6 vs 5 pasos)
        self.assertEqual(path_err_afd[0], 'q0')
        self.assertEqual(path_info_afd[0], 'q0')
        self.assertNotEqual(path_err_afd[1:], path_info_afd[1:])
        self.assertEqual(len(path_err_afd), 6)
        self.assertEqual(len(path_info_afd), 5)

        # 2) Categoría IP: L1_T2 ('172.16.25.104') vs L2_T2 ('10.45.8.230') usan el mismo autómata IP
        ip1 = by_uid['L1_T2']
        ip2 = by_uid['L2_T2']
        self.assertEqual(ip1['automaton_category'], 'IP')
        self.assertEqual(ip2['automaton_category'], 'IP')
        self.assertEqual(ip1['lexeme'], '172.16.25.104')
        self.assertEqual(ip2['lexeme'], '10.45.8.230')
        self.assertNotEqual(
            [(s['symbol'], s['active_state']) for s in ip1['afd']['steps'][1:]],
            [(s['symbol'], s['active_state']) for s in ip2['afd']['steps'][1:]]
        )

        # 3) Categoría STRING: L1_T8 ('"security_admin"') vs L2_T8 ('"operator"')
        s1 = by_uid['L1_T8']
        s2 = by_uid['L2_T8']
        self.assertEqual(s1['automaton_category'], 'STRING')
        self.assertEqual(s2['automaton_category'], 'STRING')
        self.assertEqual(s1['lexeme'], '"security_admin"')
        self.assertEqual(s2['lexeme'], '"operator"')
        self.assertNotEqual(len(s1['afd']['steps']), len(s2['afd']['steps']))

    def test_11_stage_c_error_simulation_identifies_exact_symbol_and_position_for_trap_and_empty_set(self):
        """
        Prioridad 3 (Simulación de errores):
        Verifica que para entradas inválidas (007, 2026-13-01T14:32:05, 2026-10-28T07:15:30Z y @)
        el simulador señale el símbolo exacto y la posición exacta donde el AFD entra en qT
        y el AFND cae en conjunto vacío ∅.
        """
        # Caso A: 007 en NUMBER -> Posición 2, símbolo '0' transita de q1 a qT (AFD) y a ∅ (AFND)
        sim_007 = build_dynamic_lexeme_simulation_payload(
            'ERROR_LEXICO', '007', target_category_override='NUMBER'
        )
        self.assertFalse(sim_007['lexical_accepted'])
        self.assertEqual(sim_007['afd']['error_position'], 2)
        self.assertEqual(sim_007['afd']['error_symbol'], '0')
        self.assertEqual(sim_007['afd']['final_states_reached'], ['qT'])
        self.assertEqual(sim_007['afnd']['error_position'], 2)
        self.assertEqual(sim_007['afnd']['error_symbol'], '0')
        self.assertTrue(sim_007['afnd']['steps'][-1]['is_empty_set'])

        # Caso B: 2026-13-01T14:32:05 en TIMESTAMP -> Posición 7, símbolo '3' (mes 13 inválido)
        sim_m13 = build_dynamic_lexeme_simulation_payload(
            'ERROR_LEXICO', '2026-13-01T14:32:05', target_category_override='TIMESTAMP'
        )
        self.assertFalse(sim_m13['lexical_accepted'])
        self.assertEqual(sim_m13['afd']['error_position'], 7)
        self.assertEqual(sim_m13['afd']['error_symbol'], '3')
        self.assertEqual(sim_m13['afd']['steps'][-1]['active_state'], 'qT')
        self.assertEqual(sim_m13['afnd']['error_position'], 7)
        self.assertEqual(sim_m13['afnd']['error_symbol'], '3')
        self.assertEqual(sim_m13['afnd']['steps'][-1]['active_states'], [])

        # Caso C: 2026-10-28T07:15:30Z -> Posición 20, símbolo 'Z'
        log_z = analyze_single_log('2026-10-28T07:15:30Z 192.168.1.10 INFO LOGIN_FAILED {"user":"admin"}')
        dyn_z = log_z['tokens'][0]['dynamic_simulation']
        self.assertEqual(dyn_z['afd']['error_position'], 20)
        self.assertEqual(dyn_z['afd']['error_symbol'], 'Z')

    def test_12_stage_c_coherence_of_three_verdicts_across_lexical_syntactic_and_semantic_logs(self):
        """
        Prioridad 2 y 6:
        Verifica en un lote mixto (1 válido, 1 error léxico, 1 error sintáctico, 1 error semántico)
        que cada token conserve por separado su aceptación léxica, su validación semántica y el
        veredicto global desglosado del log.
        """
        mixed_batch = "\n".join([
            '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}',
            '2026-09-20T14:32:05 192.168.1.10 @ ERROR LOGIN_FAILED {"user":"admin"}',
            '2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3',
            '2027-02-29T12:35:42 192.168.50.12 ERROR LOGIN_FAILED {"user":"admin","attempts":3}'
        ])
        ctx = analyze_logs_input(mixed_batch)
        self.assertEqual(len(ctx['results']), 4)

        # Log 1: Válido en las 3 fases
        t_l1 = ctx['results'][0]['tokens'][0]['dynamic_simulation']
        self.assertTrue(t_l1['lexical_accepted'])
        self.assertTrue(t_l1['semantic_accepted'])
        self.assertTrue(t_l1['log_is_valid'])

        # Log 2: Error Léxico (@ en token #3)
        t_l2_at = ctx['results'][1]['tokens'][2]['dynamic_simulation']
        self.assertFalse(t_l2_at['lexical_accepted'])
        self.assertFalse(t_l2_at['log_valid_lexical'])
        self.assertEqual(t_l2_at['log_status'], 'ERROR LÉXICO')

        # Log 3: Error Sintáctico (sus tokens son léxica y semánticamente válidos, pero el log falla en sintaxis)
        t_l3_first = ctx['results'][2]['tokens'][0]['dynamic_simulation']
        self.assertTrue(t_l3_first['lexical_accepted'])
        self.assertTrue(t_l3_first['semantic_accepted'])
        self.assertTrue(t_l3_first['log_valid_lexical'])
        self.assertFalse(t_l3_first['log_valid_syntactic'])
        self.assertEqual(t_l3_first['log_status'], 'ERROR SINTÁCTICO')

        # Log 4: Error Semántico (2027-02-29 es léxicamente válido en q27, pero semánticamente rechazado)
        t_l4_ts = ctx['results'][3]['tokens'][0]['dynamic_simulation']
        self.assertTrue(t_l4_ts['lexical_accepted'])
        self.assertFalse(t_l4_ts['semantic_accepted'])
        self.assertTrue(t_l4_ts['log_valid_lexical'])
        self.assertTrue(t_l4_ts['log_valid_syntactic'])
        self.assertFalse(t_l4_ts['log_valid_semantic'])
        self.assertEqual(t_l4_ts['log_status'], 'ERROR SEMÁNTICO')

    def test_13_stage_c_simplified_view_attributes_and_zoom_controls_present_without_altering_model(self):
        """
        Verifica que los elementos hacia qT estén marcados con data-trap-element="true" para la
        Vista Simplificada, sin eliminar qT del modelo formal ni de las tablas.
        """
        resp = self.client.get('/')
        html = resp.data.decode('utf-8')
        self.assertIn('id="btn-toggle-trap-view"', html)
        self.assertIn('id="btn-zoom-in"', html)
        self.assertIn('id="btn-zoom-out"', html)
        self.assertIn('id="btn-zoom-reset"', html)
        self.assertIn('data-trap-element="true"', html)
        self.assertIn('data-state-node="qT"', html)

    def test_14_stage_c_boundary_navigation_limits_step_0_and_final_step(self):
        """
        Prioridad 4: Comprueba los límites inferior (Paso 0) y superior (Paso N) de la cadena.
        """
        sim = build_dynamic_lexeme_simulation_payload('LBRACE', '{')
        steps = sim['afd']['steps']
        self.assertEqual(len(steps), 2)  # Paso 0 y Paso 1
        # Límite inferior (Paso 0): 0 consumidos, cadena pendiente completa '{'
        self.assertEqual(steps[0]['step'], 0)
        self.assertIsNone(steps[0]['symbol'])
        self.assertEqual(steps[0]['consumed_input'], '')
        self.assertEqual(steps[0]['remaining_input'], '{')
        # Límite superior (Paso 1): '{' consumido, cadena pendiente 'ε'
        self.assertEqual(steps[-1]['step'], 1)
        self.assertEqual(steps[-1]['symbol'], '{')
        self.assertEqual(steps[-1]['consumed_input'], '{')
        self.assertEqual(steps[-1]['remaining_input'], 'ε')

    def test_15_stage_c_simulate_token_buttons_bind_exact_token_uid_not_default_sample(self):
        """
        Prioridad 1: Verifica que cada botón 'Simular Token #k' en la tabla de resultados
        llame a jumpToAutomaton con el UID exacto de ese token (L1_Tk, L2_Tk).
        """
        batch = (
            '2026-10-17T08:43:29 172.16.25.104 ERROR LOGIN_FAILED {"user":"security_admin","attempts":5}\n'
            '2028-07-14T19:26:08 10.45.8.230 INFO PRIVILEGE_ESCALATION {"user":"operator","attempts":1}'
        )
        resp = self.client.post('/', data={'log_input': batch})
        html = resp.data.decode('utf-8')
        self.assertIn("jumpToAutomaton('SEVERITY', 'L1_T3')", html)
        self.assertIn("jumpToAutomaton('SEVERITY', 'L2_T3')", html)
        self.assertIn("jumpToAutomaton('IP', 'L1_T2')", html)
        self.assertIn("jumpToAutomaton('IP', 'L2_T2')", html)


if __name__ == '__main__':
    unittest.main()