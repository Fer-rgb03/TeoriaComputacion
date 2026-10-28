import os
import json
import unittest
from app import create_app
from app.config import Config
from app.services.analyzer_service import (
    analyze_single_log,
    analyze_logs_input,
    save_session_reports,
    verify_persisted_session_records
)


class TestSOCAnalyzerRegressionSuite(unittest.TestCase):
    """Suite automatizada de regresión (F-19) que verifica la Matriz Mínima de la Sección 7."""

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    # 1. TIMESTAMP 2024-02-29T23:59:59 -> Aceptar (bisiesto válido)
    def test_01_timestamp_leap_year_2024_accepted(self):
        res = analyze_single_log('2024-02-29T23:59:59 192.168.1.10 INFO LOGIN_FAILED {"user":"admin"}')
        self.assertTrue(res['is_valid'])
        self.assertEqual(res['status'], 'VÁLIDO (ACEPTADO)')

    # 2. TIMESTAMP 2026-02-29T23:59:59 -> Rechazar por calendario (2026 no es bisiesto)
    def test_02_timestamp_non_leap_2026_rejected_calendar(self):
        res = analyze_single_log('2026-02-29T23:59:59 192.168.1.10 INFO LOGIN_FAILED {"user":"admin"}')
        self.assertTrue(res['valid_lexical'])
        self.assertFalse(res['valid_semantic'])
        self.assertFalse(res['is_valid'])
        self.assertEqual(res['status'], 'ERROR SEMÁNTICO')

    # 3. TIMESTAMP 2026-13-01T14:32:05 -> Rechazar en fase léxica coherente con el AFD
    def test_03_timestamp_month_13_rejected_lexically(self):
        res = analyze_single_log('2026-13-01T14:32:05 192.168.1.10 INFO LOGIN_FAILED {"user":"admin"}')
        self.assertFalse(res['valid_lexical'])
        self.assertFalse(res['is_valid'])
        self.assertEqual(res['status'], 'ERROR LÉXICO')

    # 4. TIMESTAMP 2026-10-28T07:15:30Z -> Rechazar léxicamente (sufijo Z fuera de alcance)
    def test_04_timestamp_suffix_z_rejected_lexically(self):
        res = analyze_single_log('2026-10-28T07:15:30Z 192.168.1.10 INFO LOGIN_FAILED {"user":"admin"}')
        self.assertFalse(res['valid_lexical'])
        self.assertEqual(res['status'], 'ERROR LÉXICO')

    # 5. IP 255.255.255.255 -> Aceptar
    def test_05_ip_255_accepted(self):
        res = analyze_single_log('2026-09-20T14:32:05 255.255.255.255 ERROR LOGIN_FAILED {"user":"admin"}')
        self.assertTrue(res['is_valid'])

    # 6. IP 256.1.1.1 -> Rechazar semánticamente
    def test_06_ip_256_rejected_semantically(self):
        res = analyze_single_log('2026-09-20T14:32:05 256.1.1.1 ERROR LOGIN_FAILED {"user":"admin"}')
        self.assertTrue(res['valid_lexical'])
        self.assertFalse(res['valid_semantic'])
        self.assertEqual(res['status'], 'ERROR SEMÁNTICO')

    # 7. IP 192.168.001.1 y dígitos arábigo-índicos -> Rechazar
    def test_07_ip_leading_zeros_and_unicode_digits_rejected(self):
        res_zero = analyze_single_log('2026-09-20T14:32:05 192.168.001.1 ERROR LOGIN_FAILED {"user":"admin"}')
        self.assertFalse(res_zero['is_valid'])
        res_uni = analyze_single_log('2026-09-20T14:32:05 ١٩٢.١٦٨.١.١ ERROR LOGIN_FAILED {"user":"admin"}')
        self.assertFalse(res_uni['valid_lexical'])
        self.assertFalse(res_uni['is_valid'])

    # 8, 9 y 10. STRING "admin" (Aceptar), Unicode "中文" (Rechazar en ambos) y "usr\"admin" (Aceptar)
    def test_08_09_10_strings_ascii_unicode_and_escaped_quotes(self):
        res_ok = analyze_single_log('2026-09-20T14:32:05 10.0.0.1 INFO LOGIN_FAILED {"user":"admin"}')
        self.assertTrue(res_ok['is_valid'])

        res_esc = analyze_single_log(r'2026-09-20T14:32:05 10.0.0.1 INFO LOGIN_FAILED {"user":"usr\"admin"}')
        self.assertTrue(res_esc['is_valid'])

        res_uni = analyze_single_log('2026-09-20T14:32:05 10.0.0.1 INFO LOGIN_FAILED {"user":"中文"}')
        self.assertFalse(res_uni['valid_lexical'])
        self.assertFalse(res_uni['is_valid'])

    # 11, 12 y 13. NUMBER 0 (Aceptar), 007 (Rechazar léxicamente), 1000000001 (Rechazar por límite semántico)
    def test_11_12_13_numbers_zero_leading_zero_and_range(self):
        res_zero = analyze_single_log('2026-09-20T14:32:05 10.0.0.1 INFO LOGIN_FAILED {"attempts":0}')
        self.assertTrue(res_zero['is_valid'])

        res_007 = analyze_single_log('2026-09-20T14:32:05 10.0.0.1 INFO LOGIN_FAILED {"attempts":007}')
        self.assertFalse(res_007['valid_lexical'])
        self.assertEqual(res_007['status'], 'ERROR LÉXICO')

        res_big = analyze_single_log('2026-09-20T14:32:05 10.0.0.1 INFO LOGIN_FAILED {"attempts":1000000001}')
        self.assertTrue(res_big['valid_lexical'])
        self.assertFalse(res_big['valid_semantic'])
        self.assertEqual(res_big['status'], 'ERROR SEMÁNTICO')

    # 14. PAYLOAD {"user":"admin", "ctx":{"port":22}} -> Aceptar y preservar jerarquía en árbol semántico (F-20)
    def test_14_nested_payload_preserves_semantic_hierarchy(self):
        res = analyze_single_log('2026-09-20T14:32:05 10.0.0.1 INFO LOGIN_FAILED {"user":"admin","ctx":{"port":22}}')
        self.assertTrue(res['is_valid'])
        self.assertIn('ObjetoJSON', res['general_sem_svg'])
        self.assertIn('"port"', res['general_sem_svg'])

    # 15. Archivo de extensión no permitida -> Rechazar sin generar reporte alternativo (F-07)
    def test_15_invalid_file_extension_cancels_analysis(self):
        from io import BytesIO
        resp = self.client.post('/', data={
            'txt_file': (BytesIO(b'contenido'), 'malicioso.exe')
        }, content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')
        self.assertIn('Análisis cancelado', html)

    # 16. Lote de 201 líneas -> Procesa 200 y activa truncated_batch=True con conteo exacto (F-08)
    def test_16_batch_over_200_lines_warns_truncation(self):
        valid_line = '2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3}'
        batch_201 = "\n".join([valid_line] * 201)
        ctx = analyze_logs_input(batch_201)
        self.assertTrue(ctx['summary']['truncated_batch'])
        self.assertEqual(ctx['summary']['total_received'], 201)
        self.assertEqual(ctx['summary']['total_lines'], 200)
        self.assertEqual(ctx['summary']['discarded_lines'], 1)

    # 17. HMAC -> Registro alterado después de guardarse en disco debe fallar la verificación posterior (F-02)
    def test_17_hmac_tampered_persisted_record_fails_verification(self):
        line = '2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3}'
        res = analyze_single_log(line, line_number=1)
        run_id = "test0123456789ab"
        save_session_reports([res], run_id=run_id)

        # Verificación intacta desde disco = True
        audit_ok = verify_persisted_session_records(run_id)
        self.assertTrue(audit_ok['verificado'])
        self.assertEqual(audit_ok['integros'], 1)

        # Alterar 1 carácter en el archivo persistido en disco
        store_path = os.path.join(Config.SESSIONS_DIR, f"registros_firmados_{run_id}.json")
        with open(store_path, "r", encoding="utf-8") as f:
            stored_data = json.load(f)
        stored_data["registros"][0]["log_original"] = line.replace('"attempts":3', '"attempts":9')
        with open(store_path, "w", encoding="utf-8") as f:
            json.dump(stored_data, f)

        # La verificación posterior debe fallar (verificado=False, alterados=1)
        audit_tampered = verify_persisted_session_records(run_id)
        self.assertFalse(audit_tampered['verificado'])
        self.assertEqual(audit_tampered['alterados'], 1)


if __name__ == '__main__':
    unittest.main()