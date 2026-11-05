#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Diagnóstico aislado del vínculo lexer / simulador formal.

No modifica archivos .jff ni código de producción. Inyecta resultados
controlados en los modelos existentes mediante proxies en memoria.
IMPORTANTE: las pruebas de fallo inyectado NO equivalen a construir AFD nuevos.
"""
import os
import sys
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_CANDIDATES = [os.path.abspath(os.path.join(HERE, '..', '..')), os.getcwd()]
ROOT = next((p for p in ROOT_CANDIDATES
             if os.path.isfile(os.path.join(p, 'app', 'services', 'analyzer_service.py'))), None)
if not ROOT:
    raise RuntimeError('Ejecuta este archivo dentro de tests/diagnostics/ del proyecto.')
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.services.analyzer_service import analyze_single_log
import app.services.jflap_service as jflap_service
import app.services.analyzer_service as analyzer_service

VALID_LOG = '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":5}'
ZERO_LOG = '2026-10-17T08:43:29 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":007}'


class SimulationOverride:
    """Delegación transparente: altera solo el resultado de una palabra elegida."""
    def __init__(self, original, target, decision):
        self.original = original
        self.target = target
        self.decision = decision

    def __getattr__(self, name):
        return getattr(self.original, name)

    def simulate(self, word, *args, **kwargs):
        result = self.original.simulate(word, *args, **kwargs)
        if word != self.target:
            return result
        result = dict(result)
        result['accepted'] = self.decision
        if not self.decision:
            result['error_position'] = 1
            result['error_symbol'] = word[0] if word else ''
        return result


def injected_pair(token, target, accepted):
    """Reutiliza los AFD/AFND de producción; no instancia FormalAutomatonModel."""
    getter = jflap_service.get_formal_automaton_pair
    calls = []

    def replacement(tok_type):
        afd, afnd, meta = getter(tok_type)
        if tok_type == token:
            calls.append(tok_type)
            return (SimulationOverride(afd, target, accepted),
                    SimulationOverride(afnd, target, accepted), meta)
        return afd, afnd, meta

    return replacement, calls


class BindingDiagnostics(unittest.TestCase):
    def test_01_dynamic_payload_is_generated(self):
        observed = []
        original = analyzer_service.build_dynamic_lexeme_simulation_payload

        def trace(*args, **kwargs):
            result = original(*args, **kwargs)
            observed.append((args, kwargs, result))
            return result

        with patch.object(analyzer_service, 'build_dynamic_lexeme_simulation_payload', side_effect=trace):
            res = analyze_single_log(VALID_LOG, 1)
        self.assertTrue(res['valid_lexical'])
        self.assertGreater(len(observed), 0, 'No se llamó al generador de simulación dinámica')
        self.assertTrue(any(t.get('type') == 'SEVERITY' and t.get('value') == 'ERROR'
                            for t in res['tokens']))
        self.assertTrue(all('afd' in entry[2] and 'afnd' in entry[2] for entry in observed))

    def test_02_injected_rejection_must_be_visible(self):
        replacement, calls = injected_pair('SEVERITY', 'ERROR', False)
        with patch.object(jflap_service, 'get_formal_automaton_pair', side_effect=replacement):
            res = analyze_single_log(VALID_LOG, 1)
        self.assertGreater(len(calls), 0, 'El parche no alcanzó la simulación: resultado no concluyente')
        tok = next(t for t in res['tokens'] if t.get('type') == 'SEVERITY')
        self.assertFalse(tok['dynamic_simulation']['afd']['accepted'])
        self.assertFalse(tok['dynamic_simulation']['afnd']['accepted'])
        print('\nINYECCIÓN DE RECHAZO: AFD=False; valid_lexical=%r; status=%s' %
              (res['valid_lexical'], res['status']))
        # Este es el resultado a medir, no asumimos que la integración sea o no vinculante.
        self.assertIsInstance(res['valid_lexical'], bool)

    def test_03_lexer_leading_zero_rejects(self):
        # La decisión se modifica solo si NUMBER llega a simular "007".
        replacement, calls = injected_pair('NUMBER', '007', True)
        with patch.object(jflap_service, 'get_formal_automaton_pair', side_effect=replacement):
            res = analyze_single_log(ZERO_LOG, 1)
        print('\nCERO INICIAL: valid_lexical=%r; status=%s; consultas NUMBER=%d' %
              (res['valid_lexical'], res['status'], len(calls)))
        self.assertFalse(res['valid_lexical'])
        self.assertFalse(res['is_valid'])
        # Si NUMBER no se simuló, demuestra que el escáner rechazó antes de esa etapa;
        # no afirmar que un AFD alterado aceptó realmente ese lexema en el pipeline.

    def test_04_originals_are_restored(self):
        afd, afnd, _ = jflap_service.get_formal_automaton_pair('SEVERITY')
        self.assertTrue(afd.simulate('ERROR')['accepted'])
        self.assertTrue(afnd.simulate('ERROR')['accepted'])
        afd, afnd, _ = jflap_service.get_formal_automaton_pair('NUMBER')
        self.assertFalse(afd.simulate('007')['accepted'])
        self.assertFalse(afnd.simulate('007')['accepted'])


if __name__ == '__main__':
    print('DIAGNÓSTICO DE INYECCIÓN EN MEMORIA (SIN CAMBIOS DE PRODUCCIÓN)')
    unittest.main(verbosity=2)
