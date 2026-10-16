import re

class GrammarSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GrammarSingleton, cls).__new__(cls)
            cls._instance._init_grammar()
        return cls._instance

    def _init_grammar(self):
        self.TOKEN_SPECS = [
            ('TIMESTAMP',  r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
            ('IP',         r'(\d{1,3}\.){3}\d{1,3}'),
            ('SEVERITY',   r'INFO|WARNING|ERROR|CRITICAL'),
            ('EVENT_TYPE', r'[A-Z]+(_[A-Z]+)*'),
            ('LBRACE',     r'\{'),
            ('RBRACE',     r'\}'),
            ('STRING',     r'"[^"]*"'),
            ('COLON',      r':'),
            ('COMMA',      r','),
            ('NUMBER',     r'\d+'),
            ('SPACE',      r'[ \t\r]+'),
            ('NEWLINE',    r'\n'),
            ('MISMATCH',   r'.'),
        ]
        self.TOK_REGEX = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in self.TOKEN_SPECS)

        self.DEFAULT_LOGS = (
            '2026-09-20T14:32:05 192.168.1.10 ERROR LOGIN_FAILED {"user":"admin","attempts":3}\n'
            '2026-10-12T08:15:30 10.0.0.5 CRITICAL PRIVILEGE_ESCALATION {"user":"root","ctx":{"port":22}}'
        )

        self.TOKEN_METADATA = {
            'TIMESTAMP': {
                'categoria': 'Fecha / Hora ISO-8601',
                'regex': r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
                'quintupla_afd': {'Q': '{q0..q19, qT}', 'Sigma': '{0-9, -, T, :}', 'q0': 'q0', 'F': '{q19}', 'delta': 'f: Q × Σ → Q'},
                'quintupla_afnd': {'Q': '{q0..q19}', 'Sigma': '{0-9, -, T, :}', 'q0': 'q0', 'F': '{q19}', 'delta': 'f: Q × Σ → P(Q)'}
            },
            'IP': {
                'categoria': 'Dirección de Red IPv4',
                'regex': r'(\d{1,3}\.){3}\d{1,3}',
                'quintupla_afd': {'Q': '{q0..q5, qT}', 'Sigma': '{0-9, .}', 'q0': 'q0', 'F': '{q5}', 'delta': 'f: Q × Σ → Q'},
                'quintupla_afnd': {'Q': '{q0..q5}', 'Sigma': '{0-9, .}', 'q0': 'q0', 'F': '{q5}', 'delta': 'f: Q × Σ → P(Q)'}
            },
            'SEVERITY': {
                'categoria': 'Nivel de Severidad (Enum)',
                'regex': r'INFO|WARNING|ERROR|CRITICAL',
                'quintupla_afd': {'Q': '{q0, qI, qW, qE, qC, qF, qT}', 'Sigma': '{A-Z}', 'q0': 'q0', 'F': '{qF}', 'delta': 'f: Q × Σ → Q'},
                'quintupla_afnd': {'Q': '{q0, qI, qW, qE, qC, qF}', 'Sigma': '{A-Z, λ}', 'q0': 'q0', 'F': '{qF}', 'delta': 'f: Q × (Σ∪{λ}) → P(Q)'}
            },
            'EVENT_TYPE': {
                'categoria': 'Identificador de Evento SOC',
                'regex': r'[A-Z]+(_[A-Z]+)*',
                'quintupla_afd': {'Q': '{q0, q1, q2, qT}', 'Sigma': '{A-Z, _}', 'q0': 'q0', 'F': '{q1}', 'delta': 'f: Q × Σ → Q'},
                'quintupla_afnd': {'Q': '{q0, q1, q2}', 'Sigma': '{A-Z, _}', 'q0': 'q0', 'F': '{q1}', 'delta': 'f: Q × Σ → P(Q)'}
            },
            'STRING': {
                'categoria': 'Literal de Cadena JSON',
                'regex': r'"[^"]*"',
                'quintupla_afd': {'Q': '{q0, q1, q2, qT}', 'Sigma': '{" , ASCII}', 'q0': 'q0', 'F': '{q2}', 'delta': 'f: Q × Σ → Q'},
                'quintupla_afnd': {'Q': '{q0, q1, q2}', 'Sigma': '{" , ASCII}', 'q0': 'q0', 'F': '{q2}', 'delta': 'f: Q × Σ → P(Q)'}
            },
            'NUMBER': {
                'categoria': 'Constante Numérica JSON',
                'regex': r'\d+',
                'quintupla_afd': {'Q': '{q0, q1, qT}', 'Sigma': '{0-9}', 'q0': 'q0', 'F': '{q1}', 'delta': 'f: Q × Σ → Q'},
                'quintupla_afnd': {'Q': '{q0, q1}', 'Sigma': '{0-9}', 'q0': 'q0', 'F': '{q1}', 'delta': 'f: Q × Σ → P(Q)'}
            }
        }

        for d_tok, sym_c, d_desc in [
            ('LBRACE', '{', 'Inicio de Objeto JSON'),
            ('RBRACE', '}', 'Fin de Objeto JSON'),
            ('COLON', ':', 'Separador Clave-Valor'),
            ('COMMA', ',', 'Separador de Campos')
        ]:
            self.TOKEN_METADATA[d_tok] = {
                'categoria': d_desc,
                'regex': f'\\{sym_c}' if sym_c in '{}' else sym_c,
                'quintupla_afd': {'Q': '{q0, q1, qT}', 'Sigma': f'{{{sym_c}}}', 'q0': 'q0', 'F': '{q1}', 'delta': 'f: Q × Σ → Q'},
                'quintupla_afnd': {'Q': '{q0, q1}', 'Sigma': f'{{{sym_c}}}', 'q0': 'q0', 'F': '{q1}', 'delta': 'f: Q × Σ → P(Q)'}
            }