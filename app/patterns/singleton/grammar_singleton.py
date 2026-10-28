import re


class GrammarSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GrammarSingleton, cls).__new__(cls)
            cls._instance._init_grammar()
        return cls._instance

    def _init_grammar(self):
        # Punto 2.5: STRING admite secuencias de escape JSON válidas (\", \\, \/, \b, \f, \n, \r, \t, \uXXXX)
        self.TOKEN_SPECS = [
            ('TIMESTAMP',  r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'),
            ('IP',         r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
            ('SEVERITY',   r'\b(?:INFO|WARNING|ERROR|CRITICAL)\b'),
            ('EVENT_TYPE', r'\b[A-Z]+(?:_[A-Z]+)*\b'),
            ('LBRACE',     r'\{'),
            ('RBRACE',     r'\}'),
            ('COLON',      r':'),
            ('COMMA',      r','),
            ('STRING',     r'"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\\x00-\x1f])*"'),
            ('NUMBER',     r'\b\d+\b'),
            ('SPACE',      r'[ \t]+'),
            ('NEWLINE',    r'\n'),
            ('MISMATCH',   r'.'),
        ]

        self.TOK_REGEX = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in self.TOKEN_SPECS)

        # Punto 2.1 y 2.2: Metadatos sincronizados con las definiciones formales y alfabetos explícitos
        self.TOKEN_METADATA = {
            'TIMESTAMP': {
                'categoria': 'Marca Temporal ISO-8601',
                'regex': r'[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]',
            },
            'IP': {
                'categoria': 'Dirección de Red IPv4',
                'regex': r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
            },
            'SEVERITY': {
                'categoria': 'Palabra Reservada de Criticidad',
                'regex': r'(INFO|WARNING|ERROR|CRITICAL)',
            },
            'EVENT_TYPE': {
                'categoria': 'Identificador de Evento SOC',
                'regex': r'[A-Z]+(_[A-Z]+)*',
            },
            'STRING': {
                'categoria': 'Literal de Cadena JSON (con soporte de escape \\")',
                'regex': r'"(\Sigma_{base} | \\["\\/bfnrt])*"',
            },
            'NUMBER': {
                'categoria': 'Constante Entera No Negativa',
                'regex': r'[0-9]+',
            },
            'LBRACE': {
                'categoria': 'Delimitador Apertura JSON',
                'regex': r'\{',
            },
            'RBRACE': {
                'categoria': 'Delimitador Cierre JSON',
                'regex': r'\}',
            },
            'COLON': {
                'categoria': 'Separador Clave-Valor JSON',
                'regex': r':',
            },
            'COMMA': {
                'categoria': 'Separador de Atributos JSON',
                'regex': r',',
            }
        }