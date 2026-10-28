import re


class GrammarSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GrammarSingleton, cls).__new__(cls)
            cls._instance._init_grammar()
        return cls._instance

    def _init_grammar(self):
        # F-04, F-05, F-06, F-12 y F-13:
        # Alfabeto formal unificado: ASCII imprimible estricto (códigos 32..126).
        # Se reemplaza \d por [0-9] para impedir que dígitos Unicode (p. ej. ١٢٣) pasen el lexer.
        self.TOKEN_SPECS = [
            (
                'TIMESTAMP',
                r'(?:[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9])(?=[ \t\r\n]|$)'
            ),
            (
                'MALFORMED_TIMESTAMP',
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[^\s]*'
            ),
            (
                'IP',
                r'(?:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?=[ \t\r\n]|$)'
            ),
            ('SEVERITY',     r'\b(?:INFO|WARNING|ERROR|CRITICAL)\b'),
            ('EVENT_TYPE',   r'\b[A-Z]+(?:_[A-Z]+)*\b'),
            ('LBRACE',       r'\{'),
            ('RBRACE',       r'\}'),
            ('COLON',        r':'),
            ('COMMA',        r','),
            # F-12: STRING restringido a ASCII imprimible (0x20..0x7E) sin '"' ni '\' salvo escapes válidos
            ('STRING',       r'"(?:\\["\\/bfnrt]|[\x20-\x21\x23-\x5b\x5d-\x7e])*"'),
            ('LEADING_ZERO', r'\b0[0-9]+\b'),
            ('NUMBER',       r'\b(?:0|[1-9][0-9]*)(?=[ \t\r\n,}\]]|$)'),
            ('SPACE',        r'[ \t\r]+'),
            ('NEWLINE',      r'\n'),
            ('MISMATCH',     r'.'),
        ]

        self.TOK_REGEX = re.compile(
            '|'.join(f'(?P<{name}>{pattern})' for name, pattern in self.TOKEN_SPECS),
            re.ASCII
        )

        self.VALID_SOC_EVENTS = {
            'LOGIN_FAILED': 'Autenticación fallida (Control de Acceso SBS)',
            'PRIVILEGE_ESCALATION': 'Escalamiento de privilegios (Crítico SOC)',
            'BRUTE_FORCE_DETECTED': 'Ataque de fuerza bruta detectado',
            'SQL_INJECTION_ATTEMPT': 'Intento de inyección en capa de datos',
            'MALWARE_DETECTED': 'Ejecución de código malicioso bloqueada',
            'FIREWALL_DROP': 'Paquete descartado por regla perimetral',
            'UNAUTHORIZED_ACCESS': 'Acceso no autorizado a recurso sensible',
            'SESSION_HIJACK': 'Anomalía de secuestro de sesión',
            'DATA_EXFILTRATION': 'Alerta de transferencia anómala de datos',
            'PORT_SCAN': 'Reconocimiento de puertos en red interna',
            'ACCOUNT_LOCKED': 'Bloqueo preventivo de cuenta de usuario',
            'CONFIG_CHANGE': 'Modificación de configuración auditada'
        }

        self.CANONICAL_TOKEN_ORDER = [
            'TIMESTAMP', 'IP', 'SEVERITY', 'EVENT_TYPE',
            'STRING', 'NUMBER', 'LBRACE', 'RBRACE', 'COLON', 'COMMA'
        ]

        self.TOKEN_METADATA = {
            'TIMESTAMP': {
                'categoria': 'Marca Temporal ISO-8601 (Sin sufijo de zona)',
                'regex': r'[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]',
            },
            'IP': {
                'categoria': 'Dirección de Red IPv4 (ASCII)',
                'regex': r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',
            },
            'SEVERITY': {
                'categoria': 'Palabra Reservada de Criticidad',
                'regex': r'(INFO|WARNING|ERROR|CRITICAL)',
            },
            'EVENT_TYPE': {
                'categoria': 'Identificador Taxonómico de Evento SOC',
                'regex': r'[A-Z]+(_[A-Z]+)*',
            },
            'STRING': {
                'categoria': 'Literal de Cadena JSON Simplificado (ASCII 32..126)',
                'regex': r'"([\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\/bfnrt])*"',
            },
            'NUMBER': {
                'categoria': 'Entero JSON sin ceros iniciales (0..10^9)',
                'regex': r'0|[1-9][0-9]*',
            },
            'LBRACE': {
                'categoria': 'Delimitador Apertura de Objeto JSON',
                'regex': r'\{',
            },
            'RBRACE': {
                'categoria': 'Delimitador Cierre de Objeto JSON',
                'regex': r'\}',
            },
            'COLON': {
                'categoria': 'Separador Clave-Valor JSON',
                'regex': r':',
            },
            'COMMA': {
                'categoria': 'Separador de Pares JSON',
                'regex': r',',
            },
            'ERROR_LEXICO': {
                'categoria': 'Token Inválido / Fuera del Lenguaje Léxico',
                'regex': r'∉ L(AFD)',
            }
        }