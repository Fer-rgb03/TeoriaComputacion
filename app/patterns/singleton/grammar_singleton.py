class GrammarSingleton:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GrammarSingleton, cls).__new__(cls)
            cls._instance._init_grammar()
        return cls._instance

    def _init_grammar(self):
        # H-05 y M-12: NUMBER restringido a 0|[1-9][0-9]* (prohíbe ceros iniciales como 007).
        # M-10: STRING con secuencias de escape JSON simplificado (\", \\, \/, \b, \f, \n, \r, \t) y soporte UTF-8/Latin-1.
        self.TOKEN_SPECS = [
            ('TIMESTAMP',    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2}|\.\d+)?'),
            ('IP',           r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
            ('SEVERITY',     r'\b(?:INFO|WARNING|ERROR|CRITICAL)\b'),
            ('EVENT_TYPE',   r'\b[A-Z]+(?:_[A-Z]+)*\b'),
            ('LBRACE',       r'\{'),
            ('RBRACE',       r'\}'),
            ('COLON',        r':'),
            ('COMMA',        r','),
            ('STRING',       r'"(?:\\["\\/bfnrt]|[^"\\\x00-\x1f])*"'),
            ('LEADING_ZERO', r'\b0\d+\b'),
            ('NUMBER',       r'\b(?:0|[1-9]\d*)\b'),
            ('SPACE',        r'[ \t\r]+'),
            ('NEWLINE',      r'\n'),
            ('MISMATCH',     r'.'),
        ]

        self.TOK_REGEX = '|'.join(f'(?P<{name}>{pattern})' for name, pattern in self.TOKEN_SPECS)

        # B-14: Catálogo taxonómico real de eventos de seguridad SOC (Resolución SBS N.° 504-2021)
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

        # M-10: Expresiones regulares limpias (sin artefactos LaTeX ni espacios ambiguos)
        self.TOKEN_METADATA = {
            'TIMESTAMP': {
                'categoria': 'Marca Temporal ISO-8601 (UTC Local)',
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
                'categoria': 'Identificador Taxonómico de Evento SOC',
                'regex': r'[A-Z]+(_[A-Z]+)*',
            },
            'STRING': {
                'categoria': 'Literal de Cadena JSON Simplificado',
                'regex': r'"([^"\\\x00-\x1f]|\\["\\/bfnrt])*"',
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
                'categoria': 'Token Inválido / Símbolo o Formato Prohibido',
                'regex': r'∉ L(Σ_token)',
            }
        }