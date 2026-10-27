import re
import calendar
from app.utils.helpers import escape_svg_text

SUSPICIOUS_TREE_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b|--|;|\bOR\b\s+['\"\d]+=['\"\d]+|"
    r"\$ne|\$gt|\$lt|\$where|<script|javascript:|\.\./|\x00)",
    re.IGNORECASE
)


def compute_tree_layout(node, depth=0, x_Step=118, y_step=76, counter=None):
    if counter is None:
        counter = [0]
    children = node.get('children', [])
    node['depth'] = depth
    node['y'] = 44 + depth * y_step

    if not children:
        node['x'] = 68 + counter[0] * x_Step
        counter[0] += 1
    else:
        for ch in children:
            compute_tree_layout(ch, depth + 1, x_Step, y_step, counter)
        node['x'] = (children[0]['x'] + children[-1]['x']) / 2.0

    return counter[0]


def get_max_depth(node):
    children = node.get('children', [])
    if not children:
        return node.get('depth', 0)
    return max(get_max_depth(ch) for ch in children)


def tree_to_parentheses(node):
    lbl = node.get('label', '')
    sub = node.get('sub', '')
    head = f"{lbl}:{sub}" if sub else lbl
    children = node.get('children', [])
    if not children:
        return head
    inner = ", ".join(tree_to_parentheses(ch) for ch in children)
    return f"( {head} ( {inner} ) )"


def render_real_tree_svg(root, tree_kind="syntactic"):
    x_step = 112
    y_step = 78
    leaf_count = compute_tree_layout(root, 0, x_step, y_step)
    max_depth = get_max_depth(root)

    width = max(560, int(leaf_count * x_step + 90))
    height = max(210, int((max_depth + 1) * y_step + 55))

    if tree_kind == "syntactic":
        root_fill, root_stroke = "#fef3c7", "#b45309"
        int_fill, int_stroke = "#e0f2fe", "#0369a1"
        leaf_fill, leaf_stroke = "#dcfce7", "#15803d"
    else:
        root_fill, root_stroke = "#f3e8ff", "#6d28d9"
        int_fill, int_stroke = "#fae8ff", "#a21caf"
        leaf_fill, leaf_stroke = "#fef9c3", "#a16207"

    edges_svg = []
    nodes_svg = []

    def traverse(n, is_root=False):
        children = n.get('children', [])
        x, y = n['x'], n['y']
        for ch in children:
            cx, cy = ch['x'], ch['y']
            edges_svg.append(
                f'<line x1="{x:.1f}" y1="{y + 18:.1f}" x2="{cx:.1f}" y2="{cy - 20:.1f}" '
                f'stroke="#334155" stroke-width="1.8" marker-end="url(#tree-arrow)"/>'
            )
            traverse(ch, is_root=False)

        if is_root:
            fill, stroke = root_fill, root_stroke
            role_tag = "Raíz (Nivel 1)"
        elif children:
            fill, stroke = int_fill, int_stroke
            role_tag = f"Nodo Interior (Niv. {n['depth']+1})"
        else:
            fill, stroke = leaf_fill, leaf_stroke
            role_tag = "Nodo Hoja"

        lbl = escape_svg_text(n.get('label', ''))
        sub = escape_svg_text(n.get('sub', ''))

        box_w = max(88, max(len(lbl), len(sub)) * 6.8 + 20)
        box_h = 38 if sub else 28

        nodes_svg.append(
            f'<rect x="{x - box_w/2:.1f}" y="{y - box_h/2:.1f}" width="{box_w:.1f}" height="{box_h:.1f}" '
            f'rx="7" fill="{fill}" stroke="{stroke}" stroke-width="1.8"/>'
        )
        if sub:
            nodes_svg.append(
                f'<text x="{x:.1f}" y="{y - 3:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="10.5" font-weight="bold" fill="#0f172a">{lbl}</text>'
            )
            nodes_svg.append(
                f'<text x="{x:.1f}" y="{y + 11:.1f}" text-anchor="middle" font-family="monospace" '
                f'font-size="9.5" fill="#334155">{sub}</text>'
            )
        else:
            nodes_svg.append(
                f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="11" font-weight="bold" fill="#0f172a">{lbl}</text>'
            )

        nodes_svg.append(
            f'<text x="{x:.1f}" y="{y - box_h/2 - 5:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
            f'font-size="8.5" fill="#64748b">{role_tag}</text>'
        )

    traverse(root, is_root=True)

    svg = [
        f'<svg viewBox="0 0 {width} {height}" class="w-full h-auto rounded-lg border border-slate-300 bg-white shadow-sm" xmlns="http://www.w3.org/2000/svg">',
        '<defs>',
        '  <marker id="tree-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5.5" markerHeight="5.5" orient="auto">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#334155"/>',
        '  </marker>',
        '</defs>',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        *edges_svg,
        *nodes_svg,
        '</svg>'
    ]
    return '\n'.join(svg)


def build_token_real_trees(tok_type, val):
    """
    Puntos 2.3, 2.4 y 2.9: Construye el Árbol Sintáctico y el Árbol Semántico de cada token
    aplicando exactamente las mismas reglas de calendario (incluyendo años bisiestos),
    octetos IPv4 (0..255 sin ceros iniciales ambiguos) y seguridad de cadenas.
    """
    if tok_type == 'TIMESTAMP':
        y_str, m_str, d_str = val[0:4], val[5:7], val[8:10]
        hh_str, mm_str, ss_str = val[11:13], val[14:16], val[17:19]

        y_int, m_int, d_int = int(y_str), int(m_str), int(d_str)
        hh_int, mm_int, ss_int = int(hh_str), int(mm_str), int(ss_str)

        errors_ts = []
        if not (1970 <= y_int <= 2100):
            errors_ts.append(f"Año fuera de rango ({y_int})")
        if not (1 <= m_int <= 12):
            errors_ts.append(f"Mes inválido ({m_int}; rango 01..12)")
            max_day = 31
        else:
            max_day = calendar.monthrange(y_int, m_int)[1]
            if not (1 <= d_int <= max_day):
                bisiesto_str = "bisiesto" if calendar.isleap(y_int) else "no bisiesto"
                errors_ts.append(f"Día inválido ({d_int}) para mes {m_int:02d}/{y_int} ({bisiesto_str}, máx {max_day})")
        if not (0 <= hh_int <= 23):
            errors_ts.append(f"Hora inválida ({hh_int}; rango 00..23)")
        if not (0 <= mm_int <= 59):
            errors_ts.append(f"Minuto inválido ({mm_int}; rango 00..59)")
        if not (0 <= ss_int <= 59):
            errors_ts.append(f"Segundo inválido ({ss_int}; rango 00..59)")

        sem_ok = len(errors_ts) == 0
        sem_msg = "Fecha/hora ISO-8601 válida en calendario" if sem_ok else " | ".join(errors_ts)

        syn_tree = {
            'label': 'TIMESTAMP',
            'children': [
                {'label': 'FECHA', 'children': [
                    {'label': 'AAAA', 'sub': y_str},
                    {'label': 'SEP', 'sub': '-'},
                    {'label': 'MM', 'sub': m_str},
                    {'label': 'SEP', 'sub': '-'},
                    {'label': 'DD', 'sub': d_str}
                ]},
                {'label': 'SEP_T', 'sub': 'T'},
                {'label': 'HORA', 'children': [
                    {'label': 'HH', 'sub': hh_str},
                    {'label': 'SEP', 'sub': ':'},
                    {'label': 'MI', 'sub': mm_str},
                    {'label': 'SEP', 'sub': ':'},
                    {'label': 'SS', 'sub': ss_str}
                ]}
            ]
        }
        sem_tree = {
            'label': 'TIMESTAMP.sem',
            'sub': 'Calendario OK' if sem_ok else 'ERROR CALENDARIO',
            'children': [
                {'label': 'Fecha', 'sub': f"{y_str}-{m_str}-{d_str}", 'children': [
                    {'label': 'Mes (1..12)', 'sub': f"{m_int} ({'OK' if 1<=m_int<=12 else 'ERR'})"},
                    {'label': f'Día (1..{max_day})', 'sub': f"{d_int} ({'OK' if 1<=m_int<=12 and 1<=d_int<=max_day else 'ERR'})"}
                ]},
                {'label': 'Reloj 24h', 'sub': f"{hh_str}:{mm_str}:{ss_str}", 'children': [
                    {'label': 'HH (0..23)', 'sub': f"{hh_int} ({'OK' if 0<=hh_int<=23 else 'ERR'})"},
                    {'label': 'MI:SS (0..59)', 'sub': f"{mm_int}:{ss_int} ({'OK' if 0<=mm_int<=59 and 0<=ss_int<=59 else 'ERR'})"}
                ]}
            ]
        }

    elif tok_type == 'IP':
        parts = val.split('.')
        oct_errors = []
        oct_nodes_sem = []

        for idx, p in enumerate(parts, start=1):
            if len(p) > 1 and p.startswith('0'):
                oct_errors.append(f"Octeto #{idx} ({p}) con cero inicial no permitido")
                oct_ok = False
            else:
                v_int = int(p)
                oct_ok = (0 <= v_int <= 255)
                if not oct_ok:
                    oct_errors.append(f"Octeto #{idx} ({v_int}) fuera de rango [0..255]")
            oct_nodes_sem.append({
                'label': f'Octeto {idx}',
                'sub': f"{p} ({'0..255 OK' if oct_ok else 'INVÁLIDO'})"
            })

        sem_ok = (len(parts) == 4) and (len(oct_errors) == 0)
        sem_msg = "IPv4 válida (octetos en 0..255)" if sem_ok else " | ".join(oct_errors)

        syn_tree = {
            'label': 'IP',
            'children': [
                {'label': 'OCT_1', 'sub': parts[0]},
                {'label': 'DOT', 'sub': '.'},
                {'label': 'OCT_2', 'sub': parts[1]},
                {'label': 'DOT', 'sub': '.'},
                {'label': 'OCT_3', 'sub': parts[2]},
                {'label': 'DOT', 'sub': '.'},
                {'label': 'OCT_4', 'sub': parts[3]}
            ]
        }
        sem_tree = {
            'label': 'IP.sem',
            'sub': 'IPv4 VÁLIDA' if sem_ok else 'ERROR RANGO IPv4',
            'children': oct_nodes_sem
        }

    elif tok_type == 'SEVERITY':
        sla_map = {
            'INFO': ('Prioridad P4', 'Informativo'),
            'WARNING': ('Prioridad P3', 'SLA < 4 horas'),
            'ERROR': ('Prioridad P2', 'SLA < 1 hora'),
            'CRITICAL': ('Prioridad P1', 'SLA < 15 min')
        }
        prio, sla = sla_map.get(val, ('Desconocido', 'N/A'))
        sem_ok = val in sla_map
        sem_msg = f"{prio} ({sla})"

        syn_tree = {'label': 'SEVERITY', 'children': [{'label': 'LITERAL_ENUM', 'sub': val}]}
        sem_tree = {
            'label': 'SEVERITY.sem',
            'sub': prio,
            'children': [
                {'label': 'Nivel', 'sub': val},
                {'label': 'Respuesta SOC', 'sub': sla}
            ]
        }

    elif tok_type == 'EVENT_TYPE':
        parts = val.split('_')
        sem_ok = True
        sem_msg = "Taxonomía de evento SOC registrada"
        syn_tree = {
            'label': 'EVENT_TYPE',
            'children': [{'label': f'PALABRA_{i+1}', 'sub': p} for i, p in enumerate(parts)]
        }
        sem_tree = {
            'label': 'EVENT_TYPE.sem',
            'sub': 'Categoría SOC',
            'children': [
                {'label': 'Identificador', 'sub': val},
                {'label': 'Normativa', 'sub': 'SBS 504-2021'}
            ]
        }

    elif tok_type == 'STRING':
        inner = val[1:-1]
        match_susp = SUSPICIOUS_TREE_PATTERNS.search(inner)
        has_ctrl = any(ord(c) < 32 for c in inner)

        if has_ctrl:
            sem_ok = False
            sem_msg = "Contiene caracteres de control ASCII no permitidos"
        elif match_susp:
            sem_ok = False
            sem_msg = f"Entrada sospechosa detectada ({match_susp.group(0)!r}): posible vector de inyección"
        else:
            sem_ok = True
            sem_msg = f"Cadena verificada (long={len(inner)})"

        syn_tree = {
            'label': 'STRING',
            'children': [
                {'label': 'QUOTE_OPEN', 'sub': '"'},
                {'label': 'CONTENIDO', 'sub': inner or 'ε'},
                {'label': 'QUOTE_CLOSE', 'sub': '"'}
            ]
        }
        sem_tree = {
            'label': 'STRING.sem',
            'sub': 'Cadena Segura' if sem_ok else 'ALERTA SEGURIDAD',
            'children': [
                {'label': 'Valor', 'sub': inner[:24] + ('...' if len(inner) > 24 else '') or 'vacío'},
                {'label': 'Inspección', 'sub': 'Limpio' if sem_ok else 'Patrón Sospechoso'}
            ]
        }

    elif tok_type == 'NUMBER':
        num_val = int(val)
        sem_ok = (0 <= num_val <= 10**9)
        sem_msg = f"Entero válido ({num_val})" if sem_ok else f"Entero fuera de rango ({num_val})"
        syn_tree = {'label': 'NUMBER', 'children': [{'label': 'DIGITOS', 'sub': val}]}
        sem_tree = {
            'label': 'NUMBER.sem',
            'sub': 'int64',
            'children': [
                {'label': 'Valor Numérico', 'sub': str(num_val)},
                {'label': 'Rango', 'sub': '0..10^9 OK' if sem_ok else 'Fuera de rango'}
            ]
        }

    else:
        sem_ok = True
        sem_msg = "Delimitador estructural JSON"
        syn_tree = {'label': tok_type, 'children': [{'label': 'SIMBOLO', 'sub': val}]}
        sem_tree = {
            'label': f'{tok_type}.sem',
            'sub': 'Delimitador GLC',
            'children': [{'label': 'Símbolo', 'sub': val}]
        }

    return (
        render_real_tree_svg(syn_tree, "syntactic"),
        render_real_tree_svg(sem_tree, "semantic"),
        tree_to_parentheses(syn_tree),
        sem_ok,
        sem_msg
    )