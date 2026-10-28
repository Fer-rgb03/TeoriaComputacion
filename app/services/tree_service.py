import re
import calendar
from app.utils.helpers import escape_svg_text
from app.patterns.singleton.grammar_singleton import GrammarSingleton

grammar_ref = GrammarSingleton()

SUSPICIOUS_TREE_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b|--|;|\bOR\b\s+['\"\d]+=['\"\d]+|"
    r"\$ne|\$gt|\$lt|\$where|<script|javascript:|\.\./|\x00)",
    re.IGNORECASE
)


def compute_tree_layout(node, depth=0, x_step=125, y_step=85, counter=None):
    """
    Algoritmo de layout recursivo para árboles n-arios (AST).
    Asigna una hoja exclusiva en el eje X para cada nodo terminal y promedia 
    las posiciones X para los nodos padre, sin límite de profundidad (N niveles).
    """
    if counter is None:
        counter = [0]
    
    children = node.get('children', [])
    node['depth'] = depth
    node['y'] = 45 + depth * y_step

    if not children:
        # Nodo hoja: ocupa un espacio nuevo en el eje X
        node['x'] = 75 + counter[0] * x_step
        counter[0] += 1
    else:
        # Nodo interior: primero acomoda a todos sus descendientes
        for ch in children:
            compute_tree_layout(ch, depth + 1, x_step, y_step, counter)
        # Su posición X es exactamente el centro de todos sus hijos directos
        node['x'] = (children[0]['x'] + children[-1]['x']) / 2.0

    return counter[0]


def get_max_depth(node):
    """Calcula la profundidad máxima del árbol recursivamente."""
    children = node.get('children', [])
    if not children:
        return node.get('depth', 0)
    return max(get_max_depth(ch) for ch in children)


def tree_to_parentheses(node):
    """Representación textual anidada (Notación LISP)."""
    lbl = node.get('label', '')
    sub = node.get('sub', '')
    head = f"{lbl}:{sub}" if sub else lbl
    children = node.get('children', [])
    if not children:
        return head
    inner = ", ".join(tree_to_parentheses(ch) for ch in children)
    return f"( {head} ( {inner} ) )"


def render_real_tree_svg(root, tree_kind="syntactic"):
    """
    Renderiza el SVG usando un lienzo cuyo tamaño (ancho y alto) se ajusta 
    dinámicamente a la cantidad de hojas y a la profundidad máxima real.
    """
    x_step = 130
    y_step = 85
    leaf_count = compute_tree_layout(root, 0, x_step, y_step)
    max_depth = get_max_depth(root)

    # El lienzo se adapta al tamaño real del árbol (para admitir anidamiento JSON infinito)
    width = max(560, int(leaf_count * x_step + 90))
    height = max(240, int((max_depth + 1) * y_step + 60))

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
        
        # Dibujar aristas (líneas conectoras) hacia los hijos
        for ch in children:
            cx, cy = ch['x'], ch['y']
            edges_svg.append(
                f'<line x1="{x:.1f}" y1="{y + 18:.1f}" x2="{cx:.1f}" y2="{cy - 20:.1f}" '
                f'stroke="#334155" stroke-width="1.8" marker-end="url(#tree-arrow)"/>'
            )
            traverse(ch, is_root=False)

        # Dibujar nodo actual
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

        # Calcular ancho del rectángulo dinámicamente según la longitud del texto
        box_w = max(90, max(len(lbl), len(sub)) * 7.2 + 24)
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
            f'<text x="{x:.1f}" y="{y - box_h/2 - 6:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
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
    if tok_type == 'TIMESTAMP':
        core = val[:19]
        extra_tz = val[19:]
        y_str, m_str, d_str = core[0:4], core[5:7], core[8:10]
        hh_str, mm_str, ss_str = core[11:13], core[14:16], core[17:19]

        y_int, m_int, d_int = int(y_str), int(m_str), int(d_str)
        hh_int, mm_int, ss_int = int(hh_str), int(mm_str), int(ss_str)

        errors_ts = []
        if extra_tz:
            errors_ts.append(f"Zona horaria '{extra_tz}' fuera del alcance UTC")
        if not (1970 <= y_int <= 2100):
            errors_ts.append(f"Año fuera de rango ({y_int})")
        if not (1 <= m_int <= 12):
            errors_ts.append(f"Mes inválido ({m_int:02d})")
            max_day = 31
        else:
            max_day = calendar.monthrange(y_int, m_int)[1]
            if not (1 <= d_int <= max_day):
                errors_ts.append(f"Día inválido ({d_int:02d}) para mes {m_int:02d}/{y_int} (máx {max_day})")
        if not (0 <= hh_int <= 23):
            errors_ts.append(f"Hora inválida ({hh_int:02d})")
        if not (0 <= mm_int <= 59):
            errors_ts.append(f"Minuto inválido ({mm_int:02d})")
        if not (0 <= ss_int <= 59):
            errors_ts.append(f"Segundo inválido ({ss_int:02d})")

        sem_ok = len(errors_ts) == 0
        sem_msg = "Fecha/hora ISO-8601 válida" if sem_ok else " | ".join(errors_ts)

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
                    {'label': 'Mes (01..12)', 'sub': f"{m_int:02d} ({'OK' if 1<=m_int<=12 else 'ERR'})"},
                    {'label': f'Día (01..{max_day:02d})', 'sub': f"{d_int:02d} ({'OK' if 1<=m_int<=12 and 1<=d_int<=max_day else 'ERR'})"}
                ]},
                {'label': 'Reloj 24h', 'sub': f"{hh_str}:{mm_str}:{ss_str}", 'children': [
                    {'label': 'HH (00..23)', 'sub': f"{hh_int:02d} ({'OK' if 0<=hh_int<=23 else 'ERR'})"},
                    {'label': 'MI:SS (00..59)', 'sub': f"{mm_int:02d}:{ss_int:02d} ({'OK' if 0<=mm_int<=59 and 0<=ss_int<=59 else 'ERR'})"}
                ]}
            ]
        }

    elif tok_type == 'IP':
        parts = val.split('.')
        oct_errors = []
        oct_nodes_sem = []

        for idx, p in enumerate(parts, start=1):
            if len(p) > 1 and p.startswith('0'):
                oct_errors.append(f"Octeto #{idx} ({p}) cero inicial prohibido")
                oct_ok = False
            else:
                v_int = int(p)
                oct_ok = (0 <= v_int <= 255)
                if not oct_ok:
                    oct_errors.append(f"Octeto #{idx} ({v_int}) fuera de rango")
            oct_nodes_sem.append({
                'label': f'Octeto {idx}',
                'sub': f"{p} ({'0..255 OK' if oct_ok else 'INVÁLIDO'})"
            })

        sem_ok = (len(parts) == 4) and (len(oct_errors) == 0)
        sem_msg = "IPv4 válida" if sem_ok else " | ".join(oct_errors)

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
            'sub': 'IPv4 VÁLIDA' if sem_ok else 'ERROR IPv4',
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
        catalog_desc = grammar_ref.VALID_SOC_EVENTS.get(val)
        if catalog_desc:
            sem_ok = True
            sem_msg = f"Catálogo SOC: {catalog_desc}"
        else:
            sem_ok = False
            sem_msg = f"Evento {val!r} no registrado en SBS 504-2021"

        syn_tree = {
            'label': 'EVENT_TYPE',
            'children': [{'label': f'PALABRA_{i+1}', 'sub': p} for i, p in enumerate(parts)]
        }
        sem_tree = {
            'label': 'EVENT_TYPE.sem',
            'sub': 'CATÁLOGO OK' if sem_ok else 'NO REGISTRADO',
            'children': [
                {'label': 'Identificador', 'sub': val},
                {'label': 'Taxonomía SBS', 'sub': 'Registrado' if sem_ok else 'No Existe'}
            ]
        }

    elif tok_type == 'STRING':
        inner = val[1:-1]
        match_susp = SUSPICIOUS_TREE_PATTERNS.search(inner)
        has_ctrl = any(ord(c) < 32 for c in inner)

        if has_ctrl:
            sem_ok = False
            sem_msg = "Caracteres de control no permitidos"
        elif match_susp:
            sem_ok = False
            sem_msg = f"Entrada sospechosa detectada ({match_susp.group(0)!r})"
        else:
            sem_ok = True
            sem_msg = f"Literal verificado (long={len(inner)})"

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
            'sub': 'Literal Aceptado' if sem_ok else 'PATRÓN SOSPECHOSO',
            'children': [
                {'label': 'Valor', 'sub': inner[:24] + ('...' if len(inner) > 24 else '') or 'vacío'},
                {'label': 'Filtro Patrones', 'sub': 'Sin alertas' if sem_ok else f'Alerta: {match_susp.group(0) if match_susp else "Ctrl"}'}
            ]
        }

    elif tok_type == 'NUMBER':
        if len(val) > 1 and val.startswith('0'):
            sem_ok = False
            sem_msg = f"Cero a la izquierda prohibido ({val})"
            num_val = val
        else:
            num_val = int(val)
            sem_ok = (0 <= num_val <= 10**9)
            sem_msg = f"Entero válido [0..10^9]" if sem_ok else f"Entero fuera de rango ({num_val})"

        syn_tree = {'label': 'NUMBER', 'children': [{'label': 'ENTERO_JSON', 'sub': val}]}
        sem_tree = {
            'label': 'NUMBER.sem',
            'sub': 'Entero [0..10^9]' if sem_ok else 'FUERA DE RANGO',
            'children': [
                {'label': 'Valor', 'sub': str(num_val)},
                {'label': 'Dominio', 'sub': '0..10^9 OK' if sem_ok else 'Excede 10^9'}
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