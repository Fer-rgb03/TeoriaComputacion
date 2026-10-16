from app.utils.helpers import escape_svg_text

def tree_to_parentheses(node):
    lbl = node['label']
    if not node.get('children'):
        return lbl
    inner = ", ".join(tree_to_parentheses(c) for c in node['children'])
    return f"( {lbl} ( {inner} ) )"

def render_real_tree_svg(root_node, tree_kind="syntactic"):
    leaf_spacing = 118
    level_height = 92

    def compute_width(node):
        children = node.get('children', [])
        if not children:
            node['_width'] = leaf_spacing
            return leaf_spacing
        total = sum(compute_width(c) for c in children)
        node['_width'] = max(leaf_spacing, total)
        return node['_width']

    def compute_depth(node):
        children = node.get('children', [])
        if not children:
            return 1
        return 1 + max(compute_depth(c) for c in children)

    total_w = max(560, compute_width(root_node) + 60)
    max_d = compute_depth(root_node)
    total_h = max(220, max_d * level_height + 55)

    edges = []
    nodes_list = []

    def assign_coords(node, left_x, depth, is_root=False):
        w = node['_width']
        cx = left_x + w / 2.0
        cy = 48 + depth * level_height
        node['_x'] = cx
        node['_y'] = cy
        children = node.get('children', [])
        node['_role'] = 'root' if is_root else ('leaf' if not children else 'internal')
        nodes_list.append(node)

        cur_x = left_x
        for ch in children:
            assign_coords(ch, cur_x, depth + 1, is_root=False)
            edges.append((cx, cy, ch['_x'], ch['_y']))
            cur_x += ch['_width']

    assign_coords(root_node, (total_w - root_node['_width']) / 2.0, 0, is_root=True)

    svg = [
        f'<svg viewBox="0 0 {int(total_w)} {int(total_h)}" class="w-full h-auto rounded-lg border border-slate-300 bg-white shadow-inner" xmlns="http://www.w3.org/2000/svg">',
        '<defs>',
        '  <filter id="tree-shadow" x="-10%" y="-10%" width="125%" height="125%">',
        '    <feDropShadow dx="0" dy="1.5" stdDeviation="1.2" flood-opacity="0.16"/>',
        '  </filter>',
        '</defs>',
        f'<rect width="{int(total_w)}" height="{int(total_h)}" fill="#ffffff"/>',
        '<g transform="translate(14, 18)" font-family="Arial, sans-serif" font-size="10.5" font-weight="bold">',
        '  <circle cx="8" cy="0" r="6" fill="#fef08a" stroke="#1e293b" stroke-width="1.8"/>',
        '  <text x="19" y="4" fill="#1e293b">Nodo Raíz (Nivel 1)</text>',
        '  <circle cx="145" cy="0" r="6" fill="#dbeafe" stroke="#1e3a8a" stroke-width="1.5"/>',
        '  <text x="156" y="4" fill="#1e3a8a">Nodo Interior (No Terminal)</text>',
        '  <circle cx="325" cy="0" r="6" fill="#dcfce7" stroke="#166534" stroke-width="1.5"/>',
        '  <text x="336" y="4" fill="#166534">Nodo Hoja (Terminal / Lexema)</text>',
        '</g>'
    ]

    for x1, y1, x2, y2 in edges:
        svg.append(
            f'<line x1="{x1:.1f}" y1="{y1 + 20:.1f}" x2="{x2:.1f}" y2="{y2 - 20:.1f}" '
            f'stroke="#1e293b" stroke-width="1.8"/>'
        )

    for n in nodes_list:
        x, y = n['_x'], n['_y']
        role = n['_role']
        lbl = escape_svg_text(n.get('label', ''))
        sub = escape_svg_text(n.get('sub', ''))

        if role == 'root':
            fill, stroke, text_col = "#fef08a", "#0f172a", "#0f172a"
            rx, ry = max(32, len(lbl) * 4.5 + 14), 22
            svg.append(f'<ellipse cx="{x:.1f}" cy="{y:.1f}" rx="{rx:.1f}" ry="{ry}" fill="{fill}" stroke="{stroke}" stroke-width="2.2" filter="url(#tree-shadow)"/>')
            svg.append(f'<ellipse cx="{x:.1f}" cy="{y:.1f}" rx="{rx-4:.1f}" ry="{ry-4}" fill="none" stroke="{stroke}" stroke-width="1"/>')
        elif role == 'internal':
            fill = "#f3e8ff" if tree_kind == "semantic" else "#dbeafe"
            stroke = "#6b21a8" if tree_kind == "semantic" else "#1e40af"
            text_col = "#1e1b4b"
            rx, ry = max(28, len(lbl) * 4.2 + 12), 20
            svg.append(f'<ellipse cx="{x:.1f}" cy="{y:.1f}" rx="{rx:.1f}" ry="{ry}" fill="{fill}" stroke="{stroke}" stroke-width="1.8" filter="url(#tree-shadow)"/>')
        else:
            fill = "#fae8ff" if tree_kind == "semantic" else "#dcfce7"
            stroke = "#86198f" if tree_kind == "semantic" else "#15803d"
            text_col = "#052e16"
            rx, ry = max(26, max(len(lbl), len(sub)) * 3.8 + 12), 21
            svg.append(f'<ellipse cx="{x:.1f}" cy="{y:.1f}" rx="{rx:.1f}" ry="{ry}" fill="{fill}" stroke="{stroke}" stroke-width="1.8" filter="url(#tree-shadow)"/>')

        if sub:
            svg.append(f'<text x="{x:.1f}" y="{y - 2:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11" font-weight="bold" fill="{text_col}">{lbl}</text>')
            svg.append(f'<text x="{x:.1f}" y="{y + 11:.1f}" text-anchor="middle" font-family="monospace" font-size="10" font-weight="bold" fill="#b91c1c">{sub}</text>')
        else:
            svg.append(f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="middle" font-family="Arial, sans-serif" font-size="11.5" font-weight="bold" fill="{text_col}">{lbl}</text>')

    svg.append('</svg>')
    return '\n'.join(svg)


def build_token_real_trees(tok_type, value):
    if tok_type == 'TIMESTAMP':
        yr, mo, dy = value[0:4], value[5:7], value[8:10]
        hr, mn, sc = value[11:13], value[14:16], value[17:19]
        valid_date = (1 <= int(mo) <= 12) and (1 <= int(dy) <= 31) and (0 <= int(hr) <= 23) and (0 <= int(mn) <= 59) and (0 <= int(sc) <= 59)
        syn_dict = {
            'label': 'TIMESTAMP',
            'children': [
                {'label': 'FECHA', 'children': [
                    {'label': 'AÑO', 'sub': yr},
                    {'label': 'GUION', 'sub': '-'},
                    {'label': 'MES', 'sub': mo},
                    {'label': 'GUION', 'sub': '-'},
                    {'label': 'DÍA', 'sub': dy}
                ]},
                {'label': 'SEP_T', 'sub': 'T'},
                {'label': 'HORA', 'children': [
                    {'label': 'HH', 'sub': hr},
                    {'label': 'DP', 'sub': ':'},
                    {'label': 'MM', 'sub': mn},
                    {'label': 'DP', 'sub': ':'},
                    {'label': 'SS', 'sub': sc}
                ]}
            ]
        }
        sem_status = "VÁLIDO (ISO-8601)" if valid_date else "FUERA DE RANGO"
        sem_dict = {
            'label': 'TIMESTAMP.sem',
            'sub': 'DateTime',
            'children': [
                {'label': 'Valor Canónico', 'sub': value},
                {'label': 'Validación Calendario', 'children': [
                    {'label': f'Mes ({mo})', 'sub': '∈ [01..12]' if 1 <= int(mo) <= 12 else 'ERROR > 12'},
                    {'label': f'Día ({dy})', 'sub': '∈ [01..31]' if 1 <= int(dy) <= 31 else 'ERROR > 31'},
                    {'label': f'Hora ({hr}:{mn}:{sc})', 'sub': '∈ [00..23:59]'}
                ]}
            ]
        }
        return render_real_tree_svg(syn_dict, "syntactic"), render_real_tree_svg(sem_dict, "semantic"), tree_to_parentheses(syn_dict), valid_date, sem_status

    elif tok_type == 'IP':
        octs = value.split('.')
        valid_ip = all(0 <= int(o) <= 255 for o in octs)
        syn_dict = {
            'label': 'IP',
            'children': [
                {'label': 'OCTETO_1', 'sub': octs[0]},
                {'label': 'PUNTO', 'sub': '.'},
                {'label': 'OCTETO_2', 'sub': octs[1]},
                {'label': 'PUNTO', 'sub': '.'},
                {'label': 'OCTETO_3', 'sub': octs[2]},
                {'label': 'PUNTO', 'sub': '.'},
                {'label': 'OCTETO_4', 'sub': octs[3]}
            ]
        }
        sem_status = "VÁLIDO (Octetos 0..255)" if valid_ip else "ERROR SEMÁNTICO (Octeto > 255)"
        zona = "Red Privada SOC" if octs[0] in ('10', '172', '192') else "Red Pública"
        sem_dict = {
            'label': 'IP.sem',
            'sub': 'IPv4Address',
            'children': [
                {'label': 'Zona Red', 'sub': zona},
                {'label': 'Rango Octetos [0..255]', 'children': [
                    {'label': f'Oct 1 ({octs[0]})', 'sub': 'OK ≤ 255' if int(octs[0]) <= 255 else 'ERR > 255'},
                    {'label': f'Oct 2 ({octs[1]})', 'sub': 'OK ≤ 255' if int(octs[1]) <= 255 else 'ERR > 255'},
                    {'label': f'Oct 3 ({octs[2]})', 'sub': 'OK ≤ 255' if int(octs[2]) <= 255 else 'ERR > 255'},
                    {'label': f'Oct 4 ({octs[3]})', 'sub': 'OK ≤ 255' if int(octs[3]) <= 255 else 'ERR > 255'}
                ]}
            ]
        }
        return render_real_tree_svg(syn_dict, "syntactic"), render_real_tree_svg(sem_dict, "semantic"), tree_to_parentheses(syn_dict), valid_ip, sem_status

    elif tok_type == 'SEVERITY':
        prio_map = {
            'INFO': ('Nivel 1 (Bajo)', 'Log Informativo'),
            'WARNING': ('Nivel 2 (Medio)', 'Alerta Preventiva'),
            'ERROR': ('Nivel 3 (Alto)', 'Incidente Activo'),
            'CRITICAL': ('Nivel 4 (Crítico)', 'Escalamiento Inmediato')
        }
        prio, SLA = prio_map.get(value, ('Desconocido', 'N/A'))
        syn_dict = {
            'label': 'SEVERITY',
            'children': [
                {'label': 'PALABRA_RESERVADA', 'children': [{'label': f'char[{i}]', 'sub': c} for i, c in enumerate(value)]}
            ]
        }
        sem_dict = {
            'label': 'SEVERITY.sem',
            'sub': 'Enum(Severidad)',
            'children': [
                {'label': 'Lexema', 'sub': value},
                {'label': 'Prioridad SOC', 'sub': prio},
                {'label': 'Acción SLA', 'sub': SLA}
            ]
        }
        return render_real_tree_svg(syn_dict, "syntactic"), render_real_tree_svg(sem_dict, "semantic"), tree_to_parentheses(syn_dict), True, f"Prioridad: {prio}"

    elif tok_type == 'EVENT_TYPE':
        parts = value.split('_')
        ch_nodes = []
        for idx_p, p in enumerate(parts):
            if idx_p > 0:
                ch_nodes.append({'label': 'SEP', 'sub': '_'})
            ch_nodes.append({'label': f'ID_{idx_p+1}', 'sub': p})
        syn_dict = {'label': 'EVENT_TYPE', 'children': ch_nodes}
        sem_dict = {
            'label': 'EVENT_TYPE.sem',
            'sub': 'EventCode',
            'children': [
                {'label': 'Código', 'sub': value},
                {'label': 'Clasificación', 'sub': 'Seguridad SOC'},
                {'label': 'Norma', 'sub': 'SBS 504-2021'}
            ]
        }
        return render_real_tree_svg(syn_dict, "syntactic"), render_real_tree_svg(sem_dict, "semantic"), tree_to_parentheses(syn_dict), True, "Identificador Válido"

    elif tok_type == 'STRING':
        clean_s = value[1:-1]
        syn_dict = {
            'label': 'STRING',
            'children': [
                {'label': 'COMILLA_INI', 'sub': '"'},
                {'label': 'CONTENIDO', 'sub': clean_s or 'ε'},
                {'label': 'COMILLA_FIN', 'sub': '"'}
            ]
        }
        sem_dict = {
            'label': 'STRING.sem',
            'sub': 'UTF-8 String',
            'children': [
                {'label': 'Valor Literal', 'sub': clean_s},
                {'label': 'Longitud', 'sub': f'{len(clean_s)} chars'}
            ]
        }
        return render_real_tree_svg(syn_dict, "syntactic"), render_real_tree_svg(sem_dict, "semantic"), tree_to_parentheses(syn_dict), True, f"String (len={len(clean_s)})"

    elif tok_type == 'NUMBER':
        syn_dict = {
            'label': 'NUMBER',
            'children': [{'label': f'Dígito_{i+1}', 'sub': d} for i, d in enumerate(value)]
        }
        sem_dict = {
            'label': 'NUMBER.sem',
            'sub': 'Integer (int64)',
            'children': [
                {'label': 'Valor Numérico', 'sub': str(int(value))},
                {'label': 'Base', 'sub': 'Decimal (10)'}
            ]
        }
        return render_real_tree_svg(syn_dict, "syntactic"), render_real_tree_svg(sem_dict, "semantic"), tree_to_parentheses(syn_dict), True, f"Entero = {int(value)}"

    else:
        syn_dict = {'label': tok_type, 'children': [{'label': 'TERMINAL', 'sub': value}]}
        sem_dict = {
            'label': f'{tok_type}.sem',
            'sub': 'Delimitador GLC',
            'children': [
                {'label': 'Símbolo', 'sub': value},
                {'label': 'Operación PDA', 'sub': 'Control JSON'}
            ]
        }
        return render_real_tree_svg(syn_dict, "syntactic"), render_real_tree_svg(sem_dict, "semantic"), tree_to_parentheses(syn_dict), True, "Delimitador Estructural"