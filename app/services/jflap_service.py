import math
import base64
from app.utils.helpers import escape_svg_text


def expand_symbol_for_jff(label, tok_type="TOKEN"):
    """
    Expande cada etiqueta simbólica en caracteres individuales de 1 símbolo para el XML .jff
    de JFLAP 7.1, asegurando que las transiciones hacia qT sean disjuntas de las válidas.
    """
    digits = [str(d) for d in range(10)]
    uppers = [chr(c) for c in range(ord('A'), ord('Z') + 1)]
    lowers = [chr(c) for c in range(ord('a'), ord('z') + 1)]

    if label in ('λ', 'ε', ''):
        return ['']
    if label == '0..9':
        return digits
    if label == 'A..Z':
        return uppers
    if label == 'Σ_str':
        return lowers + uppers + digits + ['_', '-', '.', ':', '/', ' ', '@']

    if label == '≠díg':
        if tok_type == 'TIMESTAMP':
            return ['-', 'T', ':', '/', ' ']
        if tok_type == 'IP':
            return ['.', '-', '/', 'a', ' ']
        return ['a', 'z', '-', '_', '.', '/']
    if label == '≠-':
        return digits + ['T', ':', '/', '.']
    if label == '≠T':
        return digits + ['-', ':', '/', ' ']
    if label == '≠:':
        return digits + ['-', 'T', '/', '.']
    if label == '≠A..Z':
        return ['_', '-', '0', '1', 'a', ' ']
    if label == '≠"':
        return lowers + uppers + digits + ['_', '-', ':']
    if label == 'Σ_err':
        if tok_type == 'TIMESTAMP':
            return digits + ['-', 'T', ':', '/']
        if tok_type == 'IP':
            return digits + ['.', '-', '/']
        if tok_type == 'SEVERITY':
            return uppers + digits + ['_']
        if tok_type == 'EVENT_TYPE':
            return uppers + ['_', '0', '1', '-']
        if tok_type == 'STRING':
            return lowers + uppers + digits + ['"', '_', '-']
        if tok_type == 'NUMBER':
            return digits + ['a', 'z', '-', '.']
        return ['{', '}', ':', ',', 'a', '0']

    return [label]


def build_formal_quintuple_from_graph(states, transitions, sigma_desc, is_afnd=False):
    """
    Punto 2.1: Construye la quíntupla formal (Q, Σ, δ, q0, F) directamente a partir de los
    vectores 'states' y 'transitions' del autómata, garantizando 0% de discrepancia entre
    los estados declarados en la interfaz, la tabla de transición, el diagrama y el archivo .jff.
    """
    q_list = [s['id'] for s in states]
    initial_list = [s['id'] for s in states if s.get('initial')]
    final_list = [s['id'] for s in states if s.get('final')]

    q0_str = initial_list[0] if initial_list else q_list[0]
    q_formatted = "{" + ", ".join(q_list) + "}"
    f_formatted = "{" + ", ".join(final_list) + "}"

    if is_afnd:
        delta_str = "δ' : Q' × (Σ ∪ {λ}) → P(Q')"
    else:
        delta_str = "δ : Q × Σ → Q"

    return {
        "Q": q_formatted,
        "Sigma": sigma_desc,
        "delta": delta_str,
        "q0": q0_str,
        "F": f_formatted
    }


def build_jff_download_uri(states, transitions, tok_type="TOKEN"):
    """
    Punto 2.2: Genera el XML .jff nativo de JFLAP 7.1 sin omitir ningún estado ni transición.
    """
    state_id_map = {s['id']: idx for idx, s in enumerate(states)}

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
        '<!-- Generado por SOC Analyzer & JFLAP Studio - Compatible con JFLAP 7.1 -->',
        '<structure>',
        '  <type>fa</type>',
        '  <automaton>'
    ]

    for idx, s in enumerate(states):
        xml_lines.append(f'    <state id="{idx}" name="{escape_svg_text(s["id"])}">')
        xml_lines.append(f'      <x>{float(s["x"]):.1f}</x>')
        xml_lines.append(f'      <y>{float(s["y"]):.1f}</y>')
        if s.get('initial'):
            xml_lines.append('      <initial/>')
        if s.get('final'):
            xml_lines.append('      <final/>')
        xml_lines.append('    </state>')

    for t in transitions:
        if t['from'] not in state_id_map or t['to'] not in state_id_map:
            continue
        u_id = state_id_map[t['from']]
        v_id = state_id_map[t['to']]
        for ch in expand_symbol_for_jff(t['label'], tok_type=tok_type):
            xml_lines.append('    <transition>')
            xml_lines.append(f'      <from>{u_id}</from>')
            xml_lines.append(f'      <to>{v_id}</to>')
            if ch == '':
                xml_lines.append('      <read/>')
            else:
                xml_lines.append(f'      <read>{escape_svg_text(ch)}</read>')
            xml_lines.append('    </transition>')

    xml_lines.append('  </automaton>')
    xml_lines.append('</structure>')
    raw_xml = '\n'.join(xml_lines).encode('utf-8')
    b64_xml = base64.b64encode(raw_xml).decode('ascii')
    return f"data:application/xml;base64,{b64_xml}"


def render_transition_table_html(states, transitions, is_afnd=False, tok_type="TOKEN"):
    """
    Puntos 2.1 y 2.2: Renderiza la tabla de transición formal verificando que cada fila
    corresponda exactamente a los estados declarados en Q / Q' y todas las transiciones sean válidas.
    """
    state_ids = {s['id'] for s in states}
    valid_transitions = [
        t for t in transitions if t['from'] in state_ids and t['to'] in state_ids
    ]

    symbols = []
    for t in valid_transitions:
        lbl = t['label']
        if lbl not in symbols:
            symbols.append(lbl)

    jff_uri = build_jff_download_uri(states, valid_transitions, tok_type=tok_type)
    tipo_str = "AFND" if is_afnd else "AFD"
    filename = f"{tipo_str}_{tok_type}.jff"
    conjunto_str = "Q'" if is_afnd else "Q"
    titulo_tabla = (
        f"Tabla de Transición Formal δ' — {tipo_str} (Conjunto de Estados {conjunto_str})"
        if is_afnd else
        f"Tabla de Transición Formal δ — {tipo_str} (Conjunto de Estados {conjunto_str})"
    )

    html_out = [
        '<div class="mt-3 rounded-lg border border-slate-300 bg-white shadow-sm overflow-hidden">',
        '  <div class="bg-slate-800 text-white px-3 py-2 text-xs font-bold flex flex-wrap items-center justify-between gap-2">',
        f'    <span>{escape_svg_text(titulo_tabla)}</span>',
        '    <div class="flex items-center gap-3">',
        '      <span class="text-[11px] font-normal text-slate-300">→ Estado Inicial | * Estado Final</span>',
        f'      <a href="{jff_uri}" download="{filename}" '
        '         class="px-2.5 py-1 rounded bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-[11px] shadow transition">',
        f'        ⬇ Descargar {filename} (JFLAP 7.1)',
        '      </a>',
        '    </div>',
        '  </div>',
        '  <div class="overflow-x-auto max-h-64">',
        '    <table class="w-full text-xs text-left border-collapse">',
        '      <thead class="sticky top-0">',
        '        <tr class="bg-slate-100 border-b border-slate-300 text-slate-700">',
        f'          <th class="py-1.5 px-2.5 font-bold border-r border-slate-300">Estado ({conjunto_str})</th>'
    ]

    for sym in symbols:
        html_out.append(
            f'          <th class="py-1.5 px-2.5 font-mono font-bold text-center border-r border-slate-200">'
            f'{escape_svg_text(sym)}</th>'
        )
    html_out.append('        </tr>')
    html_out.append('      </thead>')
    html_out.append('      <tbody class="divide-y divide-slate-200">')

    has_trap = any(s.get('trap') for s in states)

    for s in states:
        sid = s['id']
        prefix = ""
        if s.get('initial'):
            prefix += "→ "
        if s.get('final'):
            prefix += "* "

        row_bg = "bg-rose-50/70" if s.get('trap') else ("bg-emerald-50/60" if s.get('final') else "bg-white")
        note = f" <span class='text-[10px] font-normal text-slate-500'>({escape_svg_text(s['note'])})</span>" if s.get('note') else ""

        html_out.append(f'        <tr class="{row_bg} hover:bg-slate-50">')
        html_out.append(
            f'          <td class="py-1.5 px-2.5 font-mono font-bold text-slate-900 border-r border-slate-300 whitespace-nowrap">'
            f'{escape_svg_text(prefix + sid)}{note}</td>'
        )

        for sym in symbols:
            targets = [t['to'] for t in valid_transitions if t['from'] == sid and t['label'] == sym]
            if targets:
                cell_val = "{" + ", ".join(targets) + "}" if is_afnd else targets[0]
                cell_style = "text-rose-700 font-bold" if "qT" in targets else "text-blue-700 font-bold"
            else:
                if is_afnd:
                    cell_val = "∅"
                    cell_style = "text-slate-400"
                else:
                    cell_val = "qT" if has_trap else "∅"
                    cell_style = "text-rose-600 font-semibold" if has_trap else "text-slate-400"

            html_out.append(
                f'          <td class="py-1.5 px-2.5 font-mono text-center border-r border-slate-200 {cell_style}">'
                f'{escape_svg_text(cell_val)}</td>'
            )

        html_out.append('        </tr>')

    html_out.append('      </tbody>')
    html_out.append('    </table>')
    html_out.append('  </div>')

    fn_name = "δ'" if is_afnd else "δ"
    trans_items = [
        f"{fn_name}({escape_svg_text(t['from'])}, {escape_svg_text(t['label'])}) = "
        f"{'{' + escape_svg_text(t['to']) + '}' if is_afnd else escape_svg_text(t['to'])}"
        for t in valid_transitions
    ]
    html_out.append(
        '  <div class="bg-slate-50 px-3 py-2 border-t border-slate-200 text-[11px] font-mono text-slate-700">'
        f'    <span class="font-bold text-slate-900"> Pares de Transición ({fn_name}): </span>' +
        " &nbsp;|&nbsp; ".join(trans_items) +
        '  </div>'
    )
    html_out.append('</div>')
    return '\n'.join(html_out)


def render_jflap_svg(states, transitions, width=860, height=260, is_afnd=False, tok_type="TOKEN", node_radius=18):
    state_map = {s['id']: s for s in states}
    r = node_radius

    svg = [
        f'<svg viewBox="0 0 {width} {height}" class="w-full h-auto rounded-b-lg border border-slate-400 bg-[#fafafa] shadow-inner" xmlns="http://www.w3.org/2000/svg">',
        '<defs>',
        '  <marker id="jflap-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 10 5 L 0 9 z" fill="#111111"/>',
        '  </marker>',
        '  <filter id="jflap-shadow" x="-10%" y="-10%" width="125%" height="125%">',
        '    <feDropShadow dx="1" dy="1.5" stdDeviation="1" flood-opacity="0.18"/>',
        '  </filter>',
        '</defs>',
        f'<rect width="{width}" height="{height}" fill="#fbfbfb"/>'
    ]

    for t in transitions:
        if t['from'] not in state_map or t['to'] not in state_map:
            continue
        u = state_map[t['from']]
        v = state_map[t['to']]
        lbl = escape_svg_text(t['label'])
        curve = t.get('curve', 0)
        stroke_col = "#b91c1c" if t['to'] == 'qT' else "#111111"

        if t['from'] == t['to']:
            direction = -1 if curve >= 0 else 1
            x, y = u['x'], u['y']
            sy = y + direction * (r - 3)
            cy = y + direction * (r + 34)
            ly = y + direction * (r + 31)
            svg.append(
                f'<path d="M {x-8},{sy} C {x-22},{cy} {x+22},{cy} {x+8},{sy}" '
                f'fill="none" stroke="{stroke_col}" stroke-width="1.5" marker-end="url(#jflap-arrow)"/>'
            )
            svg.append(
                f'<text x="{x}" y="{ly}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="10" font-weight="bold" fill="{stroke_col}">{lbl}</text>'
            )
        else:
            x1, y1 = u['x'], u['y']
            x2, y2 = v['x'], v['y']
            dx, dy = x2 - x1, y2 - y1
            dist = math.hypot(dx, dy) or 1.0
            ux, uy = dx / dist, dy / dist
            nx, ny = -uy, ux

            if curve == 0:
                sx, sy = x1 + ux * r, y1 + uy * r
                ex, ey = x2 - ux * (r + 2), y2 - uy * (r + 2)
                mx, my = (sx + ex) / 2, (sy + ey) / 2 - 6
                svg.append(
                    f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" '
                    f'stroke="{stroke_col}" stroke-width="1.5" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{mx:.1f}" y="{my:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="9.5" font-weight="bold" fill="{stroke_col}">{lbl}</text>'
                )
            else:
                cx = (x1 + x2) / 2 + nx * curve
                cy = (y1 + y2) / 2 + ny * curve
                d1x, d1y = cx - x1, cy - y1
                l1 = math.hypot(d1x, d1y) or 1.0
                sx, sy = x1 + (d1x / l1) * r, y1 + (d1y / l1) * r

                d2x, d2y = x2 - cx, y2 - cy
                l2 = math.hypot(d2x, d2y) or 1.0
                ex, ey = x2 - (d2x / l2) * (r + 2), y2 - (d2y / l2) * (r + 2)

                lx = 0.25 * sx + 0.5 * cx + 0.25 * ex
                ly = 0.25 * sy + 0.5 * cy + 0.25 * ey - (5 if curve >= 0 else -11)
                svg.append(
                    f'<path d="M {sx:.1f},{sy:.1f} Q {cx:.1f},{cy:.1f} {ex:.1f},{ey:.1f}" '
                    f'fill="none" stroke="{stroke_col}" stroke-width="1.4" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="9.5" font-weight="bold" fill="{stroke_col}">{lbl}</text>'
                )

    for s in states:
        x, y = s['x'], s['y']
        sid = escape_svg_text(s['id'])
        fill_color = "#ffe4e1" if s.get('trap') else "#ffff96"

        if s.get('initial'):
            svg.append(
                f'<polygon points="{x - r - 16},{y - 11} {x - r - 16},{y + 11} {x - r - 1},{y}" '
                f'fill="#ffffff" stroke="#111111" stroke-width="1.5"/>'
            )

        svg.append(
            f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill_color}" stroke="#111111" '
            f'stroke-width="1.6" filter="url(#jflap-shadow)"/>'
        )

        if s.get('final'):
            svg.append(
                f'<circle cx="{x}" cy="{y}" r="{r - 4}" fill="none" stroke="#111111" stroke-width="1.3"/>'
            )

        svg.append(
            f'<text x="{x}" y="{y + 3.5}" text-anchor="middle" font-family="Arial, sans-serif" '
            f'font-size="10.5" font-weight="bold" fill="#000000">{sid}</text>'
        )

        if s.get('note'):
            note_txt = escape_svg_text(s['note'])
            svg.append(
                f'<text x="{x}" y="{y + r + 11}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="8.5" fill="#475569">{note_txt}</text>'
            )

    svg.append('</svg>')
    svg.append(render_transition_table_html(states, transitions, is_afnd=is_afnd, tok_type=tok_type))
    return '\n'.join(svg)


def build_jflap_models_for_token(tok_type, lexeme=""):
    """
    Construye los diagramas SVG, tablas de transición, archivos .jff y las quíntuplas formales
    exactas (quintupla_afd y quintupla_afnd) a partir de una única definición de estados.
    """
    if tok_type == 'TIMESTAMP':
        states_afd = []
        for i in range(11):
            states_afd.append({
                'id': f'q{i}',
                'x': 50 + i * 75,
                'y': 50,
                'initial': (i == 0),
                'note': 'Inicio' if i == 0 else ('Año' if i == 4 else ('Mes' if i == 7 else ('Día' if i == 10 else '')))
            })
        for j, st_idx in enumerate(range(11, 20)):
            states_afd.append({
                'id': f'q{st_idx}',
                'x': 80 + j * 80,
                'y': 140,
                'final': (st_idx == 19),
                'note': 'Sep T' if st_idx == 11 else ('Acepta' if st_idx == 19 else '')
            })
        states_afd.append({'id': 'qT', 'x': 430, 'y': 225, 'trap': True, 'note': 'Estado Trampa'})

        pattern_steps = [
            ('q0', 'q1', '0..9'), ('q1', 'q2', '0..9'), ('q2', 'q3', '0..9'), ('q3', 'q4', '0..9'),
            ('q4', 'q5', '-'),
            ('q5', 'q6', '0..9'), ('q6', 'q7', '0..9'),
            ('q7', 'q8', '-'),
            ('q8', 'q9', '0..9'), ('q9', 'q10', '0..9'),
            ('q10', 'q11', 'T'),
            ('q11', 'q12', '0..9'), ('q12', 'q13', '0..9'),
            ('q13', 'q14', ':'),
            ('q14', 'q15', '0..9'), ('q15', 'q16', '0..9'),
            ('q16', 'q17', ':'),
            ('q17', 'q18', '0..9'), ('q18', 'q19', '0..9')
        ]
        trans_afd = [{'from': u, 'to': v, 'label': lbl} for u, v, lbl in pattern_steps] + [
            {'from': 'q0', 'to': 'qT', 'label': '≠díg', 'curve': 18},
            {'from': 'q4', 'to': 'qT', 'label': '≠-', 'curve': 12},
            {'from': 'q7', 'to': 'qT', 'label': '≠-', 'curve': -12},
            {'from': 'q10', 'to': 'qT', 'label': '≠T', 'curve': -18},
            {'from': 'q13', 'to': 'qT', 'label': '≠:', 'curve': 12},
            {'from': 'q16', 'to': 'qT', 'label': '≠:', 'curve': -12},
            {'from': 'q19', 'to': 'qT', 'label': 'Σ_err', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_err', 'curve': -1}
        ]

        states_afnd = [{'id': 'qS', 'x': 35, 'y': 140, 'initial': True, 'note': 'λ-Inicio'}] + [
            dict(s, initial=False) for s in states_afd if not s.get('trap')
        ]
        trans_afnd = [{'from': 'qS', 'to': 'q0', 'label': 'λ'}] + [
            t for t in trans_afd if t['to'] != 'qT' and t['from'] != 'qT'
        ]
        sigma_afd = "{0..9, '-', 'T', ':'}"
        sigma_afnd = "{0..9, '-', 'T', ':', λ}"
        runs = [
            (lexeme or '2026-10-26T14:30:45', 'Accept', 'Recorre q0..q19 carácter por carácter y culmina en q19 ∈ F'),
            ('2026-09-20T14:32:05', 'Accept', 'Estructura sintáctica aceptada en q19 ∈ F (calendario validado en fase semántica)'),
            ('2026/09/20T14:32:05', 'Reject', 'En q4 recibe "/" (≠-) y transita al estado trampa qT'),
            ('2026-09-20', 'Reject', 'Finaliza en q10 ∉ F (cadena incompleta)')
        ]
        h_afd, h_afnd, rad = 265, 210, 16

    elif tok_type == 'IP':
        states_afd = [
            {'id': 'q0', 'x': 50, 'y': 55, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 145, 'y': 55, 'note': 'Oct1(1)'},
            {'id': 'q2', 'x': 240, 'y': 55, 'note': 'Oct1(2)'},
            {'id': 'q3', 'x': 335, 'y': 55, 'note': 'Oct1(3)'},
            {'id': 'q4', 'x': 435, 'y': 55, 'note': 'Punto 1'},
            {'id': 'q5', 'x': 535, 'y': 55, 'note': 'Oct2(1)'},
            {'id': 'q6', 'x': 635, 'y': 55, 'note': 'Oct2(2)'},
            {'id': 'q7', 'x': 735, 'y': 55, 'note': 'Oct2(3)'},
            {'id': 'q8', 'x': 50, 'y': 150, 'note': 'Punto 2'},
            {'id': 'q9', 'x': 150, 'y': 150, 'note': 'Oct3(1)'},
            {'id': 'q10', 'x': 250, 'y': 150, 'note': 'Oct3(2)'},
            {'id': 'q11', 'x': 350, 'y': 150, 'note': 'Oct3(3)'},
            {'id': 'q12', 'x': 455, 'y': 150, 'note': 'Punto 3'},
            {'id': 'q13', 'x': 560, 'y': 150, 'final': True, 'note': 'Oct4(1)'},
            {'id': 'q14', 'x': 665, 'y': 150, 'final': True, 'note': 'Oct4(2)'},
            {'id': 'q15', 'x': 770, 'y': 150, 'final': True, 'note': 'Oct4(3)'},
            {'id': 'qT', 'x': 435, 'y': 230, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '0..9'},
            {'from': 'q1', 'to': 'q2', 'label': '0..9'},
            {'from': 'q2', 'to': 'q3', 'label': '0..9'},
            {'from': 'q1', 'to': 'q4', 'label': '.', 'curve': -24},
            {'from': 'q2', 'to': 'q4', 'label': '.', 'curve': -15},
            {'from': 'q3', 'to': 'q4', 'label': '.'},
            {'from': 'q4', 'to': 'q5', 'label': '0..9'},
            {'from': 'q5', 'to': 'q6', 'label': '0..9'},
            {'from': 'q6', 'to': 'q7', 'label': '0..9'},
            {'from': 'q5', 'to': 'q8', 'label': '.'},
            {'from': 'q6', 'to': 'q8', 'label': '.'},
            {'from': 'q7', 'to': 'q8', 'label': '.'},
            {'from': 'q8', 'to': 'q9', 'label': '0..9'},
            {'from': 'q9', 'to': 'q10', 'label': '0..9'},
            {'from': 'q10', 'to': 'q11', 'label': '0..9'},
            {'from': 'q9', 'to': 'q12', 'label': '.', 'curve': 24},
            {'from': 'q10', 'to': 'q12', 'label': '.', 'curve': 15},
            {'from': 'q11', 'to': 'q12', 'label': '.'},
            {'from': 'q12', 'to': 'q13', 'label': '0..9'},
            {'from': 'q13', 'to': 'q14', 'label': '0..9'},
            {'from': 'q14', 'to': 'q15', 'label': '0..9'},
            {'from': 'q0', 'to': 'qT', 'label': '≠díg', 'curve': 18},
            {'from': 'q3', 'to': 'qT', 'label': '0..9', 'curve': 10},
            {'from': 'q4', 'to': 'qT', 'label': '≠díg'},
            {'from': 'q7', 'to': 'qT', 'label': '0..9', 'curve': -15},
            {'from': 'q8', 'to': 'qT', 'label': '≠díg', 'curve': 15},
            {'from': 'q11', 'to': 'qT', 'label': '0..9'},
            {'from': 'q12', 'to': 'qT', 'label': '≠díg'},
            {'from': 'q15', 'to': 'qT', 'label': 'Σ_err', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_err', 'curve': -1}
        ]
        states_afnd = [s for s in states_afd if not s.get('trap')]
        trans_afnd = [t for t in trans_afd if t['to'] != 'qT' and t['from'] != 'qT'] + [
            {'from': 'q1', 'to': 'q3', 'label': 'λ', 'curve': 20},
            {'from': 'q5', 'to': 'q7', 'label': 'λ', 'curve': 20},
            {'from': 'q9', 'to': 'q11', 'label': 'λ', 'curve': -20}
        ]
        sigma_afd = "{0..9, '.'}"
        sigma_afnd = "{0..9, '.', λ}"
        runs = [
            (lexeme or '192.168.1.10', 'Accept', 'Avanza dígito por dígito y culmina en q14 ∈ F (rango 0..255 validado en fase semántica)'),
            ('255.255.255.255', 'Accept', 'Aceptada en estado final q15 ∈ F'),
            ('192.168.1', 'Reject', 'Dirección incompleta: finaliza en q9 ∉ F'),
            ('192.168.1.1000', 'Reject', 'Excede 3 dígitos en cuarto octeto y transita a qT')
        ]
        h_afd, h_afnd, rad = 265, 210, 16

    elif tok_type == 'SEVERITY':
        states_afd = [
            {'id': 'q0', 'x': 50, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 175, 'y': 30}, {'id': 'q2', 'x': 300, 'y': 30}, {'id': 'q3', 'x': 425, 'y': 30},
            {'id': 'q4', 'x': 175, 'y': 80}, {'id': 'q5', 'x': 290, 'y': 80}, {'id': 'q6', 'x': 405, 'y': 80}, {'id': 'q7', 'x': 520, 'y': 80},
            {'id': 'q8', 'x': 155, 'y': 135}, {'id': 'q9', 'x': 250, 'y': 135}, {'id': 'q10', 'x': 345, 'y': 135},
            {'id': 'q11', 'x': 440, 'y': 135}, {'id': 'q12', 'x': 535, 'y': 135}, {'id': 'q13', 'x': 630, 'y': 135},
            {'id': 'q14', 'x': 140, 'y': 190}, {'id': 'q15', 'x': 225, 'y': 190}, {'id': 'q16', 'x': 310, 'y': 190},
            {'id': 'q17', 'x': 395, 'y': 190}, {'id': 'q18', 'x': 480, 'y': 190}, {'id': 'q19', 'x': 565, 'y': 190}, {'id': 'q20', 'x': 650, 'y': 190},
            {'id': 'q21', 'x': 765, 'y': 105, 'final': True, 'note': 'Acepta'},
            {'id': 'qT', 'x': 765, 'y': 215, 'trap': True, 'note': 'Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': 'I'}, {'from': 'q1', 'to': 'q2', 'label': 'N'},
            {'from': 'q2', 'to': 'q3', 'label': 'F'}, {'from': 'q3', 'to': 'q21', 'label': 'O'},
            {'from': 'q0', 'to': 'q4', 'label': 'E'}, {'from': 'q4', 'to': 'q5', 'label': 'R'},
            {'from': 'q5', 'to': 'q6', 'label': 'R'}, {'from': 'q6', 'to': 'q7', 'label': 'O'},
            {'from': 'q7', 'to': 'q21', 'label': 'R'},
            {'from': 'q0', 'to': 'q8', 'label': 'W'}, {'from': 'q8', 'to': 'q9', 'label': 'A'},
            {'from': 'q9', 'to': 'q10', 'label': 'R'}, {'from': 'q10', 'to': 'q11', 'label': 'N'},
            {'from': 'q11', 'to': 'q12', 'label': 'I'}, {'from': 'q12', 'to': 'q13', 'label': 'N'},
            {'from': 'q13', 'to': 'q21', 'label': 'G'},
            {'from': 'q0', 'to': 'q14', 'label': 'C'}, {'from': 'q14', 'to': 'q15', 'label': 'R'},
            {'from': 'q15', 'to': 'q16', 'label': 'I'}, {'from': 'q16', 'to': 'q17', 'label': 'T'},
            {'from': 'q17', 'to': 'q18', 'label': 'I'}, {'from': 'q18', 'to': 'q19', 'label': 'C'},
            {'from': 'q19', 'to': 'q20', 'label': 'A'}, {'from': 'q20', 'to': 'q21', 'label': 'L'},
            {'from': 'q21', 'to': 'qT', 'label': 'Σ_err'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_err', 'curve': -1}
        ]
        states_afnd = [{'id': 'qS', 'x': 25, 'y': 195, 'initial': True, 'note': 'λ-Inicio'}] + [
            dict(s, initial=False) for s in states_afd if not s.get('trap')
        ]
        trans_afnd = [{'from': 'qS', 'to': 'q0', 'label': 'λ'}] + [
            t for t in trans_afd if t['to'] != 'qT' and t['from'] != 'qT'
        ]
        sigma_afd = "{A..Z}"
        sigma_afnd = "{A..Z, λ}"
        runs = [
            (lexeme or 'ERROR', 'Accept', 'Recorre E -> R -> R -> O -> R hasta q21 ∈ F'),
            ('CRITICAL', 'Accept', 'Recorre C -> R -> I -> T -> I -> C -> A -> L hasta q21 ∈ F'),
            ('ERR', 'Reject', 'Se detiene en q6 ∉ F (prefijo incompleto)'),
            ('ERRORX', 'Reject', 'En q21 recibe carácter extra y transita a qT')
        ]
        h_afd, h_afnd, rad = 260, 235, 14

    elif tok_type == 'EVENT_TYPE':
        states_afd = [
            {'id': 'q0', 'x': 120, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 370, 'y': 85, 'final': True, 'note': 'Letra A..Z'},
            {'id': 'q2', 'x': 630, 'y': 85, 'note': 'Guion _'},
            {'id': 'qT', 'x': 370, 'y': 195, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': 'A..Z'},
            {'from': 'q1', 'to': 'q1', 'label': 'A..Z', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '_', 'curve': 26},
            {'from': 'q2', 'to': 'q1', 'label': 'A..Z', 'curve': 26},
            {'from': 'q0', 'to': 'qT', 'label': '≠A..Z', 'curve': 15},
            {'from': 'q2', 'to': 'qT', 'label': '≠A..Z', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_err', 'curve': -1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 120, 'y': 110, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 330, 'y': 110, 'final': True, 'note': 'Acepta'},
            {'id': 'q2', 'x': 540, 'y': 110, 'note': 'Sep _'},
            {'id': 'q3', 'x': 730, 'y': 110, 'final': True, 'note': 'Sufijo A..Z'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': 'A..Z'},
            {'from': 'q1', 'to': 'q0', 'label': 'λ', 'curve': 24},
            {'from': 'q1', 'to': 'q2', 'label': '_'},
            {'from': 'q2', 'to': 'q3', 'label': 'A..Z'},
            {'from': 'q3', 'to': 'q1', 'label': 'λ', 'curve': 28}
        ]
        sigma_afd = "{A..Z, '_'}"
        sigma_afnd = "{A..Z, '_', λ}"
        runs = [
            (lexeme or 'LOGIN_FAILED', 'Accept', 'Culmina en estado de aceptación q1 ∈ F'),
            ('PRIVILEGE_ESCALATION', 'Accept', 'Cumple patrón [A-Z]+(_[A-Z]+)* en q1 ∈ F'),
            ('_LOGIN', 'Reject', 'Inicia con "_" (≠A..Z) y transita a qT'),
            ('LOGIN__', 'Reject', 'Doble guion bajo en q2 transita a qT')
        ]
        h_afd, h_afnd, rad = 245, 210, 18

    elif tok_type == 'STRING':
        states_afd = [
            {'id': 'q0', 'x': 120, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 380, 'y': 85, 'note': 'Interior " "'},
            {'id': 'q2', 'x': 640, 'y': 85, 'final': True, 'note': 'Cierre "'},
            {'id': 'qT', 'x': 380, 'y': 195, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q1', 'label': 'Σ_str', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '"'},
            {'from': 'q0', 'to': 'qT', 'label': '≠"', 'curve': 15},
            {'from': 'q2', 'to': 'qT', 'label': 'Σ_err', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_err', 'curve': -1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 110, 'y': 110, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 300, 'y': 110, 'note': 'Abre "'},
            {'id': 'q2', 'x': 510, 'y': 110, 'note': 'Cuerpo'},
            {'id': 'q3', 'x': 720, 'y': 110, 'final': True, 'note': 'Cierra "'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q2', 'label': 'λ'},
            {'from': 'q2', 'to': 'q2', 'label': 'Σ_str', 'curve': 1},
            {'from': 'q2', 'to': 'q3', 'label': '"'}
        ]
        sigma_afd = '{"\"" , Σ_str}'
        sigma_afnd = '{"\"" , Σ_str, λ}'
        runs = [
            (lexeme or '"admin"', 'Accept', 'Abre con ", lee caracteres válidos y cierra con " (q2 ∈ F en AFD / q3 ∈ F\' en AFND)'),
            ('""', 'Accept', 'Cadena vacía entre comillas aceptada'),
            ('"admin', 'Reject', 'Sin comilla final no alcanza el estado de aceptación'),
            ('admin"', 'Reject', 'No inicia con comilla y cae en qT')
        ]
        h_afd, h_afnd, rad = 245, 210, 18

    elif tok_type == 'NUMBER':
        states_afd = [
            {'id': 'q0', 'x': 150, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 430, 'y': 85, 'final': True, 'note': 'Dígito 0..9'},
            {'id': 'qT', 'x': 680, 'y': 85, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '0..9'},
            {'from': 'q1', 'to': 'q1', 'label': '0..9', 'curve': 1},
            {'from': 'q0', 'to': 'qT', 'label': '≠díg', 'curve': -35},
            {'from': 'q1', 'to': 'qT', 'label': '≠díg'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_err', 'curve': 1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 160, 'y': 110, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 430, 'y': 110, 'note': 'Dígito'},
            {'id': 'q2', 'x': 680, 'y': 110, 'final': True, 'note': 'Acepta'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': '0..9'},
            {'from': 'q1', 'to': 'q0', 'label': 'λ', 'curve': 25},
            {'from': 'q1', 'to': 'q2', 'label': 'λ'}
        ]
        sigma_afd = "{0..9}"
        sigma_afnd = "{0..9, λ}"
        runs = [
            (lexeme or '3', 'Accept', 'Dígito numérico válido (q1 ∈ F en AFD / q2 ∈ F\' en AFND)'),
            ('2026', 'Accept', 'Secuencia continua de dígitos aceptada'),
            ('3a', 'Reject', 'El carácter no numérico "a" transita a qT')
        ]
        h_afd, h_afnd, rad = 215, 210, 18

    else:
        sym = lexeme or {'LBRACE': '{', 'RBRACE': '}', 'COLON': ':', 'COMMA': ','}.get(tok_type, '{')
        states_afd = [
            {'id': 'q0', 'x': 150, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 430, 'y': 85, 'final': True, 'note': f'Leyó {sym}'},
            {'id': 'qT', 'x': 680, 'y': 85, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': sym},
            {'from': 'q1', 'to': 'qT', 'label': 'Σ_err'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_err', 'curve': 1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 160, 'y': 110, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 430, 'y': 110, 'note': 'Paso λ'},
            {'id': 'q2', 'x': 680, 'y': 110, 'final': True, 'note': f'Acepta {sym}'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': 'λ'},
            {'from': 'q1', 'to': 'q2', 'label': sym}
        ]
        sigma_afd = f"{{'{sym}'}}"
        sigma_afnd = f"{{'{sym}', λ}}"
        runs = [
            (sym, 'Accept', f'Reconoce el delimitador {sym!r} (q1 ∈ F en AFD / q2 ∈ F\' en AFND)'),
            (sym + sym, 'Reject', 'Un segundo carácter transita a qT')
        ]
        h_afd, h_afnd, rad = 210, 210, 18

    quintupla_afd = build_formal_quintuple_from_graph(states_afd, trans_afd, sigma_afd, is_afnd=False)
    quintupla_afnd = build_formal_quintuple_from_graph(states_afnd, trans_afnd, sigma_afnd, is_afnd=True)

    return (
        render_jflap_svg(states_afd, trans_afd, height=h_afd, is_afnd=False, tok_type=tok_type, node_radius=rad),
        render_jflap_svg(states_afnd, trans_afnd, height=h_afnd, is_afnd=True, tok_type=tok_type, node_radius=rad),
        runs,
        quintupla_afd,
        quintupla_afnd
    )