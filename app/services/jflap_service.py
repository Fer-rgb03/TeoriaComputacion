import math
import base64
from app.utils.helpers import escape_svg_text


def expand_symbol_for_jff(label):
    """
    Expande etiquetas de conjuntos de caracteres en símbolos individuales de 1 carácter
    para que el archivo .jff sea 100% válido y ejecutable en JFLAP 7.1.
    """
    if label in ('λ', 'ε', ''):
        return ['']  # Transición vacía (lambda) en JFLAP XML
    if label == '0..9':
        return [str(d) for d in range(10)]
    if label == 'A..Z':
        return [chr(c) for c in range(ord('A'), ord('Z') + 1)]
    if label == 'Σ_str':
        # Caracteres imprimibles comunes dentro de un STRING JSON (sin comillas)
        chars = (
            [chr(c) for c in range(ord('a'), ord('z') + 1)] +
            [chr(c) for c in range(ord('A'), ord('Z') + 1)] +
            [str(d) for d in range(10)] +
            ['_', '-', '.', ':', '/', ' ', '@', '(', ')', ';', "'"]
        )
        return chars
    return [label]


def build_jff_download_uri(states, transitions):
    """
    Construye el archivo XML .jff nativo de JFLAP 7.1 y lo codifica en Base64
    para poder abrirlo y validarlo directamente en JFLAP con Multiple Run = Accept.
    """
    state_id_map = {}
    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
        '<!-- Generado por SOC Analyzer USIL - Compatible con JFLAP 7.1 -->',
        '<structure>',
        '  <type>fa</type>',
        '  <automaton>'
    ]

    for idx, s in enumerate(states):
        if s.get('trap'):
            continue
        state_id_map[s['id']] = idx
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
        for ch in expand_symbol_for_jff(t['label']):
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
    Genera dinámicamente la Tabla de Transición formal (δ) carácter por carácter
    y el botón de descarga del archivo .jff para validación directa en JFLAP.
    """
    valid_transitions = [t for t in transitions if t['to'] != 'qT' and t['from'] != 'qT']
    display_states = [s for s in states if not s.get('trap')]

    symbols = []
    for t in valid_transitions:
        lbl = t['label']
        if lbl not in symbols:
            symbols.append(lbl)

    jff_uri = build_jff_download_uri(display_states, valid_transitions)
    tipo_str = "AFND" if is_afnd else "AFD"
    filename = f"{tipo_str}_{tok_type}.jff"
    titulo_tabla = (
        f"Tabla de Transición Formal δ — {tipo_str} (Subconjuntos P(Q))"
        if is_afnd else
        f"Tabla de Transición Formal δ — {tipo_str} (Carácter por Carácter)"
    )

    html_out = [
        '<div class="mt-3 rounded-lg border border-slate-300 bg-white shadow-sm overflow-hidden">',
        '  <div class="bg-slate-800 text-white px-3 py-2 text-xs font-bold flex flex-wrap items-center justify-between gap-2">',
        f'    <span>{escape_svg_text(titulo_tabla)}</span>',
        '    <div class="flex items-center gap-3">',
        '      <span class="text-[11px] font-normal text-slate-300">→ Inicial | * Final (F)</span>',
        f'      <a href="{jff_uri}" download="{filename}" '
        '         class="px-2.5 py-1 rounded bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-[11px] shadow transition">',
        f'        ⬇ Descargar {filename} (Abrir en JFLAP)',
        '      </a>',
        '    </div>',
        '  </div>',
        '  <div class="overflow-x-auto max-h-64">',
        '    <table class="w-full text-xs text-left border-collapse">',
        '      <thead class="sticky top-0">',
        '        <tr class="bg-slate-100 border-b border-slate-300 text-slate-700">',
        '          <th class="py-1.5 px-2.5 font-bold border-r border-slate-300">Estado (Q)</th>'
    ]

    for sym in symbols:
        sym_header = "0,1,2,3,4,5,6,7,8,9" if sym == "0..9" else ("A,B,...,Z" if sym == "A..Z" else sym)
        html_out.append(
            f'          <th class="py-1.5 px-2.5 font-mono font-bold text-center border-r border-slate-200">'
            f'{escape_svg_text(sym_header)}</th>'
        )
    html_out.append('        </tr>')
    html_out.append('      </thead>')
    html_out.append('      <tbody class="divide-y divide-slate-200">')

    for s in display_states:
        sid = s['id']
        prefix = ""
        if s.get('initial'):
            prefix += "→ "
        if s.get('final'):
            prefix += "* "

        row_bg = "bg-emerald-50/60" if s.get('final') else "bg-white"
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
                cell_style = "text-blue-700 font-bold"
            else:
                cell_val = "∅"
                cell_style = "text-slate-400"

            html_out.append(
                f'          <td class="py-1.5 px-2.5 font-mono text-center border-r border-slate-200 {cell_style}">'
                f'{escape_svg_text(cell_val)}</td>'
            )

        html_out.append('        </tr>')

    html_out.append('      </tbody>')
    html_out.append('    </table>')
    html_out.append('  </div>')

    # Lista formal de transiciones δ(q, σ) = p (Etapa 2 - Punto 8)
    trans_items = [
        f"δ({escape_svg_text(t['from'])}, {escape_svg_text(t['label'])}) = "
        f"{'{' + escape_svg_text(t['to']) + '}' if is_afnd else escape_svg_text(t['to'])}"
        for t in valid_transitions
    ]
    html_out.append(
        '  <div class="bg-slate-50 px-3 py-2 border-t border-slate-200 text-[11px] font-mono text-slate-700">'
        '    <span class="font-bold text-slate-900">Transiciones δ paso a paso: </span>' +
        " &nbsp;|&nbsp; ".join(trans_items) +
        '  </div>'
    )
    html_out.append('</div>')
    return '\n'.join(html_out)


def render_jflap_svg(states, transitions, width=860, height=250, is_afnd=False, tok_type="TOKEN", node_radius=20):
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
        u = state_map[t['from']]
        v = state_map[t['to']]
        lbl = escape_svg_text(t['label'])
        curve = t.get('curve', 0)

        if t['from'] == t['to']:
            direction = -1 if curve >= 0 else 1
            x, y = u['x'], u['y']
            sy = y + direction * (r - 3)
            cy = y + direction * (r + 36)
            ly = y + direction * (r + 33)
            svg.append(
                f'<path d="M {x-9},{sy} C {x-24},{cy} {x+24},{cy} {x+9},{sy}" '
                f'fill="none" stroke="#111111" stroke-width="1.5" marker-end="url(#jflap-arrow)"/>'
            )
            svg.append(
                f'<text x="{x}" y="{ly}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="10.5" font-weight="bold" fill="#111111">{lbl}</text>'
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
                    f'stroke="#111111" stroke-width="1.5" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{mx:.1f}" y="{my:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="10" font-weight="bold" fill="#111111">{lbl}</text>'
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
                ly = 0.25 * sy + 0.5 * cy + 0.25 * ey - (5 if curve >= 0 else -12)
                svg.append(
                    f'<path d="M {sx:.1f},{sy:.1f} Q {cx:.1f},{cy:.1f} {ex:.1f},{ey:.1f}" '
                    f'fill="none" stroke="#111111" stroke-width="1.5" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="10" font-weight="bold" fill="#111111">{lbl}</text>'
                )

    for s in states:
        x, y = s['x'], s['y']
        sid = escape_svg_text(s['id'])
        fill_color = "#ffe4e1" if s.get('trap') else "#ffff96"

        if s.get('initial'):
            svg.append(
                f'<polygon points="{x - r - 18},{y - 12} {x - r - 18},{y + 12} {x - r - 1},{y}" '
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
            f'<text x="{x}" y="{y + 4}" text-anchor="middle" font-family="Arial, sans-serif" '
            f'font-size="11" font-weight="bold" fill="#000000">{sid}</text>'
        )

        if s.get('note'):
            note_txt = escape_svg_text(s['note'])
            svg.append(
                f'<text x="{x}" y="{y + r + 12}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="9" fill="#475569">{note_txt}</text>'
            )

    svg.append('</svg>')
    svg.append(render_transition_table_html(states, transitions, is_afnd=is_afnd, tok_type=tok_type))
    return '\n'.join(svg)


def build_jflap_models_for_token(tok_type, lexeme=""):
    """
    Construye los modelos AFD y AFND exactos carácter por carácter (1 símbolo por transición)
    para que al validarlos en JFLAP 7.1 acepten todas las cadenas válidas sin fallar.
    """
    if tok_type == 'TIMESTAMP':
        # 20 estados reales (q0 a q19): 1 transición de 1 carácter por cada posición de AAAA-MM-DDTHH:MM:SS
        states_afd = []
        # Fila superior: q0 a q10 (Fecha: AAAA-MM-DD)
        for i in range(11):
            states_afd.append({
                'id': f'q{i}',
                'x': 55 + i * 76,
                'y': 60,
                'initial': (i == 0),
                'note': 'Inicio' if i == 0 else ('Año' if i == 4 else ('Mes' if i == 7 else ('Día' if i == 10 else '')))
            })
        # Fila inferior: q11 a q19 (Hora: THH:MM:SS)
        for j, st_idx in enumerate(range(11, 20)):
            states_afd.append({
                'id': f'q{st_idx}',
                'x': 130 + j * 82,
                'y': 175,
                'final': (st_idx == 19),
                'note': 'Sep T' if st_idx == 11 else ('Acepta' if st_idx == 19 else '')
            })

        # Cada paso consume exactamente 1 carácter: dígito (0..9), '-', 'T' o ':'
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
        trans_afd = [{'from': u, 'to': v, 'label': lbl} for u, v, lbl in pattern_steps]

        # AFND: Incluye transición espontánea λ inicial de Thompson (qS -> q0)
        states_afnd = [{'id': 'qS', 'x': 40, 'y': 175, 'initial': True, 'note': 'λ-Inicio'}] + [
            dict(s, initial=False) for s in states_afd
        ]
        trans_afnd = [{'from': 'qS', 'to': 'q0', 'label': 'λ'}] + trans_afd

        runs = [
            (lexeme or '2026-09-20T14:32:05', 'Accept', 'Recorre los 19 pasos carácter por carácter desde q0 hasta q19 ∈ F'),
            ('2026-10-12T08:15:30', 'Accept', 'Cumple las 19 transiciones individuales en JFLAP (q19 ∈ F)'),
            ('2026/09/20 14:32:05', 'Reject', 'En q4 espera "-" pero recibe "/" (sin transición definida)'),
            ('2026-09-20', 'Reject', 'Se detiene en q10 ∉ F (cadena incompleta)')
        ]
        return (
            render_jflap_svg(states_afd, trans_afd, height=235, is_afnd=False, tok_type=tok_type, node_radius=17),
            render_jflap_svg(states_afnd, trans_afnd, height=235, is_afnd=True, tok_type=tok_type, node_radius=17),
            runs
        )

    elif tok_type == 'IP':
        # 16 estados (q0 a q15): 1 a 3 dígitos por cada uno de los 4 octetos separados por '.'
        states_afd = [
            # Fila 1: Octeto 1 y Octeto 2
            {'id': 'q0', 'x': 55, 'y': 65, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 150, 'y': 65, 'note': 'Oct1(1)'},
            {'id': 'q2', 'x': 245, 'y': 65, 'note': 'Oct1(2)'},
            {'id': 'q3', 'x': 340, 'y': 65, 'note': 'Oct1(3)'},
            {'id': 'q4', 'x': 445, 'y': 65, 'note': 'Punto 1'},
            {'id': 'q5', 'x': 545, 'y': 65, 'note': 'Oct2(1)'},
            {'id': 'q6', 'x': 645, 'y': 65, 'note': 'Oct2(2)'},
            {'id': 'q7', 'x': 745, 'y': 65, 'note': 'Oct2(3)'},
            # Fila 2: Octeto 3 y Octeto 4 (estados finales q13, q14, q15)
            {'id': 'q8', 'x': 55, 'y': 185, 'note': 'Punto 2'},
            {'id': 'q9', 'x': 155, 'y': 185, 'note': 'Oct3(1)'},
            {'id': 'q10', 'x': 255, 'y': 185, 'note': 'Oct3(2)'},
            {'id': 'q11', 'x': 355, 'y': 185, 'note': 'Oct3(3)'},
            {'id': 'q12', 'x': 465, 'y': 185, 'note': 'Punto 3'},
            {'id': 'q13', 'x': 570, 'y': 185, 'final': True, 'note': 'Oct4(1)'},
            {'id': 'q14', 'x': 675, 'y': 185, 'final': True, 'note': 'Oct4(2)'},
            {'id': 'q15', 'x': 780, 'y': 185, 'final': True, 'note': 'Oct4(3)'}
        ]
        trans_afd = [
            # Octeto 1
            {'from': 'q0', 'to': 'q1', 'label': '0..9'},
            {'from': 'q1', 'to': 'q2', 'label': '0..9'},
            {'from': 'q2', 'to': 'q3', 'label': '0..9'},
            {'from': 'q1', 'to': 'q4', 'label': '.', 'curve': -28},
            {'from': 'q2', 'to': 'q4', 'label': '.', 'curve': -18},
            {'from': 'q3', 'to': 'q4', 'label': '.'},
            # Octeto 2
            {'from': 'q4', 'to': 'q5', 'label': '0..9'},
            {'from': 'q5', 'to': 'q6', 'label': '0..9'},
            {'from': 'q6', 'to': 'q7', 'label': '0..9'},
            {'from': 'q5', 'to': 'q8', 'label': '.'},
            {'from': 'q6', 'to': 'q8', 'label': '.'},
            {'from': 'q7', 'to': 'q8', 'label': '.'},
            # Octeto 3
            {'from': 'q8', 'to': 'q9', 'label': '0..9'},
            {'from': 'q9', 'to': 'q10', 'label': '0..9'},
            {'from': 'q10', 'to': 'q11', 'label': '0..9'},
            {'from': 'q9', 'to': 'q12', 'label': '.', 'curve': 28},
            {'from': 'q10', 'to': 'q12', 'label': '.', 'curve': 18},
            {'from': 'q11', 'to': 'q12', 'label': '.'},
            # Octeto 4 (Aceptación en q13, q14, q15)
            {'from': 'q12', 'to': 'q13', 'label': '0..9'},
            {'from': 'q13', 'to': 'q14', 'label': '0..9'},
            {'from': 'q14', 'to': 'q15', 'label': '0..9'}
        ]
        states_afnd = list(states_afd)
        trans_afnd = trans_afd + [
            {'from': 'q1', 'to': 'q3', 'label': 'λ', 'curve': 22},
            {'from': 'q5', 'to': 'q7', 'label': 'λ', 'curve': 22},
            {'from': 'q9', 'to': 'q11', 'label': 'λ', 'curve': -22}
        ]
        runs = [
            (lexeme or '192.168.1.10', 'Accept', 'Avanza dígito por dígito y punto por punto hasta q14 ∈ F'),
            ('10.0.0.5', 'Accept', 'Octetos de 1 y 2 dígitos aceptados en q13 ∈ F'),
            ('192.168.1', 'Reject', 'Se detiene en q9 ∉ F (falta cuarto octeto)'),
            ('192.168.1.1000', 'Reject', 'Excede los 3 dígitos permitidos en el cuarto octeto')
        ]
        return (
            render_jflap_svg(states_afd, trans_afd, height=245, is_afnd=False, tok_type=tok_type, node_radius=17),
            render_jflap_svg(states_afnd, trans_afnd, height=245, is_afnd=True, tok_type=tok_type, node_radius=17),
            runs
        )

    elif tok_type == 'SEVERITY':
        # Reconocimiento letra por letra de INFO, ERROR, WARNING y CRITICAL
        states_afd = [
            {'id': 'q0', 'x': 55, 'y': 125, 'initial': True, 'note': 'Inicio'},
            # Rama INFO (y=35)
            {'id': 'q1', 'x': 185, 'y': 35}, {'id': 'q2', 'x': 315, 'y': 35}, {'id': 'q3', 'x': 445, 'y': 35},
            # Rama ERROR (y=95)
            {'id': 'q4', 'x': 185, 'y': 95}, {'id': 'q5', 'x': 300, 'y': 95}, {'id': 'q6', 'x': 415, 'y': 95}, {'id': 'q7', 'x': 530, 'y': 95},
            # Rama WARNING (y=155)
            {'id': 'q8', 'x': 160, 'y': 155}, {'id': 'q9', 'x': 255, 'y': 155}, {'id': 'q10', 'x': 350, 'y': 155},
            {'id': 'q11', 'x': 445, 'y': 155}, {'id': 'q12', 'x': 540, 'y': 155}, {'id': 'q13', 'x': 635, 'y': 155},
            # Rama CRITICAL (y=215)
            {'id': 'q14', 'x': 145, 'y': 215}, {'id': 'q15', 'x': 230, 'y': 215}, {'id': 'q16', 'x': 315, 'y': 215},
            {'id': 'q17', 'x': 400, 'y': 215}, {'id': 'q18', 'x': 485, 'y': 215}, {'id': 'q19', 'x': 570, 'y': 215}, {'id': 'q20', 'x': 655, 'y': 215},
            # Estado Final común q21
            {'id': 'q21', 'x': 785, 'y': 125, 'final': True, 'note': 'Acepta'}
        ]
        trans_afd = [
            # I - N - F - O
            {'from': 'q0', 'to': 'q1', 'label': 'I'}, {'from': 'q1', 'to': 'q2', 'label': 'N'},
            {'from': 'q2', 'to': 'q3', 'label': 'F'}, {'from': 'q3', 'to': 'q21', 'label': 'O'},
            # E - R - R - O - R
            {'from': 'q0', 'to': 'q4', 'label': 'E'}, {'from': 'q4', 'to': 'q5', 'label': 'R'},
            {'from': 'q5', 'to': 'q6', 'label': 'R'}, {'from': 'q6', 'to': 'q7', 'label': 'O'},
            {'from': 'q7', 'to': 'q21', 'label': 'R'},
            # W - A - R - N - I - N - G
            {'from': 'q0', 'to': 'q8', 'label': 'W'}, {'from': 'q8', 'to': 'q9', 'label': 'A'},
            {'from': 'q9', 'to': 'q10', 'label': 'R'}, {'from': 'q10', 'to': 'q11', 'label': 'N'},
            {'from': 'q11', 'to': 'q12', 'label': 'I'}, {'from': 'q12', 'to': 'q13', 'label': 'N'},
            {'from': 'q13', 'to': 'q21', 'label': 'G'},
            # C - R - I - T - I - C - A - L
            {'from': 'q0', 'to': 'q14', 'label': 'C'}, {'from': 'q14', 'to': 'q15', 'label': 'R'},
            {'from': 'q15', 'to': 'q16', 'label': 'I'}, {'from': 'q16', 'to': 'q17', 'label': 'T'},
            {'from': 'q17', 'to': 'q18', 'label': 'I'}, {'from': 'q18', 'to': 'q19', 'label': 'C'},
            {'from': 'q19', 'to': 'q20', 'label': 'A'}, {'from': 'q20', 'to': 'q21', 'label': 'L'}
        ]
        states_afnd = list(states_afd)
        trans_afnd = list(trans_afd)
        runs = [
            (lexeme or 'ERROR', 'Accept', 'Avanza letra por letra E -> R -> R -> O -> R hasta q21 ∈ F'),
            ('CRITICAL', 'Accept', 'Avanza C -> R -> I -> T -> I -> C -> A -> L hasta q21 ∈ F'),
            ('WARNING', 'Accept', 'Avanza W -> A -> R -> N -> I -> N -> G hasta q21 ∈ F'),
            ('ERR', 'Reject', 'Se detiene en q6 ∉ F (prefijo incompleto)')
        ]
        return (
            render_jflap_svg(states_afd, trans_afd, height=255, is_afnd=False, tok_type=tok_type, node_radius=15),
            render_jflap_svg(states_afnd, trans_afnd, height=255, is_afnd=True, tok_type=tok_type, node_radius=15),
            runs
        )

    elif tok_type == 'EVENT_TYPE':
        states_afd = [
            {'id': 'q0', 'x': 140, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 400, 'y': 115, 'final': True, 'note': 'Letra A..Z'},
            {'id': 'q2', 'x': 660, 'y': 115, 'note': 'Guion _'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': 'A..Z'},
            {'from': 'q1', 'to': 'q1', 'label': 'A..Z', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '_', 'curve': 28},
            {'from': 'q2', 'to': 'q1', 'label': 'A..Z', 'curve': 28}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 120, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 330, 'y': 115, 'final': True, 'note': 'Acepta'},
            {'id': 'q2', 'x': 540, 'y': 115, 'note': 'Sep _'},
            {'id': 'q3', 'x': 730, 'y': 115, 'final': True, 'note': 'Sufijo A..Z'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': 'A..Z'},
            {'from': 'q1', 'to': 'q0', 'label': 'λ', 'curve': 25},
            {'from': 'q1', 'to': 'q2', 'label': '_'},
            {'from': 'q2', 'to': 'q3', 'label': 'A..Z'},
            {'from': 'q3', 'to': 'q1', 'label': 'λ', 'curve': 30}
        ]
        runs = [
            (lexeme or 'LOGIN_FAILED', 'Accept', 'Cada letra A..Z y "_" avanza carácter por carácter hasta q1 ∈ F'),
            ('PRIVILEGE_ESCALATION', 'Accept', 'Aceptada en q1 ∈ F'),
            ('_LOGIN', 'Reject', 'No existe transición con "_" desde q0'),
            ('LOGIN_', 'Reject', 'Termina en q2 ∉ F')
        ]
        return (
            render_jflap_svg(states_afd, trans_afd, height=220, is_afnd=False, tok_type=tok_type),
            render_jflap_svg(states_afnd, trans_afnd, height=220, is_afnd=True, tok_type=tok_type),
            runs
        )

    elif tok_type == 'STRING':
        states_afd = [
            {'id': 'q0', 'x': 150, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 420, 'y': 115, 'note': 'Interior " "'},
            {'id': 'q2', 'x': 690, 'y': 115, 'final': True, 'note': 'Cierre "'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q1', 'label': 'Σ_str', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '"'}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 110, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 300, 'y': 115, 'note': 'Abre "'},
            {'id': 'q2', 'x': 510, 'y': 115, 'note': 'Cuerpo'},
            {'id': 'q3', 'x': 720, 'y': 115, 'final': True, 'note': 'Cierra "'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q2', 'label': 'λ'},
            {'from': 'q2', 'to': 'q2', 'label': 'Σ_str', 'curve': 1},
            {'from': 'q2', 'to': 'q3', 'label': '"'}
        ]
        runs = [
            (lexeme or '"admin"', 'Accept', 'Abre con ", consume caracteres en q1 y cierra con " hacia q2 ∈ F'),
            ('""', 'Accept', 'Cadena vacía entre comillas aceptada en q2 ∈ F'),
            ('"admin', 'Reject', 'Sin comilla final permanece en q1 ∉ F')
        ]
        return (
            render_jflap_svg(states_afd, trans_afd, height=220, is_afnd=False, tok_type=tok_type),
            render_jflap_svg(states_afnd, trans_afnd, height=220, is_afnd=True, tok_type=tok_type),
            runs
        )

    elif tok_type == 'NUMBER':
        states_afd = [
            {'id': 'q0', 'x': 220, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 560, 'y': 115, 'final': True, 'note': 'Dígito 0..9'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '0..9'},
            {'from': 'q1', 'to': 'q1', 'label': '0..9', 'curve': 1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 160, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 430, 'y': 115, 'note': 'Dígito'},
            {'id': 'q2', 'x': 680, 'y': 115, 'final': True, 'note': 'Acepta'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': '0..9'},
            {'from': 'q1', 'to': 'q0', 'label': 'λ', 'curve': 26},
            {'from': 'q1', 'to': 'q2', 'label': 'λ'}
        ]
        runs = [
            (lexeme or '3', 'Accept', 'Consume dígito numérico y finaliza en estado de aceptación'),
            ('2026', 'Accept', 'Recorre el bucle 0..9 carácter por carácter'),
            ('3a', 'Reject', 'El símbolo "a" no tiene transición definida')
        ]
        return (
            render_jflap_svg(states_afd, trans_afd, height=220, is_afnd=False, tok_type=tok_type),
            render_jflap_svg(states_afnd, trans_afnd, height=220, is_afnd=True, tok_type=tok_type),
            runs
        )

    else:
        sym = lexeme or {'LBRACE': '{', 'RBRACE': '}', 'COLON': ':', 'COMMA': ','}.get(tok_type, '{')
        states_afd = [
            {'id': 'q0', 'x': 220, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 560, 'y': 115, 'final': True, 'note': f'Leyó {sym}'}
        ]
        trans_afd = [{'from': 'q0', 'to': 'q1', 'label': sym}]

        states_afnd = [
            {'id': 'q0', 'x': 160, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 430, 'y': 115, 'note': 'Paso λ'},
            {'id': 'q2', 'x': 680, 'y': 115, 'final': True, 'note': 'Acepta'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': 'λ'},
            {'from': 'q1', 'to': 'q2', 'label': sym}
        ]
        runs = [
            (sym, 'Accept', f'Consume el carácter único {sym!r} y llega a aceptación'),
            (sym + sym, 'Reject', 'Rechaza cadenas de longitud mayor a 1')
        ]
        return (
            render_jflap_svg(states_afd, trans_afd, height=210, is_afnd=False, tok_type=tok_type),
            render_jflap_svg(states_afnd, trans_afnd, height=210, is_afnd=True, tok_type=tok_type),
            runs
        )