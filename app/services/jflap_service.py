import math
import base64
from app.utils.helpers import escape_svg_text


def expand_symbol_for_jff(label, tok_type="TOKEN"):
    """
    M-11: Expande cada etiqueta simbólica en caracteres individuales de longitud 1
    para que JFLAP 7.1 ejecute exactamente las mismas transiciones que la interfaz web.
    """
    digits = [str(d) for d in range(10)]
    uppers = [chr(c) for c in range(ord('A'), ord('Z') + 1)]
    lowers = [chr(c) for c in range(ord('a'), ord('z') + 1)]
    latin_ext = list("áéíóúÁÉÍÓÚñÑüÜ")

    if label in ('λ', 'ε', ''):
        return ['']
    if label == '0..9':
        return digits
    if label == '1..9':
        return [str(d) for d in range(1, 10)]
    if label == '0..1':
        return ['0', '1']
    if label == '0..2':
        return ['0', '1', '2']
    if label == '1..2':
        return ['1', '2']
    if label == '0..3':
        return ['0', '1', '2', '3']
    if label == '0..5':
        return [str(d) for d in range(6)]
    if label == '2..9':
        return [str(d) for d in range(2, 10)]
    if label == '3..9':
        return [str(d) for d in range(3, 10)]
    if label == '4..9':
        return [str(d) for d in range(4, 10)]
    if label == '6..9':
        return ['6', '7', '8', '9']
    if label == 'A..Z':
        return uppers
    if label == 'Σ_base':
        return lowers + uppers + digits + latin_ext + ['_', '-', '.', ':', '/', ' ', '@', '(', ')', ';', "'", '=', '+', '$', '<', '>']
    if label == 'Σ_esc':
        return ['"', '\\', '/', 'b', 'f', 'n', 'r', 't']

    # M-06: Particiones complementarias con notación de diferencia de conjuntos ∖ (sin usar \)
    if label == 'Σ ∖ díg':
        return ['-', 'T', ':', '/', '.', ' ', 'a', 'Z', '+']
    if label == "Σ ∖ {'-'}":
        return digits + ['T', ':', '/', '.']
    if label == "Σ ∖ {'T'}":
        return digits + ['-', ':', '/', ' ']
    if label == "Σ ∖ {':'}":
        return digits + ['-', 'T', '/', '.']
    if label == "Σ ∖ {'0','1'}":
        return [str(d) for d in range(2, 10)] + ['-', 'T', ':', '/']
    if label == "Σ ∖ {'1'..'9'}":
        return ['0', '-', 'T', ':', '/']
    if label == "Σ ∖ {'0'..'2'}":
        return [str(d) for d in range(3, 10)] + ['-', 'T', ':', '/']
    if label == "Σ ∖ {'0'..'3'}":
        return [str(d) for d in range(4, 10)] + ['-', 'T', ':', '/']
    if label == "Σ ∖ {'0'..'5'}":
        return ['6', '7', '8', '9', '-', 'T', ':', '/']
    if label == 'Σ ∖ A..Z':
        return ['_', '-', '0', '1', 'a', ' ']
    if label == 'Σ ∖ {"\\""}':
        return lowers + uppers + digits + ['_', '-', ':']
    if label == 'Σ ∖ Σ_esc':
        return ['a', 'c', 'e', 'g', 'u', '0', '1', '9', '_']
    if label == 'Σ_otros':
        if tok_type == 'TIMESTAMP':
            return digits + ['-', 'T', ':', '/', 'Z', '+']
        if tok_type == 'IP':
            return digits + ['.', '-', '/', 'a']
        if tok_type == 'SEVERITY':
            return uppers + digits + ['_']
        if tok_type == 'EVENT_TYPE':
            return uppers + ['_', '0', '1', '-']
        if tok_type == 'STRING':
            return lowers + uppers + digits + ['"', '\\', '_', '-']
        if tok_type == 'NUMBER':
            return digits + ['a', 'z', '-', '.']
        return ['{', '}', ':', ',', 'a', '0', '"']

    return [label]


def char_matches_label(ch, label, tok_type="TOKEN"):
    """Evalúa si un carácter individual pertenece a la etiqueta de transición dada."""
    if label in ('λ', 'ε', ''):
        return False
    return ch in expand_symbol_for_jff(label, tok_type=tok_type)


def simulate_real_trace(states, transitions, input_str, tok_type="TOKEN", is_afnd=False):
    """
    H-02: Ejecuta realmente el autómata (AFD o AFND con λ-clausura) carácter por carácter
    sobre la cadena de entrada 'input_str', generando la traza real de estados sin texto fijo.
    """
    state_map = {s['id']: s for s in states}
    initial_ids = [s['id'] for s in states if s.get('initial')]
    final_ids = {s['id'] for s in states if s.get('final')}

    if not initial_ids:
        return "Reject", "Autómata sin estado inicial definido."

    if not is_afnd:
        curr = initial_ids[0]
        steps = [curr]
        for idx, ch in enumerate(input_str):
            next_state = None
            for t in transitions:
                if t['from'] == curr and t['to'] != 'qT' and char_matches_label(ch, t['label'], tok_type):
                    next_state = t['to']
                    break
            if next_state is None:
                # Verificar si cae en el estado trampa qT
                has_trap = any(s.get('trap') for s in states)
                if has_trap:
                    steps.append(f"--'{ch}'--> qT")
                    return (
                        "Reject",
                        f"Traza AFD: {' '.join(steps)} (En pos {idx+1} lee {ch!r} y transita al estado trampa qT ∉ F)"
                    )
                return (
                    "Reject",
                    f"Traza AFD: {' '.join(steps)} (En pos {idx+1} no existe transición para {ch!r})"
                )
            curr = next_state
            if len(input_str) <= 10 or idx < 4 or idx >= len(input_str) - 2:
                steps.append(f"--'{ch}'--> {curr}")
            elif idx == 4:
                steps.append("--> ... ")

        if curr in final_ids:
            return "Accept", f"Traza AFD real: {' '.join(steps)} (Culmina en estado de aceptación {curr} ∈ F)"
        return "Reject", f"Traza AFD real: {' '.join(steps)} (Entrada agotada en {curr} ∉ F; cadena incompleta)"

    else:
        # Simulación real de AFND con cálculo de λ-clausura (jamás menciona qT)
        def lambda_closure(state_set):
            stack = list(state_set)
            closure = set(state_set)
            while stack:
                u = stack.pop()
                for t in transitions:
                    if t['from'] == u and t['label'] in ('λ', 'ε', '') and t['to'] not in closure:
                        closure.add(t['to'])
                        stack.append(t['to'])
            return sorted(closure, key=lambda x: int(x[1:]) if x[1:].isdigit() else x)

        curr_set = lambda_closure(initial_ids)
        trace_sets = ["{" + ",".join(curr_set) + "}"]

        for idx, ch in enumerate(input_str):
            move_set = set()
            for u in curr_set:
                for t in transitions:
                    if t['from'] == u and char_matches_label(ch, t['label'], tok_type):
                        move_set.add(t['to'])
            if not move_set:
                return (
                    "Reject",
                    f"Traza AFND: {' '.join(trace_sets)} --'{ch}'--> ∅ (Se detiene por conjunto vacío ∅ en pos {idx+1}; sin estado trampa)"
                )
            curr_set = lambda_closure(move_set)
            if len(input_str) <= 8 or idx < 3 or idx >= len(input_str) - 2:
                trace_sets.append(f"--'{ch}'--> {{" + ",".join(curr_set) + "}")
            elif idx == 3:
                trace_sets.append("--> ... ")

        accepted_finals = [s for s in curr_set if s in final_ids]
        if accepted_finals:
            return (
                "Accept",
                f"Traza AFND real: {' '.join(trace_sets)} (Alcanza {accepted_finals[0]} ∈ F')"
            )
        return (
            "Reject",
            f"Traza AFND real: {' '.join(trace_sets)} (Ningún estado activo pertenece a F')"
        )


def build_formal_quintuple_from_graph(states, transitions, sigma_desc, is_afnd=False):
    """
    M-06: Usa notación sin ambigüedad M = (Q, Σ, δ, q_ini, F) para AFD y
    M' = (Q', Σ, δ', q_ini, F') para AFND, donde el estado inicial siempre es q0.
    """
    q_list = [s['id'] for s in states]
    initial_list = [s['id'] for s in states if s.get('initial')]
    final_list = [s['id'] for s in states if s.get('final')]

    q_ini_str = initial_list[0] if initial_list else q_list[0]
    q_formatted = "{" + ", ".join(q_list) + "}"
    f_formatted = "{" + ", ".join(final_list) + "}"
    delta_str = "δ' : Q' × (Σ ∪ {λ}) → P(Q')" if is_afnd else "δ : Q × Σ → Q"

    return {
        "Q": q_formatted,
        "Sigma": sigma_desc,
        "delta": delta_str,
        "q_ini": q_ini_str,
        "F": f_formatted
    }


def build_jff_download_uri(states, transitions, tok_type="TOKEN"):
    """M-11: Construye el XML .jff nativo de JFLAP 7.1 expandiendo cada símbolo en 1 carácter."""
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


def render_transition_table_html(states, transitions, is_afnd=False, tok_type="TOKEN", alphabet_legend=""):
    state_ids = {s['id'] for s in states}
    valid_transitions = [t for t in transitions if t['from'] in state_ids and t['to'] in state_ids]

    symbols = []
    for t in valid_transitions:
        lbl = t['label']
        if lbl not in symbols:
            symbols.append(lbl)

    jff_uri = build_jff_download_uri(states, valid_transitions, tok_type=tok_type)
    tipo_str = "AFND (Construcción de Thompson)" if is_afnd else "AFD (Determinista Completo con qT)"
    short_type = "AFND" if is_afnd else "AFD"
    filename = f"{short_type}_{tok_type}.jff"
    conjunto_str = "Q'" if is_afnd else "Q"
    titulo_tabla = f"Tabla de Transición Formal {'δ\'' if is_afnd else 'δ'} — {tipo_str}"

    html_out = [
        '<div class="mt-3 rounded-lg border border-slate-300 bg-white shadow-sm overflow-hidden">',
        '  <div class="bg-slate-800 text-white px-3 py-2 text-xs font-bold flex flex-wrap items-center justify-between gap-2">',
        f'    <span>{escape_svg_text(titulo_tabla)}</span>',
        '    <div class="flex items-center gap-3">',
        '      <span class="text-[11px] font-normal text-slate-300">→ q_ini | * Estado Final</span>',
        f'      <a href="{jff_uri}" download="{filename}" '
        '         class="px-2.5 py-1 rounded bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-[11px] shadow transition">',
        f'        ⬇ Descargar {filename} (JFLAP 7.1)',
        '      </a>',
        '    </div>',
        '  </div>'
    ]

    if alphabet_legend:
        html_out.append(
            f'  <div class="bg-amber-50 px-3 py-1.5 border-b border-amber-200 text-[11px] font-mono text-slate-800">'
            f'    <span class="font-bold text-amber-900">Alfabeto Global Σ (ASCII imprimible) y Particiones: </span>{escape_svg_text(alphabet_legend)}'
            f'  </div>'
        )

    html_out.extend([
        '  <div class="overflow-x-auto max-h-64">',
        '    <table class="w-full text-xs text-left border-collapse">',
        '      <thead class="sticky top-0">',
        '        <tr class="bg-slate-100 border-b border-slate-300 text-slate-700">',
        f'          <th class="py-1.5 px-2.5 font-bold border-r border-slate-300">Estado ({conjunto_str})</th>'
    ])

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
    html_out.append('</div>')
    return '\n'.join(html_out)


def render_jflap_svg(states, transitions, width=860, height=270, is_afnd=False, tok_type="TOKEN", node_radius=17, alphabet_legend=""):
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
            cy = y + direction * (r + 32)
            ly = y + direction * (r + 29)
            svg.append(
                f'<path d="M {x-8},{sy} C {x-22},{cy} {x+22},{cy} {x+8},{sy}" '
                f'fill="none" stroke="{stroke_col}" stroke-width="1.4" marker-end="url(#jflap-arrow)"/>'
            )
            svg.append(
                f'<text x="{x}" y="{ly}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="9.5" font-weight="bold" fill="{stroke_col}">{lbl}</text>'
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
                mx, my = (sx + ex) / 2, (sy + ey) / 2 - 5
                svg.append(
                    f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" '
                    f'stroke="{stroke_col}" stroke-width="1.4" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{mx:.1f}" y="{my:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="9" font-weight="bold" fill="{stroke_col}">{lbl}</text>'
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
                ly = 0.25 * sy + 0.5 * cy + 0.25 * ey - (4 if curve >= 0 else -10)
                svg.append(
                    f'<path d="M {sx:.1f},{sy:.1f} Q {cx:.1f},{cy:.1f} {ex:.1f},{ey:.1f}" '
                    f'fill="none" stroke="{stroke_col}" stroke-width="1.3" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="9" font-weight="bold" fill="{stroke_col}">{lbl}</text>'
                )

    for s in states:
        x, y = s['x'], s['y']
        sid = escape_svg_text(s['id'])
        fill_color = "#ffe4e1" if s.get('trap') else "#ffff96"

        if s.get('initial'):
            svg.append(
                f'<polygon points="{x - r - 15},{y - 10} {x - r - 15},{y + 10} {x - r - 1},{y}" '
                f'fill="#ffffff" stroke="#111111" stroke-width="1.5"/>'
            )

        svg.append(
            f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill_color}" stroke="#111111" '
            f'stroke-width="1.5" filter="url(#jflap-shadow)"/>'
        )

        if s.get('final'):
            svg.append(
                f'<circle cx="{x}" cy="{y}" r="{r - 3.5}" fill="none" stroke="#111111" stroke-width="1.2"/>'
            )

        svg.append(
            f'<text x="{x}" y="{y + 3.5}" text-anchor="middle" font-family="Arial, sans-serif" '
            f'font-size="9.5" font-weight="bold" fill="#000000">{sid}</text>'
        )

        if s.get('note'):
            note_txt = escape_svg_text(s['note'])
            svg.append(
                f'<text x="{x}" y="{y + r + 10}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="8" fill="#475569">{note_txt}</text>'
            )

    svg.append('</svg>')
    svg.append(render_transition_table_html(states, transitions, is_afnd=is_afnd, tok_type=tok_type, alphabet_legend=alphabet_legend))
    return '\n'.join(svg)


def get_token_automata_spec(tok_type):
    """
    H-01, H-05, M-06, M-07, B-13:
    Define la especificación formal exacta (AFD, AFND de Thompson y correspondencia de subconjuntos)
    de cada tipo de token.
    """
    if tok_type == 'TIMESTAMP':
        # H-01: AFD con estados separados por decena para ser 100% equivalente a:
        # [0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]
        states_afd = [
            {'id': 'q0', 'x': 42, 'y': 65, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 112, 'y': 65, 'note': 'A1'},
            {'id': 'q2', 'x': 182, 'y': 65, 'note': 'A2'},
            {'id': 'q3', 'x': 252, 'y': 65, 'note': 'A3'},
            {'id': 'q4', 'x': 322, 'y': 65, 'note': 'A4'},
            {'id': 'q5', 'x': 392, 'y': 65, 'note': 'Guion1'},
            # Ramas de Mes: 0[1-9] (q6a) | 1[0-2] (q6b)
            {'id': 'q6a', 'x': 470, 'y': 30, 'note': 'Mes 0'},
            {'id': 'q6b', 'x': 470, 'y': 100, 'note': 'Mes 1'},
            {'id': 'q7', 'x': 550, 'y': 65, 'note': 'Mes OK'},
            {'id': 'q8', 'x': 625, 'y': 65, 'note': 'Guion2'},
            # Ramas de Día: 0[1-9] (q9a) | [12][0-9] (q9b) | 3[01] (q9c)
            {'id': 'q9a', 'x': 710, 'y': 22, 'note': 'Día 0'},
            {'id': 'q9b', 'x': 710, 'y': 65, 'note': 'Día 1..2'},
            {'id': 'q9c', 'x': 710, 'y': 110, 'note': 'Día 3'},
            {'id': 'q10', 'x': 800, 'y': 65, 'note': 'Día OK'},
            # Fila inferior: SEP_T y Hora ([01][0-9] en q12a | 2[0-3] en q12b), Minuto, Segundo
            {'id': 'q11', 'x': 75, 'y': 195, 'note': 'SEP_T'},
            {'id': 'q12a', 'x': 170, 'y': 160, 'note': 'Hora 0..1'},
            {'id': 'q12b', 'x': 170, 'y': 230, 'note': 'Hora 2'},
            {'id': 'q13', 'x': 265, 'y': 195, 'note': 'Hora OK'},
            {'id': 'q14', 'x': 350, 'y': 195, 'note': 'DosPts1'},
            {'id': 'q15', 'x': 435, 'y': 195, 'note': 'Min 0..5'},
            {'id': 'q16', 'x': 520, 'y': 195, 'note': 'Min OK'},
            {'id': 'q17', 'x': 605, 'y': 195, 'note': 'DosPts2'},
            {'id': 'q18', 'x': 690, 'y': 195, 'note': 'Seg 0..5'},
            {'id': 'q19', 'x': 785, 'y': 195, 'final': True, 'note': 'Acepta'},
            {'id': 'qT', 'x': 435, 'y': 265, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '0..9'},
            {'from': 'q1', 'to': 'q2', 'label': '0..9'},
            {'from': 'q2', 'to': 'q3', 'label': '0..9'},
            {'from': 'q3', 'to': 'q4', 'label': '0..9'},
            {'from': 'q4', 'to': 'q5', 'label': '-'},
            # Mes exacto 01..12
            {'from': 'q5', 'to': 'q6a', 'label': '0'},
            {'from': 'q5', 'to': 'q6b', 'label': '1'},
            {'from': 'q6a', 'to': 'q7', 'label': '1..9'},
            {'from': 'q6b', 'to': 'q7', 'label': '0..2'},
            {'from': 'q7', 'to': 'q8', 'label': '-'},
            # Día exacto 01..31
            {'from': 'q8', 'to': 'q9a', 'label': '0'},
            {'from': 'q8', 'to': 'q9b', 'label': '1..2'},
            {'from': 'q8', 'to': 'q9c', 'label': '3'},
            {'from': 'q9a', 'to': 'q10', 'label': '1..9'},
            {'from': 'q9b', 'to': 'q10', 'label': '0..9'},
            {'from': 'q9c', 'to': 'q10', 'label': '0..1'},
            # Separador T y Hora exacta 00..23
            {'from': 'q10', 'to': 'q11', 'label': 'T'},
            {'from': 'q11', 'to': 'q12a', 'label': '0..1'},
            {'from': 'q11', 'to': 'q12b', 'label': '2'},
            {'from': 'q12a', 'to': 'q13', 'label': '0..9'},
            {'from': 'q12b', 'to': 'q13', 'label': '0..3'},
            # Minutos 00..59 y Segundos 00..59
            {'from': 'q13', 'to': 'q14', 'label': ':'},
            {'from': 'q14', 'to': 'q15', 'label': '0..5'},
            {'from': 'q15', 'to': 'q16', 'label': '0..9'},
            {'from': 'q16', 'to': 'q17', 'label': ':'},
            {'from': 'q17', 'to': 'q18', 'label': '0..5'},
            {'from': 'q18', 'to': 'q19', 'label': '0..9'},
            # Transiciones explícitas al estado trampa qT
            {'from': 'q5', 'to': 'qT', 'label': "Σ ∖ {'0','1'}", 'curve': 12},
            {'from': 'q6a', 'to': 'qT', 'label': "Σ ∖ {'1'..'9'}", 'curve': 15},
            {'from': 'q6b', 'to': 'qT', 'label': "Σ ∖ {'0'..'2'}", 'curve': 10},
            {'from': 'q8', 'to': 'qT', 'label': "Σ ∖ {'0'..'3'}", 'curve': -12},
            {'from': 'q9a', 'to': 'qT', 'label': "Σ ∖ {'1'..'9'}", 'curve': -15},
            {'from': 'q9c', 'to': 'qT', 'label': "Σ ∖ {'0','1'}", 'curve': -10},
            {'from': 'q11', 'to': 'qT', 'label': "Σ ∖ {'0'..'2'}", 'curve': 12},
            {'from': 'q12b', 'to': 'qT', 'label': "Σ ∖ {'0'..'3'}", 'curve': 8},
            {'from': 'q14', 'to': 'qT', 'label': "Σ ∖ {'0'..'5'}", 'curve': 8},
            {'from': 'q17', 'to': 'qT', 'label': "Σ ∖ {'0'..'5'}", 'curve': -8},
            {'from': 'q19', 'to': 'qT', 'label': 'Σ_otros', 'curve': -12},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_otros', 'curve': -1}
        ]
        # AFND con unión λ de Thompson en las bifurcaciones de mes, día y hora (sin qT)
        states_afnd = [s for s in states_afd if not s.get('trap')]
        trans_afnd = [t for t in trans_afd if t['to'] != 'qT' and t['from'] != 'qT']
        sigma_afd = "Σ = {0..9, '-', 'T', ':'} ∪ Σ_otros"
        sigma_afnd = "Σ = {0..9, '-', 'T', ':'} (con transiciones λ)"
        legend = "Mes: 0[1-9] (q6a) | 1[0-2] (q6b) • Día: 0[1-9] (q9a) | [12][0-9] (q9b) | 3[01] (q9c) • Hora: [01][0-9] (q12a) | 2[0-3] (q12b) • Días por mes (30/31 y bisiestos) verificados en fase semántica."
        subset_info = "q5 ramifica en q6a ('0') y q6b ('1'); q8 ramifica en q9a ('0'), q9b ('1..2') y q9c ('3'); q11 ramifica en q12a ('0..1') y q12b ('2')."
        test_samples = ['2026-09-20T14:32:05', '2026-00-10T14:32:05', '2026-13-01T14:32:05', '2026-10-12T24:00:00']
        h_afd, h_afnd, rad = 295, 240, 14

    elif tok_type == 'IP':
        states_afd = [
            {'id': 'q0', 'x': 50, 'y': 55, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 145, 'y': 55, 'note': 'Oct1(1d)'},
            {'id': 'q2', 'x': 240, 'y': 55, 'note': 'Oct1(2d)'},
            {'id': 'q3', 'x': 335, 'y': 55, 'note': 'Oct1(3d)'},
            {'id': 'q4', 'x': 435, 'y': 55, 'note': 'Punto 1'},
            {'id': 'q5', 'x': 535, 'y': 55, 'note': 'Oct2(1d)'},
            {'id': 'q6', 'x': 635, 'y': 55, 'note': 'Oct2(2d)'},
            {'id': 'q7', 'x': 735, 'y': 55, 'note': 'Oct2(3d)'},
            {'id': 'q8', 'x': 50, 'y': 150, 'note': 'Punto 2'},
            {'id': 'q9', 'x': 150, 'y': 150, 'note': 'Oct3(1d)'},
            {'id': 'q10', 'x': 250, 'y': 150, 'note': 'Oct3(2d)'},
            {'id': 'q11', 'x': 350, 'y': 150, 'note': 'Oct3(3d)'},
            {'id': 'q12', 'x': 455, 'y': 150, 'note': 'Punto 3'},
            {'id': 'q13', 'x': 560, 'y': 150, 'final': True, 'note': 'Oct4(1d)'},
            {'id': 'q14', 'x': 665, 'y': 150, 'final': True, 'note': 'Oct4(2d)'},
            {'id': 'q15', 'x': 770, 'y': 150, 'final': True, 'note': 'Oct4(3d)'},
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
            {'from': 'q0', 'to': 'qT', 'label': 'Σ ∖ díg', 'curve': 18},
            {'from': 'q3', 'to': 'qT', 'label': '0..9', 'curve': 10},
            {'from': 'q4', 'to': 'qT', 'label': 'Σ ∖ díg'},
            {'from': 'q7', 'to': 'qT', 'label': '0..9', 'curve': -15},
            {'from': 'q8', 'to': 'qT', 'label': 'Σ ∖ díg', 'curve': 15},
            {'from': 'q11', 'to': 'qT', 'label': '0..9'},
            {'from': 'q12', 'to': 'qT', 'label': 'Σ ∖ díg'},
            {'from': 'q15', 'to': 'qT', 'label': 'Σ_otros', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_otros', 'curve': -1}
        ]
        states_afnd = [s for s in states_afd if not s.get('trap')]
        trans_afnd = [t for t in trans_afd if t['to'] != 'qT' and t['from'] != 'qT'] + [
            {'from': 'q1', 'to': 'q3', 'label': 'λ', 'curve': 20},
            {'from': 'q5', 'to': 'q7', 'label': 'λ', 'curve': 20},
            {'from': 'q9', 'to': 'q11', 'label': 'λ', 'curve': -20}
        ]
        sigma_afd = "Σ = {0..9, '.'} ∪ Σ_otros"
        sigma_afnd = "Σ = {0..9, '.'} (con saltos λ de longitud de octeto)"
        legend = "q13 acepta cuarto octeto de 1 dígito (p. ej. 10.0.0.5) | q14 acepta 2 dígitos (192.168.1.10) | q15 acepta 3 dígitos (255.255.255.255) | Rango 0..255 y prohibición de ceros iniciales (010) en fase semántica."
        subset_info = "λ-clausura(q1) = {q1, q3}, λ-clausura(q5) = {q5, q7}, λ-clausura(q9) = {q9, q11}, F = {q13, q14, q15}."
        test_samples = ['192.168.1.10', '10.0.0.5', '1.1.1', '192.168.1.1000']
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
            {'from': 'q21', 'to': 'qT', 'label': 'Σ_otros'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_otros', 'curve': -1}
        ]
        # M-06 y M-07: AFND de Thompson iniciando en q0 con bifurcación en las 4 ramas (sin qS ambiguo)
        states_afnd = [s for s in states_afd if not s.get('trap')]
        trans_afnd = [t for t in trans_afd if t['to'] != 'qT' and t['from'] != 'qT']
        sigma_afd = "Σ = {A, C, E, F, G, I, L, N, O, R, T, W} ∪ Σ_otros"
        sigma_afnd = "Σ = {A, C, E, F, G, I, L, N, O, R, T, W}"
        legend = "Rama 1: I-N-F-O (q0..q3->q21) | Rama 2: E-R-R-O-R (q0,q4..q7->q21) | Rama 3: W-A-R-N-I-N-G (q0,q8..q13->q21) | Rama 4: C-R-I-T-I-C-A-L (q0,q14..q20->q21)."
        subset_info = "Unión de 4 lenguajes finitos prefijo-disjuntos: cada estado del AFD corresponde a un subconjunto unitario {qi} del AFND."
        test_samples = ['ERROR', 'CRITICAL', 'WARNING', 'ERR']
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
            {'from': 'q0', 'to': 'qT', 'label': 'Σ ∖ A..Z', 'curve': 15},
            {'from': 'q2', 'to': 'qT', 'label': 'Σ ∖ A..Z', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_otros', 'curve': -1}
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
        sigma_afd = "Σ = {A..Z, '_'} ∪ Σ_otros"
        sigma_afnd = "Σ = {A..Z, '_'} (con clausura λ de Thompson)"
        legend = "A..Z = Letras mayúsculas ASCII | '_' = Separador de palabras | Σ ∖ A..Z = Complemento hacia qT | Pertenencia al catálogo SBS 504-2021 verificada en semántica."
        subset_info = "Construcción de Subconjuntos: q0_AFD = {q0}, q1_AFD = λ-clausura({q1, q3}) = {q0, q1, q3} ∈ F, q2_AFD = {q2}."
        test_samples = ['LOGIN_FAILED', 'PRIVILEGE_ESCALATION', '_LOGIN', 'LOGIN__']
        h_afd, h_afnd, rad = 245, 210, 18

    elif tok_type == 'STRING':
        states_afd = [
            {'id': 'q0', 'x': 95, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 310, 'y': 85, 'note': 'Cuerpo Cadena'},
            {'id': 'q2', 'x': 525, 'y': 40, 'note': 'Escape \\'},
            {'id': 'q3', 'x': 735, 'y': 85, 'final': True, 'note': 'Cierre "'},
            {'id': 'qT', 'x': 310, 'y': 195, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q1', 'label': 'Σ_base', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '\\', 'curve': 18},
            {'from': 'q2', 'to': 'q1', 'label': 'Σ_esc', 'curve': 18},
            {'from': 'q1', 'to': 'q3', 'label': '"'},
            {'from': 'q0', 'to': 'qT', 'label': 'Σ ∖ {"\\""}', 'curve': 15},
            {'from': 'q2', 'to': 'qT', 'label': 'Σ ∖ Σ_esc', 'curve': -15},
            {'from': 'q3', 'to': 'qT', 'label': 'Σ_otros', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_otros', 'curve': -1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 90, 'y': 110, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 250, 'y': 110, 'note': 'Abre "'},
            {'id': 'q2', 'x': 430, 'y': 110, 'note': 'Bucle λ'},
            {'id': 'q3', 'x': 580, 'y': 45, 'note': 'Escape \\'},
            {'id': 'q4', 'x': 740, 'y': 110, 'final': True, 'note': 'Cierra "'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q2', 'label': 'λ'},
            {'from': 'q2', 'to': 'q2', 'label': 'Σ_base', 'curve': 1},
            {'from': 'q2', 'to': 'q3', 'label': '\\', 'curve': 18},
            {'from': 'q3', 'to': 'q2', 'label': 'Σ_esc', 'curve': 18},
            {'from': 'q2', 'to': 'q4', 'label': '"'}
        ]
        sigma_afd = 'Σ = {"\\"", "\\\\", Σ_base, Σ_esc} ∪ Σ_otros'
        sigma_afnd = 'Σ = {"\\"", "\\\\", Σ_base, Σ_esc} (con transición λ)'
        legend = 'Σ_base = Imprimibles UTF-8/ASCII ∖ {"\\"", "\\\\"} | Σ_esc = {"\\"", "\\\\", "/", "b", "f", "n", "r", "t"} | Notación ∖ denota diferencia de conjuntos.'
        subset_info = "Construcción de Subconjuntos: q0_AFD = {q0}, q1_AFD = λ-clausura({q1}) = {q1, q2}, q2_AFD = {q3}, q3_AFD = {q4} ∈ F'."
        test_samples = ['"admin"', '"café"', '"usr\\"admin\\""', '"admin']
        h_afd, h_afnd, rad = 245, 210, 17

    elif tok_type == 'NUMBER':
        # H-05 y M-12: ER = 0 | [1-9][0-9]* -> El '0' va a q1 (final sin bucle de dígitos),
        # '1..9' va a q2 (final con bucle 0..9). Así '007' transita de q1 con '0' a qT (Reject).
        states_afd = [
            {'id': 'q0', 'x': 120, 'y': 95, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 360, 'y': 38, 'final': True, 'note': 'Cero Único'},
            {'id': 'q2', 'x': 360, 'y': 145, 'final': True, 'note': 'Entero 1..9'},
            {'id': 'qT', 'x': 650, 'y': 95, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '0', 'curve': 12},
            {'from': 'q0', 'to': 'q2', 'label': '1..9', 'curve': -12},
            {'from': 'q2', 'to': 'q2', 'label': '0..9', 'curve': -1},
            {'from': 'q1', 'to': 'qT', 'label': '0..9', 'curve': 12},
            {'from': 'q0', 'to': 'qT', 'label': 'Σ ∖ díg', 'curve': -42},
            {'from': 'q1', 'to': 'qT', 'label': 'Σ ∖ díg'},
            {'from': 'q2', 'to': 'qT', 'label': 'Σ ∖ díg'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_otros', 'curve': 1}
        ]
        # M-07: Construcción de Thompson genuina para 0 | [1-9][0-9]*
        states_afnd = [
            {'id': 'q0', 'x': 90, 'y': 105, 'initial': True, 'note': 'Unión λ'},
            {'id': 'q1', 'x': 270, 'y': 45, 'note': 'Rama 0'},
            {'id': 'q2', 'x': 270, 'y': 160, 'note': 'Rama 1..9'},
            {'id': 'q3', 'x': 480, 'y': 160, 'note': 'Clausura *'},
            {'id': 'q4', 'x': 700, 'y': 105, 'final': True, 'note': 'Acepta'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': 'λ', 'curve': 12},
            {'from': 'q0', 'to': 'q2', 'label': 'λ', 'curve': -12},
            {'from': 'q1', 'to': 'q4', 'label': '0', 'curve': 12},
            {'from': 'q2', 'to': 'q3', 'label': '1..9'},
            {'from': 'q3', 'to': 'q3', 'label': '0..9', 'curve': -1},
            {'from': 'q3', 'to': 'q4', 'label': 'λ', 'curve': -12}
        ]
        sigma_afd = "Σ = {'0', 1..9} ∪ Σ_otros"
        sigma_afnd = "Σ = {'0', 1..9} (Construcción de Thompson con λ)"
        legend = "ER = 0 | [1-9][0-9]* | El literal '0' transita a q1 ∈ F sin bucle (rechaza ceros a la izquierda como '007' hacia qT) | '1..9' transita a q2 ∈ F con bucle 0..9."
        subset_info = "Construcción de Subconjuntos: q0_AFD = λ-clausura(q0) = {q0, q1, q2}; con '0' alcanza q1_AFD = {q4} ∈ F; con '1..9' alcanza q2_AFD = {q3, q4} ∈ F."
        test_samples = ['3', '0', '2026', '007']
        h_afd, h_afnd, rad = 225, 220, 17

    else:
        sym = {'LBRACE': '{', 'RBRACE': '}', 'COLON': ':', 'COMMA': ','}.get(tok_type, '{')
        # M-07: Para un símbolo elemental 'a' de longitud 1, la Construcción Base de Thompson
        # tiene exactamente 2 estados (q0 --a--> q1) sin transiciones λ artificiales de relleno.
        states_afd = [
            {'id': 'q0', 'x': 150, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 430, 'y': 85, 'final': True, 'note': f'Acepta {sym}'},
            {'id': 'qT', 'x': 680, 'y': 85, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': sym},
            {'from': 'q0', 'to': 'qT', 'label': 'Σ_otros', 'curve': -32},
            {'from': 'q1', 'to': 'qT', 'label': 'Σ_otros'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ_otros', 'curve': 1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 220, 'y': 100, 'initial': True, 'note': 'Base Thompson'},
            {'id': 'q1', 'x': 580, 'y': 100, 'final': True, 'note': f'Acepta {sym}'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': sym}
        ]
        sigma_afd = f"Σ = {{'{sym}'}} ∪ Σ_otros"
        sigma_afnd = f"Σ = {{'{sym}'}} (Caso base elemental de Thompson)"
        legend = f"Caso Base de Thompson para símbolo literal único '{sym}': AFND de 2 estados {{q0, q1}}; al completarse a AFD total se incorpora el estado trampa qT para Σ ∖ {{'{sym}'}}."
        subset_info = f"Construcción de Subconjuntos: q0_AFD = {{q0}}, q1_AFD = {{q1}} ∈ F, y el subconjunto vacío ∅ en AFND se mapea al estado trampa qT en el AFD."
        test_samples = [sym, sym + sym, 'a']
        h_afd, h_afnd, rad = 205, 185, 18

    return states_afd, trans_afd, states_afnd, trans_afnd, sigma_afd, sigma_afnd, legend, subset_info, test_samples, h_afd, h_afnd, rad


def build_jflap_models_for_token(tok_type, lexeme=""):
    """
    H-02 y H-04: Construye los modelos formales y ejecuta el simulador real sobre 'lexeme'
    y sobre el banco de pruebas tanto en el AFD como en el AFND.
    """
    (
        states_afd, trans_afd, states_afnd, trans_afnd,
        sigma_afd, sigma_afnd, legend, subset_info,
        test_samples, h_afd, h_afnd, rad
    ) = get_token_automata_spec(tok_type)

    quintupla_afd = build_formal_quintuple_from_graph(states_afd, trans_afd, sigma_afd, is_afnd=False)
    quintupla_afnd = build_formal_quintuple_from_graph(states_afnd, trans_afnd, sigma_afnd, is_afnd=True)

    eval_inputs = []
    if lexeme and lexeme not in eval_inputs:
        eval_inputs.append(lexeme)
    for sample in test_samples:
        if sample not in eval_inputs:
            eval_inputs.append(sample)

    runs = []
    for inp in eval_inputs:
        res_afd, trace_afd = simulate_real_trace(states_afd, trans_afd, inp, tok_type=tok_type, is_afnd=False)
        res_afnd, trace_afnd = simulate_real_trace(states_afnd, trans_afnd, inp, tok_type=tok_type, is_afnd=True)
        runs.append((inp, res_afd, f"{trace_afd}  ||  {trace_afnd}"))

    afd_svg = render_jflap_svg(states_afd, trans_afd, height=h_afd, is_afnd=False, tok_type=tok_type, node_radius=rad, alphabet_legend=legend)
    afnd_svg = render_jflap_svg(states_afnd, trans_afnd, height=h_afnd, is_afnd=True, tok_type=tok_type, node_radius=rad, alphabet_legend=legend)

    return afd_svg, afnd_svg, runs, quintupla_afd, quintupla_afnd


def simulate_token_both_traces(tok_type, lexeme):
    """H-02: Devuelve la traza exacta en vivo del lexema actual sobre su AFD y AFND."""
    states_afd, trans_afd, states_afnd, trans_afnd, *_ = get_token_automata_spec(tok_type)
    _, trace_afd = simulate_real_trace(states_afd, trans_afd, lexeme, tok_type=tok_type, is_afnd=False)
    _, trace_afnd = simulate_real_trace(states_afnd, trans_afnd, lexeme, tok_type=tok_type, is_afnd=True)
    return f"{trace_afd} | {trace_afnd}"


def build_master_automata_catalog():
    """
    H-04: Genera por única vez el catálogo maestro con los 10 autómatas del lenguaje
    para eliminar la duplicación de SVGs y tablas en cada ocurrencia de token.
    """
    catalog = {}
    order = ['TIMESTAMP', 'IP', 'SEVERITY', 'EVENT_TYPE', 'STRING', 'NUMBER', 'LBRACE', 'RBRACE', 'COLON', 'COMMA']
    for tok_type in order:
        (
            states_afd, trans_afd, states_afnd, trans_afnd,
            sigma_afd, sigma_afnd, legend, subset_info,
            test_samples, h_afd, h_afnd, rad
        ) = get_token_automata_spec(tok_type)
        afd_svg, afnd_svg, runs, q_afd, q_afnd = build_jflap_models_for_token(tok_type, test_samples[0])
        catalog[tok_type] = {
            'type': tok_type,
            'quintupla_afd': q_afd,
            'quintupla_afnd': q_afnd,
            'jflap_afd_svg': afd_svg,
            'jflap_afnd_svg': afnd_svg,
            'jflap_runs': runs,
            'subset_info': subset_info
        }
    return catalog