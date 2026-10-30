import os
import math
import base64
from collections import deque
from app.utils.helpers import escape_svg_text
from app.services.automata_engine import (
    SIGMA_ASCII,
    TOKEN_FORMAL_REGEX_AST_SPECS,
    FormalAutomatonModel,
    expand_atomic_label,
    build_thompson_afnd,
    subset_construction_afnd_to_afd,
    simulate_afd_structured,
    simulate_afnd_structured
)


def expand_symbol_for_jff(label, tok_type="TOKEN"):
    return expand_atomic_label(label)


def char_matches_label(ch, label, tok_type="TOKEN"):
    if label in ('λ', 'ε', ''):
        return False
    return ch in expand_atomic_label(label)


def assign_topological_coordinates(states, transitions, width=940, is_afnd=False):
    """
    Fase 4 (Mejoras visuales):
    Distribuye los estados activos en niveles topológicos despejados y separa el
    estado trampa qT en una banda inferior dedicada ('Zona de Rechazo qT') con
    curvaturas diferenciadas para evitar cruces sobre los estados principales.
    """
    non_trap = [s for s in states if not s.get('trap')]
    trap_states = [s for s in states if s.get('trap')]
    if not non_trap:
        return states, 240

    init_id = [s['id'] for s in non_trap if s.get('initial')][0]
    levels = {init_id: 0}
    queue = deque([init_id])
    while queue:
        u = queue.popleft()
        for t in transitions:
            v = t['to']
            if t['from'] == u and v != 'qT' and v not in levels:
                levels[v] = levels[u] + 1
                queue.append(v)

    for s in non_trap:
        if s['id'] not in levels:
            levels[s['id']] = 0

    max_lvl = max(levels.values()) if levels else 1
    wrap_threshold = 10

    if max_lvl <= wrap_threshold:
        by_lvl = {}
        for s in non_trap:
            by_lvl.setdefault(levels[s['id']], []).append(s)
        x_step = max(68, min(155, int((width - 120) / max(1, max_lvl))))
        max_rows = max(len(v) for v in by_lvl.values())
        height = max(240, max_rows * 76 + (95 if trap_states else 35))

        for lvl, group in by_lvl.items():
            k = len(group)
            for idx, st in enumerate(group):
                st['x'] = 60 + lvl * x_step
                if k == 1:
                    st['y'] = 82 if trap_states else 110
                else:
                    span = min(height - 120, (k - 1) * 62)
                    st['y'] = 44 + idx * (span / max(1, k - 1))
    else:
        half = (max_lvl + 1) // 2
        by_lvl = {}
        for s in non_trap:
            by_lvl.setdefault(levels[s['id']], []).append(s)
        height = 340 if trap_states else 270
        for lvl, group in by_lvl.items():
            band = 0 if lvl < half else 1
            col = lvl if band == 0 else (lvl - half)
            cols_in_band = half if band == 0 else (max_lvl - half + 1)
            x_step = max(58, int((width - 110) / max(1, cols_in_band)))
            base_y = 65 if band == 0 else 175
            k = len(group)
            for idx, st in enumerate(group):
                st['x'] = 55 + col * x_step
                if k == 1:
                    st['y'] = base_y
                else:
                    offset = (idx - (k - 1) / 2.0) * 42
                    st['y'] = base_y + offset

    # Separar el estado trampa qT en la zona inferior dedicada y curvar sus aristas
    for tr in trap_states:
        tr['x'] = width // 2
        tr['y'] = height - 36

    for idx, t in enumerate(transitions):
        if t['to'] == 'qT' and t['from'] != 'qT':
            t['curve'] = 18 if (idx % 2 == 0) else -18
        elif t['from'] != t['to'] and abs(levels.get(t['to'], 0) - levels.get(t['from'], 0)) > 1:
            if 'curve' not in t:
                t['curve'] = -24

    return states, height


def simulate_real_trace(states, transitions, input_str, tok_type="TOKEN", is_afnd=False):
    if is_afnd:
        res = simulate_afnd_structured(states, transitions, input_str)
    else:
        res = simulate_afd_structured(states, transitions, input_str)
    return {
        'accepted': res['accepted'],
        'result': res['result'],
        'trace': res['summary_text'],
        'structured': res
    }


def build_formal_quintuple_from_graph(states, transitions, sigma_desc, is_afnd=False):
    model = FormalAutomatonModel("TOKEN", is_afnd, states, transitions, sigma_desc)
    return model.quintuple


def export_lightweight_dfa_jff_xml(tok_type):
    """
    Sección 3: Función reutilizable para exportar el AFD ligero (sin estado trampa qT
    ni transiciones de rechazo masivas) para cualquiera de las 10 categorías léxicas.
    """
    afd_model, _, _ = get_formal_automaton_pair(tok_type)
    return afd_model.to_lightweight_jff_xml()


def export_jff_xml_string(states, transitions, tok_type="TOKEN", is_afnd=False, include_trap=False):
    """
    Genera el XML .jff desde el modelo formal unificado.
    Por defecto (include_trap=False) exporta el AFD ligero para JFLAP 7.1 (sin qT).
    """
    sigma_desc = "Σ_ASCII ∪ {ε}" if is_afnd else "Σ_ASCII (códigos 33..126)"
    model = FormalAutomatonModel(tok_type, is_afnd, states, transitions, sigma_desc)
    return model.to_jff_xml(include_trap=include_trap)


def build_jff_download_uri(states, transitions, tok_type="TOKEN", is_afnd=False, include_trap=False):
    raw_xml = export_jff_xml_string(
        states, transitions, tok_type=tok_type, is_afnd=is_afnd, include_trap=include_trap
    ).encode('utf-8')
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

    # El botón de descarga entrega el AFD ligero (include_trap=False) para compatibilidad con JFLAP 7.1,
    # mientras que la tabla formal HTML muestra el AFD completo interno con su estado trampa qT.
    jff_uri = build_jff_download_uri(
        states, valid_transitions, tok_type=tok_type, is_afnd=is_afnd, include_trap=False
    )
    tipo_str = "AFND (Construcción de Thompson)" if is_afnd else "AFD Completo Interno (Subconjuntos con qT)"
    short_type = "AFND" if is_afnd else "AFD"
    filename = f"{short_type}_{tok_type}.jff"
    btn_label = f"⬇ Descargar {filename} (JFLAP 7.1)" if is_afnd else f"⬇ Descargar {filename} (JFLAP 7.1 Ligero sin qT)"
    conjunto_str = "Q'" if is_afnd else "Q"
    titulo_tabla = f"Tabla de Transición Formal {'δ\'' if is_afnd else 'δ'} — {tipo_str}"

    html_out = [
        '<div class="mt-3 rounded-lg border border-slate-300 bg-white shadow-sm overflow-hidden">',
        '  <div class="bg-slate-800 text-white px-3 py-2 text-xs font-bold flex flex-wrap items-center justify-between gap-2">',
        f'    <span>{escape_svg_text(titulo_tabla)}</span>',
        '    <div class="flex flex-wrap items-center gap-2">',
        '      <span class="text-[11px] font-normal text-slate-300">→ q_ini | * Estado Final</span>',
        f'      <a href="{jff_uri}" download="{filename}" '
        '         class="px-2.5 py-1 rounded bg-amber-400 hover:bg-amber-300 text-slate-950 font-bold text-[11px] shadow transition">',
        f'        {escape_svg_text(btn_label)}',
        '      </a>',
        '    </div>',
        '  </div>'
    ]

    if alphabet_legend:
        html_out.append(
            f'  <div class="bg-amber-50 px-3 py-1.5 border-b border-amber-200 text-[11px] font-mono text-slate-800">'
            f'    <span class="font-bold text-amber-900">Especificación Formal: </span>{escape_svg_text(alphabet_legend)}'
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

        html_out.append(f'        <tr class="{row_bg} hover:bg-slate-50" data-state-row="{escape_svg_text(sid)}">')
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


def render_jflap_svg(states, transitions, width=940, height=270, is_afnd=False, tok_type="TOKEN", node_radius=17, alphabet_legend=""):
    state_map = {s['id']: s for s in states}
    r = node_radius
    has_trap = any(s.get('trap') for s in states)

    svg = [
        f'<svg viewBox="0 0 {width} {height}" class="jflap-diagram-svg w-full h-auto rounded-b-lg border border-slate-400 bg-[#fafafa] shadow-inner transition-transform duration-150" xmlns="http://www.w3.org/2000/svg">',
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

    if has_trap:
        sep_y = height - 68
        svg.append(
            f'<line x1="20" y1="{sep_y}" x2="{width - 20}" y2="{sep_y}" '
            f'stroke="#fda4af" stroke-width="1" stroke-dasharray="6,4" data-trap-element="true"/>'
        )
        svg.append(
            f'<text x="{width - 28}" y="{sep_y + 14}" text-anchor="end" font-family="Arial, sans-serif" '
            f'font-size="8.5" font-weight="bold" fill="#be123c" data-trap-element="true">'
            f'Zona de Rechazo Léxico (Estado Trampa qT ∉ F)</text>'
        )

    for t in transitions:
        if t['from'] not in state_map or t['to'] not in state_map:
            continue
        u = state_map[t['from']]
        v = state_map[t['to']]
        u_id_esc = escape_svg_text(t['from'])
        v_id_esc = escape_svg_text(t['to'])
        lbl = escape_svg_text(t['label'])
        display_lbl = lbl
        if t['to'] == 'qT' and t['from'] != 'qT' and len(t['label']) > 12:
            display_lbl = escape_svg_text("Σ ∖ válidos")

        curve = t.get('curve', 0)
        is_eps = t['label'] in ('ε', 'λ', '')
        is_trap_edge = (t['to'] == 'qT' or t['from'] == 'qT')
        stroke_col = "#b91c1c" if is_trap_edge else ("#6d28d9" if is_eps else "#111111")
        stroke_opacity = ' stroke-opacity="0.45"' if (is_trap_edge and t['from'] != 'qT') else ''
        trap_attr = ' data-trap-element="true"' if is_trap_edge else ''

        edge_attrs = (
            f'class="jflap-edge" data-edge-from="{u_id_esc}" '
            f'data-edge-to="{v_id_esc}" data-edge-label="{lbl}" '
            f'data-default-stroke="{stroke_col}"{stroke_opacity}{trap_attr}'
        )
        text_attrs = (
            f'class="jflap-edge-label" data-edge-from="{u_id_esc}" '
            f'data-edge-to="{v_id_esc}" data-edge-label="{lbl}" '
            f'data-default-fill="{stroke_col}"{trap_attr}'
        )

        if t['from'] == t['to']:
            direction = -1 if curve >= 0 else 1
            x, y = u['x'], u['y']
            sy = y + direction * (r - 3)
            cy = y + direction * (r + 32)
            ly = y + direction * (r + 29)
            svg.append(
                f'<path d="M {x-8},{sy} C {x-22},{cy} {x+22},{cy} {x+8},{sy}" '
                f'{edge_attrs} fill="none" stroke="{stroke_col}" stroke-width="1.4" marker-end="url(#jflap-arrow)"/>'
            )
            svg.append(
                f'<text x="{x}" y="{ly}" {text_attrs} text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="9.5" font-weight="bold" fill="{stroke_col}">{display_lbl}</text>'
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
                    f'{edge_attrs} stroke="{stroke_col}" stroke-width="1.4" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{mx:.1f}" y="{my:.1f}" {text_attrs} text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="8.5" font-weight="bold" fill="{stroke_col}">{display_lbl}</text>'
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
                    f'{edge_attrs} fill="none" stroke="{stroke_col}" stroke-width="1.2" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" {text_attrs} text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="8" font-weight="bold" fill="{stroke_col}">{display_lbl}</text>'
                )

    for s in states:
        x, y = s['x'], s['y']
        sid = escape_svg_text(s['id'])
        is_trap_node = bool(s.get('trap'))
        trap_node_attr = ' data-trap-element="true"' if is_trap_node else ''
        fill_color = "#ffe4e1" if is_trap_node else "#ffff96"

        if s.get('initial'):
            svg.append(
                f'<polygon points="{x - r - 15},{y - 10} {x - r - 15},{y + 10} {x - r - 1},{y}" '
                f'fill="#ffffff" stroke="#111111" stroke-width="1.5"/>'
            )

        svg.append(
            f'<circle cx="{x}" cy="{y}" r="{r}" class="jflap-state-node" data-state-node="{sid}" '
            f'data-default-fill="{fill_color}"{trap_node_attr} fill="{fill_color}" stroke="#111111" '
            f'stroke-width="1.5" filter="url(#jflap-shadow)"/>'
        )

        if s.get('final') and not is_trap_node:
            svg.append(
                f'<circle cx="{x}" cy="{y}" r="{r - 3.5}" fill="none" stroke="#111111" stroke-width="1.2" pointer-events="none"/>'
            )

        svg.append(
            f'<text x="{x}" y="{y + 3.5}"{trap_node_attr} text-anchor="middle" font-family="Arial, sans-serif" '
            f'font-size="9.5" font-weight="bold" fill="#000000" pointer-events="none">{sid}</text>'
        )

        if s.get('note'):
            note_txt = escape_svg_text(s['note'])
            svg.append(
                f'<text x="{x}" y="{y + r + 10}"{trap_node_attr} text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="8" fill="#475569" pointer-events="none">{note_txt}</text>'
            )

    svg.append('</svg>')
    svg.append(render_transition_table_html(states, transitions, is_afnd=is_afnd, tok_type=tok_type, alphabet_legend=alphabet_legend))
    return '\n'.join(svg)


_COMPILED_SPECS_CACHE = {}
_FORMAL_MODELS_CACHE = {}


def get_formal_automaton_pair(tok_type):
    if tok_type in _FORMAL_MODELS_CACHE:
        return _FORMAL_MODELS_CACHE[tok_type]

    (
        states_afd, trans_afd, states_afnd, trans_afnd,
        sigma_afd, sigma_afnd, legend, subset_info,
        test_samples, h_afd, h_afnd, rad
    ) = get_token_automata_spec(tok_type)

    afd_model = FormalAutomatonModel(
        tok_type=tok_type,
        is_afnd=False,
        states=states_afd,
        grouped_transitions=trans_afd,
        sigma_desc=sigma_afd,
        height=h_afd,
        node_radius=rad
    )
    afnd_model = FormalAutomatonModel(
        tok_type=tok_type,
        is_afnd=True,
        states=states_afnd,
        grouped_transitions=trans_afnd,
        sigma_desc=sigma_afnd,
        height=h_afnd,
        node_radius=rad
    )
    meta = {
        'legend': legend,
        'subset_info': subset_info,
        'test_samples': test_samples
    }
    _FORMAL_MODELS_CACHE[tok_type] = (afd_model, afnd_model, meta)
    return afd_model, afnd_model, meta


def get_token_automata_spec(tok_type):
    if tok_type in _COMPILED_SPECS_CACHE:
        return _COMPILED_SPECS_CACHE[tok_type]

    regex_expr = TOKEN_FORMAL_REGEX_AST_SPECS.get(tok_type, "\\{")
    states_afnd, trans_afnd = build_thompson_afnd(tok_type, regex_expr)
    states_afd, trans_afd, subset_mapping = subset_construction_afnd_to_afd(
        states_afnd, trans_afnd, tok_type=tok_type, include_trap=True
    )

    states_afnd, h_afnd = assign_topological_coordinates(states_afnd, trans_afnd, is_afnd=True)
    states_afd, h_afd = assign_topological_coordinates(states_afd, trans_afd, is_afnd=False)

    has_eps = any(t['label'] in ('ε', 'λ', '') for t in trans_afnd)
    sigma_afd = "Σ_ASCII (códigos 33..126)"
    sigma_afnd = "Σ_ASCII ∪ {ε}" if has_eps else "Σ_ASCII (Caso Base Thompson)"

    legend = (
        f"ER Formal = {regex_expr} | "
        f"AFND Thompson: {len(states_afnd)} estados, {sum(1 for t in trans_afnd if t['label'] == 'ε')} transiciones ε | "
        f"AFD Interno Completo: {len(states_afd) - 1} estados activos + qT (JFF Ligero exportado: {len(states_afd) - 1} estados sin qT)."
    )
    subset_info = " ; ".join(subset_mapping[:8]) + (" ..." if len(subset_mapping) > 8 else "")

    sample_map = {
        'TIMESTAMP': ['2026-10-17T08:43:29', '2027-02-29T12:35:42', '2026-13-17T08:43:29', '2026-10-28T07:15:30Z'],
        'IP': ['192.168.1.10', '192.168.001.10', '192.168.256.10', '192.168.1', '192.168.1.10.5'],
        'SEVERITY': ['ERROR', 'INFO', 'CRITICAL', 'ERR'],
        'EVENT_TYPE': ['LOGIN_FAILED', 'PRIVILEGE_ESCALATION', '_LOGIN', 'LOGIN__'],
        'STRING': ['"security_admin"', '"usr\\"admin"', '"admin', '"中文"'],
        'NUMBER': ['5', '0', '2026', '007'],
        'LBRACE': ['{', '{{', 'a'],
        'RBRACE': ['}', '}}', 'a'],
        'COLON': [':', '::', 'a'],
        'COMMA': [',', ',,', 'a'],
    }
    test_samples = sample_map.get(tok_type, ['{', '{{'])
    rad = 14 if len(states_afd) > 16 else 17

    spec_tuple = (
        states_afd, trans_afd, states_afnd, trans_afnd,
        sigma_afd, sigma_afnd, legend, subset_info,
        test_samples, h_afd, h_afnd, rad
    )
    _COMPILED_SPECS_CACHE[tok_type] = spec_tuple
    return spec_tuple


def build_jflap_models_for_token(tok_type, lexeme=""):
    afd_model, afnd_model, meta = get_formal_automaton_pair(tok_type)

    eval_inputs = []
    if lexeme and lexeme not in eval_inputs:
        eval_inputs.append(lexeme)
    for sample in meta['test_samples']:
        if sample not in eval_inputs:
            eval_inputs.append(sample)

    runs = []
    for inp in eval_inputs:
        sim_afd = afd_model.simulate(inp)
        sim_afnd = afnd_model.simulate(inp)
        runs.append((inp, sim_afd['result'], f"{sim_afd['summary_text']}  ||  {sim_afnd['summary_text']}"))

    afd_svg = render_jflap_svg(
        afd_model.states, afd_model.grouped_transitions,
        height=afd_model.height, is_afnd=False, tok_type=tok_type,
        node_radius=afd_model.node_radius, alphabet_legend=meta['legend']
    )
    afnd_svg = render_jflap_svg(
        afnd_model.states, afnd_model.grouped_transitions,
        height=afnd_model.height, is_afnd=True, tok_type=tok_type,
        node_radius=afnd_model.node_radius, alphabet_legend=meta['legend']
    )

    return afd_svg, afnd_svg, runs, afd_model.quintuple, afnd_model.quintuple


def simulate_token_both_traces(tok_type, lexeme):
    afd_model, afnd_model, _ = get_formal_automaton_pair(tok_type)
    sim_afd = afd_model.simulate(lexeme)
    sim_afnd = afnd_model.simulate(lexeme)
    return {
        'afd_accepted': sim_afd['accepted'],
        'afnd_accepted': sim_afnd['accepted'],
        'afd_trace': sim_afd['summary_text'],
        'afnd_trace': sim_afnd['summary_text'],
        'afd_structured': sim_afd,
        'afnd_structured': sim_afnd,
        'combined_trace': f"{sim_afd['summary_text']} | {sim_afnd['summary_text']}"
    }


def build_dynamic_lexeme_simulation_payload(
    tok_type,
    lexeme,
    line_number=1,
    column=1,
    token_index=1,
    sem_ok=True,
    sem_msg="",
    valid_lexical_line=True,
    target_category_override=None
):
    if target_category_override and target_category_override in TOKEN_FORMAL_REGEX_AST_SPECS:
        target_category = target_category_override
    else:
        target_category = tok_type if tok_type in TOKEN_FORMAL_REGEX_AST_SPECS else 'EVENT_TYPE'

    afd_model, afnd_model, _ = get_formal_automaton_pair(target_category)

    sim_afd = afd_model.simulate(lexeme)
    sim_afnd = afnd_model.simulate(lexeme)

    lexical_accepted = bool(sim_afd['accepted'] and sim_afnd['accepted'] and tok_type != 'ERROR_LEXICO')
    semantic_accepted = bool(sem_ok and lexical_accepted)

    if not lexical_accepted:
        overall_badge = "RECHAZO LÉXICO (AFD → qT / AFND → ∅)"
    elif not semantic_accepted:
        overall_badge = f"FORMATO LÉXICO ACEPTADO ({sim_afd['final_states'][0]} ∈ F), PERO RECHAZADO SEMÁNTICAMENTE"
    elif not valid_lexical_line:
        overall_badge = "TOKEN VÁLIDO EN LÍNEA INVALIDADA POR OTRO ERROR"
    else:
        overall_badge = "ACEPTADO LÉXICA Y SEMÁNTICAMENTE"

    return {
        "token_uid": f"L{line_number}_T{token_index}",
        "line": line_number,
        "column": column,
        "token_index": token_index,
        "token_type": tok_type,
        "automaton_category": target_category,
        "lexeme": lexeme,
        "lexical_accepted": lexical_accepted,
        "semantic_accepted": semantic_accepted,
        "semantic_message": sem_msg,
        "overall_badge": overall_badge,
        "afd": {
            "accepted": sim_afd['accepted'],
            "result": sim_afd['result'],
            "initial_state": sim_afd['initial_state'],
            "final_states_defined": sim_afd['final_states_defined'],
            "final_states_reached": sim_afd['final_states'],
            "error_position": sim_afd['error_position'],
            "error_symbol": sim_afd.get('error_symbol'),
            "error_reason": sim_afd['error_reason'],
            "summary_text": sim_afd['summary_text'],
            "steps": sim_afd['navigation_steps'],
            "trace": sim_afd['trace']
        },
        "afnd": {
            "accepted": sim_afnd['accepted'],
            "result": sim_afnd['result'],
            "initial_state": sim_afnd['initial_state'],
            "final_states_defined": sim_afnd['final_states_defined'],
            "final_states_reached": sim_afnd['final_states'],
            "error_position": sim_afnd['error_position'],
            "error_symbol": sim_afnd.get('error_symbol'),
            "error_reason": sim_afnd['error_reason'],
            "summary_text": sim_afnd['summary_text'],
            "steps": sim_afnd['navigation_steps'],
            "trace": sim_afnd['trace']
        }
    }


def save_jff_files_for_token(tok_type, output_dir="app/storage/jff"):
    """
    Secciones 1, 2 y 3:
    Exporta el AFD ligero para JFLAP 7.1 (AFD_<tok_type>.jff, sin qT) y el AFND de Thompson
    (AFND_<tok_type>.jff) reutilizando export_lightweight_dfa_jff_xml().
    """
    os.makedirs(output_dir, exist_ok=True)
    _, afnd_model, _ = get_formal_automaton_pair(tok_type)
    xml_afd_light = export_lightweight_dfa_jff_xml(tok_type)
    xml_afnd = afnd_model.to_jff_xml()

    path_afd = os.path.join(output_dir, f"AFD_{tok_type}.jff")
    path_afnd = os.path.join(output_dir, f"AFND_{tok_type}.jff")
    with open(path_afd, "w", encoding="utf-8") as f1:
        f1.write(xml_afd_light)
    with open(path_afnd, "w", encoding="utf-8") as f2:
        f2.write(xml_afnd)

    # Limpiar archivos antiguos *_diagnostico_sin_trampa.jff si existieran para mantener exactamente 20 archivos
    old_diag = os.path.join(output_dir, f"AFD_{tok_type}_diagnostico_sin_trampa.jff")
    if os.path.exists(old_diag):
        try:
            os.remove(old_diag)
        except OSError:
            pass

    return path_afd, path_afnd, xml_afd_light, xml_afnd


def regenerate_all_ten_jff_pairs(output_dir="app/storage/jff"):
    """
    Regenera los 20 archivos .jff funcionales (10 AFD ligeros + 10 AFND de Thompson)
    en el directorio especificado.
    """
    _COMPILED_SPECS_CACHE.clear()
    _FORMAL_MODELS_CACHE.clear()
    os.makedirs(output_dir, exist_ok=True)
    generated = {}
    for tok_type in TOKEN_FORMAL_REGEX_AST_SPECS:
        path_afd, path_afnd, _, _ = save_jff_files_for_token(tok_type, output_dir=output_dir)
        generated[tok_type] = (path_afd, path_afnd)
    return generated


def build_master_automata_catalog():
    """
    Construye el catálogo maestro conservando el AFD completo interno en la aplicación
    y sincronizando los 20 archivos .jff (10 AFD ligeros + 10 AFND) en app/storage/jff/.
    """
    catalog = {}
    order = ['TIMESTAMP', 'IP', 'SEVERITY', 'EVENT_TYPE', 'STRING', 'NUMBER', 'LBRACE', 'RBRACE', 'COLON', 'COMMA']
    for tok_type in order:
        afd_model, afnd_model, meta = get_formal_automaton_pair(tok_type)
        afd_svg, afnd_svg, demo_runs, q_afd, q_afnd = build_jflap_models_for_token(tok_type, meta['test_samples'][0])
        save_jff_files_for_token(tok_type, output_dir="app/storage/jff")
        catalog[tok_type] = {
            'type': tok_type,
            'quintupla_afd': q_afd,
            'quintupla_afnd': q_afnd,
            'jflap_afd_svg': afd_svg,
            'jflap_afnd_svg': afnd_svg,
            'jflap_runs': demo_runs,
            'demo_runs': demo_runs,
            'subset_info': meta['subset_info'],
            'legend': meta['legend'],
            'afd_states': afd_model.states,
            'afd_transitions': afd_model.grouped_transitions,
            'afnd_states': afnd_model.states,
            'afnd_transitions': afnd_model.grouped_transitions
        }
    return catalog