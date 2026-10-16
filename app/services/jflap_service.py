import math
from app.utils.helpers import escape_svg_text

def render_jflap_svg(states, transitions, width=820, height=230):
    state_map = {s['id']: s for s in states}
    r = 25

    svg = [
        f'<svg viewBox="0 0 {width} {height}" class="w-full h-auto rounded-b-lg border border-slate-400 bg-[#fafafa] shadow-inner" xmlns="http://www.w3.org/2000/svg">',
        '<defs>',
        '  <marker id="jflap-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">',
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
            sy = y + direction * (r - 4)
            cy = y + direction * (r + 44)
            ly = y + direction * (r + 40)
            svg.append(
                f'<path d="M {x-11},{sy} C {x-28},{cy} {x+28},{cy} {x+11},{sy}" '
                f'fill="none" stroke="#111111" stroke-width="1.7" marker-end="url(#jflap-arrow)"/>'
            )
            svg.append(
                f'<text x="{x}" y="{ly}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="11.5" font-weight="bold" fill="#111111">{lbl}</text>'
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
                mx, my = (sx + ex) / 2, (sy + ey) / 2 - 8
                svg.append(
                    f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" '
                    f'stroke="#111111" stroke-width="1.7" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{mx:.1f}" y="{my:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="11.5" font-weight="bold" fill="#111111">{lbl}</text>'
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
                ly = 0.25 * sy + 0.5 * cy + 0.25 * ey - (6 if curve >= 0 else -14)
                svg.append(
                    f'<path d="M {sx:.1f},{sy:.1f} Q {cx:.1f},{cy:.1f} {ex:.1f},{ey:.1f}" '
                    f'fill="none" stroke="#111111" stroke-width="1.7" marker-end="url(#jflap-arrow)"/>'
                )
                svg.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-family="Arial, sans-serif" '
                    f'font-size="11.5" font-weight="bold" fill="#111111">{lbl}</text>'
                )

    for s in states:
        x, y = s['x'], s['y']
        sid = escape_svg_text(s['id'])
        fill_color = "#ffe4e1" if s.get('trap') else "#ffff96"

        if s.get('initial'):
            svg.append(
                f'<polygon points="{x - r - 24},{y - 16} {x - r - 24},{y + 16} {x - r - 1},{y}" '
                f'fill="#ffffff" stroke="#111111" stroke-width="1.7"/>'
            )

        svg.append(
            f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill_color}" stroke="#111111" '
            f'stroke-width="1.8" filter="url(#jflap-shadow)"/>'
        )

        if s.get('final'):
            svg.append(
                f'<circle cx="{x}" cy="{y}" r="{r - 5}" fill="none" stroke="#111111" stroke-width="1.5"/>'
            )

        svg.append(
            f'<text x="{x}" y="{y + 4}" text-anchor="middle" font-family="Arial, sans-serif" '
            f'font-size="13" font-weight="bold" fill="#000000">{sid}</text>'
        )

        if s.get('note'):
            note_txt = escape_svg_text(s['note'])
            svg.append(
                f'<text x="{x}" y="{y + r + 15}" text-anchor="middle" font-family="Arial, sans-serif" '
                f'font-size="10" fill="#475569">{note_txt}</text>'
            )

    svg.append('</svg>')
    return '\n'.join(svg)


def build_jflap_models_for_token(tok_type, lexeme=""):
    if tok_type == 'TIMESTAMP':
        states_afd = [
            {'id': 'q0', 'x': 75, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q4', 'x': 195, 'y': 85, 'note': 'AAAA'},
            {'id': 'q5', 'x': 305, 'y': 85, 'note': '-'},
            {'id': 'q7', 'x': 415, 'y': 85, 'note': 'MM'},
            {'id': 'q10', 'x': 535, 'y': 85, 'note': '-DD'},
            {'id': 'q11', 'x': 645, 'y': 85, 'note': 'T'},
            {'id': 'q19', 'x': 765, 'y': 85, 'final': True, 'note': 'HH:MM:SS'},
            {'id': 'qT', 'x': 415, 'y': 185, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q4', 'label': '[0-9]{4}'},
            {'from': 'q4', 'to': 'q5', 'label': '-'},
            {'from': 'q5', 'to': 'q7', 'label': '[0-9]{2}'},
            {'from': 'q7', 'to': 'q10', 'label': '-[0-9]{2}'},
            {'from': 'q10', 'to': 'q11', 'label': 'T'},
            {'from': 'q11', 'to': 'q19', 'label': '[0-9]{2}:[0-9]{2}:[0-9]{2}'},
            {'from': 'q0', 'to': 'qT', 'label': 'otro', 'curve': 20},
            {'from': 'q4', 'to': 'qT', 'label': 'otro', 'curve': 15},
            {'from': 'q10', 'to': 'qT', 'label': 'otro', 'curve': -15},
            {'from': 'q19', 'to': 'qT', 'label': '0-9, otro', 'curve': -20},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ', 'curve': -1}
        ]
        states_afnd = [dict(s, y=110) for s in states_afd if not s.get('trap')]
        trans_afnd = [t for t in trans_afd if t['to'] != 'qT']
        runs = [
            (lexeme or '2026-09-20T14:32:05', 'Accept', 'Cumple patrón ISO-8601 exacto (q19 ∈ F)'),
            ('2026/09/20 14:32:05', 'Reject', 'Usa barras / en lugar de guiones'),
            ('2026-09-20', 'Reject', 'Incompleto (no llega a q19)')
        ]
    elif tok_type == 'IP':
        states_afd = [
            {'id': 'q0', 'x': 80, 'y': 85, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 210, 'y': 85, 'note': 'Octeto 1'},
            {'id': 'q2', 'x': 340, 'y': 85, 'note': 'Punto 1'},
            {'id': 'q3', 'x': 480, 'y': 85, 'note': 'Octetos 2-3'},
            {'id': 'q4', 'x': 620, 'y': 85, 'note': 'Punto 3'},
            {'id': 'q5', 'x': 750, 'y': 85, 'final': True, 'note': 'Octeto 4'},
            {'id': 'qT', 'x': 415, 'y': 185, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '0-9 (1..3)'},
            {'from': 'q1', 'to': 'q2', 'label': '.'},
            {'from': 'q2', 'to': 'q3', 'label': '0-9 (1..3)'},
            {'from': 'q3', 'to': 'q4', 'label': '. [0-9]{1..3} .'},
            {'from': 'q4', 'to': 'q5', 'label': '0-9 (1..3)'},
            {'from': 'q0', 'to': 'qT', 'label': '.', 'curve': 20},
            {'from': 'q1', 'to': 'qT', 'label': '>3 díg', 'curve': 10},
            {'from': 'q5', 'to': 'qT', 'label': '.', 'curve': -20},
            {'from': 'qT', 'to': 'qT', 'label': '0-9, .', 'curve': -1}
        ]
        states_afnd = [dict(s, y=110) for s in states_afd if not s.get('trap')]
        trans_afnd = [t for t in trans_afd if t['to'] != 'qT']
        runs = [
            (lexeme or '192.168.1.10', 'Accept', '4 octetos separados por 3 puntos (q5 ∈ F)'),
            ('10.0.0.5', 'Accept', 'Octetos cortos válidos'),
            ('192.168.1', 'Reject', 'Solo 3 octetos (incompleto)'),
            ('.192.168.1.1', 'Reject', 'Inicia con punto (va a qT / ∅)')
        ]
    elif tok_type == 'SEVERITY':
        states_afd = [
            {'id': 'q0', 'x': 85, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'qI', 'x': 260, 'y': 40, 'note': 'Leyó I'},
            {'id': 'qW', 'x': 260, 'y': 95, 'note': 'Leyó W'},
            {'id': 'qE', 'x': 260, 'y': 150, 'note': 'Leyó E'},
            {'id': 'qC', 'x': 260, 'y': 205, 'note': 'Leyó C'},
            {'id': 'qF', 'x': 520, 'y': 115, 'final': True, 'note': 'Aceptación'},
            {'id': 'qT', 'x': 710, 'y': 115, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'qI', 'label': 'I'},
            {'from': 'q0', 'to': 'qW', 'label': 'W'},
            {'from': 'q0', 'to': 'qE', 'label': 'E'},
            {'from': 'q0', 'to': 'qC', 'label': 'C'},
            {'from': 'qI', 'to': 'qF', 'label': 'NFO'},
            {'from': 'qW', 'to': 'qF', 'label': 'ARNING'},
            {'from': 'qE', 'to': 'qF', 'label': 'RROR'},
            {'from': 'qC', 'to': 'qF', 'label': 'RITICAL'},
            {'from': 'qF', 'to': 'qT', 'label': 'A-Z'},
            {'from': 'qT', 'to': 'qT', 'label': 'A-Z', 'curve': 1}
        ]
        states_afnd = [s for s in states_afd if not s.get('trap')]
        trans_afnd = [
            {'from': 'q0', 'to': 'qI', 'label': 'λ / I'},
            {'from': 'q0', 'to': 'qW', 'label': 'λ / W'},
            {'from': 'q0', 'to': 'qE', 'label': 'λ / E'},
            {'from': 'q0', 'to': 'qC', 'label': 'λ / C'},
            {'from': 'qI', 'to': 'qF', 'label': 'NFO'},
            {'from': 'qW', 'to': 'qF', 'label': 'ARNING'},
            {'from': 'qE', 'to': 'qF', 'label': 'RROR'},
            {'from': 'qC', 'to': 'qF', 'label': 'RITICAL'}
        ]
        runs = [
            (lexeme or 'ERROR', 'Accept', 'Reconoce palabra reservada de severidad (qF ∈ F)'),
            ('CRITICAL', 'Accept', 'Rama C -> RITICAL aceptada'),
            ('ERR', 'Reject', 'Prefijo incompleto'),
            ('DEBUG', 'Reject', 'No pertenece al conjunto de severidades SOC')
        ]
    elif tok_type == 'EVENT_TYPE':
        states_afd = [
            {'id': 'q0', 'x': 110, 'y': 95, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 330, 'y': 95, 'final': True, 'note': 'Letra Mayús.'},
            {'id': 'q2', 'x': 560, 'y': 95, 'note': 'Guion bajo (_)'},
            {'id': 'qT', 'x': 330, 'y': 190, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': 'A-Z'},
            {'from': 'q1', 'to': 'q1', 'label': 'A-Z', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '_', 'curve': 28},
            {'from': 'q2', 'to': 'q1', 'label': 'A-Z', 'curve': 28},
            {'from': 'q0', 'to': 'qT', 'label': '_ , 0-9', 'curve': 18},
            {'from': 'q2', 'to': 'qT', 'label': '_ (doble)', 'curve': -18},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ', 'curve': -1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 140, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 390, 'y': 115, 'final': True, 'note': 'Aceptación'},
            {'id': 'q2', 'x': 640, 'y': 115, 'note': 'Separador _'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': 'A-Z'},
            {'from': 'q1', 'to': 'q1', 'label': 'A-Z', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '_', 'curve': 28},
            {'from': 'q2', 'to': 'q1', 'label': 'A-Z', 'curve': 28}
        ]
        runs = [
            (lexeme or 'LOGIN_FAILED', 'Accept', 'Mayúsculas separadas por _ terminando en q1 ∈ F'),
            ('UNAUTHORIZED_ACCESS', 'Accept', 'Cumple patrón [A-Z]+(_[A-Z]+)*'),
            ('_LOGIN', 'Reject', 'Inicia con guion bajo (va a qT / ∅)'),
            ('LOGIN_', 'Reject', 'Termina en q2 (no es estado final)')
        ]
    elif tok_type == 'STRING':
        states_afd = [
            {'id': 'q0', 'x': 110, 'y': 95, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 330, 'y': 95, 'note': 'Dentro de " "'},
            {'id': 'q2', 'x': 560, 'y': 95, 'final': True, 'note': 'Cierre "'},
            {'id': 'qT', 'x': 330, 'y': 190, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q1', 'label': 'ASCII ≠ "', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '"'},
            {'from': 'q0', 'to': 'qT', 'label': '≠ "', 'curve': 15},
            {'from': 'q2', 'to': 'qT', 'label': 'Σ', 'curve': -15},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ', 'curve': -1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 150, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 400, 'y': 115, 'note': 'Cuerpo String'},
            {'id': 'q2', 'x': 650, 'y': 115, 'final': True, 'note': 'Aceptación'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': '"'},
            {'from': 'q1', 'to': 'q1', 'label': 'ASCII ≠ "', 'curve': 1},
            {'from': 'q1', 'to': 'q2', 'label': '"'}
        ]
        runs = [
            (lexeme or '"admin"', 'Accept', 'Inicia y cierra con comillas dobles (q2 ∈ F)'),
            ('""', 'Accept', 'Cadena vacía entre comillas válida'),
            ('"admin', 'Reject', 'Falta comilla de cierre (queda en q1 ∉ F)')
        ]
    elif tok_type == 'NUMBER':
        states_afd = [
            {'id': 'q0', 'x': 150, 'y': 95, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 420, 'y': 95, 'final': True, 'note': 'Dígitos 0-9'},
            {'id': 'qT', 'x': 660, 'y': 95, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': '0-9'},
            {'from': 'q1', 'to': 'q1', 'label': '0-9', 'curve': 1},
            {'from': 'q0', 'to': 'qT', 'label': 'a-z, otro', 'curve': -35},
            {'from': 'q1', 'to': 'qT', 'label': 'a-z, otro'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ', 'curve': 1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 220, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 540, 'y': 115, 'final': True, 'note': 'Aceptación'}
        ]
        trans_afnd = [
            {'from': 'q0', 'to': 'q1', 'label': '0-9'},
            {'from': 'q1', 'to': 'q1', 'label': '0-9', 'curve': 1}
        ]
        runs = [
            (lexeme or '3', 'Accept', 'Uno o más dígitos numéricos (q1 ∈ F)'),
            ('2026', 'Accept', 'Secuencia continua 0-9 en bucle q1'),
            ('3a', 'Reject', 'Contiene letra (cae en qT / ∅)')
        ]
    else:
        sym = lexeme or {'LBRACE': '{', 'RBRACE': '}', 'COLON': ':', 'COMMA': ','}.get(tok_type, '{')
        states_afd = [
            {'id': 'q0', 'x': 150, 'y': 95, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 420, 'y': 95, 'final': True, 'note': f'Leyó {sym}'},
            {'id': 'qT', 'x': 660, 'y': 95, 'trap': True, 'note': 'Estado Trampa'}
        ]
        trans_afd = [
            {'from': 'q0', 'to': 'q1', 'label': sym},
            {'from': 'q0', 'to': 'qT', 'label': f'≠ {sym}', 'curve': -35},
            {'from': 'q1', 'to': 'qT', 'label': 'Σ'},
            {'from': 'qT', 'to': 'qT', 'label': 'Σ', 'curve': 1}
        ]
        states_afnd = [
            {'id': 'q0', 'x': 220, 'y': 115, 'initial': True, 'note': 'Inicio'},
            {'id': 'q1', 'x': 540, 'y': 115, 'final': True, 'note': 'Aceptación'}
        ]
        trans_afnd = [{'from': 'q0', 'to': 'q1', 'label': sym}]
        runs = [
            (sym, 'Accept', f'Reconoce delimitador exacto {sym!r} (q1 ∈ F)'),
            (sym + sym, 'Reject', 'Longitud excedida (va a qT / ∅)')
        ]

    return (
        render_jflap_svg(states_afd, trans_afd, height=235),
        render_jflap_svg(states_afnd, trans_afnd, height=225),
        runs
    )