import xml.etree.ElementTree as ET
from collections import deque
from app.utils.helpers import escape_svg_text

# Alfabeto formal de tokens para JFLAP 7.1: caracteres ASCII gráficos visibles (códigos 33..126, 94 símbolos).
# Se excluye chr(32) (' ') porque es el delimitador léxico entre tokens y porque DOMPrettier de JFLAP 7.1
# aplica String.trim() a los nodos de texto XML, convirtiendo <read> </read> en <read/> (transición λ).
SIGMA_ASCII = [chr(c) for c in range(33, 127)]
ASCII_DIGITS = [chr(c) for c in range(ord('0'), ord('9') + 1)]
ASCII_UPPERS = [chr(c) for c in range(ord('A'), ord('Z') + 1)]
ASCII_STRING_BASE = [c for c in SIGMA_ASCII if c not in ('"', '\\')]
ASCII_STRING_ESC = ['"', '\\', '/', 'b', 'f', 'n', 'r', 't']

SYMBOL_CLASS_MAP = {
    '0..9': ASCII_DIGITS,
    '1..9': [str(d) for d in range(1, 10)],
    '0..1': ['0', '1'],
    '0..2': ['0', '1', '2'],
    '1..2': ['1', '2'],
    '0..3': ['0', '1', '2', '3'],
    '0..5': [str(d) for d in range(6)],
    'A..Z': ASCII_UPPERS,
    'Σ_base': ASCII_STRING_BASE,
    'Σ_esc': ASCII_STRING_ESC,
}

_REGISTERED_COMPLEMENT_SETS = {}


def expand_atomic_label(label):
    """Expande una etiqueta simbólica en su lista exacta de caracteres ASCII gráficos individuales."""
    if label in ('ε', 'λ', ''):
        return ['']
    if label in SYMBOL_CLASS_MAP:
        return list(SYMBOL_CLASS_MAP[label])
    if label == 'Σ':
        return list(SIGMA_ASCII)
    if label in _REGISTERED_COMPLEMENT_SETS:
        excl = _REGISTERED_COMPLEMENT_SETS[label]
        return [c for c in SIGMA_ASCII if c not in excl]
    if label.startswith('Σ ∖ '):
        rest = label[4:].strip()
        if rest == 'díg':
            excl = set(ASCII_DIGITS)
        elif rest == 'A..Z':
            excl = set(ASCII_UPPERS)
        elif rest == 'Σ_esc':
            excl = set(ASCII_STRING_ESC)
        elif rest == "(díg ∪ {'.'})":
            excl = set(ASCII_DIGITS + ['.'])
        elif rest == "(A..Z ∪ {'_'})":
            excl = set(ASCII_UPPERS + ['_'])
        elif rest in ('{"\\""}', "{'\"'}", '{"}'):
            excl = {'"'}
        elif rest in ("{','}", "{,}"):
            excl = {','}
        elif rest.startswith('{') and rest.endswith('}'):
            inner = rest[1:-1].strip()
            if '..' in inner and ',' not in inner:
                parts = inner.replace("'", "").split('..')
                excl = {chr(c) for c in range(ord(parts[0]), ord(parts[1]) + 1)}
            else:
                excl = set()
                i = 0
                while i < len(inner):
                    if inner[i] == "'" and i + 2 < len(inner) and inner[i + 2] == "'":
                        excl.add(inner[i + 1])
                        i += 3
                    else:
                        i += 1
        else:
            excl = set()
        return [c for c in SIGMA_ASCII if c not in excl]
    return [label]


def build_complement_label(outgoing_chars):
    """Construye la etiqueta formal del complemento Σ_ASCII ∖ outgoing_chars hacia qT."""
    excl_frozen = frozenset(outgoing_chars)
    if len(excl_frozen) >= len(SIGMA_ASCII):
        return None
    if not excl_frozen:
        return 'Σ'
    if excl_frozen == frozenset(ASCII_DIGITS):
        lbl = 'Σ ∖ díg'
    elif excl_frozen == frozenset(ASCII_UPPERS):
        lbl = 'Σ ∖ A..Z'
    elif excl_frozen == frozenset(ASCII_UPPERS + ['_']):
        lbl = "Σ ∖ (A..Z ∪ {'_'})"
    elif excl_frozen == frozenset(ASCII_DIGITS + ['.']):
        lbl = "Σ ∖ (díg ∪ {'.'})"
    elif excl_frozen == frozenset(ASCII_STRING_ESC):
        lbl = 'Σ ∖ Σ_esc'
    elif excl_frozen == frozenset({'0', '1'}):
        lbl = "Σ ∖ {'0','1'}"
    elif excl_frozen == frozenset({'0', '1', '2'}):
        lbl = "Σ ∖ {'0'..'2'}"
    elif excl_frozen == frozenset({'0', '1', '2', '3'}):
        lbl = "Σ ∖ {'0'..'3'}"
    elif excl_frozen == frozenset(str(d) for d in range(6)):
        lbl = "Σ ∖ {'0'..'5'}"
    elif excl_frozen == frozenset(str(d) for d in range(1, 10)):
        lbl = "Σ ∖ {'1'..'9'}"
    elif len(excl_frozen) == 1:
        only_ch = next(iter(excl_frozen))
        if only_ch == '"':
            lbl = 'Σ ∖ {"\\""}'
        elif only_ch == ',':
            lbl = "Σ ∖ {','}"
        else:
            lbl = f"Σ ∖ {{'{only_ch}'}}"
    else:
        sorted_items = ", ".join(f"'{c}'" for c in sorted(excl_frozen))
        lbl = f"Σ ∖ {{{sorted_items}}}"

    _REGISTERED_COMPLEMENT_SETS[lbl] = excl_frozen
    return lbl


# ==============================================================================
# 1. PARSER DE EXPRESIONES REGULARES PARA CONSTRUCCIÓN DE THOMPSON
# ==============================================================================

TOKEN_FORMAL_REGEX_AST_SPECS = {
    'TIMESTAMP': (
        "[0..9][0..9][0..9][0..9]-"
        "(0[1..9]|1[0..2])-"
        "(0[1..9]|[1..2][0..9]|3[0..1])T"
        "([0..1][0..9]|2[0..3]):"
        "[0..5][0..9]:[0..5][0..9]"
    ),
    'IP': (
        "[0..9]([0..9]([0..9])?)?\\."
        "[0..9]([0..9]([0..9])?)?\\."
        "[0..9]([0..9]([0..9])?)?\\."
        "[0..9]([0..9]([0..9])?)?"
    ),
    'SEVERITY': "INFO|WARNING|ERROR|CRITICAL",
    'EVENT_TYPE': "[A..Z]+(_[A..Z]+)*",
    'STRING': '"([Σ_base]|\\\\[Σ_esc])*"',
    'NUMBER': "0|[1..9][0..9]*",
    'LBRACE': "\\{",
    'RBRACE': "\\}",
    'COLON': ":",
    'COMMA': ","
}


def tokenize_formal_regex(regex_str):
    raw_tokens = []
    i = 0
    n = len(regex_str)
    while i < n:
        ch = regex_str[i]
        if ch == '\\':
            i += 1
            raw_tokens.append(('SYM', regex_str[i]))
            i += 1
        elif ch == '[':
            end = regex_str.index(']', i)
            cls_name = regex_str[i + 1:end]
            raw_tokens.append(('SYM', cls_name))
            i = end + 1
        elif ch == '(':
            raw_tokens.append(('LPAREN', '('))
            i += 1
        elif ch == ')':
            raw_tokens.append(('RPAREN', ')'))
            i += 1
        elif ch == '|':
            raw_tokens.append(('UNION', '|'))
            i += 1
        elif ch == '*':
            raw_tokens.append(('STAR', '*'))
            i += 1
        elif ch == '+':
            raw_tokens.append(('PLUS', '+'))
            i += 1
        elif ch == '?':
            raw_tokens.append(('OPT', '?'))
            i += 1
        else:
            raw_tokens.append(('SYM', ch))
            i += 1

    out = []
    for idx, tok in enumerate(raw_tokens):
        out.append(tok)
        if idx + 1 < len(raw_tokens):
            t1 = tok[0]
            t2 = raw_tokens[idx + 1][0]
            if t1 in ('SYM', 'RPAREN', 'STAR', 'PLUS', 'OPT') and t2 in ('SYM', 'LPAREN'):
                out.append(('CONCAT', '.'))
    return out


def regex_to_postfix(regex_str):
    prec = {'STAR': 4, 'PLUS': 4, 'OPT': 4, 'CONCAT': 3, 'UNION': 2}
    tokens = tokenize_formal_regex(regex_str)
    output = []
    op_stack = []

    for ttype, tval in tokens:
        if ttype == 'SYM':
            output.append((ttype, tval))
        elif ttype in ('STAR', 'PLUS', 'OPT'):
            output.append((ttype, tval))
        elif ttype == 'LPAREN':
            op_stack.append((ttype, tval))
        elif ttype == 'RPAREN':
            while op_stack and op_stack[-1][0] != 'LPAREN':
                output.append(op_stack.pop())
            if op_stack and op_stack[-1][0] == 'LPAREN':
                op_stack.pop()
        elif ttype in ('CONCAT', 'UNION'):
            while (
                op_stack and op_stack[-1][0] != 'LPAREN'
                and prec.get(op_stack[-1][0], 0) >= prec[ttype]
            ):
                output.append(op_stack.pop())
            op_stack.append((ttype, tval))

    while op_stack:
        output.append(op_stack.pop())

    return output


# ==============================================================================
# 2. CONSTRUCCIÓN AUTÉNTICA DE THOMPSON (ER -> AFND-ε)
# ==============================================================================

def build_thompson_afnd(tok_type, regex_str=None):
    if regex_str is None:
        regex_str = TOKEN_FORMAL_REGEX_AST_SPECS[tok_type]

    postfix = regex_to_postfix(regex_str)
    next_id = [0]
    transitions = []

    def new_state():
        sid = next_id[0]
        next_id[0] += 1
        return sid

    def replace_state_id(old_id, target_id):
        for t in transitions:
            if t['from'] == old_id:
                t['from'] = target_id
            if t['to'] == old_id:
                t['to'] = target_id

    stack = []
    for ttype, tval in postfix:
        if ttype == 'SYM':
            s = new_state()
            f = new_state()
            transitions.append({'from': s, 'to': f, 'label': tval})
            stack.append((s, f))

        elif ttype == 'CONCAT':
            s2, f2 = stack.pop()
            s1, f1 = stack.pop()
            replace_state_id(s2, f1)
            stack.append((s1, f2))

        elif ttype == 'UNION':
            s2, f2 = stack.pop()
            s1, f1 = stack.pop()
            s = new_state()
            f = new_state()
            transitions.append({'from': s, 'to': s1, 'label': 'ε'})
            transitions.append({'from': s, 'to': s2, 'label': 'ε'})
            transitions.append({'from': f1, 'to': f, 'label': 'ε'})
            transitions.append({'from': f2, 'to': f, 'label': 'ε'})
            stack.append((s, f))

        elif ttype == 'STAR':
            s1, f1 = stack.pop()
            s = new_state()
            f = new_state()
            transitions.append({'from': s, 'to': s1, 'label': 'ε'})
            transitions.append({'from': s, 'to': f, 'label': 'ε'})
            transitions.append({'from': f1, 'to': s1, 'label': 'ε'})
            transitions.append({'from': f1, 'to': f, 'label': 'ε'})
            stack.append((s, f))

        elif ttype == 'PLUS':
            s1, f1 = stack.pop()
            s = new_state()
            f = new_state()
            transitions.append({'from': s, 'to': s1, 'label': 'ε'})
            transitions.append({'from': f1, 'to': s1, 'label': 'ε'})
            transitions.append({'from': f1, 'to': f, 'label': 'ε'})
            stack.append((s, f))

        elif ttype == 'OPT':
            s1, f1 = stack.pop()
            s = new_state()
            f = new_state()
            transitions.append({'from': s, 'to': s1, 'label': 'ε'})
            transitions.append({'from': s, 'to': f, 'label': 'ε'})
            transitions.append({'from': f1, 'to': f, 'label': 'ε'})
            stack.append((s, f))

    start_raw, accept_raw = stack.pop()

    visited_order = []
    queue = deque([start_raw])
    seen = {start_raw}
    while queue:
        u = queue.popleft()
        visited_order.append(u)
        for t in transitions:
            if t['from'] == u and t['to'] not in seen:
                seen.add(t['to'])
                queue.append(t['to'])

    if accept_raw not in seen:
        visited_order.append(accept_raw)

    id_map = {old: f"q{idx}" for idx, old in enumerate(visited_order)}

    states_afnd = []
    for old in visited_order:
        sname = id_map[old]
        states_afnd.append({
            'id': sname,
            'initial': (old == start_raw),
            'final': (old == accept_raw),
            'note': 'Inicio' if old == start_raw else ('Acepta' if old == accept_raw else '')
        })

    trans_afnd = [
        {'from': id_map[t['from']], 'to': id_map[t['to']], 'label': t['label']}
        for t in transitions
    ]

    return states_afnd, trans_afnd


# ==============================================================================
# 3. EPSILON-CLAUSURA, MOVE(S, a) Y CONSTRUCCIÓN POR SUBCONJUNTOS (AFND -> AFD)
# ==============================================================================

def compute_epsilon_closure(state_set, transitions):
    stack = list(state_set)
    closure = set(state_set)
    while stack:
        u = stack.pop()
        for t in transitions:
            if t['from'] == u and t['label'] in ('ε', 'λ', '') and t['to'] not in closure:
                closure.add(t['to'])
                stack.append(t['to'])
    return frozenset(closure)


def move_afnd(state_set, char_symbol, transitions):
    reached = set()
    for u in state_set:
        for t in transitions:
            if t['from'] == u:
                lbl = t['label']
                if lbl not in ('ε', 'λ', ''):
                    if char_symbol in expand_atomic_label(lbl) or (lbl == 'Σ_base' and char_symbol == ' '):
                        reached.add(t['to'])
    return frozenset(reached)


def _sort_nfa_state_names(state_iterable):
    return sorted(state_iterable, key=lambda s: int(s[1:]) if s[1:].isdigit() else s)


def subset_construction_afnd_to_afd(states_afnd, trans_afnd, tok_type="TOKEN", include_trap=True):
    initial_nfa = [s['id'] for s in states_afnd if s.get('initial')][0]
    final_nfa_set = {s['id'] for s in states_afnd if s.get('final')}

    raw_labels = []
    for t in trans_afnd:
        if t['label'] not in ('ε', 'λ', '') and t['label'] not in raw_labels:
            raw_labels.append(t['label'])

    relevant_chars = []
    for lbl in raw_labels:
        for c in expand_atomic_label(lbl):
            if c not in relevant_chars:
                relevant_chars.append(c)

    d0 = compute_epsilon_closure({initial_nfa}, trans_afnd)
    subset_to_id = {d0: 'q0'}
    id_to_subset = {'q0': d0}
    queue = deque([d0])
    dfa_char_transitions = {}

    while queue:
        curr_set = queue.popleft()
        u_id = subset_to_id[curr_set]

        for ch in relevant_chars:
            mv = move_afnd(curr_set, ch, trans_afnd)
            if not mv:
                continue
            target_set = compute_epsilon_closure(mv, trans_afnd)
            if target_set not in subset_to_id:
                new_id = f"q{len(subset_to_id)}"
                subset_to_id[target_set] = new_id
                id_to_subset[new_id] = target_set
                queue.append(target_set)
            v_id = subset_to_id[target_set]
            dfa_char_transitions[(u_id, ch)] = v_id

    states_afd = []
    for dfa_id, nfa_subset in id_to_subset.items():
        sorted_sub = _sort_nfa_state_names(nfa_subset)
        subset_str = "{" + ",".join(sorted_sub) + "}"
        is_init = (dfa_id == 'q0')
        is_fin = bool(nfa_subset & final_nfa_set)
        states_afd.append({
            'id': dfa_id,
            'initial': is_init,
            'final': is_fin,
            'nfa_subset': sorted_sub,
            'nfa_subset_str': subset_str,
            'note': f"={subset_str}"
        })

    grouped_pairs = {}
    for (u_id, ch), v_id in dfa_char_transitions.items():
        grouped_pairs.setdefault((u_id, v_id), set()).add(ch)

    def compress_char_set_to_label(char_set):
        for lbl_name, lbl_chars in [
            ('0..9', set(ASCII_DIGITS)),
            ('1..9', {str(d) for d in range(1, 10)}),
            ('0..1', {'0', '1'}),
            ('0..2', {'0', '1', '2'}),
            ('1..2', {'1', '2'}),
            ('0..3', {'0', '1', '2', '3'}),
            ('0..5', {str(d) for d in range(6)}),
            ('A..Z', set(ASCII_UPPERS)),
            ('Σ_base', set(ASCII_STRING_BASE)),
            ('Σ_esc', set(ASCII_STRING_ESC)),
        ]:
            if char_set == lbl_chars:
                return [lbl_name]
        if len(char_set) == 1:
            return [next(iter(char_set))]
        return sorted(char_set)

    trans_afd = []
    for (u_id, v_id), ch_set in grouped_pairs.items():
        for lbl in compress_char_set_to_label(ch_set):
            trans_afd.append({'from': u_id, 'to': v_id, 'label': lbl})

    if include_trap:
        states_afd.append({
            'id': 'qT',
            'initial': False,
            'final': False,
            'trap': True,
            'nfa_subset': [],
            'nfa_subset_str': '∅',
            'note': '=∅ (Trampa)'
        })
        for s in states_afd:
            if s.get('trap'):
                continue
            uid = s['id']
            outgoing_chars = {ch for (u, ch) in dfa_char_transitions if u == uid}
            comp_label = build_complement_label(outgoing_chars)
            if comp_label:
                trans_afd.append({'from': uid, 'to': 'qT', 'label': comp_label})

        trans_afd.append({'from': 'qT', 'to': 'qT', 'label': 'Σ'})

    subset_mapping = [
        f"{s['id']} = ε-clausura → {s['nfa_subset_str']}"
        for s in states_afd if not s.get('trap')
    ]

    return states_afd, trans_afd, subset_mapping


# ==============================================================================
# 4. SIMULADOR FORMAL ESTRUCTURADO CON PASOS DE NAVEGACIÓN
# ==============================================================================

def _compute_epsilon_closure_with_edges(state_set, transitions):
    stack = list(state_set)
    closure = set(state_set)
    eps_edges = []
    seen_edges = set()

    while stack:
        u = stack.pop()
        for t in transitions:
            if t['from'] == u and t['label'] in ('ε', 'λ', ''):
                v = t['to']
                edge_key = (u, v, t['label'])
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    eps_edges.append({'from': u, 'to': v, 'label': 'ε'})
                if v not in closure:
                    closure.add(v)
                    stack.append(v)

    return frozenset(closure), eps_edges


def simulate_afd_structured(states_afd, trans_afd, input_str):
    initial_id = [s['id'] for s in states_afd if s.get('initial')][0]
    final_ids = {s['id'] for s in states_afd if s.get('final')}

    curr = initial_id
    trace_steps = []
    compact_steps = [curr]

    navigation_steps = [{
        "step": 0,
        "position": 0,
        "symbol": None,
        "consumed_input": "",
        "remaining_input": input_str if input_str else "ε",
        "from_state": None,
        "active_state": initial_id,
        "transition_used": None,
        "rule": f"Configuración inicial: ({initial_id}, {input_str if input_str else 'ε'})",
        "is_initial": True,
        "is_final": (initial_id in final_ids),
        "is_trap": False,
        "status": "INICIO"
    }]

    for idx, ch in enumerate(input_str):
        pos = idx + 1
        consumed = input_str[:pos]
        remaining = input_str[pos:] if pos < len(input_str) else "ε"

        # Permitir espacio ASCII 32 únicamente dentro de Σ_base en literales STRING en memoria
        is_string_space = (
            ch == ' ' and any(
                t['from'] == curr and t['label'] == 'Σ_base' for t in trans_afd
            )
        )

        if ch not in SIGMA_ASCII and not is_string_space:
            reason = f"Posición {pos}: Símbolo {ch!r} (U+{ord(ch):04X}) ∉ Σ_ASCII."
            navigation_steps.append({
                "step": pos,
                "position": pos,
                "symbol": ch,
                "consumed_input": consumed,
                "remaining_input": remaining,
                "from_state": curr,
                "active_state": "qT",
                "transition_used": {"from": curr, "to": "qT", "label": "∉ Σ_ASCII"},
                "rule": f"Rechazo léxico: {ch!r} ∉ Σ_ASCII → qT",
                "is_initial": False,
                "is_final": False,
                "is_trap": True,
                "status": "RECHAZO_ALFABETO"
            })
            return {
                "accepted": False,
                "result": "Reject",
                "initial_state": initial_id,
                "final_states_defined": sorted(final_ids),
                "trace": trace_steps,
                "navigation_steps": navigation_steps,
                "final_states": ['qT'],
                "error_position": pos,
                "error_symbol": ch,
                "error_reason": reason,
                "summary_text": f"Traza AFD (Reject): {' '.join(compact_steps)} --'{ch}'--> qT ({reason})"
            }

        next_st = None
        matched_lbl = None
        for t in trans_afd:
            if t['from'] == curr and t['to'] != 'qT':
                if ch in expand_atomic_label(t['label']) or (is_string_space and t['label'] == 'Σ_base'):
                    next_st = t['to']
                    matched_lbl = t['label']
                    break

        if next_st is None:
            trap_lbl = "Σ ∖ válidos"
            for t in trans_afd:
                if t['from'] == curr and t['to'] == 'qT' and ch in expand_atomic_label(t['label']):
                    trap_lbl = t['label']
                    break

            step_dict = {
                "step": pos,
                "from": curr,
                "symbol": ch,
                "to": "qT",
                "label": trap_lbl,
                "position": pos,
                "consumed_input": consumed,
                "remaining_input": remaining,
                "rule": f"δ({curr}, {ch!r}) = qT"
            }
            trace_steps.append(step_dict)
            navigation_steps.append({
                "step": pos,
                "position": pos,
                "symbol": ch,
                "consumed_input": consumed,
                "remaining_input": remaining,
                "from_state": curr,
                "active_state": "qT",
                "transition_used": {"from": curr, "to": "qT", "label": trap_lbl},
                "rule": f"δ({curr}, {ch!r}) = qT (por {trap_lbl})",
                "is_initial": False,
                "is_final": False,
                "is_trap": True,
                "status": "ESTADO_TRAMPA"
            })
            compact_steps.append(f"--'{ch}'--> qT")
            reason = f"En pos {pos} desde {curr} lee {ch!r} y transita al estado trampa qT ∉ F"
            return {
                "accepted": False,
                "result": "Reject",
                "initial_state": initial_id,
                "final_states_defined": sorted(final_ids),
                "trace": trace_steps,
                "navigation_steps": navigation_steps,
                "final_states": ["qT"],
                "error_position": pos,
                "error_symbol": ch,
                "error_reason": reason,
                "summary_text": f"Traza AFD (Reject): {' '.join(compact_steps)} ({reason})"
            }

        step_dict = {
            "step": pos,
            "from": curr,
            "symbol": ch,
            "to": next_st,
            "label": matched_lbl,
            "position": pos,
            "consumed_input": consumed,
            "remaining_input": remaining,
            "rule": f"δ({curr}, {ch!r}) = {next_st}"
        }
        trace_steps.append(step_dict)
        navigation_steps.append({
            "step": pos,
            "position": pos,
            "symbol": ch,
            "consumed_input": consumed,
            "remaining_input": remaining,
            "from_state": curr,
            "active_state": next_st,
            "transition_used": {"from": curr, "to": next_st, "label": matched_lbl},
            "rule": f"δ({curr}, {ch!r}) = {next_st} (etiqueta '{matched_lbl}')",
            "is_initial": (next_st == initial_id),
            "is_final": (next_st in final_ids),
            "is_trap": False,
            "status": "ACEPTADO" if (pos == len(input_str) and next_st in final_ids) else "EN_PROGRESO"
        })
        if len(input_str) <= 10 or idx < 4 or idx >= len(input_str) - 2:
            compact_steps.append(f"--'{ch}'--> {next_st}")
        elif idx == 4:
            compact_steps.append("--> ... ")
        curr = next_st

    accepted = (curr in final_ids)
    if accepted:
        return {
            "accepted": True,
            "result": "Accept",
            "initial_state": initial_id,
            "final_states_defined": sorted(final_ids),
            "trace": trace_steps,
            "navigation_steps": navigation_steps,
            "final_states": [curr],
            "error_position": None,
            "error_symbol": None,
            "error_reason": None,
            "summary_text": f"Traza AFD (Accept): {' '.join(compact_steps)} (Culmina en {curr} ∈ F)"
        }

    reason = f"Cadena agotada en estado no final {curr} ∉ F (entrada incompleta)"
    if navigation_steps:
        navigation_steps[-1]["status"] = "INCOMPLETO_NO_FINAL"
    return {
        "accepted": False,
        "result": "Reject",
        "initial_state": initial_id,
        "final_states_defined": sorted(final_ids),
        "trace": trace_steps,
        "navigation_steps": navigation_steps,
        "final_states": [curr],
        "error_position": len(input_str),
        "error_symbol": input_str[-1] if input_str else None,
        "error_reason": reason,
        "summary_text": f"Traza AFD (Reject): {' '.join(compact_steps)} ({reason})"
    }


def simulate_afnd_structured(states_afnd, trans_afnd, input_str):
    initial_id = [s['id'] for s in states_afnd if s.get('initial')][0]
    final_ids = {s['id'] for s in states_afnd if s.get('final')}

    curr_closure, init_eps_edges = _compute_epsilon_closure_with_edges({initial_id}, trans_afnd)
    sorted_init = _sort_nfa_state_names(curr_closure)
    trace_steps = []
    compact_sets = ["{" + ",".join(sorted_init) + "}"]

    navigation_steps = [{
        "step": 0,
        "position": 0,
        "symbol": None,
        "consumed_input": "",
        "remaining_input": input_str if input_str else "ε",
        "from_states": [],
        "move_states": [initial_id],
        "active_states": sorted_init,
        "transitions_used": [],
        "epsilon_transitions_used": init_eps_edges,
        "rule": f"ε-clausura({{{initial_id}}}) = {{{', '.join(sorted_init)}}}",
        "has_final": bool(curr_closure & final_ids),
        "is_empty_set": False,
        "status": "INICIO"
    }]

    for idx, ch in enumerate(input_str):
        pos = idx + 1
        consumed = input_str[:pos]
        remaining = input_str[pos:] if pos < len(input_str) else "ε"
        prev_sorted = _sort_nfa_state_names(curr_closure)

        is_string_space = (
            ch == ' ' and any(
                t['from'] in curr_closure and t['label'] == 'Σ_base' for t in trans_afnd
            )
        )

        if ch not in SIGMA_ASCII and not is_string_space:
            reason = f"Posición {pos}: Símbolo {ch!r} ∉ Σ_ASCII."
            navigation_steps.append({
                "step": pos,
                "position": pos,
                "symbol": ch,
                "consumed_input": consumed,
                "remaining_input": remaining,
                "from_states": prev_sorted,
                "move_states": [],
                "active_states": [],
                "transitions_used": [],
                "epsilon_transitions_used": [],
                "rule": f"Rechazo: {ch!r} ∉ Σ_ASCII → ∅",
                "has_final": False,
                "is_empty_set": True,
                "status": "CONJUNTO_VACIO"
            })
            return {
                "accepted": False,
                "result": "Reject",
                "initial_state": sorted_init,
                "final_states_defined": _sort_nfa_state_names(final_ids),
                "trace": trace_steps,
                "navigation_steps": navigation_steps,
                "final_states": [],
                "error_position": pos,
                "error_symbol": ch,
                "error_reason": reason,
                "summary_text": f"Traza AFND (Reject): {' '.join(compact_sets)} --'{ch}'--> ∅ ({reason})"
            }

        reached = set()
        used_sym_edges = []
        for u in prev_sorted:
            for t in trans_afnd:
                if t['from'] == u and t['label'] not in ('ε', 'λ', ''):
                    if ch in expand_atomic_label(t['label']) or (is_string_space and t['label'] == 'Σ_base'):
                        reached.add(t['to'])
                        used_sym_edges.append({'from': u, 'to': t['to'], 'label': t['label']})

        mv = frozenset(reached)
        if not mv:
            reason = f"Conjunto vacío ∅ en pos {pos} al leer {ch!r}"
            trace_steps.append({
                "step": pos,
                "from_set": prev_sorted,
                "symbol": ch,
                "move_set": [],
                "closure_set": [],
                "position": pos,
                "consumed_input": consumed,
                "remaining_input": remaining
            })
            navigation_steps.append({
                "step": pos,
                "position": pos,
                "symbol": ch,
                "consumed_input": consumed,
                "remaining_input": remaining,
                "from_states": prev_sorted,
                "move_states": [],
                "active_states": [],
                "transitions_used": [],
                "epsilon_transitions_used": [],
                "rule": f"ε-clausura(move({{{','.join(prev_sorted)}}}, {ch!r})) = ∅",
                "has_final": False,
                "is_empty_set": True,
                "status": "CONJUNTO_VACIO"
            })
            return {
                "accepted": False,
                "result": "Reject",
                "initial_state": sorted_init,
                "final_states_defined": _sort_nfa_state_names(final_ids),
                "trace": trace_steps,
                "navigation_steps": navigation_steps,
                "final_states": [],
                "error_position": pos,
                "error_symbol": ch,
                "error_reason": reason,
                "summary_text": f"Traza AFND (Reject): {' '.join(compact_sets)} --'{ch}'--> ∅ ({reason})"
            }

        next_closure, eps_edges = _compute_epsilon_closure_with_edges(mv, trans_afnd)
        sorted_mv = _sort_nfa_state_names(mv)
        sorted_next = _sort_nfa_state_names(next_closure)

        trace_steps.append({
            "step": pos,
            "from_set": prev_sorted,
            "symbol": ch,
            "move_set": sorted_mv,
            "closure_set": sorted_next,
            "position": pos,
            "consumed_input": consumed,
            "remaining_input": remaining,
            "transitions_used": used_sym_edges,
            "epsilon_transitions_used": eps_edges
        })
        navigation_steps.append({
            "step": pos,
            "position": pos,
            "symbol": ch,
            "consumed_input": consumed,
            "remaining_input": remaining,
            "from_states": prev_sorted,
            "move_states": sorted_mv,
            "active_states": sorted_next,
            "transitions_used": used_sym_edges,
            "epsilon_transitions_used": eps_edges,
            "rule": (
                f"move({{{','.join(prev_sorted)}}}, {ch!r}) = {{{','.join(sorted_mv)}}} "
                f"→ ε-clausura = {{{','.join(sorted_next)}}}"
            ),
            "has_final": bool(next_closure & final_ids),
            "is_empty_set": False,
            "status": "ACEPTADO" if (pos == len(input_str) and bool(next_closure & final_ids)) else "EN_PROGRESO"
        })
        if len(input_str) <= 8 or idx < 3 or idx >= len(input_str) - 2:
            compact_sets.append(f"--'{ch}'--> {{" + ",".join(sorted_next) + "}")
        elif idx == 3:
            compact_sets.append("--> ... ")
        curr_closure = next_closure

    final_active = _sort_nfa_state_names(curr_closure)
    accepted_finals = [s for s in final_active if s in final_ids]
    if accepted_finals:
        return {
            "accepted": True,
            "result": "Accept",
            "initial_state": sorted_init,
            "final_states_defined": _sort_nfa_state_names(final_ids),
            "trace": trace_steps,
            "navigation_steps": navigation_steps,
            "final_states": final_active,
            "error_position": None,
            "error_symbol": None,
            "error_reason": None,
            "summary_text": f"Traza AFND (Accept): {' '.join(compact_sets)} (Alcanza {accepted_finals[0]} ∈ F')"
        }

    reason = f"Ningún estado activo en {final_active} pertenece a F'"
    if navigation_steps:
        navigation_steps[-1]["status"] = "INCOMPLETO_NO_FINAL"
    return {
        "accepted": False,
        "result": "Reject",
        "initial_state": sorted_init,
        "final_states_defined": _sort_nfa_state_names(final_ids),
        "trace": trace_steps,
        "navigation_steps": navigation_steps,
        "final_states": final_active,
        "error_position": len(input_str),
        "error_symbol": input_str[-1] if input_str else None,
        "error_reason": reason,
        "summary_text": f"Traza AFND (Reject): {' '.join(compact_sets)} ({reason})"
    }


# ==============================================================================
# 5. MODELO FORMAL UNIFICADO: AFD COMPLETO INTERNO + AFD LIGERO EXPORTABLE JFLAP
# ==============================================================================

class FormalAutomatonModel:
    """
    Mantiene simultáneamente:
      A) Modelo Formal Interno Completo (con estado trampa qT y función de transición total)
         utilizado por el simulador web paso a paso, la quíntupla, el diagrama SVG y la tabla δ.
      B) Modelo Exportable Ligero para JFLAP 7.1 (representación parcial de diagnóstico sin qT
         ni transiciones de rechazo masivas, con transiciones de 1 carácter real).
    """
    def __init__(self, tok_type, is_afnd, states, grouped_transitions, sigma_desc, height=260, node_radius=17):
        self.tok_type = tok_type
        self.is_afnd = is_afnd
        # A. Representación formal interna completa (incluye qT en AFD)
        self.states = states
        self.grouped_transitions = grouped_transitions
        self.sigma_desc = sigma_desc
        self.height = height
        self.node_radius = node_radius

        self.state_ids = [s['id'] for s in states]
        self.state_id_to_index = {s['id']: idx for idx, s in enumerate(states)}
        self.initial_state = [s['id'] for s in states if s.get('initial')][0]
        self.final_states = [s['id'] for s in states if s.get('final')]

        # Transiciones atómicas del modelo completo interno (incluye transiciones hacia/en qT)
        self.atomic_transitions = self._build_atomic_transitions(include_trap=True)
        self.quintuple = self._build_quintuple()

        # B. Representación ligera exportable para JFLAP 7.1 (omite qT y sus transiciones en AFD)
        if self.is_afnd:
            self.lightweight_states = list(self.states)
        else:
            self.lightweight_states = [
                s for s in self.states if not s.get('trap') and s['id'] != 'qT'
            ]
        self.lightweight_state_ids = [s['id'] for s in self.lightweight_states]
        self.lightweight_state_id_to_index = {
            s['id']: idx for idx, s in enumerate(self.lightweight_states)
        }
        self.lightweight_atomic_transitions = self._build_atomic_transitions(include_trap=False)

    def _build_atomic_transitions(self, include_trap=True):
        atomic = []
        seen_edges = set()
        idx_map = self.state_id_to_index if (include_trap or self.is_afnd) else {
            s['id']: idx for idx, s in enumerate(self.states)
            if not s.get('trap') and s['id'] != 'qT'
        }

        for t in self.grouped_transitions:
            u = t['from']
            v = t['to']
            if not include_trap and not self.is_afnd:
                if u == 'qT' or v == 'qT':
                    continue
            if u not in idx_map or v not in idx_map:
                continue
            for ch in expand_atomic_label(t['label']):
                edge_key = (u, v, ch)
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    atomic.append({
                        'from': u,
                        'to': v,
                        'from_idx': idx_map[u],
                        'to_idx': idx_map[v],
                        'read': ch
                    })
        return atomic

    def _build_quintuple(self):
        q_formatted = "{" + ", ".join(self.state_ids) + "}"
        f_formatted = "{" + ", ".join(self.final_states) + "}"
        delta_str = "δ' : Q' × (Σ_ASCII ∪ {ε}) → P(Q')" if self.is_afnd else "δ : Q × Σ_ASCII → Q"
        return {
            "Q": q_formatted,
            "Sigma": self.sigma_desc,
            "delta": delta_str,
            "q_ini": self.initial_state,
            "F": f_formatted
        }

    def to_lightweight_jff_xml(self):
        """
        Exporta la representación ligera del AFD (sin estado trampa qT ni aristas de rechazo)
        o el AFND de Thompson para compatibilidad directa con Editor, Multiple Run y Step by State
        en JFLAP 7.1.
        """
        return self.to_jff_xml(include_trap=False)

    def to_jff_xml(self, include_trap=False):
        """
        Genera el XML .jff para JFLAP 7.1:
          - Por defecto (include_trap=False): exporta el AFD ligero parcial (sin qT) o el AFND.
          - Si include_trap=True: exporta el AFD completo con estado trampa qT explícito.
        """
        if self.is_afnd:
            export_states = self.states
            export_edges = self.atomic_transitions
            mode_desc = f"AFND de Thompson para {self.tok_type}"
        elif include_trap:
            export_states = self.states
            export_edges = self.atomic_transitions
            mode_desc = f"AFD Completo Interno (Función Total con qT) para {self.tok_type}"
        else:
            export_states = self.lightweight_states
            export_edges = self.lightweight_atomic_transitions
            mode_desc = (
                f"AFD Ligero para JFLAP 7.1 (Representación Parcial de Diagnóstico sin qT) "
                f"para {self.tok_type}"
            )

        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
            f'<!-- {mode_desc} - Compatible con JFLAP 7.1 -->',
            '<structure>',
            '  <type>fa</type>',
            '  <automaton>'
        ]

        for idx, s in enumerate(export_states):
            is_trap = bool(s.get('trap') or s['id'] == 'qT')
            is_final = bool(s.get('final')) and not is_trap
            xml_lines.append(f'    <state id="{idx}" name="{escape_svg_text(s["id"])}">')
            xml_lines.append(f'      <x>{float(s.get("x", 60 + idx * 50)):.1f}</x>')
            xml_lines.append(f'      <y>{float(s.get("y", 100)):.1f}</y>')
            if s.get('initial'):
                xml_lines.append('      <initial/>')
            if is_final:
                xml_lines.append('      <final/>')
            xml_lines.append('    </state>')

        for edge in export_edges:
            xml_lines.append('    <transition>')
            xml_lines.append(f'      <from>{edge["from_idx"]}</from>')
            xml_lines.append(f'      <to>{edge["to_idx"]}</to>')
            if edge['read'] == '':
                xml_lines.append('      <read/>')
            else:
                xml_lines.append(f'      <read>{escape_svg_text(edge["read"])}</read>')
            xml_lines.append('    </transition>')

        xml_lines.append('  </automaton>')
        xml_lines.append('</structure>')
        return '\n'.join(xml_lines)

    def simulate(self, input_str):
        if self.is_afnd:
            return simulate_afnd_structured(self.states, self.grouped_transitions, input_str)
        return simulate_afd_structured(self.states, self.grouped_transitions, input_str)


# ==============================================================================
# 6. VALIDADOR DE REQUISITOS JFF Y DEMOSTRACIÓN DE EQUIVALENCIA TRIPLE
# ==============================================================================

def validate_jff_xml_ten_requirements(xml_string, is_afnd=False, require_complete_dfa=False):
    """
    Verifica los 10 requisitos estructurales sobre un archivo .jff:
      - Cuando require_complete_dfa=False (por defecto para el AFD ligero de JFLAP 7.1),
        verifica además que NO contenga el estado trampa qT ni transiciones hacia qT.
      - Cuando require_complete_dfa=True (para validar la versión completa interna),
        verifica que cada estado defina exactamente las |Σ_ASCII| transiciones salientes.
    """
    errors = []
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as exc:
        return {"valid": False, "errors": [f"Req 1 falló (XML mal formado): {exc}"]}

    type_el = root.find('type')
    if type_el is None or (type_el.text or '').strip() != 'fa':
        errors.append("Req 2 falló: <type> debe ser 'fa'.")

    automaton = root.find('automaton')
    if automaton is None:
        return {"valid": False, "errors": errors + ["No existe el nodo <automaton>."]}

    state_els = automaton.findall('state')
    seen_ids = set()
    seen_names = set()
    id_to_name = {}
    initial_count = 0
    final_count = 0

    for st in state_els:
        sid = st.attrib.get('id')
        sname = st.attrib.get('name')
        if sid is None or sid in seen_ids:
            errors.append(f"Req 3 falló: ID de estado duplicado o ausente ({sid}).")
        if sname is None or sname in seen_names:
            errors.append(f"Req 3 falló: Nombre de estado duplicado o ausente ({sname}).")
        if sid is not None:
            seen_ids.add(sid)
            id_to_name[sid] = sname or sid
        if sname is not None:
            seen_names.add(sname)
        if st.find('initial') is not None:
            initial_count += 1
        if st.find('final') is not None:
            final_count += 1
            if sname == 'qT':
                errors.append("Req 5 falló: El estado trampa qT no puede ser estado de aceptación (<final/>).")

    if initial_count != 1:
        errors.append(f"Req 4 falló: Debe existir exactamente 1 estado inicial, se encontraron {initial_count}.")
    if final_count < 1:
        errors.append("Req 5 falló: Debe existir al menos 1 estado final.")

    seen_edges = set()
    afd_state_char_pairs = set()
    afd_symbols_by_state = {sid: [] for sid in seen_ids}

    for tr in automaton.findall('transition'):
        from_el = tr.find('from')
        to_el = tr.find('to')
        read_el = tr.find('read')
        u = from_el.text.strip() if (from_el is not None and from_el.text) else None
        v = to_el.text.strip() if (to_el is not None and to_el.text) else None

        if u not in seen_ids or v not in seen_ids:
            errors.append(f"Req 6 falló: Transición apunta a estado inexistente ({u} -> {v}).")

        sym = read_el.text if (read_el is not None and read_el.text is not None) else ''
        if sym == '':
            if not is_afnd:
                errors.append(f"Req 7 falló: El AFD contiene una transición epsilon en ({u} -> {v}).")
        else:
            if len(sym.strip()) == 0:
                errors.append(
                    f"Req 8 falló (Incompatibilidad DOMPrettier JFLAP 7.1): <read>{sym!r}</read> "
                    f"se convierte en transición λ vacía al aplicar .trim() en JFLAP."
                )
            elif len(sym) != 1:
                errors.append(f"Req 8 falló: Etiqueta no atómica de longitud != 1 ({sym!r}).")
            elif sym not in SIGMA_ASCII:
                errors.append(f"Req 9 falló: Símbolo {sym!r} fuera de Σ_ASCII.")

        edge_tuple = (u, v, sym)
        if edge_tuple in seen_edges:
            errors.append(f"Req 10 falló: Transición idéntica duplicada {edge_tuple}.")
        seen_edges.add(edge_tuple)

        if not is_afnd and sym != '':
            pair_key = (u, sym)
            if pair_key in afd_state_char_pairs:
                errors.append(
                    f"Req 10 falló (No determinismo): Estado {id_to_name.get(u, u)} (id={u}) "
                    f"define múltiples transiciones para el símbolo {sym!r}."
                )
            afd_state_char_pairs.add(pair_key)
            if u in afd_symbols_by_state and sym in SIGMA_ASCII:
                afd_symbols_by_state[u].append(sym)

    if not is_afnd and require_complete_dfa:
        sigma_set = set(SIGMA_ASCII)
        for sid in sorted(seen_ids, key=lambda x: int(x) if x.isdigit() else x):
            st_label = f"{id_to_name.get(sid, sid)} (id={sid})"
            recorded_list = afd_symbols_by_state.get(sid, [])
            recorded_set = set(recorded_list)
            missing_chars = sorted(sigma_set - recorded_set)
            if missing_chars:
                errors.append(
                    f"Req 10 falló (AFD incompleto): Al estado {st_label} le faltan "
                    f"{len(missing_chars)} símbolos de Σ_ASCII (ej. {missing_chars[:5]})."
                )
            if len(recorded_list) != len(SIGMA_ASCII):
                errors.append(
                    f"Req 10 falló (Cardinalidad δ en {st_label}): Se esperaban exactamente "
                    f"{len(SIGMA_ASCII)} transiciones salientes y se encontraron {len(recorded_list)}."
                )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "state_count": len(seen_ids),
        "transition_count": len(seen_edges),
        "initial_count": initial_count,
        "final_count": final_count,
        "has_trap_state": ('qT' in seen_names)
    }


def parse_jff_xml_to_automaton(xml_string):
    root = ET.fromstring(xml_string)
    automaton = root.find('automaton')
    id_to_name = {}
    states = []

    for st_el in automaton.findall('state'):
        xml_id = st_el.attrib['id']
        name = st_el.attrib['name']
        id_to_name[xml_id] = name
        is_init = (st_el.find('initial') is not None)
        is_final = (st_el.find('final') is not None)
        states.append({
            'id': name,
            'initial': is_init,
            'final': is_final,
            'trap': (name == 'qT')
        })

    transitions = []
    for tr_el in automaton.findall('transition'):
        u_name = id_to_name[tr_el.find('from').text.strip()]
        v_name = id_to_name[tr_el.find('to').text.strip()]
        read_el = tr_el.find('read')
        sym = read_el.text if (read_el is not None and read_el.text is not None) else 'ε'
        transitions.append({'from': u_name, 'to': v_name, 'label': sym})

    return states, transitions


def simulate_loaded_jff_directly(jff_path, input_str):
    with open(jff_path, "r", encoding="utf-8") as f:
        xml_str = f.read()
    states, transitions = parse_jff_xml_to_automaton(xml_str)

    initial_ids = [s['id'] for s in states if s.get('initial')]
    final_ids = {s['id'] for s in states if s.get('final')}

    def jff_eps_closure(st_set):
        stack = list(st_set)
        clos = set(st_set)
        while stack:
            u = stack.pop()
            for t in transitions:
                if t['from'] == u and t['label'] == 'ε' and t['to'] not in clos:
                    clos.add(t['to'])
                    stack.append(t['to'])
        return frozenset(clos)

    curr = jff_eps_closure(initial_ids)
    for ch in input_str:
        next_set = set()
        for u in curr:
            for t in transitions:
                if t['from'] == u and t['label'] == ch:
                    next_set.add(t['to'])
        curr = jff_eps_closure(next_set)
        if not curr:
            return False

    return bool(curr & final_ids)


def prove_jff_files_equivalence(jff_afd_path, jff_afnd_path):
    """
    Compara formalmente un archivo AFD .jff (sea ligero parcial sin qT o completo con qT)
    contra un archivo AFND .jff mediante producto de autómatas y búsqueda BFS de contraejemplos.
    Para el AFD parcial ligero, las transiciones ausentes se interpretan como rechazo
    mediante el estado trampa implícito '__IMPLICIT_QT__'.
    """
    with open(jff_afd_path, "r", encoding="utf-8") as f1:
        afd_states, afd_trans = parse_jff_xml_to_automaton(f1.read())
    with open(jff_afnd_path, "r", encoding="utf-8") as f2:
        afnd_states, afnd_trans = parse_jff_xml_to_automaton(f2.read())

    init_afd = [s['id'] for s in afd_states if s.get('initial')][0]
    finals_afd = {s['id'] for s in afd_states if s.get('final')}

    init_afnd = [s['id'] for s in afnd_states if s.get('initial')][0]
    finals_afnd = {s['id'] for s in afnd_states if s.get('final')}

    afd_delta = {}
    for t in afd_trans:
        if t['label'] == 'ε':
            return {
                "equivalent": False,
                "shortest_witness": "<epsilon_in_afd>",
                "afd_accepts": None,
                "afnd_accepts": None,
                "error_detail": f"Transición ε ilegal en AFD: {t}"
            }
        key = (t['from'], t['label'])
        if key in afd_delta and afd_delta[key] != t['to']:
            return {
                "equivalent": False,
                "shortest_witness": t['label'],
                "afd_accepts": None,
                "afnd_accepts": None,
                "error_detail": (
                    f"No determinismo detectado en AFD JFF para {key}: "
                    f"destinos en conflicto {afd_delta[key]} vs {t['to']}"
                )
            }
        afd_delta[key] = t['to']

    eps_adj = {}
    char_adj = {}
    for t in afnd_trans:
        if t['label'] == 'ε':
            eps_adj.setdefault(t['from'], []).append(t['to'])
        else:
            char_adj.setdefault((t['from'], t['label']), []).append(t['to'])

    def jff_closure(state_set):
        stack = list(state_set)
        clos = set(state_set)
        while stack:
            u = stack.pop()
            for v in eps_adj.get(u, ()):
                if v not in clos:
                    clos.add(v)
                    stack.append(v)
        return frozenset(clos)

    def jff_move(state_set, ch):
        nxt = set()
        for u in state_set:
            for v in char_adj.get((u, ch), ()):
                nxt.add(v)
        return jff_closure(nxt) if nxt else frozenset()

    implicit_trap = '__IMPLICIT_QT__'
    start_afnd_set = jff_closure({init_afnd})
    start_config = (init_afd, start_afnd_set)
    queue = deque([(start_config, "")])
    visited = {start_config}

    while queue:
        (q_d, s_n), word = queue.popleft()
        afd_acc = (q_d in finals_afd)
        afnd_acc = bool(s_n & finals_afnd)

        if afd_acc != afnd_acc:
            return {
                "equivalent": False,
                "shortest_witness": word,
                "afd_accepts": afd_acc,
                "afnd_accepts": afnd_acc,
                "visited_configurations": len(visited)
            }

        for ch in SIGMA_ASCII:
            next_qd = afd_delta.get((q_d, ch), implicit_trap) if q_d != implicit_trap else implicit_trap
            next_sn = jff_move(s_n, ch)
            nxt_cfg = (next_qd, next_sn)
            if nxt_cfg not in visited:
                visited.add(nxt_cfg)
                queue.append((nxt_cfg, word + ch))

    return {
        "equivalent": True,
        "shortest_witness": None,
        "afd_accepts": None,
        "afnd_accepts": None,
        "visited_configurations": len(visited)
    }


def prove_three_way_equivalence(afd_complete_model, jff_light_afd_path, jff_afnd_path):
    """
    Sección 4:
    Demuestra formalmente mediante el producto triple de autómatas y búsqueda BFS de
    contraejemplos sobre Σ_ASCII que:
      1) El AFD completo interno (con estado trampa explícito qT),
      2) El AFD ligero exportado en .jff (parcial sin qT, interpretando transiciones
         ausentes mediante un estado trampa implícito), y
      3) El AFND de Thompson exportado en .jff
    aceptan exactamente el mismo lenguaje formal:
      L(AFD_completo) == L(AFD_ligero) == L(AFND_Thompson).
    """
    # 1. AFD Completo Interno
    init_comp = afd_complete_model.initial_state
    finals_comp = set(afd_complete_model.final_states)
    comp_delta = {}
    for e in afd_complete_model.atomic_transitions:
        comp_delta[(e['from'], e['read'])] = e['to']

    # 2. AFD Ligero Exportado (leído desde archivo .jff)
    with open(jff_light_afd_path, "r", encoding="utf-8") as f1:
        light_states, light_trans = parse_jff_xml_to_automaton(f1.read())
    init_light = [s['id'] for s in light_states if s.get('initial')][0]
    finals_light = {s['id'] for s in light_states if s.get('final')}
    light_delta = {}
    for t in light_trans:
        if t['label'] != 'ε':
            light_delta[(t['from'], t['label'])] = t['to']

    # 3. AFND de Thompson Exportado (leído desde archivo .jff)
    with open(jff_afnd_path, "r", encoding="utf-8") as f2:
        afnd_states, afnd_trans = parse_jff_xml_to_automaton(f2.read())
    init_afnd = [s['id'] for s in afnd_states if s.get('initial')][0]
    finals_afnd = {s['id'] for s in afnd_states if s.get('final')}

    eps_adj = {}
    char_adj = {}
    for t in afnd_trans:
        if t['label'] == 'ε':
            eps_adj.setdefault(t['from'], []).append(t['to'])
        else:
            char_adj.setdefault((t['from'], t['label']), []).append(t['to'])

    def jff_closure(state_set):
        stack = list(state_set)
        clos = set(state_set)
        while stack:
            u = stack.pop()
            for v in eps_adj.get(u, ()):
                if v not in clos:
                    clos.add(v)
                    stack.append(v)
        return frozenset(clos)

    def jff_move(state_set, ch):
        nxt = set()
        for u in state_set:
            for v in char_adj.get((u, ch), ()):
                nxt.add(v)
        return jff_closure(nxt) if nxt else frozenset()

    implicit_trap = '__IMPLICIT_QT__'
    start_triple = (init_comp, init_light, jff_closure({init_afnd}))
    queue = deque([(start_triple, "")])
    visited = {start_triple}

    while queue:
        (q_c, q_l, s_n), word = queue.popleft()
        acc_c = (q_c in finals_comp)
        acc_l = (q_l in finals_light)
        acc_n = bool(s_n & finals_afnd)

        if not (acc_c == acc_l == acc_n):
            return {
                "equivalent": False,
                "shortest_witness": word,
                "complete_afd_accepts": acc_c,
                "lightweight_afd_accepts": acc_l,
                "thompson_afnd_accepts": acc_n,
                "visited_triples": len(visited)
            }

        for ch in SIGMA_ASCII:
            next_qc = comp_delta.get((q_c, ch), 'qT')
            next_ql = light_delta.get((q_l, ch), implicit_trap) if q_l != implicit_trap else implicit_trap
            next_sn = jff_move(s_n, ch)
            nxt_triple = (next_qc, next_ql, next_sn)
            if nxt_triple not in visited:
                visited.add(nxt_triple)
                queue.append((nxt_triple, word + ch))

    return {
        "equivalent": True,
        "shortest_witness": None,
        "complete_afd_accepts": None,
        "lightweight_afd_accepts": None,
        "thompson_afnd_accepts": None,
        "visited_triples": len(visited)
    }


def prove_dfa_equivalence_by_product(states_1, trans_1, states_2, trans_2):
    init_1 = [s['id'] for s in states_1 if s.get('initial')][0]
    finals_1 = {s['id'] for s in states_1 if s.get('final')}

    init_2 = [s['id'] for s in states_2 if s.get('initial')][0]
    finals_2 = {s['id'] for s in states_2 if s.get('final')}

    def build_delta_lookup(states, trans):
        lookup = {}
        for s in states:
            sid = s['id']
            for ch in SIGMA_ASCII:
                lookup[(sid, ch)] = 'qT'
        for t in trans:
            u, v, lbl = t['from'], t['to'], t['label']
            if lbl not in ('ε', 'λ', ''):
                for ch in expand_atomic_label(lbl):
                    if v != 'qT' or lookup.get((u, ch)) == 'qT':
                        lookup[(u, ch)] = v
        return lookup

    d1 = build_delta_lookup(states_1, trans_1)
    d2 = build_delta_lookup(states_2, trans_2)

    start_pair = (init_1, init_2)
    queue = deque([(start_pair, "")])
    visited = {start_pair}

    while queue:
        (p, q), word = queue.popleft()
        if (p in finals_1) != (q in finals_2):
            return {
                "equivalent": False,
                "distinguishing_word": word,
                "visited_pairs": len(visited)
            }

        for ch in SIGMA_ASCII:
            np = d1.get((p, ch), 'qT')
            nq = d2.get((q, ch), 'qT')
            nxt = (np, nq)
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, word + ch))

    return {
        "equivalent": True,
        "distinguishing_word": None,
        "visited_pairs": len(visited)
    }