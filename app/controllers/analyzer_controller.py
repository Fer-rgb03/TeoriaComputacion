from flask import render_template, request
from app.patterns.singleton.grammar_singleton import GrammarSingleton
from app.services.analyzer_service import analyze_single_log, save_results_to_storage

grammar = GrammarSingleton()

def index_controller():
    log_input = grammar.DEFAULT_LOGS
    if request.method == 'POST':
        uploaded_file = request.files.get('txt_file')
        if uploaded_file and uploaded_file.filename != '':
            log_input = uploaded_file.read().decode('utf-8', errors='replace')
        else:
            log_input = request.form.get('log_input', grammar.DEFAULT_LOGS)

    lines = [line.strip() for line in log_input.splitlines() if line.strip()]
    results = [analyze_single_log(line, idx + 1) for idx, line in enumerate(lines)]

    # Persistir en archivos planos dentro de app/storage/
    save_results_to_storage(results)

    summary = {
        'total_lines': len(results),
        'total_tokens': sum(len(r['tokens']) for r in results),
        'accepted': sum(1 for r in results if r['valid_lexical'] and r['valid_syntactic'] and r['valid_semantic']),
        'rejected': sum(1 for r in results if not (r['valid_lexical'] and r['valid_syntactic'] and r['valid_semantic']))
    }

    return render_template(
        'index.html',
        log_input=log_input,
        results=results,
        summary=summary
    )