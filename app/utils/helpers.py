import html

def escape_svg_text(text):
    """Sanitiza caracteres especiales para que los gráficos SVG no se rompan."""
    return html.escape(str(text))