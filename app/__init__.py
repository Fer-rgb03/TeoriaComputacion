from flask import Flask
from app.config import Config

def create_app():
    # Conectamos Flask con la carpeta views/templates y views/static del profesor
    app = Flask(
        __name__,
        template_folder='views/templates',
        static_folder='views/static'
    )
    app.config.from_object(Config)

    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app