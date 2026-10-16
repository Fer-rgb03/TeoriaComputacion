import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'soc-interbank-tcom-2026')
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    STORAGE_DIR = os.path.join(BASE_DIR, 'storage')