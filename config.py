"""
Phoenix CTI Forge - Secure Configuration
Cyber Threat Intelligence Educational Platform
Created by Australian Phoenix CyberOps
"""
import os
import secrets


class Config:
    """Base configuration with security-focused defaults."""

    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        SECRET_KEY = secrets.token_hex(32)

    WTF_CSRF_ENABLED = True
    WTF_CSRF_CHECK_DEFAULT = False
    WTF_CSRF_TIME_LIMIT = 3600

    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 1800

    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    ALLOWED_UPLOAD_EXTENSIONS = {'.txt', '.md', '.json', '.csv'}

    RATELIMIT_STORAGE_URI = 'memory://'
    RATELIMIT_STRATEGY = 'fixed-window'

    CSP = {
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': "'self' data:",
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'",
        'form-action': "'self'",
        'base-uri': "'self'",
    }

    # FIX: Corrected key name (was 'Phoenix_APP_VERSION' in app.py inject_globals)
    APP_NAME = "Phoenix CTI Forge"
    APP_VERSION = "2.0.0"


class DevelopmentConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = False
    TEMPLATES_AUTO_RELOAD = True


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME = 'https'


config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
