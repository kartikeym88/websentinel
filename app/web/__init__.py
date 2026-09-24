from flask import Flask
from datetime import datetime, timezone, timedelta

def format_datetime_ist(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        ist_offset = timezone(timedelta(hours=5, minutes=30))
        ist_time = value.astimezone(ist_offset)
        return ist_time.strftime('%Y-%m-%d %H:%M:%S IST')
    return value

def create_app():
    app = Flask(__name__)
    app.jinja_env.filters['ist_time'] = format_datetime_ist
    
    from app.web.routes import bp
    app.register_blueprint(bp)
    
    @app.after_request
    def set_security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return response
    
    return app
