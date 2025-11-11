"""
Main Flask Application for Palo Alto Firewall Dashboard
Refactored for modularity and maintainability
"""
from flask import Flask
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
import urllib3
import os

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Flask app
app = Flask(__name__)

# Configuration
# Secret key for sessions - use environment variable or generate random key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# CSRF Protection
csrf = CSRFProtect(app)

# CORS Configuration
CORS(app, origins=['http://localhost:3000', 'http://127.0.0.1:3000'], supports_credentials=True)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# Initialize authentication
from auth import init_auth_file
init_auth_file()

# Initialize device metadata file
from device_metadata import init_metadata_file, load_metadata
init_metadata_file()
# Pre-load metadata at startup for immediate availability
load_metadata(use_cache=False)  # Load fresh at startup

# Initialize MAC vendor and service port databases
from config import load_vendor_database, load_service_port_database
from logger import debug
debug("Initializing MAC vendor database...")
vendor_db = load_vendor_database(use_cache=False)  # Fresh load at startup, then cached
debug(f"MAC vendor database loaded with {len(vendor_db)} entries")
debug("Initializing service port database...")
service_db = load_service_port_database(use_cache=False)  # Fresh load at startup, then cached
debug(f"Service port database loaded with {len(service_db)} entries")

# Check and fix encryption key permissions
from encryption import check_key_permissions
check_key_permissions()

# NOTE: Scheduled tasks (throughput collection, database cleanup, alerts) are now handled
# by the separate clock.py process. This keeps the Flask web server lightweight and
# follows production best practices for separating web and background task concerns.
#
# However, the web server DOES need read-only access to the throughput database
# to serve historical data via API endpoints.
from config import THROUGHPUT_DB_FILE, load_settings
from throughput_collector import init_collector
settings = load_settings()
retention_days = settings.get('throughput_retention_days', 90)
if settings.get('throughput_collection_enabled', True):
    debug(f"Initializing throughput collector (read-only access for web server)")
    init_collector(THROUGHPUT_DB_FILE, retention_days)
    debug("Throughput collector initialized (database access only, no scheduled collection)")

# Register all routes
from routes import register_routes
register_routes(app, csrf, limiter)

if __name__ == '__main__':
    # Get debug mode from environment variable (default: False for production)
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

    print("Starting Flask app (web server only)...")
    print("Scheduled tasks are handled by separate clock.py process")
    app.run(debug=debug_mode, host='0.0.0.0', port=3000, use_reloader=False, threaded=True)
