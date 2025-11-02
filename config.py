"""
Configuration constants and settings for the Palo Alto Firewall Dashboard
"""
import os
import json
# Note: Settings are stored as plain JSON (no encryption)
# Only API keys in devices.json are encrypted

# Palo Alto Firewall Configuration (moved to settings)
# These are fallback defaults only - users must configure devices via UI
DEFAULT_FIREWALL_IP = ""
DEFAULT_API_KEY = ""

# File paths
DEBUG_LOG_FILE = os.path.join(os.path.dirname(__file__), 'debug.log')
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), 'settings.json')
DEVICES_FILE = os.path.join(os.path.dirname(__file__), 'devices.json')
VENDOR_DB_FILE = os.path.join(os.path.dirname(__file__), 'mac_vendor_db.json')
SERVICE_PORT_DB_FILE = os.path.join(os.path.dirname(__file__), 'service_port_db.json')
AUTH_FILE = os.path.join(os.path.dirname(__file__), 'auth.json')
METADATA_FILE = os.path.join(os.path.dirname(__file__), 'device_metadata.json')
SECURITY_LOG_FILE = os.path.join(os.path.dirname(__file__), 'security.log')

# Default settings
DEFAULT_SETTINGS = {
    'refresh_interval': 15,
    'debug_logging': False,
    'selected_device_id': '',
    'monitored_interface': 'ethernet1/12',
    'tony_mode': False,
    'timezone': 'UTC'  # Default timezone for displaying times
}

# Lazy import to avoid circular dependency
def _get_logger():
    """Import logger functions lazily to avoid circular import"""
    from logger import debug, error, warning
    return debug, error, warning

def ensure_settings_file_exists():
    """Create settings.json if it doesn't exist"""
    if not os.path.exists(SETTINGS_FILE):
        # Create with default settings
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)

def load_settings():
    """
    Load settings from file or return defaults.
    Settings are stored as plain JSON (no decryption needed).

    Note: This function does NOT use logging to avoid circular dependencies
    since logger.is_debug_enabled() calls load_settings().
    """
    # Ensure file exists before loading
    ensure_settings_file_exists()

    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
                return settings

        return DEFAULT_SETTINGS.copy()
    except Exception:
        return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    """
    Save settings to file.
    Settings are stored in plain JSON (no encryption needed for non-sensitive data).
    Only API keys in devices.json are encrypted.
    """
    debug, error, _ = _get_logger()
    debug(f"Saving settings to file: {settings}")
    try:
        # Save settings as plain JSON (no encryption)
        # Only API keys need encryption, and those are in devices.json
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        debug("Settings saved successfully")
        return True
    except Exception as e:
        error(f"Failed to save settings: {e}")
        return False


# Note: Settings migration is not needed - settings are stored as plain JSON
# Only API keys (stored in devices.json) need encryption


def load_vendor_database():
    """
    Load MAC vendor database from file.
    Returns dictionary mapping MAC prefixes to vendor names.
    """
    debug, error, _ = _get_logger()
    debug("Loading MAC vendor database")

    if not os.path.exists(VENDOR_DB_FILE):
        debug("Vendor database file does not exist")
        return {}

    try:
        with open(VENDOR_DB_FILE, 'r') as f:
            vendor_list = json.load(f)

        # Convert list to dictionary for faster lookups
        vendor_dict = {}
        for entry in vendor_list:
            mac_prefix = entry.get('macPrefix', '').upper().replace(':', '')
            vendor_name = entry.get('vendorName', '')
            if mac_prefix and vendor_name:
                vendor_dict[mac_prefix] = vendor_name

        debug(f"Loaded {len(vendor_dict)} MAC vendor entries")
        return vendor_dict

    except Exception as e:
        error(f"Failed to load vendor database: {e}")
        return {}


def save_vendor_database(vendor_data):
    """
    Save MAC vendor database to file.
    vendor_data should be a JSON array from the source.
    """
    debug, error, _ = _get_logger()
    debug("Saving MAC vendor database")

    try:
        with open(VENDOR_DB_FILE, 'w') as f:
            json.dump(vendor_data, f)
            f.flush()
            os.fsync(f.fileno())

        debug(f"Vendor database saved successfully ({len(vendor_data)} entries)")
        return True

    except Exception as e:
        error(f"Failed to save vendor database: {e}")
        return False


def get_vendor_db_info():
    """
    Get information about the vendor database file.
    """
    debug, _, _ = _get_logger()
    debug("get_vendor_db_info called")
    if os.path.exists(VENDOR_DB_FILE):
        file_size = os.path.getsize(VENDOR_DB_FILE)
        file_mtime = os.path.getmtime(VENDOR_DB_FILE)
        from datetime import datetime
        modified_date = datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')

        # Count entries
        try:
            with open(VENDOR_DB_FILE, 'r') as f:
                vendor_list = json.load(f)
                entry_count = len(vendor_list)
        except:
            entry_count = 0

        return {
            'exists': True,
            'size': file_size,
            'size_mb': round(file_size / (1024 * 1024), 2),
            'modified': modified_date,
            'entries': entry_count
        }
    else:
        return {
            'exists': False,
            'size': 0,
            'size_mb': 0,
            'modified': 'N/A',
            'entries': 0
        }


def load_service_port_database():
    """
    Load service port database from file.
    Returns dictionary mapping port numbers to service information.
    Format: {port: {'tcp': {'name': 'http', 'description': '...'}, 'udp': {...}}}
    """
    debug, error, _ = _get_logger()
    debug("Loading service port database")

    if not os.path.exists(SERVICE_PORT_DB_FILE):
        debug("Service port database file does not exist")
        return {}

    try:
        with open(SERVICE_PORT_DB_FILE, 'r') as f:
            service_data = json.load(f)

        debug(f"Loaded service port database with {len(service_data)} port entries")
        return service_data

    except Exception as e:
        error(f"Failed to load service port database: {e}")
        return {}


def save_service_port_database(service_data):
    """
    Save service port database to file.
    service_data should be a dictionary mapping ports to service info.
    """
    debug, error, _ = _get_logger()
    debug("Saving service port database")

    try:
        with open(SERVICE_PORT_DB_FILE, 'w') as f:
            json.dump(service_data, f)
            f.flush()
            os.fsync(f.fileno())

        debug(f"Service port database saved successfully ({len(service_data)} port entries)")
        return True

    except Exception as e:
        error(f"Failed to save service port database: {e}")
        return False


def get_service_port_db_info():
    """
    Get information about the service port database file.
    """
    debug, _, _ = _get_logger()
    debug("get_service_port_db_info called")
    if os.path.exists(SERVICE_PORT_DB_FILE):
        file_size = os.path.getsize(SERVICE_PORT_DB_FILE)
        file_mtime = os.path.getmtime(SERVICE_PORT_DB_FILE)
        from datetime import datetime
        modified_date = datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')

        # Count entries
        try:
            with open(SERVICE_PORT_DB_FILE, 'r') as f:
                service_data = json.load(f)
                entry_count = len(service_data)
        except:
            entry_count = 0

        return {
            'exists': True,
            'size': file_size,
            'size_mb': round(file_size / (1024 * 1024), 2),
            'modified': modified_date,
            'entries': entry_count
        }
    else:
        return {
            'exists': False,
            'size': 0,
            'size_mb': 0,
            'modified': 'N/A',
            'entries': 0
        }
