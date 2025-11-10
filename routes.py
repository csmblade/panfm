"""
Flask route orchestrator - Registers all route modules
This module imports and coordinates all route sub-modules for clean organization
"""
from logger import debug, info


def register_routes(app, csrf, limiter):
    """
    Register all Flask routes with authentication, CSRF protection, and rate limiting

    This orchestrator function imports and registers route modules in the following categories:
    - Authentication (login, logout, password management)
    - Monitoring (throughput, health, services, database)
    - Devices (device CRUD, metadata, connected devices, vendors, backup/restore)
    - Upgrades (PAN-OS versions, downloads, installs, content updates)
    - Operations (logs, applications, interfaces, licenses, settings, tech support)

    Args:
        app: Flask application instance
        csrf: CSRFProtect instance for CSRF token validation
        limiter: Limiter instance for rate limiting
    """
    info("=== Starting route registration ===")

    # Import all route modules
    from routes_auth import register_auth_routes
    from routes_monitoring import register_monitoring_routes
    from routes_devices import register_devices_routes
    from routes_upgrades import register_upgrades_routes
    from routes_operations import register_operations_routes

    # Register route modules in logical order
    debug("Registering route modules...")

    # 1. Authentication routes (must be first - no login required)
    register_auth_routes(app, csrf, limiter)
    debug("✓ Authentication routes registered")

    # 2. Monitoring routes (throughput, health checks, services)
    register_monitoring_routes(app, csrf, limiter)
    debug("✓ Monitoring routes registered")

    # 3. Operations routes (logs, applications, interfaces, settings, tech support)
    register_operations_routes(app, csrf, limiter)
    debug("✓ Operations routes registered")

    # 4. Device management routes (devices, metadata, vendors, backup/restore)
    register_devices_routes(app, csrf, limiter)
    debug("✓ Device management routes registered")

    # 5. Upgrade routes (PAN-OS and content updates)
    register_upgrades_routes(app, csrf, limiter)
    debug("✓ Upgrade routes registered")

    info("=== All routes registered successfully ===")
    info(f"Total endpoints registered: {len([rule for rule in app.url_map.iter_rules()])}")
