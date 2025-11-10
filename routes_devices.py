"""
Flask route handlers for device management (AGGREGATOR MODULE)
This module serves as the main entry point and re-exports all specialized route modules
Refactored in v1.8.2 to improve maintainability and adherence to file size guidelines

Specialized Modules:
- routes_device_management.py: Device CRUD operations
- routes_device_metadata.py: Connected devices, DHCP, device metadata
- routes_databases_backup.py: Vendor/service databases, backup/restore
"""
from logger import debug


def register_devices_routes(app, csrf, limiter):
    """
    Register all device-related routes by delegating to specialized modules

    This function maintains backward compatibility while splitting functionality
    across focused modules for better maintainability.
    """
    debug("Registering device routes (aggregator)")

    # Import and register specialized route modules
    from routes_device_management import register_device_management_routes
    from routes_device_metadata import register_device_metadata_routes
    from routes_databases_backup import register_databases_backup_routes

    # Register all route modules
    register_device_management_routes(app, csrf, limiter)
    register_device_metadata_routes(app, csrf, limiter)
    register_databases_backup_routes(app, csrf, limiter)

    debug("All device routes registered successfully via aggregator")
