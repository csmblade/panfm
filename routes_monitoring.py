"""
Flask route handlers for monitoring and throughput (AGGREGATOR MODULE)
This module serves as the main entry point and re-exports all specialized route modules
Refactored in v1.8.2 to improve maintainability and adherence to file size guidelines

Specialized Modules:
- routes_throughput.py: Throughput data, history, exports, statistics
- routes_system.py: Health checks, version info, services status, database management
"""
from logger import debug


def register_monitoring_routes(app, csrf, limiter):
    """
    Register all monitoring-related routes by delegating to specialized modules

    This function maintains backward compatibility while splitting functionality
    across focused modules for better maintainability.
    """
    debug("Registering monitoring routes (aggregator)")

    # Import and register specialized route modules
    from routes_throughput import register_throughput_routes
    from routes_system import register_system_routes

    # Register all route modules
    register_throughput_routes(app, csrf, limiter)
    register_system_routes(app, csrf, limiter)

    debug("All monitoring routes registered successfully via aggregator")
