"""
Flask route handlers for operational endpoints
Handles logs, applications, interfaces, licenses, settings, and tech support
"""
from flask import jsonify, request, render_template, send_from_directory
from datetime import datetime
import os
from auth import login_required
from config import load_settings, save_settings
from firewall_api import (
    get_system_logs,
    get_traffic_logs,
    get_software_updates,
    get_license_info,
    get_application_statistics,
    generate_tech_support_file,
    check_tech_support_job_status,
    get_tech_support_file_url,
    get_interface_info,
    get_interface_traffic_counters,
    get_firewall_config
)
from logger import debug, error


def register_operations_routes(app, csrf, limiter):
    """Register operational endpoints (logs, applications, interfaces, settings, tech support)"""
    debug("Registering operational routes")

    # ============================================================================
    # Base Routes
    # ============================================================================

    @app.route('/')
    @login_required
    def index():
        """Serve the main dashboard"""
        return render_template('index.html')

    @app.route('/images/<path:filename>')
    @login_required
    def serve_images(filename):
        """Serve image files"""
        images_dir = os.path.join(os.path.dirname(__file__), 'images')
        return send_from_directory(images_dir, filename)

    # ============================================================================
    # Logs Endpoints
    # ============================================================================

    @app.route('/api/system-logs')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def system_logs_api():
        """API endpoint for system logs"""
        debug("=== System Logs API endpoint called ===")
        try:
            settings = load_settings()
            debug(f"Selected device ID from settings: {settings.get('selected_device_id', 'NONE')}")
            firewall_config = get_firewall_config()
            logs = get_system_logs(firewall_config, max_logs=50)
            return jsonify({
                'status': 'success',
                'logs': logs,
                'total': len(logs),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e),
                'logs': []
            })

    @app.route('/api/traffic-logs')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def traffic_logs_api():
        """API endpoint for traffic logs"""
        debug("=== Traffic Logs API endpoint called ===")
        try:
            settings = load_settings()
            debug(f"Selected device ID from settings: {settings.get('selected_device_id', 'NONE')}")
            firewall_config = get_firewall_config()
            max_logs = request.args.get('max_logs', 50, type=int)
            logs = get_traffic_logs(firewall_config, max_logs)
            return jsonify({
                'status': 'success',
                'logs': logs,
                'total': len(logs),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e),
                'logs': []
            })

    # ============================================================================
    # Applications Endpoint
    # ============================================================================

    @app.route('/api/applications')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def applications_api():
        """API endpoint for application statistics"""
        debug("=== Applications API endpoint called ===")
        try:
            firewall_config = get_firewall_config()
            max_logs = request.args.get('max_logs', 5000, type=int)
            data = get_application_statistics(firewall_config, max_logs)
            applications = data.get('applications', [])
            summary = data.get('summary', {})
            debug(f"Retrieved {len(applications)} applications from firewall")
            return jsonify({
                'status': 'success',
                'applications': applications,
                'summary': summary,
                'total': len(applications),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            error(f"Error in applications API: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'applications': [],
                'summary': {
                    'total_applications': 0,
                    'total_sessions': 0,
                    'total_bytes': 0,
                    'vlans_detected': 0,
                    'zones_detected': 0
                },
                'total': 0
            })

    # ============================================================================
    # Software & License Endpoints
    # ============================================================================

    @app.route('/api/software-updates')
    @limiter.limit("120 per minute")  # Higher limit for reboot monitoring (15s intervals = 4/min, +buffer)
    @login_required
    def software_updates():
        """API endpoint for software update information"""
        debug("=== Software Updates API endpoint called ===")
        settings = load_settings()
        debug(f"Selected device ID from settings: {settings.get('selected_device_id', 'NONE')}")
        firewall_config = get_firewall_config()
        data = get_software_updates(firewall_config)
        return jsonify(data)

    @app.route('/api/license')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def license_info():
        """API endpoint for license information"""
        firewall_config = get_firewall_config()
        data = get_license_info(firewall_config)
        return jsonify(data)

    # ============================================================================
    # Tech Support Endpoints
    # ============================================================================

    @app.route('/api/tech-support/generate', methods=['POST'])
    @login_required
    def tech_support_generate():
        """API endpoint to generate tech support file"""
        debug("=== Tech Support Generate API endpoint called ===")
        firewall_config = get_firewall_config()
        data = generate_tech_support_file(firewall_config)
        return jsonify(data)

    @app.route('/api/tech-support/status/<job_id>')
    @login_required
    def tech_support_status(job_id):
        """API endpoint to check tech support job status"""
        debug(f"=== Tech Support Status API endpoint called for job: {job_id} ===")
        firewall_config = get_firewall_config()
        data = check_tech_support_job_status(firewall_config, job_id)
        return jsonify(data)

    @app.route('/api/tech-support/download/<job_id>')
    @login_required
    def tech_support_download(job_id):
        """API endpoint to get tech support file download URL"""
        debug(f"=== Tech Support Download API endpoint called for job: {job_id} ===")
        firewall_config = get_firewall_config()
        data = get_tech_support_file_url(firewall_config, job_id)
        return jsonify(data)

    # ============================================================================
    # Interfaces Endpoints
    # ============================================================================

    @app.route('/api/interfaces')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def interfaces_info():
        """API endpoint for interface information"""
        debug("=== Interfaces API endpoint called ===")
        firewall_config = get_firewall_config()
        data = get_interface_info(firewall_config)
        debug(f"Interfaces API returning {len(data.get('interfaces', []))} interfaces")
        return jsonify(data)

    @app.route('/api/interface-traffic')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def interface_traffic():
        """API endpoint for per-interface traffic counters"""
        debug("=== Interface Traffic API endpoint called ===")
        counters = get_interface_traffic_counters()
        return jsonify({'status': 'success', 'counters': counters})

    # ============================================================================
    # Settings Endpoint
    # ============================================================================

    @app.route('/api/settings', methods=['GET', 'POST'])
    @limiter.limit("600 per hour")  # Support frequent settings reads
    @login_required
    def settings():
        """API endpoint for settings"""
        if request.method == 'GET':
            # Return current settings
            settings_data = load_settings()
            return jsonify({
                'status': 'success',
                'settings': settings_data
            })
        elif request.method == 'POST':
            # Save new settings
            try:
                new_settings = request.get_json()
                debug(f"=== POST /api/settings called ===")
                debug(f"Received settings: {new_settings}")

                # Validate settings
                refresh_interval = int(new_settings.get('refresh_interval', 60))
                match_count = int(new_settings.get('match_count', 5))
                top_apps_count = int(new_settings.get('top_apps_count', 5))

                # Ensure values are within valid ranges (30s min, 300s max = 5 minutes)
                refresh_interval = max(30, min(300, refresh_interval))
                match_count = max(1, min(20, match_count))
                top_apps_count = max(1, min(10, top_apps_count))

                # Get debug logging setting
                debug_logging = new_settings.get('debug_logging', False)

                # Get selected device ID (for multi-device support)
                selected_device_id = new_settings.get('selected_device_id', '')
                debug(f"selected_device_id to save: {selected_device_id}")

                # Get monitored interface
                monitored_interface = new_settings.get('monitored_interface', 'ethernet1/12')
                debug(f"monitored_interface to save: {monitored_interface}")

                # Get Tony Mode setting (disable session timeout)
                tony_mode = new_settings.get('tony_mode', False)
                debug(f"tony_mode to save: {tony_mode}")

                # Get timezone setting
                timezone = new_settings.get('timezone', 'UTC')
                debug(f"timezone to save: {timezone}")

                settings_data = {
                    'refresh_interval': refresh_interval,
                    'match_count': match_count,
                    'top_apps_count': top_apps_count,
                    'debug_logging': debug_logging,
                    'selected_device_id': selected_device_id,
                    'monitored_interface': monitored_interface,
                    'tony_mode': tony_mode,
                    'timezone': timezone
                }

                if save_settings(settings_data):
                    return jsonify({
                        'status': 'success',
                        'message': 'Settings saved successfully',
                        'settings': settings_data
                    })
                else:
                    return jsonify({
                        'status': 'error',
                        'message': 'Failed to save settings'
                    }), 500
            except Exception as e:
                debug(f"Error in settings endpoint: {e}")
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 400

    debug("Operational routes registered successfully")
