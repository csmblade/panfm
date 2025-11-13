"""
Flask route handlers for operational endpoints
Handles logs, applications, interfaces, licenses, settings, and tech support
"""
from flask import jsonify, request, render_template, send_from_directory
from datetime import datetime
import os
from auth import login_required
from config import load_settings, save_settings, load_notification_channels, save_notification_channels
from firewall_api import (
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
from throughput_collector import get_collector


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
        """API endpoint for system logs - reads from database (Phase 3: Database-First)"""
        debug("=== System Logs API endpoint called (DATABASE-FIRST) ===")
        try:
            settings = load_settings()
            device_id = settings.get('selected_device_id')
            debug(f"Selected device ID from settings: {device_id or 'NONE'}")

            if not device_id:
                return jsonify({
                    'status': 'error',
                    'message': 'No device selected',
                    'logs': []
                })

            # Get collector instance
            collector = get_collector()
            if not collector:
                debug("Collector not initialized, returning empty logs")
                return jsonify({
                    'status': 'error',
                    'message': 'Collector not initialized',
                    'logs': []
                })

            # Read logs from database
            limit = request.args.get('limit', 50, type=int)
            logs = collector.storage.get_system_logs(device_id, limit=limit)

            debug(f"Retrieved {len(logs)} system logs from database")

            return jsonify({
                'status': 'success',
                'logs': logs,
                'total': len(logs),
                'timestamp': datetime.now().isoformat(),
                'source': 'database'  # Indicate data source
            }), 200, {'Cache-Control': 'max-age=60', 'X-Data-Source': 'database'}

        except Exception as e:
            error(f"Error retrieving system logs from database: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'logs': []
            })

    @app.route('/api/traffic-logs')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def traffic_logs_api():
        """API endpoint for traffic logs - reads from database (Phase 3: Database-First)"""
        debug("=== Traffic Logs API endpoint called (DATABASE-FIRST) ===")
        try:
            settings = load_settings()
            device_id = settings.get('selected_device_id')
            debug(f"Selected device ID from settings: {device_id or 'NONE'}")

            if not device_id:
                return jsonify({
                    'status': 'error',
                    'message': 'No device selected',
                    'logs': []
                })

            # Get collector instance
            collector = get_collector()
            if not collector:
                debug("Collector not initialized, returning empty logs")
                return jsonify({
                    'status': 'error',
                    'message': 'Collector not initialized',
                    'logs': []
                })

            # Read logs from database
            limit = request.args.get('limit', 50, type=int)
            logs = collector.storage.get_traffic_logs(device_id, limit=limit)

            debug(f"Retrieved {len(logs)} traffic logs from database")

            return jsonify({
                'status': 'success',
                'logs': logs,
                'total': len(logs),
                'timestamp': datetime.now().isoformat(),
                'source': 'database'  # Indicate data source
            }), 200, {'Cache-Control': 'max-age=60', 'X-Data-Source': 'database'}

        except Exception as e:
            error(f"Error retrieving traffic logs from database: {str(e)}")
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
        """
        API endpoint for application statistics - DATABASE ONLY

        Returns cached application data from database (collected every 15 seconds by APScheduler).
        NO firewall fallback - forces use of database to ensure fast performance.
        """
        debug("=== Applications API endpoint called (database-only) ===")
        try:
            from config import load_settings
            settings = load_settings()
            device_id = settings.get('selected_device_id', '')

            if not device_id:
                return jsonify({
                    'status': 'error',
                    'message': 'No device selected',
                    'applications': [],
                    'summary': {
                        'total_applications': 0,
                        'total_sessions': 0,
                        'total_bytes': 0,
                        'vlans_detected': 0,
                        'zones_detected': 0
                    },
                    'total': 0,
                    'source': 'none'
                })

            # Get data from database ONLY
            from throughput_collector import get_collector
            collector = get_collector()

            if not collector or not collector.storage:
                return jsonify({
                    'status': 'error',
                    'message': 'Database collector not initialized',
                    'applications': [],
                    'summary': {
                        'total_applications': 0,
                        'total_sessions': 0,
                        'total_bytes': 0,
                        'vlans_detected': 0,
                        'zones_detected': 0
                    },
                    'total': 0,
                    'source': 'error'
                })

            # Get latest application statistics from database
            applications = collector.storage.get_application_statistics(device_id, limit=500)
            summary = collector.storage.get_application_summary(device_id)

            if applications:
                debug(f"Retrieved {len(applications)} applications from DATABASE")
            else:
                debug("No application data in database yet - waiting for APScheduler collection")

            return jsonify({
                'status': 'success',
                'applications': applications,
                'summary': summary,
                'total': len(applications),
                'timestamp': datetime.now().isoformat(),
                'source': 'database'
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
                'total': 0,
                'source': 'error'
            })

    @app.route('/api/top-category')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def top_category_api():
        """
        API endpoint for top application category by volume.

        Supports time range parameter for historical aggregation.
        Query params:
            range: Time range (1h, 6h, 24h, 7d, 30d) or omit for latest snapshot

        Returns:
            JSON with status, category name, and bytes volume
        """
        debug("=== Top Category API endpoint called ===")
        try:
            from config import load_settings
            settings = load_settings()
            device_id = settings.get('selected_device_id', '')

            if not device_id:
                return jsonify({
                    'status': 'error',
                    'message': 'No device selected',
                    'category': None,
                    'bytes': 0
                })

            # Get time range parameter
            time_range = request.args.get('range', None)
            debug(f"Time range parameter: {time_range}")

            # Get data from database
            from throughput_collector import get_collector
            collector = get_collector()

            if not collector or not collector.storage:
                return jsonify({
                    'status': 'error',
                    'message': 'Database collector not initialized',
                    'category': None,
                    'bytes': 0
                })

            # Get top category for time range
            result = collector.storage.get_top_category_for_range(device_id, time_range)

            if result and 'category' in result:
                debug(f"Top category: {result['category']} with {result['bytes']} bytes")
                return jsonify({
                    'status': 'success',
                    'category': result['category'],
                    'bytes': result['bytes'],
                    'timestamp': datetime.now().isoformat(),
                    'range': time_range or 'latest'
                })
            else:
                debug("No category data available")
                return jsonify({
                    'status': 'success',
                    'category': None,
                    'bytes': 0,
                    'timestamp': datetime.now().isoformat(),
                    'range': time_range or 'latest'
                })

        except Exception as e:
            error(f"Error in top category API: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'category': None,
                'bytes': 0
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
    # Collector Status Endpoint (Phase 5)
    # ============================================================================

    @app.route('/api/collector/status')
    @limiter.limit("600 per hour")
    @login_required
    def collector_status():
        """API endpoint for throughput collector status and statistics"""
        debug("=== Collector Status API endpoint called ===")
        try:
            settings = load_settings()

            # Get collector instance
            collector = get_collector()
            if not collector:
                return jsonify({
                    'status': 'error',
                    'message': 'Collector not initialized',
                    'enabled': False
                })

            # Get collector stats
            collector_stats = collector.get_collector_stats()

            # Get database stats
            storage_stats = collector_stats.get('storage', {})

            # Get all devices to count monitored devices
            from device_manager import device_manager
            devices = device_manager.load_devices()
            enabled_devices = [d for d in devices if d.get('enabled', True)]

            # Build response
            response = {
                'status': 'success',
                'enabled': settings.get('throughput_collection_enabled', True),
                'interval_seconds': settings.get('refresh_interval', 60),
                'last_run': None,  # Would need to track this in collector
                'last_run_duration_ms': None,  # Would need to track this
                'total_collections': collector_stats.get('collection_count', 0),
                'failed_collections': 0,  # Would need to track failures
                'success_rate': 100.0,  # Would need failure tracking
                'database_size_mb': storage_stats.get('db_size_mb', 0),
                'sample_count': storage_stats.get('total_samples', 0),
                'retention_days': settings.get('throughput_retention_days', 90),
                'devices_monitored': len(enabled_devices),
                'last_cleanup': collector_stats.get('last_cleanup'),
                'timestamp': datetime.now().isoformat()
            }

            debug(f"Collector status: {response['total_collections']} collections, {response['devices_monitored']} devices")

            return jsonify(response)

        except Exception as e:
            error(f"Error retrieving collector status: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'enabled': False
            })

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

    # ============================================================================
    # Notification Channel Settings Endpoints
    # ============================================================================

    @app.route('/api/settings/notifications', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_notification_settings():
        """Get all notification channel configurations"""
        try:
            debug("=== GET /api/settings/notifications called ===")
            channels = load_notification_channels()
            return jsonify({
                'status': 'success',
                'channels': channels
            })
        except Exception as e:
            error(f"Failed to load notification channels: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/settings/notifications/email', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def save_email_notification_settings():
        """Save email notification configuration"""
        try:
            debug("=== POST /api/settings/notifications/email called ===")
            email_config = request.get_json()

            # Validate required fields
            if not email_config:
                return jsonify({
                    'status': 'error',
                    'message': 'Email configuration is required'
                }), 400

            # Load existing channels
            channels = load_notification_channels()

            # Update email config
            channels['email'] = {
                'enabled': email_config.get('enabled', False),
                'smtp_host': email_config.get('smtp_host', ''),
                'smtp_port': email_config.get('smtp_port', 587),
                'smtp_user': email_config.get('smtp_user', ''),
                'smtp_password': email_config.get('smtp_password', ''),
                'from_email': email_config.get('from_email', ''),
                'to_emails': email_config.get('to_emails', []),
                'use_tls': email_config.get('use_tls', True)
            }

            # Save channels
            if save_notification_channels(channels):
                # Reload notification manager config
                from notification_manager import notification_manager
                notification_manager.reload_config()

                debug("Email notification settings saved successfully")
                return jsonify({
                    'status': 'success',
                    'message': 'Email notification settings saved successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save email notification settings'
                }), 500
        except Exception as e:
            error(f"Failed to save email notification settings: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/settings/notifications/slack', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def save_slack_notification_settings():
        """Save Slack notification configuration"""
        try:
            debug("=== POST /api/settings/notifications/slack called ===")
            slack_config = request.get_json()

            # Validate required fields
            if not slack_config:
                return jsonify({
                    'status': 'error',
                    'message': 'Slack configuration is required'
                }), 400

            # Load existing channels
            channels = load_notification_channels()

            # Update Slack config
            channels['slack'] = {
                'enabled': slack_config.get('enabled', False),
                'webhook_url': slack_config.get('webhook_url', ''),
                'channel': slack_config.get('channel', '#alerts'),
                'username': slack_config.get('username', 'PANfm Alerts')
            }

            # Save channels
            if save_notification_channels(channels):
                # Reload notification manager config
                from notification_manager import notification_manager
                notification_manager.reload_config()

                debug("Slack notification settings saved successfully")
                return jsonify({
                    'status': 'success',
                    'message': 'Slack notification settings saved successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save Slack notification settings'
                }), 500
        except Exception as e:
            error(f"Failed to save Slack notification settings: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/settings/notifications/webhook', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def save_webhook_notification_settings():
        """Save webhook notification configuration"""
        try:
            debug("=== POST /api/settings/notifications/webhook called ===")
            webhook_config = request.get_json()

            # Validate required fields
            if not webhook_config:
                return jsonify({
                    'status': 'error',
                    'message': 'Webhook configuration is required'
                }), 400

            # Load existing channels
            channels = load_notification_channels()

            # Update webhook config
            channels['webhook'] = {
                'enabled': webhook_config.get('enabled', False),
                'url': webhook_config.get('url', ''),
                'headers': webhook_config.get('headers', {})
            }

            # Save channels
            if save_notification_channels(channels):
                # Reload notification manager config
                from notification_manager import notification_manager
                notification_manager.reload_config()

                debug("Webhook notification settings saved successfully")
                return jsonify({
                    'status': 'success',
                    'message': 'Webhook notification settings saved successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save webhook notification settings'
                }), 500
        except Exception as e:
            error(f"Failed to save webhook notification settings: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/settings/notifications/test/<channel>', methods=['POST'])
    @limiter.limit("20 per hour")
    @login_required
    def test_notification_channel(channel):
        """Test notification channel by sending a test message"""
        try:
            debug(f"=== POST /api/settings/notifications/test/{channel} called ===")
            from notification_manager import notification_manager

            if channel == 'email':
                result = notification_manager.test_email()
            elif channel == 'slack':
                result = notification_manager.test_slack()
            elif channel == 'webhook':
                result = notification_manager.test_webhook()
            else:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid notification channel: {channel}'
                }), 400

            return jsonify(result)
        except Exception as e:
            error(f"Failed to test notification channel {channel}: {e}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    debug("Operational routes registered successfully")
