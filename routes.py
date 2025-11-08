"""
Flask route handlers for the Palo Alto Firewall Dashboard
"""
from flask import render_template, jsonify, request, send_from_directory, session, send_file
from datetime import datetime
import os
import json
from config import load_settings, save_settings, save_vendor_database, get_vendor_db_info, save_service_port_database, get_service_port_db_info, load_service_port_database
from device_manager import device_manager
from auth import login_required, verify_password, create_session, destroy_session, change_password, must_change_password
from device_metadata import (
    load_metadata,
    save_metadata,
    get_device_metadata,
    update_device_metadata,
    delete_device_metadata,
    get_all_tags,
    get_all_locations,
    import_metadata,
    check_migration_needed,
    migrate_global_to_per_device
)
from backup_restore import (
    create_full_backup,
    restore_from_backup,
    export_backup_to_file,
    import_backup_from_file,
    get_backup_info
)
from firewall_api import (
    get_throughput_data,
    get_system_logs,
    get_traffic_logs,
    get_software_updates,
    get_license_info,
    get_connected_devices,
    get_firewall_config,
    get_device_uptime,
    get_device_version,
    get_application_statistics,
    generate_tech_support_file,
    check_tech_support_job_status,
    get_tech_support_file_url,
    get_interface_info,
    get_interface_traffic_counters,
    check_available_panos_versions,
    download_panos_version,
    install_panos_version,
    check_job_status,
    reboot_firewall,
    check_firewall_health,
    check_content_updates,
    download_content_update,
    install_content_update
)
from logger import debug, info, error
from utils import reverse_dns_lookup
from version import get_version_info, get_display_version

def register_routes(app, csrf, limiter):
    """Register all Flask routes with authentication, CSRF protection, and rate limiting"""

    # ============================================================================
    # Authentication Routes (no @login_required)
    # ============================================================================

    @app.route('/login')
    @csrf.exempt  # Exempt login page from CSRF (form has its own token)
    def login_page():
        """Serve the login page"""
        return render_template('login.html')

    @app.route('/api/login', methods=['POST'])
    @csrf.exempt  # Exempt login API from CSRF (not yet authenticated)
    @limiter.limit("5 per minute")  # Strict rate limit on login attempts
    def login():
        """Handle login authentication"""
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')

            if not username or not password:
                return jsonify({
                    'status': 'error',
                    'message': 'Username and password are required'
                }), 400

            if verify_password(username, password):
                create_session(username)

                # Check if password must be changed
                if must_change_password():
                    return jsonify({
                        'status': 'success',
                        'message': 'Login successful - password change required',
                        'must_change_password': True
                    })

                return jsonify({
                    'status': 'success',
                    'message': 'Login successful'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid username or password'
                }), 401
        except Exception as e:
            error(f"Login error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Login failed'
            }), 500

    @app.route('/api/logout', methods=['POST'])
    @login_required
    def logout():
        """Handle logout"""
        destroy_session()
        return jsonify({
            'status': 'success',
            'message': 'Logged out successfully'
        })

    @app.route('/api/session-keepalive', methods=['GET'])
    @limiter.limit("600 per hour")  # Support frequent keepalive pings
    @login_required
    def session_keepalive():
        """Session keepalive endpoint for Tony Mode - refreshes session expiry"""
        # Simply accessing this endpoint with @login_required refreshes the session
        # Flask automatically updates session.modified when accessed
        return jsonify({
            'status': 'success',
            'message': 'Session refreshed'
        })

    @app.route('/api/change-password', methods=['POST'])
    @login_required
    @limiter.limit("3 per hour")
    def change_password_route():
        """Handle password change"""
        try:
            data = request.get_json()
            old_password = data.get('old_password', '')
            new_password = data.get('new_password', '')

            if not old_password or not new_password:
                return jsonify({
                    'status': 'error',
                    'message': 'Old and new passwords are required'
                }), 400

            if len(new_password) < 8:
                return jsonify({
                    'status': 'error',
                    'message': 'New password must be at least 8 characters'
                }), 400

            username = session.get('username')
            success, message = change_password(username, old_password, new_password)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': message
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': message
                }), 400
        except Exception as e:
            error(f"Password change error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Failed to change password'
            }), 500

    # ============================================================================
    # Protected Routes (require authentication)
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

    @app.route('/api/throughput')
    @limiter.limit("600 per hour")  # Support auto-refresh (configurable interval)
    @login_required
    def throughput():
        """API endpoint for throughput data (reads from database, not firewall)"""
        from throughput_collector import get_collector

        debug("=== Throughput API endpoint called (database-first) ===")
        settings = load_settings()
        device_id = settings.get('selected_device_id', '')
        refresh_interval = settings.get('refresh_interval', 60)

        # If no device selected, auto-select the first enabled device
        if not device_id:
            from device_manager import device_manager
            devices = device_manager.load_devices()
            enabled_devices = [d for d in devices if d.get('enabled', True)]
            if enabled_devices:
                device_id = enabled_devices[0].get('id')
                debug(f"No device selected, auto-selected first enabled device: {device_id}")
            else:
                debug("No enabled devices found")

        debug(f"Using device ID: {device_id if device_id else 'NONE'}")
        debug(f"Refresh interval: {refresh_interval}s")

        try:
            # Get collector and storage
            collector = get_collector()
            if collector is None:
                warning("Throughput collector not initialized")
                return jsonify({
                    'error': 'Throughput collection not enabled',
                    'inbound_mbps': 0,
                    'outbound_mbps': 0,
                    'total_mbps': 0,
                    'inbound_pps': 0,
                    'outbound_pps': 0,
                    'total_pps': 0,
                    'sessions': {'active': 0, 'tcp': 0, 'udp': 0, 'icmp': 0},
                    'cpu': {'data_plane_cpu': 0, 'mgmt_plane_cpu': 0, 'memory_used_pct': 0}
                }), 503

            storage = collector.storage

            # Query latest sample from database (use 2x refresh_interval as max age to allow for timing variance)
            max_age_seconds = refresh_interval * 2
            latest_sample = storage.get_latest_sample(device_id, max_age_seconds=max_age_seconds)

            if latest_sample is None:
                debug("No recent throughput data in database, returning zeros")
                # Return zero values if no recent data (collector may be starting up)
                return jsonify({
                    'status': 'success',
                    'inbound_mbps': 0,
                    'outbound_mbps': 0,
                    'total_mbps': 0,
                    'inbound_pps': 0,
                    'outbound_pps': 0,
                    'total_pps': 0,
                    'sessions': {'active': 0, 'tcp': 0, 'udp': 0, 'icmp': 0},
                    'cpu': {'data_plane_cpu': 0, 'mgmt_plane_cpu': 0, 'memory_used_pct': 0},
                    'note': 'Waiting for collector data'
                })

            debug(f"Returning latest sample from database: {latest_sample['timestamp']}")
            # Add status field for frontend compatibility
            latest_sample['status'] = 'success'

            # Ensure all numeric fields have valid values (convert None to 0)
            numeric_fields = [
                'inbound_mbps', 'outbound_mbps', 'total_mbps',
                'inbound_pps', 'outbound_pps', 'total_pps'
            ]
            for field in numeric_fields:
                if latest_sample.get(field) is None:
                    latest_sample[field] = 0
                # Also convert to float to ensure it's a number
                latest_sample[field] = float(latest_sample[field]) if latest_sample[field] is not None else 0.0

            # Ensure nested objects exist with defaults and sanitize their values
            if not latest_sample.get('sessions'):
                latest_sample['sessions'] = {}
            sessions = latest_sample['sessions']
            sessions['active'] = int(sessions.get('active') or 0)
            sessions['tcp'] = int(sessions.get('tcp') or 0)
            sessions['udp'] = int(sessions.get('udp') or 0)
            sessions['icmp'] = int(sessions.get('icmp') or 0)

            if not latest_sample.get('cpu'):
                latest_sample['cpu'] = {}
            cpu = latest_sample['cpu']
            cpu['data_plane_cpu'] = float(cpu.get('data_plane_cpu') or 0)
            cpu['mgmt_plane_cpu'] = float(cpu.get('mgmt_plane_cpu') or 0)
            cpu['memory_used_pct'] = float(cpu.get('memory_used_pct') or 0)

            # Ensure threats object exists with defaults and sanitize values
            if not latest_sample.get('threats'):
                latest_sample['threats'] = {}
            threats = latest_sample['threats']
            threats['critical_threats'] = int(threats.get('critical_threats') or threats.get('critical') or 0)
            threats['medium_threats'] = int(threats.get('medium_threats') or threats.get('medium') or 0)
            threats['blocked_urls'] = int(threats.get('blocked_urls') or 0)
            threats['critical_logs'] = threats.get('critical_logs') or []
            threats['medium_logs'] = threats.get('medium_logs') or []
            threats['blocked_url_logs'] = threats.get('blocked_url_logs') or []

            return jsonify(latest_sample)

        except Exception as e:
            exception(f"Failed to retrieve throughput from database: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve throughput data',
                'inbound_mbps': 0,
                'outbound_mbps': 0,
                'total_mbps': 0,
                'inbound_pps': 0,
                'outbound_pps': 0,
                'total_pps': 0,
                'sessions': {'active': 0, 'tcp': 0, 'udp': 0, 'icmp': 0},
                'cpu': {'data_plane_cpu': 0, 'mgmt_plane_cpu': 0, 'memory_used_pct': 0}
            }), 500

    @app.route('/api/throughput/history')
    @limiter.limit("600 per hour")  # Support frequent queries for historical data
    @login_required
    def throughput_history():
        """API endpoint for historical throughput data"""
        from throughput_collector import get_collector
        from datetime import datetime, timedelta

        debug("=== Throughput History API endpoint called ===")

        try:
            # Get query parameters
            device_id = request.args.get('device_id')
            time_range = request.args.get('range', '24h')  # Default: 24 hours
            resolution = request.args.get('resolution', 'auto')  # auto, raw, hourly, daily

            # Validate device_id
            if not device_id:
                settings = load_settings()
                device_id = settings.get('selected_device_id')
                if not device_id:
                    return jsonify({'status': 'error', 'message': 'No device specified'}), 400

            debug(f"Query params: device_id={device_id}, range={time_range}, resolution={resolution}")

            # Parse time range
            now = datetime.utcnow()
            range_map = {
                '30m': timedelta(minutes=30),
                '1h': timedelta(hours=1),
                '6h': timedelta(hours=6),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7),
                '30d': timedelta(days=30),
                '90d': timedelta(days=90)
            }

            if time_range in range_map:
                start_time = now - range_map[time_range]
            else:
                # Try to parse as custom range (ISO format)
                try:
                    start_time = datetime.fromisoformat(request.args.get('start'))
                    end_time = datetime.fromisoformat(request.args.get('end'))
                    now = end_time
                except (ValueError, TypeError):
                    return jsonify({'status': 'error', 'message': 'Invalid time range'}), 400

            # Auto-determine resolution based on time range
            if resolution == 'auto':
                time_delta = now - start_time
                if time_delta <= timedelta(hours=6):
                    resolution = 'raw'  # Raw data for short ranges
                elif time_delta <= timedelta(days=7):
                    resolution = 'hourly'  # Hourly for week
                else:
                    resolution = 'daily'  # Daily for longer periods
                debug(f"Auto-selected resolution: {resolution} for range {time_delta}")

            # Get collector and query data
            collector = get_collector()
            if not collector:
                return jsonify({'status': 'error', 'message': 'Collector not initialized'}), 500

            samples = collector.storage.query_samples(
                device_id=device_id,
                start_time=start_time,
                end_time=now,
                resolution=resolution
            )

            debug(f"Retrieved {len(samples)} samples for device {device_id}")

            return jsonify({
                'status': 'success',
                'device_id': device_id,
                'start_time': start_time.isoformat(),
                'end_time': now.isoformat(),
                'resolution': resolution,
                'sample_count': len(samples),
                'samples': samples
            })

        except Exception as e:
            exception(f"Failed to retrieve throughput history: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/throughput/history/export')
    @limiter.limit("100 per hour")  # Lower limit for export operations
    @login_required
    def throughput_history_export():
        """Export historical throughput data to CSV"""
        from throughput_collector import get_collector
        from datetime import datetime, timedelta
        import io
        import csv
        from flask import Response

        debug("=== Throughput History Export API endpoint called ===")

        try:
            # Get query parameters
            device_id = request.args.get('device_id')
            time_range = request.args.get('range', '24h')

            # Validate device_id
            if not device_id:
                settings = load_settings()
                device_id = settings.get('selected_device_id')
                if not device_id:
                    return jsonify({'status': 'error', 'message': 'No device specified'}), 400

            # Parse time range
            now = datetime.utcnow()
            range_map = {
                '1h': timedelta(hours=1),
                '6h': timedelta(hours=6),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7),
                '30d': timedelta(days=30),
                '90d': timedelta(days=90)
            }

            if time_range in range_map:
                start_time = now - range_map[time_range]
            else:
                return jsonify({'status': 'error', 'message': 'Invalid time range'}), 400

            # Get collector and query data
            collector = get_collector()
            if not collector:
                return jsonify({'status': 'error', 'message': 'Collector not initialized'}), 500

            samples = collector.storage.query_samples(
                device_id=device_id,
                start_time=start_time,
                end_time=now,
                resolution='raw'  # Always export raw data
            )

            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)

            # Write header
            writer.writerow([
                'Timestamp', 'Inbound (Mbps)', 'Outbound (Mbps)', 'Total (Mbps)',
                'Inbound (PPS)', 'Outbound (PPS)', 'Total (PPS)',
                'Active Sessions', 'TCP Sessions', 'UDP Sessions', 'ICMP Sessions',
                'Data Plane CPU (%)', 'Mgmt Plane CPU (%)', 'Memory Used (%)'
            ])

            # Write data rows
            for sample in samples:
                writer.writerow([
                    sample['timestamp'],
                    sample.get('inbound_mbps', ''),
                    sample.get('outbound_mbps', ''),
                    sample.get('total_mbps', ''),
                    sample.get('inbound_pps', ''),
                    sample.get('outbound_pps', ''),
                    sample.get('total_pps', ''),
                    sample.get('sessions', {}).get('active', ''),
                    sample.get('sessions', {}).get('tcp', ''),
                    sample.get('sessions', {}).get('udp', ''),
                    sample.get('sessions', {}).get('icmp', ''),
                    sample.get('cpu', {}).get('data_plane_cpu', ''),
                    sample.get('cpu', {}).get('mgmt_plane_cpu', ''),
                    sample.get('cpu', {}).get('memory_used_pct', '')
                ])

            # Create response
            output.seek(0)
            filename = f"throughput_export_{device_id}_{time_range}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )

        except Exception as e:
            exception(f"Failed to export throughput history: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/throughput/history/stats')
    @limiter.limit("600 per hour")  # Same as history endpoint
    @login_required
    def throughput_history_stats():
        """Get statistics (min/max/avg) for historical throughput data"""
        from throughput_collector import get_collector
        from datetime import datetime, timedelta

        debug("=== Throughput History Stats API endpoint called ===")

        try:
            # Get query parameters
            device_id = request.args.get('device_id')
            time_range = request.args.get('range', '24h')

            # Validate device_id
            if not device_id:
                settings = load_settings()
                device_id = settings.get('selected_device_id')
                if not device_id:
                    return jsonify({'status': 'error', 'message': 'No device specified'}), 400

            # Parse time range
            now = datetime.utcnow()
            range_map = {
                '1h': timedelta(hours=1),
                '6h': timedelta(hours=6),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7),
                '30d': timedelta(days=30),
                '90d': timedelta(days=90)
            }

            if time_range in range_map:
                start_time = now - range_map[time_range]
            else:
                return jsonify({'status': 'error', 'message': 'Invalid time range'}), 400

            # Get collector and query data
            collector = get_collector()
            if not collector:
                return jsonify({'status': 'error', 'message': 'Collector not initialized'}), 500

            samples = collector.storage.query_samples(
                device_id=device_id,
                start_time=start_time,
                end_time=now,
                resolution='raw'
            )

            if not samples:
                return jsonify({
                    'status': 'success',
                    'device_id': device_id,
                    'time_range': time_range,
                    'sample_count': 0,
                    'stats': None
                })

            # Calculate statistics
            inbound_values = [s.get('inbound_mbps', 0) for s in samples if s.get('inbound_mbps') is not None]
            outbound_values = [s.get('outbound_mbps', 0) for s in samples if s.get('outbound_mbps') is not None]
            total_values = [s.get('total_mbps', 0) for s in samples if s.get('total_mbps') is not None]

            stats = {
                'inbound_mbps': {
                    'min': round(min(inbound_values), 2) if inbound_values else 0,
                    'max': round(max(inbound_values), 2) if inbound_values else 0,
                    'avg': round(sum(inbound_values) / len(inbound_values), 2) if inbound_values else 0
                },
                'outbound_mbps': {
                    'min': round(min(outbound_values), 2) if outbound_values else 0,
                    'max': round(max(outbound_values), 2) if outbound_values else 0,
                    'avg': round(sum(outbound_values) / len(outbound_values), 2) if outbound_values else 0
                },
                'total_mbps': {
                    'min': round(min(total_values), 2) if total_values else 0,
                    'max': round(max(total_values), 2) if total_values else 0,
                    'avg': round(sum(total_values) / len(total_values), 2) if total_values else 0
                }
            }

            return jsonify({
                'status': 'success',
                'device_id': device_id,
                'time_range': time_range,
                'sample_count': len(samples),
                'stats': stats
            })

        except Exception as e:
            exception(f"Failed to retrieve throughput statistics: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/health')
    @limiter.limit("600 per hour")  # Support frequent health checks
    @login_required
    def health():
        """Health check endpoint"""
        return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

    @app.route('/api/firewall-health')
    @limiter.limit("300 per hour")  # 5/min for 15s polling during reboot monitoring
    @login_required
    def firewall_health_check():
        """Lightweight firewall health check - does NOT trigger update server connections"""
        debug("=== Firewall Health Check API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_firewall_health(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in firewall health check: {str(e)}")
            return jsonify({'status': 'offline', 'message': str(e)}), 500

    @app.route('/api/version')
    def version():
        """Version information endpoint (public - no auth required)"""
        return jsonify(get_version_info())

    @app.route('/api/services/status')
    @limiter.limit("600 per hour")
    @login_required
    def services_status():
        """API endpoint for system services status (APScheduler + Database)"""
        from throughput_collector import get_collector
        import os

        debug("=== Services Status API endpoint called ===")

        try:
            result = {
                'status': 'success',
                'scheduler': {},
                'database': {},
                'jobs': [],
                'device_stats': []
            }

            # Get APScheduler status
            # Import global scheduler from app.py
            from app import scheduler

            if scheduler is not None:
                result['scheduler']['state'] = 'Running' if scheduler.running else 'Stopped'
                result['scheduler']['jobs_count'] = len(scheduler.get_jobs())

                # Get job details
                jobs = scheduler.get_jobs()
                for job in jobs:
                    job_info = {
                        'id': job.id,
                        'name': job.name,
                        'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                        'trigger': str(job.trigger)
                    }
                    result['jobs'].append(job_info)

                # Get last run time from storage
                collector = get_collector()
                if collector is not None:
                    storage = collector.storage
                    settings = load_settings()
                    device_id = settings.get('selected_device_id', '')

                    if device_id:
                        latest_sample = storage.get_latest_sample(device_id, max_age_seconds=7200)  # 2 hours
                        if latest_sample:
                            result['scheduler']['last_run'] = latest_sample['timestamp']
                        else:
                            result['scheduler']['last_run'] = None
                    else:
                        result['scheduler']['last_run'] = None
                else:
                    result['scheduler']['last_run'] = None
            else:
                result['scheduler']['state'] = 'Not Initialized'
                result['scheduler']['jobs_count'] = 0

            # Get Database status
            collector = get_collector()
            if collector is not None:
                storage = collector.storage
                db_path = storage.db_path

                if os.path.exists(db_path):
                    # Get database file size
                    db_size_bytes = os.path.getsize(db_path)
                    if db_size_bytes < 1024:
                        db_size_str = f"{db_size_bytes} bytes"
                    elif db_size_bytes < 1024 * 1024:
                        db_size_str = f"{db_size_bytes / 1024:.2f} KB"
                    else:
                        db_size_str = f"{db_size_bytes / (1024 * 1024):.2f} MB"

                    result['database']['state'] = 'Connected'
                    result['database']['size'] = db_size_str
                    result['database']['path'] = db_path

                    # Get total sample count
                    import sqlite3
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM throughput_samples")
                    total_samples = cursor.fetchone()[0]
                    result['database']['total_samples'] = total_samples

                    # Get oldest sample timestamp
                    cursor.execute("SELECT MIN(timestamp) FROM throughput_samples")
                    oldest = cursor.fetchone()[0]
                    result['database']['oldest_sample'] = oldest

                    # Get per-device statistics
                    cursor.execute("""
                        SELECT device_id, COUNT(*) as sample_count, MIN(timestamp) as oldest, MAX(timestamp) as newest
                        FROM throughput_samples
                        GROUP BY device_id
                        ORDER BY sample_count DESC
                    """)
                    device_rows = cursor.fetchall()

                    from device_manager import device_manager
                    devices = device_manager.load_devices()
                    device_map = {d['id']: d['name'] for d in devices}

                    for row in device_rows:
                        device_id, sample_count, oldest, newest = row
                        device_name = device_map.get(device_id, device_id)
                        result['device_stats'].append({
                            'device_id': device_id,
                            'device_name': device_name,
                            'sample_count': sample_count,
                            'oldest': oldest,
                            'newest': newest
                        })

                    conn.close()
                else:
                    result['database']['state'] = 'File Not Found'
                    result['database']['size'] = '0 bytes'
                    result['database']['path'] = db_path
            else:
                result['database']['state'] = 'Not Initialized'

            return jsonify(result)

        except Exception as e:
            exception(f"Failed to get services status: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/database/clear', methods=['POST'])
    @limiter.limit("5 per hour")  # Very strict limit for destructive operation
    @login_required
    def clear_database():
        """API endpoint to clear all data from throughput history database"""
        from throughput_collector import get_collector
        import sqlite3

        debug("=== Clear Database API endpoint called ===")

        try:
            collector = get_collector()
            if collector is None:
                return jsonify({
                    'status': 'error',
                    'message': 'Throughput collector not initialized'
                }), 503

            storage = collector.storage
            db_path = storage.db_path

            # Count rows before deletion
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM throughput_samples")
            count_before = cursor.fetchone()[0]

            # Delete all rows
            cursor.execute("DELETE FROM throughput_samples")
            conn.commit()

            # Verify deletion
            cursor.execute("SELECT COUNT(*) FROM throughput_samples")
            count_after = cursor.fetchone()[0]

            # Run VACUUM to reclaim disk space
            cursor.execute("VACUUM")
            conn.commit()
            conn.close()

            deleted_count = count_before - count_after

            info(f"Database cleared: {deleted_count} samples deleted by user {session.get('username', 'unknown')}")

            return jsonify({
                'status': 'success',
                'message': 'Database cleared successfully',
                'deleted_count': deleted_count
            })

        except Exception as e:
            exception(f"Failed to clear database: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

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

    @app.route('/api/license')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def license_info():
        """API endpoint for license information"""
        firewall_config = get_firewall_config()
        data = get_license_info(firewall_config)
        return jsonify(data)

    @app.route('/api/connected-devices')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def connected_devices_api():
        """API endpoint for connected devices (ARP entries)"""
        debug("=== Connected Devices API endpoint called ===")
        try:
            firewall_config = get_firewall_config()
            devices = get_connected_devices(firewall_config)
            debug(f"Retrieved {len(devices)} devices from firewall")
            return jsonify({
                'status': 'success',
                'devices': devices,
                'total': len(devices),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            error(f"Error in connected devices API: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'devices': [],
                'total': 0
            })

    @app.route('/api/dhcp-leases')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def dhcp_leases_api():
        """API endpoint for DHCP lease information"""
        debug("=== DHCP Leases API endpoint called ===")
        try:
            firewall_config = get_firewall_config()

            # Import DHCP function
            from firewall_api_dhcp import get_dhcp_leases_detailed

            leases = get_dhcp_leases_detailed(firewall_config)
            debug(f"Retrieved {len(leases)} DHCP lease(s) from firewall")

            return jsonify({
                'status': 'success',
                'leases': leases,
                'total': len(leases),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            error(f"Error in DHCP leases API: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'leases': [],
                'total': 0
            })

    # ============================================================================
    # Device Metadata Endpoints
    # ============================================================================

    @app.route('/api/device-metadata', methods=['GET'])
    @limiter.limit("600 per hour")  # Support bulk loading on page load
    @login_required
    def get_all_device_metadata():
        """Get all device metadata (for bulk loading on page load)"""
        debug("=== Get all device metadata API endpoint called ===")
        try:
            metadata = load_metadata()
            debug(f"Retrieved metadata for {len(metadata)} devices")
            return jsonify({
                'status': 'success',
                'metadata': metadata
            })
        except Exception as e:
            error(f"Error loading device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'metadata': {}
            }), 500

    @app.route('/api/device-metadata/<mac>', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_single_device_metadata(mac):
        """Get metadata for a specific MAC address"""
        debug(f"=== Get device metadata for MAC: {mac} ===")
        try:
            metadata = get_device_metadata(mac)
            if metadata:
                return jsonify({
                    'status': 'success',
                    'metadata': metadata
                })
            else:
                return jsonify({
                    'status': 'success',
                    'metadata': None,
                    'message': 'No metadata found for this MAC address'
                })
        except Exception as e:
            error(f"Error getting device metadata for {mac}: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata', methods=['POST'])
    @login_required
    @limiter.limit("100 per hour")  # Device management category
    def create_or_update_device_metadata():
        """Create or update device metadata (requires CSRF token)"""
        debug("=== Create/update device metadata API endpoint called ===")
        try:
            data = request.get_json()
            
            if not data or 'mac' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'MAC address is required'
                }), 400
            
            mac = data.get('mac')
            name = data.get('name')
            comment = data.get('comment')
            location = data.get('location')
            tags = data.get('tags')
            
            # Validate tags is a list if provided
            if tags is not None and not isinstance(tags, list):
                return jsonify({
                    'status': 'error',
                    'message': 'Tags must be a list'
                }), 400
            
            success = update_device_metadata(mac, name=name, comment=comment, location=location, tags=tags)
            
            if success:
                # Force reload cache to ensure latest data
                from device_metadata import reload_metadata_cache
                reload_metadata_cache()
                
                # Return updated metadata
                updated_metadata = get_device_metadata(mac)
                return jsonify({
                    'status': 'success',
                    'metadata': updated_metadata,
                    'message': 'Metadata saved successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save metadata'
                }), 500
        except Exception as e:
            error(f"Error saving device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata/<mac>', methods=['DELETE'])
    @login_required
    @limiter.limit("100 per hour")  # Device management category
    def delete_device_metadata_endpoint(mac):
        """Delete device metadata (requires CSRF token)"""
        debug(f"=== Delete device metadata for MAC: {mac} ===")
        try:
            success = delete_device_metadata(mac)
            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Metadata deleted successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to delete metadata'
                }), 500
        except Exception as e:
            error(f"Error deleting device metadata for {mac}: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata/tags', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_all_device_tags():
        """Get all unique tags across all devices"""
        debug("=== Get all device tags API endpoint called ===")
        try:
            tags = get_all_tags()
            return jsonify({
                'status': 'success',
                'tags': tags
            })
        except Exception as e:
            error(f"Error getting device tags: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'tags': []
            }), 500

    @app.route('/api/device-metadata/locations', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_all_device_locations():
        """Get all unique locations across all devices"""
        debug("=== Get all device locations API endpoint called ===")
        try:
            locations = get_all_locations()
            return jsonify({
                'status': 'success',
                'locations': locations
            })
        except Exception as e:
            error(f"Error getting device locations: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'locations': []
            }), 500

    @app.route('/api/device-metadata/export', methods=['GET'])
    @limiter.limit("100 per hour")
    @login_required
    def export_device_metadata():
        """Export device metadata as JSON backup file"""
        debug("=== Device metadata export endpoint called ===")
        try:
            # Load decrypted metadata
            metadata = load_metadata(use_cache=False)  # Force reload to get latest
            
            # Create JSON string
            import json
            from io import BytesIO
            from datetime import datetime
            
            # Add export metadata
            export_data = {
                'export_date': datetime.now().isoformat(),
                'version': '1.0',
                'total_devices': len(metadata),
                'metadata': metadata
            }
            
            json_str = json.dumps(export_data, indent=2)
            json_bytes = json_str.encode('utf-8')
            
            # Create BytesIO object for file download
            json_file = BytesIO(json_bytes)
            json_file.seek(0)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'device_metadata_backup_{timestamp}.json'
            
            return send_file(
                json_file,
                mimetype='application/json',
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            error(f"Error exporting device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata/import', methods=['POST'])
    @login_required
    @limiter.limit("50 per hour")  # Limit imports to prevent abuse
    def import_device_metadata():
        """Import device metadata from JSON backup file"""
        debug("=== Device metadata import endpoint called ===")
        try:
            if 'file' not in request.files:
                return jsonify({
                    'status': 'error',
                    'message': 'No file provided'
                }), 400
            
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'message': 'No file selected'
                }), 400
            
            if not file.filename.endswith('.json'):
                return jsonify({
                    'status': 'error',
                    'message': 'File must be a JSON file'
                }), 400
            
            # Read and parse JSON
            try:
                file_content = file.read().decode('utf-8')
                import_data = json.loads(file_content)
            except json.JSONDecodeError as e:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid JSON file: {str(e)}'
                }), 400
            
            # Extract metadata from import data
            # Support both old format (direct metadata dict) and new format (with export metadata)
            if 'metadata' in import_data:
                metadata_to_import = import_data['metadata']
                debug(f"Importing metadata from backup file (version: {import_data.get('version', 'unknown')}, export date: {import_data.get('export_date', 'unknown')})")
            elif isinstance(import_data, dict):
                # Assume it's a metadata dict directly
                metadata_to_import = import_data
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid metadata format in file'
                }), 400
            
            # Validate metadata structure
            if not isinstance(metadata_to_import, dict):
                return jsonify({
                    'status': 'error',
                    'message': 'Metadata must be a dictionary'
                }), 400
            
            # Import metadata (merges with existing)
            success = import_metadata(metadata_to_import)
            
            if success:
                # Reload cache
                from device_metadata import reload_metadata_cache
                reload_metadata_cache()
                
                info(f"Device metadata imported successfully: {len(metadata_to_import)} devices")
                return jsonify({
                    'status': 'success',
                    'message': f'Metadata imported successfully ({len(metadata_to_import)} devices)',
                    'devices_imported': len(metadata_to_import)
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to import metadata'
                }), 500
                
        except Exception as e:
            error(f"Error importing device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

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
    # Device Management API Endpoints
    # ============================================================================

    @app.route('/api/devices', methods=['GET'])
    @limiter.limit("600 per hour")  # Support frequent device list reads
    @login_required
    def get_devices():
        """Get all devices with encrypted API keys"""
        try:
            # Load devices with encrypted API keys for API response (security)
            devices = device_manager.load_devices(decrypt_api_keys=False)
            groups = device_manager.get_groups()

            # Fetch uptime and version for each enabled device
            for device in devices:
                if device.get('enabled', True):
                    try:
                        uptime = get_device_uptime(device['id'])
                        device['uptime'] = uptime if uptime else 'N/A'
                    except Exception as e:
                        debug(f"Error fetching uptime for device {device['id']}: {str(e)}")
                        device['uptime'] = 'N/A'

                    try:
                        version = get_device_version(device['id'])
                        device['version'] = version if version else 'N/A'
                    except Exception as e:
                        debug(f"Error fetching version for device {device['id']}: {str(e)}")
                        device['version'] = 'N/A'
                else:
                    device['uptime'] = 'Disabled'
                    device['version'] = 'N/A'

            return jsonify({
                'status': 'success',
                'devices': devices,
                'groups': groups
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices', methods=['POST'])
    @login_required
    @limiter.limit("100 per hour")
    def create_device():
        """Add a new device and manage selected_device_id"""
        debug("Create device request received")
        try:
            data = request.get_json()
            name = data.get('name', '').strip()
            ip = data.get('ip', '').strip()
            api_key = data.get('api_key', '').strip()
            group = data.get('group', 'Default')
            description = data.get('description', '')
            wan_interface = data.get('wan_interface', '').strip()

            debug(f"Adding new device: name={name}, ip={ip}, group={group}")

            # Validate required fields
            if not name or not ip or not api_key:
                debug("Validation failed: missing required fields")
                return jsonify({
                    'status': 'error',
                    'message': 'Name, IP, and API Key are required'
                }), 400

            # Get device count before adding
            existing_devices = device_manager.load_devices(decrypt_api_keys=False)
            was_first_device = len(existing_devices) == 0
            debug(f"Existing device count: {len(existing_devices)}, is_first_device: {was_first_device}")

            new_device = device_manager.add_device(name, ip, api_key, group, description, wan_interface=wan_interface)
            debug(f"Device added successfully: {new_device['name']} ({new_device['id']})")

            # Auto-select this device if it's the first device OR no device is currently selected
            settings = load_settings()
            current_selected = settings.get('selected_device_id', '')
            auto_selected = False

            # Check if current selection is valid
            if current_selected:
                # Verify the currently selected device still exists
                selected_device_exists = device_manager.get_device(current_selected) is not None
                debug(f"Current selected device {current_selected} exists: {selected_device_exists}")
                if not selected_device_exists:
                    current_selected = ''

            if not current_selected or was_first_device:
                settings['selected_device_id'] = new_device['id']
                save_settings(settings)
                auto_selected = True
                info(f"Auto-selected device {new_device['name']} ({new_device['id']}) - first_device={was_first_device}, no_selection={not current_selected}")
                debug(f"Updated selected_device_id to: {new_device['id']}")
            else:
                debug(f"Device not auto-selected. Current selection: {current_selected}")

            return jsonify({
                'status': 'success',
                'device': new_device,
                'auto_selected': auto_selected,
                'message': 'Device added successfully'
            })
        except Exception as e:
            exception(f"Error creating device: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>', methods=['GET'])
    @login_required
    def get_device(device_id):
        """Get a specific device with encrypted API key"""
        try:
            # Get all devices with encrypted keys, then find the specific one
            devices = device_manager.load_devices(decrypt_api_keys=False)
            device = next((d for d in devices if d.get('id') == device_id), None)
            if device:
                return jsonify({
                    'status': 'success',
                    'device': device
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Device not found'
                }), 404
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>', methods=['PUT'])
    @login_required
    @limiter.limit("100 per hour")
    def update_device(device_id):
        """Update a device"""
        try:
            data = request.get_json()

            # If api_key is empty or not provided, remove it from updates to preserve existing key
            if 'api_key' in data and not data['api_key']:
                debug("API key is empty, removing from updates to preserve existing key")
                del data['api_key']

            updated_device = device_manager.update_device(device_id, data)
            if updated_device:
                return jsonify({
                    'status': 'success',
                    'device': updated_device,
                    'message': 'Device updated successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Device not found'
                }), 404
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>', methods=['DELETE'])
    @login_required
    @limiter.limit("100 per hour")
    def delete_device(device_id):
        """Delete a device and manage selected_device_id"""
        debug(f"Delete device request for device_id: {device_id}")
        try:
            # Get device info before deleting for logging
            device_to_delete = device_manager.get_device(device_id)
            device_name = device_to_delete.get('name', 'unknown') if device_to_delete else 'unknown'

            success = device_manager.delete_device(device_id)
            if success:
                debug(f"Device {device_name} ({device_id}) deleted successfully")

                # Check if the deleted device was the selected one
                settings = load_settings()
                was_selected = settings.get('selected_device_id') == device_id
                debug(f"Deleted device was selected: {was_selected}")

                if was_selected:
                    # Get remaining devices (use load_devices, not decrypt for API responses)
                    remaining_devices = device_manager.load_devices(decrypt_api_keys=False)
                    debug(f"Remaining devices after deletion: {len(remaining_devices)}")

                    if remaining_devices:
                        # Select the first remaining device
                        new_selected_id = remaining_devices[0]['id']
                        new_selected_name = remaining_devices[0]['name']
                        settings['selected_device_id'] = new_selected_id
                        save_settings(settings)
                        info(f"Deleted device was selected. Auto-selected device {new_selected_name} ({new_selected_id})")
                        debug(f"Updated selected_device_id to: {new_selected_id}")
                    else:
                        # No devices left, clear selection
                        settings['selected_device_id'] = ''
                        save_settings(settings)
                        info("Deleted last device. Cleared device selection")
                        debug("Cleared selected_device_id (no devices remaining)")

                return jsonify({
                    'status': 'success',
                    'message': 'Device deleted successfully'
                })
            else:
                error(f"Failed to delete device {device_id}")
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to delete device'
                }), 500
        except Exception as e:
            exception(f"Error deleting device {device_id}: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>/test', methods=['POST'])
    @login_required
    def test_device_connection(device_id):
        """Test connection to a device"""
        try:
            device = device_manager.get_device(device_id)
            if not device:
                return jsonify({
                    'status': 'error',
                    'message': 'Device not found'
                }), 404

            result = device_manager.test_connection(device['ip'], device['api_key'])
            return jsonify({
                'status': 'success' if result['success'] else 'error',
                'message': result['message']
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/test-connection', methods=['POST'])
    @login_required
    def test_new_device_connection():
        """Test connection to a device (before saving)"""
        try:
            data = request.get_json()
            ip = data.get('ip', '').strip()
            api_key = data.get('api_key', '').strip()

            if not ip or not api_key:
                return jsonify({
                    'status': 'error',
                    'message': 'IP and API Key are required'
                }), 400

            result = device_manager.test_connection(ip, api_key)
            return jsonify({
                'status': 'success' if result['success'] else 'error',
                'message': result['message']
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/vendor-db/info', methods=['GET'])
    @login_required
    def vendor_db_info():
        """API endpoint to get vendor database information"""
        debug("=== Vendor DB info endpoint called ===")
        try:
            db_info = get_vendor_db_info()
            return jsonify({
                'status': 'success',
                'info': db_info
            })
        except Exception as e:
            error(f"Error getting vendor DB info: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/vendor-db/upload', methods=['POST'])
    @login_required
    @limiter.limit("20 per hour")
    def vendor_db_upload():
        """API endpoint to upload vendor database"""
        debug("=== Vendor DB upload endpoint called ===")
        try:
            if 'file' not in request.files:
                return jsonify({
                    'status': 'error',
                    'message': 'No file provided'
                }), 400
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'message': 'No file selected'
                }), 400
            if not file.filename.endswith('.json'):
                return jsonify({
                    'status': 'error',
                    'message': 'File must be a JSON file'
                }), 400

            # Read and parse JSON
            content = file.read().decode('utf-8')
            vendor_data = json.loads(content)

            # Validate structure
            if not isinstance(vendor_data, list):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid format: Expected JSON array'
                }), 400

            if len(vendor_data) == 0:
                return jsonify({
                    'status': 'error',
                    'message': 'Database is empty'
                }), 400

            # Check first entry has required fields
            first_entry = vendor_data[0]
            if 'macPrefix' not in first_entry or 'vendorName' not in first_entry:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid format: Entries must have "macPrefix" and "vendorName" fields'
                }), 400

            # Save to file
            if save_vendor_database(vendor_data):
                db_info = get_vendor_db_info()
                info(f"Vendor database uploaded successfully: {db_info['entries']} entries, {db_info['size_mb']} MB")
                return jsonify({
                    'status': 'success',
                    'message': f'Vendor database uploaded successfully ({db_info["entries"]} entries)',
                    'info': db_info
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save vendor database'
                }), 500

        except json.JSONDecodeError as e:
            error(f"Invalid JSON in vendor DB upload: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid JSON format'
            }), 400
        except Exception as e:
            error(f"Error uploading vendor DB: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/service-port-db/info', methods=['GET'])
    @login_required
    def service_port_db_info():
        """API endpoint to get service port database information"""
        debug("=== Service port DB info endpoint called ===")
        try:
            db_info = get_service_port_db_info()
            return jsonify({
                'status': 'success',
                'info': db_info
            })
        except Exception as e:
            error(f"Error getting service port DB info: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/service-port-db/upload', methods=['POST'])
    @login_required
    @limiter.limit("20 per hour")
    def service_port_db_upload():
        """API endpoint to upload service port database (IANA XML)"""
        debug("=== Service port DB upload endpoint called ===")
        try:
            if 'file' not in request.files:
                return jsonify({
                    'status': 'error',
                    'message': 'No file provided'
                }), 400
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'message': 'No file selected'
                }), 400
            if not file.filename.endswith('.xml'):
                return jsonify({
                    'status': 'error',
                    'message': 'File must be an XML file'
                }), 400

            # Read XML content
            content = file.read().decode('utf-8')

            # Parse XML and convert to JSON structure
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)

            # Build service port dictionary
            # Format: {port: {'tcp': {'name': 'http', 'description': '...'}, 'udp': {...}}}
            service_dict = {}

            for record in root.findall('.//{http://www.iana.org/assignments}record'):
                name_elem = record.find('{http://www.iana.org/assignments}name')
                protocol_elem = record.find('{http://www.iana.org/assignments}protocol')
                number_elem = record.find('{http://www.iana.org/assignments}number')
                desc_elem = record.find('{http://www.iana.org/assignments}description')

                # Skip if missing required fields
                if protocol_elem is None or number_elem is None:
                    continue

                protocol = protocol_elem.text
                port_str = number_elem.text

                # Skip if protocol or port is None
                if protocol is None or port_str is None:
                    continue

                # Handle port ranges (e.g., "8000-8100")
                if '-' in port_str:
                    continue  # Skip ranges for now

                try:
                    port = int(port_str)
                except ValueError:
                    continue  # Skip invalid port numbers

                # Get service name and description
                service_name = name_elem.text if name_elem is not None and name_elem.text else ''
                description = desc_elem.text if desc_elem is not None and desc_elem.text else ''

                # Initialize port entry if it doesn't exist
                port_key = str(port)
                if port_key not in service_dict:
                    service_dict[port_key] = {}

                # Add protocol-specific info
                service_dict[port_key][protocol.lower()] = {
                    'name': service_name,
                    'description': description
                }

            if len(service_dict) == 0:
                return jsonify({
                    'status': 'error',
                    'message': 'No valid service port entries found in XML'
                }), 400

            # Save to file
            if save_service_port_database(service_dict):
                db_info = get_service_port_db_info()
                info(f"Service port database uploaded successfully: {db_info['entries']} port entries, {db_info['size_mb']} MB")
                return jsonify({
                    'status': 'success',
                    'message': f'Service port database uploaded successfully ({db_info["entries"]} ports)',
                    'info': db_info
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save service port database'
                }), 500

        except ET.ParseError as e:
            error(f"Invalid XML in service port DB upload: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid XML format'
            }), 400
        except Exception as e:
            error(f"Error uploading service port DB: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/service-port-db/data', methods=['GET'])
    @login_required
    def service_port_db_data():
        """API endpoint to get service port database data"""
        debug("=== Service port DB data endpoint called ===")
        try:
            service_data = load_service_port_database()
            return jsonify({
                'status': 'success',
                'data': service_data
            })
        except Exception as e:
            error(f"Error loading service port DB data: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'data': {}
            }), 500

    @app.route('/api/reverse-dns', methods=['POST'])
    @login_required
    def reverse_dns_api():
        """
        Perform reverse DNS lookups on a list of IP addresses.

        Request body:
            {
                "ip_addresses": ["8.8.8.8", "1.1.1.1", ...],
                "timeout": 2  (optional, default: 2)
            }

        Response:
            {
                "status": "success",
                "results": {
                    "8.8.8.8": "dns.google",
                    "1.1.1.1": "one.one.one.one",
                    ...
                }
            }
        """
        debug("=== Reverse DNS API endpoint called ===")
        try:
            data = request.get_json()
            ip_addresses = data.get('ip_addresses', [])
            timeout = data.get('timeout', 2)

            # Validate input
            if not isinstance(ip_addresses, list):
                return jsonify({
                    'status': 'error',
                    'message': 'ip_addresses must be a list'
                }), 400

            if len(ip_addresses) == 0:
                return jsonify({
                    'status': 'success',
                    'results': {}
                })

            debug("Processing reverse DNS lookup for %d IP addresses", len(ip_addresses))

            # Perform reverse DNS lookups
            results = reverse_dns_lookup(ip_addresses, timeout)

            debug("Reverse DNS lookup completed successfully")
            return jsonify({
                'status': 'success',
                'results': results
            })

        except Exception as e:
            error(f"Error performing reverse DNS lookup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    # PAN-OS Upgrade API Routes
    @app.route('/api/panos-versions', methods=['GET'])
    @limiter.limit("100 per hour")  # Allow reasonable number of version checks
    @login_required
    def get_panos_versions():
        """Get available PAN-OS versions"""
        debug("=== PAN-OS Versions API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_available_panos_versions(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error checking PAN-OS versions: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/download', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow retries and multiple download operations
    @login_required
    def download_panos():
        """Download a specific PAN-OS version"""
        debug("=== PAN-OS Download API endpoint called ===")
        try:
            data = request.get_json()
            version = data.get('version')

            if not version:
                return jsonify({'status': 'error', 'message': 'Version parameter required'}), 400

            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = download_panos_version(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error downloading PAN-OS: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/install', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow retries and testing
    @login_required
    def install_panos():
        """Install a downloaded PAN-OS version"""
        debug("=== PAN-OS Install API endpoint called ===")
        try:
            data = request.get_json()
            version = data.get('version')

            if not version:
                return jsonify({'status': 'error', 'message': 'Version parameter required'}), 400

            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = install_panos_version(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error installing PAN-OS: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/job-status/<job_id>', methods=['GET'])
    @limiter.limit("2000 per hour")  # Very high limit for continuous job polling (4/min sustained = 240/hr, set 8x buffer)
    @login_required
    def get_panos_job_status(job_id):
        """Check the status of a PAN-OS upgrade job"""
        debug(f"=== PAN-OS Job Status API endpoint called for job {job_id} ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                error("No firewall configured for job status check")
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            debug(f"Checking job status for job_id={job_id} on {firewall_ip}")
            result = check_job_status(firewall_ip, api_key, job_id)
            debug(f"Job status result: {result}")
            return jsonify(result)

        except Exception as e:
            error(f"Error checking job status for job {job_id}: {str(e)}")
            import traceback
            error(f"Traceback: {traceback.format_exc()}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/reboot', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow multiple reboots for testing
    @login_required
    def reboot_panos():
        """Reboot the firewall after upgrade"""
        debug("=== PAN-OS Reboot API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = reboot_firewall(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error rebooting firewall: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ============================================================================
    # Content Update API Routes (App & Threat, Antivirus, WildFire)
    # ============================================================================

    @app.route('/api/content-updates/check', methods=['GET'])
    @limiter.limit("100 per hour")
    @login_required
    def check_content_updates_api():
        """Check for available content updates (App & Threat, AV, WildFire)"""
        debug("=== Content Updates Check API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_content_updates(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content updates check: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/content-updates/download', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def download_content_api():
        """Download latest content update"""
        debug("=== Content Update Download API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = download_content_update(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content download: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/content-updates/install', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def install_content_api():
        """Install downloaded content update"""
        debug("=== Content Update Install API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            data = request.get_json() or {}
            version = data.get('version', 'latest')

            result = install_content_update(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content install: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    # ============================================================================
    # Backup & Restore Routes (v1.6.0)
    # ============================================================================

    @app.route('/api/backup/create', methods=['POST'])
    @limiter.limit("20 per hour")
    @login_required
    def create_backup():
        """Create comprehensive site backup (Settings + Devices + Metadata)"""
        debug("=== Create Backup API endpoint called ===")
        try:
            backup_data = create_full_backup()

            if backup_data is None:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to create backup'
                }), 500

            return jsonify({
                'status': 'success',
                'message': 'Backup created successfully',
                'backup': backup_data
            })

        except Exception as e:
            error(f"Error creating backup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500


    @app.route('/api/backup/export', methods=['POST'])
    @limiter.limit("20 per hour")
    @login_required
    def export_backup():
        """Export backup to downloadable JSON file"""
        debug("=== Export Backup API endpoint called ===")
        try:
            # Create backup first
            backup_data = create_full_backup()

            if backup_data is None:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to create backup'
                }), 500

            # Generate timestamped filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"panfm_backup_{timestamp}.json"

            # Return as downloadable file
            return jsonify({
                'status': 'success',
                'message': 'Backup created successfully',
                'filename': filename,
                'data': backup_data
            })

        except Exception as e:
            error(f"Error exporting backup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500


    @app.route('/api/backup/restore', methods=['POST'])
    @limiter.limit("10 per hour")
    @login_required
    def restore_backup():
        """Restore site configuration from backup"""
        debug("=== Restore Backup API endpoint called ===")
        try:
            data = request.get_json()

            if not data or 'backup' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'No backup data provided'
                }), 400

            backup_data = data['backup']

            # Optional: selective restore
            restore_settings = data.get('restore_settings', True)
            restore_devices = data.get('restore_devices', True)
            restore_metadata = data.get('restore_metadata', True)

            result = restore_from_backup(
                backup_data,
                restore_settings=restore_settings,
                restore_devices=restore_devices,
                restore_metadata=restore_metadata
            )

            if result['success']:
                return jsonify({
                    'status': 'success',
                    'message': 'Restore completed successfully',
                    'restored': result['restored']
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Restore completed with errors',
                    'restored': result['restored'],
                    'errors': result['errors']
                }), 500

        except Exception as e:
            error(f"Error restoring backup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500


    @app.route('/api/backup/info', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def backup_info():
        """Get information about a backup file"""
        debug("=== Backup Info API endpoint called ===")
        try:
            data = request.get_json()

            if not data or 'backup' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'No backup data provided'
                }), 400

            backup_data = data['backup']
            info = get_backup_info(backup_data)

            return jsonify({
                'status': 'success',
                'info': info
            })

        except Exception as e:
            error(f"Error getting backup info: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500


    @app.route('/api/metadata/migration/check', methods=['GET'])
    @limiter.limit("100 per hour")
    @login_required
    def check_metadata_migration():
        """Check if metadata needs migration from global to per-device format"""
        debug("=== Check Metadata Migration API endpoint called ===")
        try:
            needs_migration = check_migration_needed()

            return jsonify({
                'status': 'success',
                'needs_migration': needs_migration
            })

        except Exception as e:
            error(f"Error checking migration status: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500


    @app.route('/api/metadata/migration/migrate', methods=['POST'])
    @limiter.limit("10 per hour")
    @login_required
    def migrate_metadata():
        """Migrate metadata from global to per-device format"""
        debug("=== Migrate Metadata API endpoint called ===")
        try:
            data = request.get_json() or {}
            target_device_id = data.get('device_id')

            success = migrate_global_to_per_device(target_device_id)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Metadata migrated successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Migration failed'
                }), 500

        except Exception as e:
            error(f"Error migrating metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
