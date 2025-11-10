"""
Flask route handlers for system health and services
Handles health checks, version info, services status, and database management
"""
from flask import jsonify, session
from datetime import datetime
import sqlite3
from auth import login_required
from config import load_settings
from firewall_api import get_firewall_config, check_firewall_health
from logger import debug, error, exception, info
from version import get_version_info


def register_system_routes(app, csrf, limiter):
    """Register system health and services routes"""
    debug("Registering system health and services routes")

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

    debug("System health and services routes registered successfully")
