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

            # Get APScheduler status (now runs in separate clock.py process)
            # First try direct stats from database (Priority 2)
            collector = get_collector()
            settings = load_settings()
            refresh_interval = settings.get('refresh_interval', 60)

            if collector is not None:
                storage = collector.storage

                # Try to get direct scheduler stats from database
                scheduler_stats = storage.get_latest_scheduler_stats()

                if scheduler_stats:
                    # Direct stats available from clock process!
                    result['scheduler']['state'] = scheduler_stats['state'].title()
                    result['scheduler']['total_executions'] = scheduler_stats['total_executions']
                    result['scheduler']['total_errors'] = scheduler_stats['total_errors']
                    result['scheduler']['last_execution'] = scheduler_stats['last_execution']
                    result['scheduler']['last_error'] = scheduler_stats['last_error']
                    result['scheduler']['last_error_time'] = scheduler_stats['last_error_time']
                    result['scheduler']['uptime_seconds'] = scheduler_stats['uptime_seconds']
                    result['scheduler']['execution_history'] = scheduler_stats['execution_history']
                    result['scheduler']['next_collection'] = f"Every {refresh_interval}s"
                    result['scheduler']['data_source'] = 'direct'  # Indicate we have direct stats

                    # Format uptime as human-readable
                    uptime_seconds = scheduler_stats['uptime_seconds']
                    hours = uptime_seconds // 3600
                    minutes = (uptime_seconds % 3600) // 60
                    result['scheduler']['uptime_formatted'] = f"{hours}h {minutes}m"
                else:
                    # Fall back to inference from database activity
                    device_id = settings.get('selected_device_id', '')
                    max_age = refresh_interval * 2  # Allow some buffer

                    if device_id:
                        latest_sample = storage.get_latest_sample(device_id, max_age_seconds=max_age)
                        if latest_sample:
                            result['scheduler']['state'] = 'Running (Inferred)'
                            result['scheduler']['last_collection'] = latest_sample['timestamp']
                            result['scheduler']['next_collection'] = f"Every {refresh_interval}s"
                        else:
                            result['scheduler']['state'] = 'No Recent Data'
                            result['scheduler']['last_collection'] = 'None in last 2 minutes'
                            result['scheduler']['next_collection'] = f"Expected every {refresh_interval}s"
                    else:
                        result['scheduler']['state'] = 'No Device Selected'
                        result['scheduler']['last_collection'] = 'N/A'
                        result['scheduler']['next_collection'] = f"Expected every {refresh_interval}s"

                    result['scheduler']['data_source'] = 'inferred'  # Indicate we're inferring

                # Add known job information from clock.py
                # Include per-job stats if available
                job_stats = scheduler_stats.get('jobs', {}) if scheduler_stats else {}

                result['jobs'] = [
                    {
                        'id': 'throughput_collection',
                        'name': 'Throughput Data Collection',
                        'description': 'Collects firewall metrics (throughput, CPU, memory, sessions, logs, interfaces, applications)',
                        'trigger': f'Every {refresh_interval} seconds',
                        'status': 'Active in clock process',
                        'data_collected': 'Throughput, system resources, sessions, threat stats, traffic logs, applications, licenses',
                        'success_count': job_stats.get('throughput_collection', {}).get('success_count', 0),
                        'error_count': job_stats.get('throughput_collection', {}).get('error_count', 0),
                        'last_run': job_stats.get('throughput_collection', {}).get('last_run'),
                        'last_error': job_stats.get('throughput_collection', {}).get('last_error')
                    },
                    {
                        'id': 'connected_devices_collection',
                        'name': 'Connected Devices Collection',
                        'description': 'Collects ARP entries from firewall and stores in database with hostname/metadata enrichment',
                        'trigger': f'Every {refresh_interval} seconds',
                        'status': 'Active in clock process',
                        'data_collected': 'IP addresses, MAC addresses, hostnames, VLANs, interfaces, zones, vendor info',
                        'success_count': job_stats.get('connected_devices_collection', {}).get('success_count', 0),
                        'error_count': job_stats.get('connected_devices_collection', {}).get('error_count', 0),
                        'last_run': job_stats.get('connected_devices_collection', {}).get('last_run'),
                        'last_error': job_stats.get('connected_devices_collection', {}).get('last_error')
                    },
                    {
                        'id': 'database_cleanup',
                        'name': 'Database Cleanup',
                        'description': f'Removes data older than {settings.get("throughput_retention_days", 90)} days: throughput samples, traffic logs, system logs, resolved alerts, and expired alert cooldowns',
                        'trigger': 'Daily at 02:00 UTC',
                        'status': 'Active in clock process',
                        'data_collected': 'N/A (maintenance job)',
                        'success_count': job_stats.get('database_cleanup', {}).get('success_count', 0),
                        'error_count': job_stats.get('database_cleanup', {}).get('error_count', 0),
                        'last_run': job_stats.get('database_cleanup', {}).get('last_run'),
                        'last_error': job_stats.get('database_cleanup', {}).get('last_error')
                    },
                    {
                        'id': 'persist_scheduler_stats',
                        'name': 'Scheduler Stats Persistence',
                        'description': 'Writes scheduler statistics to database every 60 seconds for monitoring',
                        'trigger': 'Every 60 seconds',
                        'status': 'Active in clock process',
                        'data_collected': 'Scheduler execution stats, job counts, errors'
                    }
                ]
            else:
                result['scheduler']['state'] = 'Collector Not Initialized'
                result['scheduler']['last_collection'] = 'N/A'
                result['scheduler']['next_collection'] = 'N/A'

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

    @app.route('/api/system/collect-now', methods=['POST'])
    @limiter.limit("20 per hour")  # Allow manual triggers for testing
    @login_required
    def manual_collection_trigger():
        """API endpoint to manually trigger throughput collection (for testing/debugging)"""
        from throughput_collector import get_collector
        from datetime import datetime

        debug("=== Manual Collection Trigger API endpoint called ===")

        try:
            collector = get_collector()
            if collector is None:
                return jsonify({
                    'status': 'error',
                    'message': 'Throughput collector not initialized'
                }), 503

            # Trigger collection
            start_time = datetime.utcnow()
            info(f"Manual collection triggered by user {session.get('username', 'unknown')}")

            try:
                collector.collect_all_devices()
                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()

                info(f"Manual collection completed in {duration:.2f}s")

                return jsonify({
                    'status': 'success',
                    'message': 'Collection completed successfully',
                    'duration_seconds': round(duration, 2),
                    'timestamp': end_time.isoformat()
                })

            except Exception as e:
                end_time = datetime.utcnow()
                duration = (end_time - start_time).total_seconds()

                exception(f"Manual collection failed after {duration:.2f}s: {str(e)}")

                return jsonify({
                    'status': 'error',
                    'message': f'Collection failed: {str(e)}',
                    'duration_seconds': round(duration, 2)
                }), 500

        except Exception as e:
            exception(f"Failed to trigger manual collection: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    debug("System health and services routes registered successfully")
