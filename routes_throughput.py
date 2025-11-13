"""
Flask route handlers for throughput data and history
Handles throughput metrics, historical data queries, exports, and statistics
"""
from flask import jsonify, request, Response
from datetime import datetime, timedelta
import io
import csv
from auth import login_required
from config import load_settings
from logger import debug, exception, warning


def register_throughput_routes(app, csrf, limiter):
    """Register throughput data and history routes"""
    debug("Registering throughput routes")

    @app.route('/api/throughput')
    @limiter.limit("600 per hour")  # Support auto-refresh (configurable interval)
    @login_required
    def throughput():
        """API endpoint for throughput data (reads from database, not firewall)

        Query parameters:
            range (optional): Time range for historical data (30m, 1h, 6h, 24h, 7d, 30d)
                             If not specified, returns latest real-time sample
        """
        from throughput_collector import get_collector

        # Check if range parameter is provided for historical data
        time_range = request.args.get('range')

        debug(f"=== Throughput API endpoint called (database-first, range={time_range}) ===")
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
                from datetime import datetime
                return jsonify({
                    'error': 'Throughput collection not enabled',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',  # Add current timestamp
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

            # If time range is specified, aggregate threat/URL data from that period
            if time_range:
                debug(f"Time range specified: {time_range}, aggregating logs...")

                # Parse time range to get start time
                range_map = {
                    '30m': 30 * 60,
                    '1h': 60 * 60,
                    '6h': 6 * 60 * 60,
                    '24h': 24 * 60 * 60,
                    '7d': 7 * 24 * 60 * 60,
                    '30d': 30 * 24 * 60 * 60
                }

                seconds = range_map.get(time_range, 60 * 60)  # Default to 1 hour
                start_time = datetime.now() - timedelta(seconds=seconds)
                start_timestamp = start_time.isoformat()

                debug(f"Fetching logs from {start_timestamp} onwards ({time_range})")

                # Get logs for the specified time range (fetch more to ensure coverage)
                critical_logs = storage.get_threat_logs(device_id, severity='critical', limit=500)
                medium_logs = storage.get_threat_logs(device_id, severity='medium', limit=500)
                url_logs = storage.get_url_filtering_logs(device_id, limit=500)

                # Filter logs by timestamp (only include logs within the time range)
                def filter_by_time(logs, start_ts):
                    filtered = []
                    for log in logs:
                        try:
                            log_time = datetime.fromisoformat(log.get('time', ''))
                            if log_time >= start_time:
                                filtered.append(log)
                        except (ValueError, TypeError):
                            pass  # Skip logs with invalid timestamps
                    return filtered

                critical_logs = filter_by_time(critical_logs, start_timestamp)
                medium_logs = filter_by_time(medium_logs, start_timestamp)
                url_logs = filter_by_time(url_logs, start_timestamp)

                debug(f"Filtered logs: {len(critical_logs)} critical, {len(medium_logs)} medium, {len(url_logs)} URL")

                # Get latest sample for throughput/sessions/CPU data
                latest_sample = storage.get_latest_sample(device_id, max_age_seconds=seconds)

                if latest_sample is None:
                    # No throughput data, create minimal response with just log data
                    latest_sample = {
                        'timestamp': datetime.now().isoformat(),
                        'inbound_mbps': 0,
                        'outbound_mbps': 0,
                        'total_mbps': 0,
                        'inbound_pps': 0,
                        'outbound_pps': 0,
                        'total_pps': 0,
                        'sessions': {'active': 0, 'tcp': 0, 'udp': 0, 'icmp': 0},
                        'cpu': {'data_plane_cpu': 0, 'mgmt_plane_cpu': 0, 'memory_used_pct': 0}
                    }

                # Override threats with aggregated historical data
                latest_sample['threats'] = {
                    'critical_threats': len(critical_logs),
                    'medium_threats': len(medium_logs),
                    'blocked_urls': len(url_logs),
                    'critical_logs': critical_logs[:50],  # Limit to 50 for modal display
                    'medium_logs': medium_logs[:50],
                    'blocked_url_logs': url_logs[:50],
                    'critical_last_seen': critical_logs[0]['time'] if critical_logs else None,
                    'medium_last_seen': medium_logs[0]['time'] if medium_logs else None,
                    'blocked_url_last_seen': url_logs[0]['time'] if url_logs else None
                }

                debug(f"Historical aggregation complete: {len(critical_logs)} critical, {len(medium_logs)} medium, {len(url_logs)} URL")
            else:
                # Real-time mode: Query latest sample from database (use 2x refresh_interval as max age to allow for timing variance)
                max_age_seconds = refresh_interval * 2
                latest_sample = storage.get_latest_sample(device_id, max_age_seconds=max_age_seconds)

            if latest_sample is None:
                debug("No recent throughput data in database, returning zeros")
                # Return zero values if no recent data (collector may be starting up)
                from datetime import datetime
                return jsonify({
                    'status': 'success',
                    'timestamp': datetime.utcnow().isoformat() + 'Z',  # Add current timestamp
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
            # (Skip sanitization if we're in historical mode - already populated above)
            if not time_range:
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
            from datetime import datetime
            return jsonify({
                'error': 'Failed to retrieve throughput data',
                'timestamp': datetime.utcnow().isoformat() + 'Z',  # Add current timestamp
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

    debug("Throughput routes registered successfully")
