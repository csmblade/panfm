"""
Alert Management System for PANfm
Handles alert configurations, threshold checking, and notification dispatch
"""
import sys
import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from logger import debug, info, warning, error, exception

# Alert database file
ALERTS_DB_FILE = os.path.join(os.path.dirname(__file__), 'alerts.db')


class AlertManager:
    """
    Manages alert configurations, threshold checking, and alert history.

    Responsibilities:
    - CRUD operations for alert configurations
    - Threshold evaluation against current metrics
    - Alert history management
    - Maintenance window handling
    - Notification channel management
    """

    def __init__(self, db_path: str = ALERTS_DB_FILE, throughput_db_path: str = None):
        """
        Initialize alert manager with database connection.

        Args:
            db_path: Path to alerts SQLite database
            throughput_db_path: Path to throughput history database (for category rolling window queries)
        """
        self.db_path = db_path
        self.throughput_db_path = throughput_db_path or os.path.join(os.path.dirname(__file__), 'throughput_history.db')
        debug(f"AlertManager initialized with alerts database: {db_path}")
        debug(f"AlertManager throughput database: {self.throughput_db_path}")
        self._ensure_database_exists()

    def _ensure_database_exists(self):
        """Create database and tables if they don't exist"""
        debug("Ensuring alerts database exists")
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create alert_configs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    threshold_value REAL NOT NULL,
                    threshold_operator TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    notification_channels TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create alert_history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_config_id INTEGER NOT NULL,
                    device_id TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    threshold_value REAL NOT NULL,
                    actual_value REAL NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged_at TIMESTAMP NULL,
                    acknowledged_by TEXT NULL,
                    resolved_at TIMESTAMP NULL,
                    resolved_reason TEXT NULL,
                    FOREIGN KEY (alert_config_id) REFERENCES alert_configs(id)
                )
            ''')

            # Create maintenance_windows table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS maintenance_windows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT,
                    name TEXT NOT NULL,
                    description TEXT,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create notification_channels table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS notification_channels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    config_json TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create alert_cooldowns table (persistent cooldown tracking)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_cooldowns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    alert_config_id INTEGER NOT NULL,
                    last_triggered_at TIMESTAMP NOT NULL,
                    cooldown_expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(device_id, alert_config_id),
                    FOREIGN KEY (alert_config_id) REFERENCES alert_configs(id) ON DELETE CASCADE
                )
            ''')

            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_config_device ON alert_configs(device_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_history_device ON alert_history(device_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_history_triggered ON alert_history(triggered_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_maintenance_time ON maintenance_windows(start_time, end_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_cooldowns_lookup ON alert_cooldowns(device_id, alert_config_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_cooldowns_expires ON alert_cooldowns(cooldown_expires_at)')

            conn.commit()
            conn.close()
            debug("Alerts database initialized successfully")

        except Exception as e:
            exception(f"Failed to initialize alerts database: {e}")
            raise

    # ===== Alert Configuration Management =====

    def create_alert_config(self, device_id: str, metric_type: str, threshold_value: float,
                          threshold_operator: str, severity: str, notification_channels: List[str],
                          enabled: bool = True) -> Optional[int]:
        """
        Create a new alert configuration.

        Args:
            device_id: Device ID to monitor
            metric_type: Metric to monitor (throughput_in, throughput_out, cpu, memory, sessions, threats)
            threshold_value: Threshold value
            threshold_operator: Comparison operator (>, <, >=, <=, ==)
            severity: Alert severity (critical, warning, info)
            notification_channels: List of notification channels (email, webhook, slack)
            enabled: Whether alert is enabled

        Returns:
            int: Alert config ID if successful, None otherwise
        """
        debug(f"Creating alert config for device {device_id}, metric {metric_type}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            channels_json = json.dumps(notification_channels)

            cursor.execute('''
                INSERT INTO alert_configs
                (device_id, metric_type, threshold_value, threshold_operator, severity,
                 notification_channels, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (device_id, metric_type, threshold_value, threshold_operator, severity,
                  channels_json, enabled))

            alert_id = cursor.lastrowid
            conn.commit()
            conn.close()

            debug(f"Created alert config with ID {alert_id}")
            return alert_id

        except Exception as e:
            exception(f"Failed to create alert config: {e}")
            return None

    def get_alert_configs(self, device_id: Optional[str] = None, enabled_only: bool = False) -> List[Dict]:
        """
        Get alert configurations, optionally filtered by device.

        Args:
            device_id: Filter by device ID (None = all devices)
            enabled_only: Only return enabled alerts

        Returns:
            List of alert configuration dictionaries
        """
        debug(f"Getting alert configs for device: {device_id}, enabled_only: {enabled_only}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = 'SELECT * FROM alert_configs WHERE 1=1'
            params = []

            if device_id:
                query += ' AND device_id = ?'
                params.append(device_id)

            if enabled_only:
                query += ' AND enabled = 1'

            query += ' ORDER BY severity DESC, created_at DESC'

            cursor.execute(query, params)
            rows = cursor.fetchall()

            configs = []
            for row in rows:
                config = dict(row)
                # Parse JSON notification channels
                if config['notification_channels']:
                    config['notification_channels'] = json.loads(config['notification_channels'])
                configs.append(config)

            conn.close()
            debug(f"Retrieved {len(configs)} alert configs")
            return configs

        except Exception as e:
            exception(f"Failed to get alert configs: {e}")
            return []

    def update_alert_config(self, alert_id: int, **kwargs) -> bool:
        """
        Update an alert configuration.

        Args:
            alert_id: Alert config ID
            **kwargs: Fields to update (threshold_value, threshold_operator, severity, enabled, etc.)

        Returns:
            bool: True if successful, False otherwise
        """
        debug(f"Updating alert config {alert_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Build dynamic update query
            update_fields = []
            params = []

            for field in ['threshold_value', 'threshold_operator', 'severity', 'enabled']:
                if field in kwargs:
                    update_fields.append(f'{field} = ?')
                    params.append(kwargs[field])

            if 'notification_channels' in kwargs:
                update_fields.append('notification_channels = ?')
                params.append(json.dumps(kwargs['notification_channels']))

            if not update_fields:
                debug("No fields to update")
                conn.close()
                return False

            # Add updated_at timestamp
            update_fields.append('updated_at = CURRENT_TIMESTAMP')

            # Add alert_id to params
            params.append(alert_id)

            query = f"UPDATE alert_configs SET {', '.join(update_fields)} WHERE id = ?"
            cursor.execute(query, params)

            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()

            debug(f"Alert config {alert_id} updated: {updated}")
            return updated

        except Exception as e:
            exception(f"Failed to update alert config: {e}")
            return False

    def delete_alert_config(self, alert_id: int) -> bool:
        """
        Delete an alert configuration.

        Args:
            alert_id: Alert config ID

        Returns:
            bool: True if successful, False otherwise
        """
        debug(f"Deleting alert config {alert_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM alert_configs WHERE id = ?', (alert_id,))

            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()

            debug(f"Alert config {alert_id} deleted: {deleted}")
            return deleted

        except Exception as e:
            exception(f"Failed to delete alert config: {e}")
            return False

    # ===== Threshold Checking =====

    def _get_top_source_for_application(self, device_id: str, app_name: str) -> dict:
        """
        Query live application statistics to identify top source IP for an application.

        Args:
            device_id: Device ID
            app_name: Application name (e.g., "ssl", "web-browsing", "dns")

        Returns:
            dict: Top source with {'ip': str, 'hostname': str, 'custom_name': str, 'bytes': int} or None
        """
        debug(f"Fetching top source for application {app_name} on device {device_id}")

        try:
            from firewall_api import get_firewall_config
            from firewall_api_applications import get_application_statistics

            # Get firewall config
            firewall_config = get_firewall_config(device_id)

            # Get application statistics
            app_stats = get_application_statistics(firewall_config)
            applications = app_stats.get('applications', [])

            # Find the specific application
            for app in applications:
                if app.get('name') == app_name:
                    # Get sources for this application
                    sources = app.get('sources', [])
                    if not sources:
                        debug(f"No sources found for application {app_name}")
                        return None

                    # Find top source by bytes
                    top_source = max(sources, key=lambda x: x.get('bytes', 0))
                    result = {
                        'ip': top_source.get('ip'),
                        'bytes': top_source.get('bytes', 0),
                        'hostname': top_source.get('original_hostname', top_source.get('hostname', '')),
                        'custom_name': top_source.get('custom_name')
                    }
                    debug(f"Top source for {app_name}: {result['ip']} ({result.get('bytes', 0)} bytes)")
                    return result

            debug(f"Application {app_name} not found in statistics")
            return None

        except Exception as e:
            exception(f"Error getting top source for application: {e}")
            return None

    def _get_application_bytes_5min(self, device_id: str, app_name: str) -> dict:
        """
        Query throughput database for total bytes of a specific application over last 5 minutes.
        Also fetches live traffic data to identify top source IP and hostname.

        Args:
            device_id: Device ID
            app_name: Application name (e.g., "ssl", "web-browsing", "dns")

        Returns:
            dict: {
                'total_mb': float - Total MB for application in 5 minutes,
                'top_source': dict - Top source with {'ip': str, 'hostname': str, 'bytes': int} or None
            }
        """
        debug(f"Querying 5-min application bytes for device {device_id}, application: {app_name}")

        try:
            conn = sqlite3.connect(self.throughput_db_path)
            cursor = conn.cursor()

            # Calculate 5 minutes ago
            five_min_ago = datetime.utcnow() - timedelta(minutes=5)

            # Query for all samples in last 5 minutes
            cursor.execute('''
                SELECT applications_json
                FROM throughput_samples
                WHERE device_id = ?
                AND timestamp >= ?
                ORDER BY timestamp DESC
            ''', (device_id, five_min_ago.isoformat()))

            rows = cursor.fetchall()
            conn.close()

            debug(f"Found {len(rows)} samples in last 5 minutes")

            # Sum bytes for the specified application across all samples
            total_bytes = 0
            for row in rows:
                applications_json_str = row[0]
                if applications_json_str:
                    try:
                        applications = json.loads(applications_json_str)
                        if app_name in applications:
                            app_data = applications[app_name]
                            if isinstance(app_data, dict) and 'bytes' in app_data:
                                total_bytes += app_data['bytes']
                    except json.JSONDecodeError:
                        warning(f"Failed to parse applications_json from database")

            # Convert bytes to MB
            total_mb = total_bytes / (1024 * 1024)
            debug(f"Application {app_name}: {total_bytes} bytes = {total_mb:.2f} MB over 5 minutes")

            # Fetch live traffic data to identify top source IP
            top_source = self._get_top_source_for_application(device_id, app_name)

            return {
                'total_mb': total_mb,
                'top_source': top_source
            }

        except Exception as e:
            exception(f"Error querying application bytes: {e}")
            return {'total_mb': 0.0, 'top_source': None}

    def check_thresholds(self, device_id: str, metrics: Dict[str, float]) -> List[Dict]:
        """
        Check if any thresholds are exceeded for the given metrics.

        Args:
            device_id: Device ID being monitored
            metrics: Dictionary of metric_type -> current value
                     Examples: {'throughput_in': 850.5, 'cpu': 75.2, 'memory': 60.0}

        Returns:
            List of triggered alerts (dicts with config and actual value)
        """
        print(f"[ALERT MANAGER] check_thresholds() called for device: {device_id}")
        sys.stdout.flush()
        debug(f"Checking thresholds for device {device_id} with {len(metrics)} metrics")

        # Check if device is in maintenance window
        if self.is_in_maintenance_window(device_id):
            print(f"[ALERT MANAGER] Device {device_id} is in maintenance window, skipping all alerts")
            sys.stdout.flush()
            debug(f"Device {device_id} is in maintenance window, skipping alerts")
            return []

        triggered_alerts = []

        # Get enabled alert configs for this device
        configs = self.get_alert_configs(device_id=device_id, enabled_only=True)

        print(f"[ALERT MANAGER] Found {len(configs)} enabled alert configs for this device")
        sys.stdout.flush()

        for config in configs:
            metric_type = config['metric_type']

            print(f"[ALERT MANAGER] Evaluating Alert ID {config['id']}:")
            print(f"[ALERT MANAGER]   Metric: {metric_type}")
            print(f"[ALERT MANAGER]   Threshold: {config['threshold_operator']} {config['threshold_value']}")
            sys.stdout.flush()

            # Check if this is an application metric (format: "app_<application_name>")
            top_source_info = None  # Store source info for application alerts
            per_ip_results = None  # Store per-IP bandwidth results

            if metric_type.startswith('app_'):
                # Extract application name (e.g., "app_ssl" -> "ssl")
                app_name = metric_type[len('app_'):]
                print(f"[ALERT MANAGER]   ► Application metric detected: {app_name}")
                print(f"[ALERT MANAGER]   ► Querying 5-minute rolling window from database...")
                sys.stdout.flush()

                # Query database for 5-minute rolling window (returns dict with total_mb and top_source)
                app_result = self._get_application_bytes_5min(device_id, app_name)
                actual_value = app_result['total_mb']
                top_source_info = app_result['top_source']
                print(f"[ALERT MANAGER]   ► 5-min total for {app_name}: {actual_value:.2f} MB")
                if top_source_info:
                    print(f"[ALERT MANAGER]   ► Top source: {top_source_info['ip']} ({top_source_info.get('bytes', 0)} bytes)")
                sys.stdout.flush()
            elif metric_type == 'per_ip_bandwidth_5min':
                # Per-IP bandwidth monitoring (1GB+ downloads/uploads in 5 minutes)
                print(f"[ALERT MANAGER]   ► Per-IP bandwidth metric detected")
                print(f"[ALERT MANAGER]   ► Querying 5-minute bandwidth per IP from database...")
                sys.stdout.flush()

                # Import ThroughputStorage to query traffic logs
                from throughput_storage import ThroughputStorage
                storage = ThroughputStorage(self.throughput_db_path)

                # Query for IPs exceeding threshold (threshold_value is in MB, convert to bytes)
                threshold_bytes = int(threshold_value * 1024 * 1024)
                per_ip_results = storage.get_per_ip_bandwidth_5min(device_id, threshold_bytes)

                # For threshold comparison, use count of IPs exceeding threshold
                actual_value = len(per_ip_results)

                print(f"[ALERT MANAGER]   ► Found {actual_value} IP(s) exceeding {threshold_value} MB in 5 minutes")
                if per_ip_results:
                    for result in per_ip_results:
                        bytes_mb = result['total_bytes'] / (1024 * 1024)
                        print(f"[ALERT MANAGER]     - {result['ip']} ({result['hostname']}): {bytes_mb:.2f} MB {result['direction']}")
                sys.stdout.flush()
            else:
                # Standard metric - use provided value
                # Skip if metric not provided
                if metric_type not in metrics:
                    print(f"[ALERT MANAGER]   ✗ SKIPPED: Metric '{metric_type}' not in collected metrics")
                    sys.stdout.flush()
                    continue

                actual_value = metrics[metric_type]

            threshold_value = config['threshold_value']
            operator = config['threshold_operator']

            print(f"[ALERT MANAGER]   Actual Value: {actual_value}")
            sys.stdout.flush()

            # Evaluate threshold
            threshold_exceeded = self._evaluate_threshold(actual_value, threshold_value, operator)

            print(f"[ALERT MANAGER]   Threshold Exceeded: {threshold_exceeded}")
            sys.stdout.flush()

            if threshold_exceeded:
                print(f"[ALERT MANAGER]   ✓ TRIGGERED: {actual_value} {operator} {threshold_value}")
                sys.stdout.flush()
                debug(f"Alert triggered: {metric_type} {operator} {threshold_value} (actual: {actual_value})")
                triggered_alerts.append({
                    'config': config,
                    'actual_value': actual_value,
                    'top_source': top_source_info,  # Include source info for category alerts
                    'per_ip_results': per_ip_results  # Include per-IP bandwidth results
                })
            else:
                print(f"[ALERT MANAGER]   ○ NOT TRIGGERED: {actual_value} NOT {operator} {threshold_value}")
                sys.stdout.flush()

        print(f"[ALERT MANAGER] ✓ Evaluation complete: {len(triggered_alerts)}/{len(configs)} alerts triggered")
        sys.stdout.flush()
        debug(f"Found {len(triggered_alerts)} triggered alerts for device {device_id}")
        return triggered_alerts

    def _evaluate_threshold(self, actual: float, threshold: float, operator: str) -> bool:
        """
        Evaluate if threshold is exceeded.

        Args:
            actual: Actual metric value
            threshold: Threshold value
            operator: Comparison operator

        Returns:
            bool: True if threshold exceeded
        """
        debug(f"Evaluating threshold: actual={actual}, operator='{operator}', threshold={threshold}")

        operators = {
            '>': lambda a, t: a > t,
            '<': lambda a, t: a < t,
            '>=': lambda a, t: a >= t,
            '<=': lambda a, t: a <= t,
            '==': lambda a, t: abs(a - t) < 0.01  # Float comparison with tolerance
        }

        if operator not in operators:
            warning(f"Unknown operator: {operator}")
            return False

        result = operators[operator](actual, threshold)
        debug(f"Threshold evaluation result: {result} ({actual} {operator} {threshold})")
        return result

    # ===== Alert History Management =====

    def record_alert(self, config_id: int, device_id: str, metric_type: str,
                   threshold_value: float, actual_value: float, severity: str, message: str) -> Optional[int]:
        """
        Record a triggered alert in history.

        Args:
            config_id: Alert configuration ID
            device_id: Device ID
            metric_type: Metric type
            threshold_value: Configured threshold
            actual_value: Actual metric value
            severity: Alert severity
            message: Alert message

        Returns:
            int: Alert history ID if successful, None otherwise
        """
        debug(f"Recording alert for device {device_id}, metric {metric_type}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO alert_history
                (alert_config_id, device_id, metric_type, threshold_value, actual_value, severity, message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (config_id, device_id, metric_type, threshold_value, actual_value, severity, message))

            history_id = cursor.lastrowid
            conn.commit()
            conn.close()

            debug(f"Recorded alert with history ID {history_id}")
            return history_id

        except Exception as e:
            exception(f"Failed to record alert: {e}")
            return None

    def acknowledge_alert(self, history_id: int, acknowledged_by: str) -> bool:
        """
        Mark an alert as acknowledged.

        Args:
            history_id: Alert history ID
            acknowledged_by: Username who acknowledged

        Returns:
            bool: True if successful
        """
        debug(f"Acknowledging alert {history_id} by {acknowledged_by}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE alert_history
                SET acknowledged_at = CURRENT_TIMESTAMP, acknowledged_by = ?
                WHERE id = ?
            ''', (acknowledged_by, history_id))

            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()

            debug(f"Alert {history_id} acknowledged: {updated}")
            return updated

        except Exception as e:
            exception(f"Failed to acknowledge alert: {e}")
            return False

    def resolve_alert(self, history_id: int, resolved_reason: str = 'Manually resolved') -> bool:
        """
        Mark an alert as resolved.

        Args:
            history_id: Alert history ID
            resolved_reason: Reason for resolution

        Returns:
            bool: True if successful
        """
        debug(f"Resolving alert {history_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE alert_history
                SET resolved_at = CURRENT_TIMESTAMP, resolved_reason = ?
                WHERE id = ?
            ''', (resolved_reason, history_id))

            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()

            debug(f"Alert {history_id} resolved: {updated}")
            return updated

        except Exception as e:
            exception(f"Failed to resolve alert: {e}")
            return False

    def get_alert_history(self, device_id: Optional[str] = None, limit: int = 100,
                         unresolved_only: bool = False, severity: Optional[str] = None) -> List[Dict]:
        """
        Get alert history, optionally filtered.

        Args:
            device_id: Filter by device ID
            limit: Maximum number of records
            unresolved_only: Only return unresolved alerts
            severity: Filter by severity ('critical', 'warning', or 'info')

        Returns:
            List of alert history dictionaries
        """
        debug(f"Getting alert history (device: {device_id}, limit: {limit}, unresolved: {unresolved_only}, severity: {severity})")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = 'SELECT * FROM alert_history WHERE 1=1'
            params = []

            if device_id:
                query += ' AND device_id = ?'
                params.append(device_id)

            if unresolved_only:
                query += ' AND resolved_at IS NULL'

            if severity:
                query += ' AND severity = ?'
                params.append(severity)

            query += ' ORDER BY triggered_at DESC LIMIT ?'
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            history = [dict(row) for row in rows]
            conn.close()

            debug(f"Retrieved {len(history)} alert history records")
            return history

        except Exception as e:
            exception(f"Failed to get alert history: {e}")
            return []

    # ===== Maintenance Windows =====

    def is_in_maintenance_window(self, device_id: str) -> bool:
        """
        Check if device is currently in a maintenance window.

        Args:
            device_id: Device ID to check

        Returns:
            bool: True if in maintenance window
        """
        debug(f"Checking maintenance window for device {device_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.now().isoformat()

            # Check device-specific and global maintenance windows
            cursor.execute('''
                SELECT COUNT(*) FROM maintenance_windows
                WHERE enabled = 1
                AND (device_id = ? OR device_id IS NULL)
                AND start_time <= ?
                AND end_time >= ?
            ''', (device_id, now, now))

            count = cursor.fetchone()[0]
            conn.close()

            in_maintenance = count > 0
            debug(f"Device {device_id} in maintenance window: {in_maintenance}")
            return in_maintenance

        except Exception as e:
            exception(f"Failed to check maintenance window: {e}")
            return False

    # ===== Alert Cooldown Management (Persistent) =====

    def check_cooldown(self, device_id: str, alert_config_id: int, cooldown_seconds: int = 900) -> bool:
        """
        Check if an alert is currently in cooldown period (persistent).

        Args:
            device_id: Device ID
            alert_config_id: Alert configuration ID
            cooldown_seconds: Cooldown period in seconds (default: 900 = 15 minutes)

        Returns:
            bool: True if in cooldown (should skip notification), False if can notify
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check for existing cooldown entry
            cursor.execute('''
                SELECT cooldown_expires_at
                FROM alert_cooldowns
                WHERE device_id = ? AND alert_config_id = ?
            ''', (device_id, alert_config_id))

            row = cursor.fetchone()
            conn.close()

            if not row:
                # No cooldown entry - not in cooldown
                debug(f"No cooldown entry for device {device_id}, alert {alert_config_id}")
                return False

            expires_at = datetime.fromisoformat(row[0])
            now = datetime.utcnow()

            if now < expires_at:
                # Still in cooldown
                remaining = (expires_at - now).total_seconds()
                debug(f"Alert {alert_config_id} for device {device_id} in cooldown ({remaining:.0f}s remaining)")
                return True
            else:
                # Cooldown expired
                debug(f"Alert {alert_config_id} for device {device_id} cooldown expired")
                return False

        except Exception as e:
            exception(f"Failed to check cooldown: {e}")
            # On error, default to NOT in cooldown (allow alert)
            return False

    def set_cooldown(self, device_id: str, alert_config_id: int, cooldown_seconds: int = 900):
        """
        Set or update cooldown period for an alert (persistent).

        Args:
            device_id: Device ID
            alert_config_id: Alert configuration ID
            cooldown_seconds: Cooldown period in seconds (default: 900 = 15 minutes)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow()
            expires_at = now + timedelta(seconds=cooldown_seconds)

            # Insert or replace cooldown entry (UNIQUE constraint handles duplicates)
            cursor.execute('''
                INSERT OR REPLACE INTO alert_cooldowns
                (device_id, alert_config_id, last_triggered_at, cooldown_expires_at)
                VALUES (?, ?, ?, ?)
            ''', (device_id, alert_config_id, now.isoformat(), expires_at.isoformat()))

            conn.commit()
            conn.close()

            debug(f"Set cooldown for alert {alert_config_id}, device {device_id} (expires: {expires_at.isoformat()})")

        except Exception as e:
            exception(f"Failed to set cooldown: {e}")

    def clear_expired_cooldowns(self) -> int:
        """
        Clean up expired cooldown entries from database.

        Returns:
            int: Number of expired entries deleted
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.utcnow().isoformat()

            cursor.execute('''
                DELETE FROM alert_cooldowns
                WHERE cooldown_expires_at < ?
            ''', (now,))

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_count > 0:
                debug(f"Cleared {deleted_count} expired cooldown entries")

            return deleted_count

        except Exception as e:
            exception(f"Failed to clear expired cooldowns: {e}")
            return 0

    def cleanup_old_alert_history(self, retention_days: int) -> int:
        """
        Delete resolved alert history older than retention period.
        Only deletes resolved alerts to preserve active/unresolved alerts.

        Args:
            retention_days: Number of days to retain resolved alerts

        Returns:
            int: Number of alert records deleted
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat()

            # Only delete resolved alerts older than retention period
            cursor.execute('''
                DELETE FROM alert_history
                WHERE resolved_at IS NOT NULL AND resolved_at < ?
            ''', (cutoff_date,))

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_count > 0:
                debug(f"Cleaned up {deleted_count} old resolved alerts (retention: {retention_days} days)")
            else:
                debug("No old alert history to clean up")

            return deleted_count

        except Exception as e:
            exception(f"Failed to cleanup old alert history: {e}")
            return 0


# Global alert manager instance
alert_manager = AlertManager()


# ===== Helper Functions =====

def get_metric_display_name(metric_type: str) -> str:
    """Get human-readable metric name"""
    # Handle application metrics (format: "app_<application_name>")
    if metric_type.startswith('app_'):
        app_name = metric_type[len('app_'):]
        # Capitalize each word and format nicely
        return f"Application: {app_name.replace('-', ' ').title()}"

    names = {
        'throughput_in': 'Inbound Throughput',
        'throughput_out': 'Outbound Throughput',
        'throughput_total': 'Total Throughput',
        'cpu': 'CPU Usage',
        'memory': 'Memory Usage',
        'sessions': 'Active Sessions',
        'threats_critical': 'Critical Threats',
        'interface_errors': 'Interface Errors',
        'per_ip_bandwidth_5min': 'Per-Device Bandwidth (5-min)'
    }
    return names.get(metric_type, metric_type.replace('_', ' ').title())


def format_alert_message(metric_type: str, actual_value: float, threshold_value: float,
                        operator: str, device_name: str = None, top_source: dict = None,
                        per_ip_results: list = None) -> str:
    """
    Format alert message for notifications.

    Args:
        metric_type: Type of metric
        actual_value: Actual metric value
        threshold_value: Configured threshold
        operator: Comparison operator
        device_name: Optional device name
        top_source: Optional dict with top source info for application alerts
                    {'ip': str, 'hostname': str, 'custom_name': str, 'bytes': int}
        per_ip_results: Optional list of per-IP bandwidth results
                       [{'ip': str, 'hostname': str, 'total_bytes': int, 'direction': str}, ...]

    Returns:
        str: Formatted alert message
    """
    metric_name = get_metric_display_name(metric_type)
    device_str = f" on {device_name}" if device_name else ""

    # Format values based on metric type
    if metric_type == 'per_ip_bandwidth_5min':
        # Per-IP bandwidth monitoring - list all IPs that exceeded threshold
        threshold_str = f"{threshold_value:.0f} MB"

        if per_ip_results and len(per_ip_results) > 0:
            # Format detailed message with all offending IPs
            details = []
            for result in per_ip_results:
                ip = result.get('ip', 'Unknown')
                hostname = result.get('hostname', ip)
                bytes_mb = result.get('total_bytes', 0) / (1024 * 1024)
                direction = result.get('direction', 'transfer')

                # Format: "192.168.1.100 (Johns-Laptop) downloaded 2,500 MB"
                details.append(f"{ip} ({hostname}) {direction}ed {bytes_mb:.0f} MB")

            ip_list_str = "\n".join(f"  • {detail}" for detail in details)
            return f"{metric_name}{device_str}: {len(per_ip_results)} device(s) exceeded {threshold_str} in 5 minutes\n{ip_list_str}"
        else:
            return f"{metric_name}{device_str}: Alert triggered but no device details available"
    elif metric_type.startswith('app_'):
        # Application metrics are in MB (5-minute totals)
        actual_str = f"{actual_value:.2f} MB"
        threshold_str = f"{threshold_value:.2f} MB"

        # Build source info string if available
        source_str = ""
        if top_source:
            source_ip = top_source.get('ip', 'Unknown')
            # Prioritize custom_name, then original_hostname, then hostname
            hostname = top_source.get('custom_name') or top_source.get('hostname', 'Unknown')
            source_bytes_mb = top_source.get('bytes', 0) / (1024 * 1024)
            source_str = f" | Top source: {source_ip} ({hostname}) - {source_bytes_mb:.2f} MB"

        return f"{metric_name}{device_str}: {actual_str} {operator} {threshold_str} (5-min total){source_str}"
    elif 'throughput' in metric_type:
        actual_str = f"{actual_value:.2f} Mbps"
        threshold_str = f"{threshold_value:.2f} Mbps"
    elif metric_type in ['cpu', 'memory']:
        actual_str = f"{actual_value:.1f}%"
        threshold_str = f"{threshold_value:.1f}%"
    else:
        actual_str = f"{int(actual_value)}"
        threshold_str = f"{int(threshold_value)}"

    return f"{metric_name}{device_str}: {actual_str} {operator} {threshold_str}"
