"""
Throughput Storage Module

This module provides SQLite-based storage for historical network throughput data.
Handles database initialization, data insertion, querying, and retention cleanup.

Author: PANfm Development Team
Created: 2025-11-06
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from logger import debug, info, warning, error, exception


class ThroughputStorage:
    """SQLite-based storage for historical throughput data."""

    def __init__(self, db_path: str):
        """
        Initialize throughput storage.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        debug("Initializing ThroughputStorage with database: %s", db_path)
        self._init_database()

    def _init_database(self):
        """Create database schema if it doesn't exist."""
        debug("Initializing database schema")
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create throughput_samples table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS throughput_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    inbound_mbps REAL,
                    outbound_mbps REAL,
                    total_mbps REAL,
                    inbound_pps INTEGER,
                    outbound_pps INTEGER,
                    total_pps INTEGER,
                    sessions_active INTEGER,
                    sessions_tcp INTEGER,
                    sessions_udp INTEGER,
                    sessions_icmp INTEGER,
                    cpu_data_plane INTEGER,
                    cpu_mgmt_plane INTEGER,
                    memory_used_pct INTEGER
                )
            ''')

            # Create indexes for efficient queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_device_timestamp
                ON throughput_samples(device_id, timestamp)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON throughput_samples(timestamp)
            ''')

            # Create threat_logs table (Phase 3: Detailed log storage)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    severity TEXT NOT NULL,
                    threat_name TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    app TEXT,
                    action TEXT,
                    category TEXT,
                    rule TEXT,
                    details_json TEXT
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_threat_device_time
                ON threat_logs(device_id, timestamp DESC, severity)
            ''')

            # Create url_filtering_logs table (Phase 3: URL filtering logs)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS url_filtering_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    url TEXT,
                    category TEXT,
                    source_ip TEXT,
                    dest_ip TEXT,
                    action TEXT,
                    details_json TEXT
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_url_device_time
                ON url_filtering_logs(device_id, timestamp DESC)
            ''')

            # Create system_logs table (Phase 3: System event logs)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    severity TEXT,
                    event_type TEXT,
                    message TEXT,
                    user TEXT,
                    details_json TEXT
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_system_device_time
                ON system_logs(device_id, timestamp DESC)
            ''')

            # Create traffic_logs table (Phase 3: Traffic session logs)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    source_port INTEGER,
                    dest_port INTEGER,
                    app TEXT,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    action TEXT,
                    details_json TEXT
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_traffic_device_time
                ON traffic_logs(device_id, timestamp DESC)
            ''')

            # Create application_statistics table (Phase 4: Application data aggregation)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS application_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    collection_time DATETIME NOT NULL,
                    app_name TEXT NOT NULL,
                    category TEXT,
                    sessions INTEGER DEFAULT 0,
                    bytes_total INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    source_count INTEGER DEFAULT 0,
                    dest_count INTEGER DEFAULT 0,
                    protocols_json TEXT,
                    ports_json TEXT,
                    vlans_json TEXT,
                    zones_json TEXT,
                    source_details_json TEXT,
                    dest_details_json TEXT
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_app_device_time
                ON application_statistics(device_id, collection_time DESC, app_name)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_app_device_app
                ON application_statistics(device_id, app_name, collection_time DESC)
            ''')

            conn.commit()
            conn.close()

            info("Database schema initialized successfully (including Phase 3 log tables and Phase 4 application_statistics)")

        except Exception as e:
            exception("Failed to initialize database schema: %s", str(e))
            raise

        # Run schema migration for Phase 2 (adds new columns)
        self._migrate_schema_phase2()

        # Run schema migration for Phase 3 (adds category support)
        self._migrate_schema_phase3()

    def _migrate_schema_phase2(self):
        """
        Migrate database schema for Phase 2: Full Dashboard Database-First Architecture.

        Adds columns for threats, applications, interfaces, license, and WAN data.
        Safe to run multiple times (uses ALTER TABLE with error handling).
        """
        debug("Checking for Phase 2 schema migration")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # List of new columns to add for Phase 2
            new_columns = [
                ('critical_threats', 'INTEGER DEFAULT 0'),
                ('medium_threats', 'INTEGER DEFAULT 0'),
                ('blocked_urls', 'INTEGER DEFAULT 0'),
                ('critical_last_seen', 'TEXT'),
                ('medium_last_seen', 'TEXT'),
                ('blocked_url_last_seen', 'TEXT'),
                ('top_apps_json', 'TEXT'),  # JSON array of top applications
                ('interface_errors', 'INTEGER DEFAULT 0'),
                ('interface_drops', 'INTEGER DEFAULT 0'),
                ('interface_stats_json', 'TEXT'),  # JSON array of interface details
                ('license_expired', 'INTEGER DEFAULT 0'),
                ('license_licensed', 'INTEGER DEFAULT 0'),
                ('wan_ip', 'TEXT'),
                ('wan_speed', 'TEXT'),
                ('hostname', 'TEXT'),
                ('uptime_seconds', 'INTEGER'),
                ('pan_os_version', 'TEXT')
            ]

            # Attempt to add each column
            columns_added = 0
            for col_name, col_type in new_columns:
                try:
                    cursor.execute(f"ALTER TABLE throughput_samples ADD COLUMN {col_name} {col_type}")
                    columns_added += 1
                    debug(f"Added column: {col_name}")
                except sqlite3.OperationalError as e:
                    if 'duplicate column name' in str(e).lower():
                        # Column already exists, this is fine
                        pass
                    else:
                        # Some other error
                        warning(f"Error adding column {col_name}: {e}")

            conn.commit()
            conn.close()

            if columns_added > 0:
                info(f"Phase 2 schema migration: added {columns_added} new columns")
            else:
                debug("Phase 2 schema already up to date")

        except Exception as e:
            exception("Error during Phase 2 schema migration: %s", str(e))
            # Don't raise - allow app to continue with existing schema

    def _migrate_schema_phase3(self):
        """
        Migrate database schema for Phase 3: Category-based alerting.

        Adds categories_json column for storing application category traffic data.
        Safe to run multiple times (uses ALTER TABLE with error handling).
        """
        debug("Checking for Phase 3 schema migration (categories)")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # List of new columns to add for Phase 3
            new_columns = [
                ('categories_json', 'TEXT'),  # JSON object of category traffic: {category_name: {bytes, sessions}}
            ]

            # Attempt to add each column
            columns_added = 0
            for col_name, col_type in new_columns:
                try:
                    cursor.execute(f"ALTER TABLE throughput_samples ADD COLUMN {col_name} {col_type}")
                    columns_added += 1
                    debug(f"Added column: {col_name}")
                except sqlite3.OperationalError as e:
                    if 'duplicate column name' in str(e).lower():
                        # Column already exists, this is fine
                        pass
                    else:
                        # Some other error
                        warning(f"Error adding column {col_name}: {e}")

            conn.commit()
            conn.close()

            if columns_added > 0:
                info(f"Phase 3 schema migration: added {columns_added} new column(s)")
            else:
                debug("Phase 3 schema already up to date")

        except Exception as e:
            exception("Error during Phase 3 schema migration: %s", str(e))
            # Don't raise - allow app to continue with existing schema

    def _format_uptime_seconds(self, uptime_seconds: Optional[int]) -> Optional[str]:
        """
        Convert uptime in seconds to human-readable format.

        Args:
            uptime_seconds: Uptime in seconds

        Returns:
            Formatted uptime string (e.g., "5 days, 12:34:56") or None
        """
        if uptime_seconds is None:
            return None

        try:
            days = uptime_seconds // 86400
            remaining_seconds = uptime_seconds % 86400
            hours = remaining_seconds // 3600
            remaining_seconds %= 3600
            minutes = remaining_seconds // 60
            seconds = remaining_seconds % 60

            if days > 0:
                return f"{days} days, {hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        except Exception as e:
            debug(f"Error formatting uptime seconds {uptime_seconds}: {e}")
            return None

    def insert_sample(self, device_id: str, sample_data: Dict) -> bool:
        """
        Insert a single throughput sample into the database.

        Args:
            device_id: Device identifier
            sample_data: Dictionary containing throughput metrics

        Returns:
            True if successful, False otherwise
        """
        debug("Inserting sample for device %s", device_id)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Extract metrics from sample data
            timestamp = sample_data.get('timestamp', datetime.utcnow().isoformat())

            # Serialize JSON fields
            top_apps_json = json.dumps(sample_data.get('top_applications', [])) if sample_data.get('top_applications') else None
            interface_stats_json = json.dumps(sample_data.get('interface_stats', [])) if sample_data.get('interface_stats') else None
            categories_json = json.dumps(sample_data.get('categories', {})) if sample_data.get('categories') else None

            cursor.execute('''
                INSERT INTO throughput_samples (
                    device_id, timestamp,
                    inbound_mbps, outbound_mbps, total_mbps,
                    inbound_pps, outbound_pps, total_pps,
                    sessions_active, sessions_tcp, sessions_udp, sessions_icmp,
                    cpu_data_plane, cpu_mgmt_plane, memory_used_pct,
                    critical_threats, medium_threats, blocked_urls,
                    critical_last_seen, medium_last_seen, blocked_url_last_seen,
                    top_apps_json,
                    interface_errors, interface_drops, interface_stats_json,
                    license_expired, license_licensed,
                    wan_ip, wan_speed,
                    hostname, uptime_seconds, pan_os_version,
                    categories_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                timestamp,
                sample_data.get('inbound_mbps'),
                sample_data.get('outbound_mbps'),
                sample_data.get('total_mbps'),
                sample_data.get('inbound_pps'),
                sample_data.get('outbound_pps'),
                sample_data.get('total_pps'),
                sample_data.get('sessions', {}).get('active'),
                sample_data.get('sessions', {}).get('tcp'),
                sample_data.get('sessions', {}).get('udp'),
                sample_data.get('sessions', {}).get('icmp'),
                sample_data.get('cpu', {}).get('data_plane_cpu'),
                sample_data.get('cpu', {}).get('mgmt_plane_cpu'),
                sample_data.get('cpu', {}).get('memory_used_pct'),
                # Phase 2 fields: Threats (handle both field name variations)
                sample_data.get('threats', {}).get('critical_threats') or sample_data.get('threats', {}).get('critical') or 0,
                sample_data.get('threats', {}).get('medium_threats') or sample_data.get('threats', {}).get('medium') or 0,
                sample_data.get('threats', {}).get('blocked_urls') or 0,
                sample_data.get('threats', {}).get('critical_last_seen'),
                sample_data.get('threats', {}).get('medium_last_seen'),
                sample_data.get('threats', {}).get('blocked_url_last_seen'),
                # Phase 2 fields: Applications (JSON)
                top_apps_json,
                # Phase 2 fields: Interfaces
                sample_data.get('interface_errors'),
                sample_data.get('interface_drops'),
                interface_stats_json,
                # Phase 2 fields: License
                sample_data.get('license', {}).get('expired'),
                sample_data.get('license', {}).get('licensed'),
                # Phase 2 fields: WAN
                sample_data.get('wan_ip'),
                sample_data.get('wan_speed'),
                # Phase 2 fields: System
                sample_data.get('hostname'),
                sample_data.get('uptime_seconds'),
                sample_data.get('pan_os_version'),
                # Phase 3 fields: Categories (JSON)
                categories_json
            ))

            conn.commit()
            conn.close()

            debug("Sample inserted successfully for device %s", device_id)
            return True

        except Exception as e:
            exception("Failed to insert sample for device %s: %s", device_id, str(e))
            return False

    def query_samples(
        self,
        device_id: str,
        start_time: datetime,
        end_time: datetime,
        resolution: Optional[str] = None
    ) -> List[Dict]:
        """
        Query throughput samples for a device within a time range.

        Args:
            device_id: Device identifier
            start_time: Start of time range
            end_time: End of time range
            resolution: Optional aggregation resolution ('raw', 'hourly', 'daily')

        Returns:
            List of sample dictionaries
        """
        debug("Querying samples for device %s from %s to %s (resolution: %s)",
              device_id, start_time, end_time, resolution)

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()

            if resolution == 'hourly':
                # Aggregate by hour
                cursor.execute('''
                    SELECT
                        strftime('%Y-%m-%d %H:00:00', timestamp) as timestamp,
                        AVG(inbound_mbps) as inbound_mbps,
                        AVG(outbound_mbps) as outbound_mbps,
                        AVG(total_mbps) as total_mbps,
                        AVG(inbound_pps) as inbound_pps,
                        AVG(outbound_pps) as outbound_pps,
                        AVG(total_pps) as total_pps,
                        AVG(sessions_active) as sessions_active,
                        AVG(sessions_tcp) as sessions_tcp,
                        AVG(sessions_udp) as sessions_udp,
                        AVG(sessions_icmp) as sessions_icmp,
                        AVG(cpu_data_plane) as cpu_data_plane,
                        AVG(cpu_mgmt_plane) as cpu_mgmt_plane,
                        AVG(memory_used_pct) as memory_used_pct
                    FROM throughput_samples
                    WHERE device_id = ? AND timestamp BETWEEN ? AND ?
                    GROUP BY strftime('%Y-%m-%d %H:00:00', timestamp)
                    ORDER BY timestamp
                ''', (device_id, start_time.isoformat(), end_time.isoformat()))

            elif resolution == 'daily':
                # Aggregate by day
                cursor.execute('''
                    SELECT
                        strftime('%Y-%m-%d 00:00:00', timestamp) as timestamp,
                        AVG(inbound_mbps) as inbound_mbps,
                        AVG(outbound_mbps) as outbound_mbps,
                        AVG(total_mbps) as total_mbps,
                        AVG(inbound_pps) as inbound_pps,
                        AVG(outbound_pps) as outbound_pps,
                        AVG(total_pps) as total_pps,
                        AVG(sessions_active) as sessions_active,
                        AVG(sessions_tcp) as sessions_tcp,
                        AVG(sessions_udp) as sessions_udp,
                        AVG(sessions_icmp) as sessions_icmp,
                        AVG(cpu_data_plane) as cpu_data_plane,
                        AVG(cpu_mgmt_plane) as cpu_mgmt_plane,
                        AVG(memory_used_pct) as memory_used_pct
                    FROM throughput_samples
                    WHERE device_id = ? AND timestamp BETWEEN ? AND ?
                    GROUP BY strftime('%Y-%m-%d 00:00:00', timestamp)
                    ORDER BY timestamp
                ''', (device_id, start_time.isoformat(), end_time.isoformat()))

            else:
                # Raw data (no aggregation)
                cursor.execute('''
                    SELECT
                        timestamp,
                        inbound_mbps, outbound_mbps, total_mbps,
                        inbound_pps, outbound_pps, total_pps,
                        sessions_active, sessions_tcp, sessions_udp, sessions_icmp,
                        cpu_data_plane, cpu_mgmt_plane, memory_used_pct
                    FROM throughput_samples
                    WHERE device_id = ? AND timestamp BETWEEN ? AND ?
                    ORDER BY timestamp
                ''', (device_id, start_time.isoformat(), end_time.isoformat()))

            rows = cursor.fetchall()
            conn.close()

            # Convert rows to dictionaries
            samples = []
            for row in rows:
                samples.append({
                    'timestamp': row['timestamp'],
                    'inbound_mbps': row['inbound_mbps'],
                    'outbound_mbps': row['outbound_mbps'],
                    'total_mbps': row['total_mbps'],
                    'inbound_pps': row['inbound_pps'],
                    'outbound_pps': row['outbound_pps'],
                    'total_pps': row['total_pps'],
                    'sessions': {
                        'active': row['sessions_active'],
                        'tcp': row['sessions_tcp'],
                        'udp': row['sessions_udp'],
                        'icmp': row['sessions_icmp']
                    },
                    'cpu': {
                        'data_plane_cpu': row['cpu_data_plane'],
                        'mgmt_plane_cpu': row['cpu_mgmt_plane'],
                        'memory_used_pct': row['memory_used_pct']
                    }
                })

            debug("Retrieved %d samples for device %s", len(samples), device_id)
            return samples

        except Exception as e:
            exception("Failed to query samples for device %s: %s", device_id, str(e))
            return []

    def cleanup_old_samples(self, retention_days: int) -> int:
        """
        Delete samples older than retention period.

        Args:
            retention_days: Number of days to retain data

        Returns:
            Number of samples deleted
        """
        debug("Cleaning up samples older than %d days", retention_days)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            cursor.execute('''
                DELETE FROM throughput_samples
                WHERE timestamp < ?
            ''', (cutoff_date.isoformat(),))

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_count > 0:
                info("Cleaned up %d old samples (cutoff: %s)", deleted_count, cutoff_date)
            else:
                debug("No old samples to clean up")

            return deleted_count

        except Exception as e:
            exception("Failed to cleanup old samples: %s", str(e))
            return 0

    def get_latest_sample(self, device_id: str, max_age_seconds: int = 30) -> Optional[Dict]:
        """
        Get the most recent throughput sample for a device.

        Args:
            device_id: Device identifier
            max_age_seconds: Maximum age of sample in seconds (default: 30)

        Returns:
            Dictionary with latest sample data, or None if no recent data
        """
        debug("Retrieving latest sample for device %s (max age: %ds)", device_id, max_age_seconds)

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Calculate cutoff time
            cutoff_time = datetime.utcnow() - timedelta(seconds=max_age_seconds)

            # Query most recent sample within time window (all Phase 1 + Phase 2 columns)
            cursor.execute('''
                SELECT
                    timestamp,
                    inbound_mbps, outbound_mbps, total_mbps,
                    inbound_pps, outbound_pps, total_pps,
                    sessions_active, sessions_tcp, sessions_udp, sessions_icmp,
                    cpu_data_plane, cpu_mgmt_plane, memory_used_pct,
                    critical_threats, medium_threats, blocked_urls,
                    critical_last_seen, medium_last_seen, blocked_url_last_seen,
                    top_apps_json,
                    interface_errors, interface_drops, interface_stats_json,
                    license_expired, license_licensed,
                    wan_ip, wan_speed,
                    hostname, uptime_seconds, pan_os_version
                FROM throughput_samples
                WHERE device_id = ? AND timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT 1
            ''', (device_id, cutoff_time.isoformat()))

            row = cursor.fetchone()
            conn.close()

            if row is None:
                debug("No recent sample found for device %s", device_id)
                return None

            # Deserialize JSON fields
            top_apps = json.loads(row['top_apps_json']) if row['top_apps_json'] else []
            interface_stats = json.loads(row['interface_stats_json']) if row['interface_stats_json'] else []

            # Convert to dictionary with same format as firewall_api.get_throughput_data()
            sample = {
                'timestamp': row['timestamp'],
                'inbound_mbps': row['inbound_mbps'],
                'outbound_mbps': row['outbound_mbps'],
                'total_mbps': row['total_mbps'],
                'inbound_pps': row['inbound_pps'],
                'outbound_pps': row['outbound_pps'],
                'total_pps': row['total_pps'],
                'sessions': {
                    'active': row['sessions_active'],
                    'tcp': row['sessions_tcp'],
                    'udp': row['sessions_udp'],
                    'icmp': row['sessions_icmp']
                },
                'cpu': {
                    'data_plane_cpu': row['cpu_data_plane'],
                    'mgmt_plane_cpu': row['cpu_mgmt_plane'],
                    'memory_used_pct': row['memory_used_pct'],
                    'uptime': self._format_uptime_seconds(row['uptime_seconds'])  # Convert seconds to string
                },
                # Phase 2 fields: Threats
                'threats': {
                    'critical_threats': row['critical_threats'],
                    'medium_threats': row['medium_threats'],
                    'critical': row['critical_threats'],  # Backward compatibility
                    'medium': row['medium_threats'],  # Backward compatibility
                    'blocked_urls': row['blocked_urls'],
                    'critical_last_seen': row['critical_last_seen'],
                    'medium_last_seen': row['medium_last_seen'],
                    'blocked_url_last_seen': row['blocked_url_last_seen'],
                    # Phase 3: Load detailed threat logs from database
                    'critical_logs': self.get_threat_logs(device_id, severity='critical', limit=10),
                    'medium_logs': self.get_threat_logs(device_id, severity='medium', limit=10),
                    'blocked_url_logs': self.get_url_filtering_logs(device_id, limit=10)
                },
                # Phase 2 fields: Applications
                'top_applications': top_apps,
                # Phase 2 fields: Interfaces
                'interface_errors': row['interface_errors'],
                'interface_drops': row['interface_drops'],
                'interface_stats': interface_stats,
                # Phase 2 fields: License
                'license': {
                    'expired': row['license_expired'],
                    'licensed': row['license_licensed']
                },
                # Phase 2 fields: WAN
                'wan_ip': row['wan_ip'],
                'wan_speed': row['wan_speed'],
                # Phase 2 fields: System
                'hostname': row['hostname'],
                'uptime_seconds': row['uptime_seconds'],
                'pan_os_version': row['pan_os_version'],
                'panos_version': row['pan_os_version']  # Dashboard UI expects 'panos_version'
            }

            debug("Retrieved latest sample for device %s from %s", device_id, sample['timestamp'])
            return sample

        except Exception as e:
            exception("Failed to get latest sample for device %s: %s", device_id, str(e))
            return None

    def get_storage_stats(self) -> Dict:
        """
        Get statistics about stored data.

        Returns:
            Dictionary with storage statistics
        """
        debug("Retrieving storage statistics")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total samples
            cursor.execute('SELECT COUNT(*) FROM throughput_samples')
            total_samples = cursor.fetchone()[0]

            # Samples per device
            cursor.execute('''
                SELECT device_id, COUNT(*) as count
                FROM throughput_samples
                GROUP BY device_id
            ''')
            device_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Date range
            cursor.execute('''
                SELECT MIN(timestamp), MAX(timestamp)
                FROM throughput_samples
            ''')
            date_range = cursor.fetchone()

            # Database file size
            db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0

            conn.close()

            stats = {
                'total_samples': total_samples,
                'device_counts': device_counts,
                'oldest_sample': date_range[0],
                'newest_sample': date_range[1],
                'db_size_bytes': db_size,
                'db_size_mb': round(db_size / (1024 * 1024), 2)
            }

            debug("Storage stats: %d total samples, %.2f MB", total_samples, stats['db_size_mb'])
            return stats

        except Exception as e:
            exception("Failed to get storage statistics: %s", str(e))
            return {
                'total_samples': 0,
                'device_counts': {},
                'oldest_sample': None,
                'newest_sample': None,
                'db_size_bytes': 0,
                'db_size_mb': 0
            }

    # ========================================================================
    # Phase 3: Detailed Log Storage Methods
    # ========================================================================

    def insert_threat_logs(self, device_id: str, logs: List[Dict], severity: str) -> bool:
        """
        Insert threat logs (critical or medium) into database.
        Automatically enforces 1,000-entry retention per device per severity level.

        Args:
            device_id: Device identifier
            logs: List of threat log dictionaries
            severity: 'critical' or 'medium'

        Returns:
            True if successful, False otherwise
        """
        if not logs:
            return True  # Nothing to insert

        debug(f"Inserting {len(logs)} {severity} threat logs for device {device_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert logs
            for log in logs:
                cursor.execute('''
                    INSERT INTO threat_logs (
                        device_id, timestamp, severity,
                        threat_name, source_ip, dest_ip, app, action,
                        category, rule, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    log.get('time') or log.get('timestamp') or datetime.utcnow().isoformat(),
                    severity,
                    log.get('threat') or log.get('threat_name'),
                    log.get('src') or log.get('source_ip'),
                    log.get('dst') or log.get('dest_ip'),
                    log.get('app'),
                    log.get('action'),
                    log.get('category'),
                    log.get('rule'),
                    json.dumps(log) if log else None
                ))

            # Enforce 1,000-entry retention per device per severity
            cursor.execute('''
                DELETE FROM threat_logs
                WHERE device_id = ? AND severity = ?
                AND id NOT IN (
                    SELECT id FROM threat_logs
                    WHERE device_id = ? AND severity = ?
                    ORDER BY timestamp DESC
                    LIMIT 1000
                )
            ''', (device_id, severity, device_id, severity))

            deleted_count = cursor.rowcount
            if deleted_count > 0:
                debug(f"Cleaned up {deleted_count} old {severity} threat logs for device {device_id}")

            conn.commit()
            conn.close()

            debug(f"Successfully inserted {len(logs)} {severity} threat logs for device {device_id}")
            return True

        except Exception as e:
            exception(f"Failed to insert {severity} threat logs for device {device_id}: {str(e)}")
            return False

    def get_threat_logs(self, device_id: str, severity: str = None, limit: int = 50) -> List[Dict]:
        """
        Retrieve threat logs from database.

        Args:
            device_id: Device identifier
            severity: Filter by severity ('critical', 'medium'), or None for all
            limit: Maximum number of logs to return (default: 50)

        Returns:
            List of threat log dictionaries
        """
        debug(f"Retrieving threat logs for device {device_id}, severity={severity}, limit={limit}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if severity:
                cursor.execute('''
                    SELECT * FROM threat_logs
                    WHERE device_id = ? AND severity = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (device_id, severity, limit))
            else:
                cursor.execute('''
                    SELECT * FROM threat_logs
                    WHERE device_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (device_id, limit))

            rows = cursor.fetchall()
            conn.close()

            logs = []
            for row in rows:
                logs.append({
                    'time': row['timestamp'],
                    'threat': row['threat_name'],
                    'src': row['source_ip'],
                    'dst': row['dest_ip'],
                    'app': row['app'],
                    'action': row['action'],
                    'category': row['category'],
                    'rule': row['rule'],
                    'severity': row['severity']
                })

            debug(f"Retrieved {len(logs)} threat logs")
            return logs

        except Exception as e:
            exception(f"Failed to retrieve threat logs: {str(e)}")
            return []

    def insert_url_filtering_logs(self, device_id: str, logs: List[Dict]) -> bool:
        """
        Insert URL filtering logs into database.
        Automatically enforces 1,000-entry retention per device.

        Args:
            device_id: Device identifier
            logs: List of URL filtering log dictionaries

        Returns:
            True if successful, False otherwise
        """
        if not logs:
            return True

        debug(f"Inserting {len(logs)} URL filtering logs for device {device_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert logs
            for log in logs:
                cursor.execute('''
                    INSERT INTO url_filtering_logs (
                        device_id, timestamp, url, category,
                        source_ip, dest_ip, action, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    log.get('time') or log.get('timestamp') or datetime.utcnow().isoformat(),
                    log.get('url') or log.get('threat'),  # threat field sometimes contains URL
                    log.get('category'),
                    log.get('src') or log.get('source_ip'),
                    log.get('dst') or log.get('dest_ip'),
                    log.get('action'),
                    json.dumps(log) if log else None
                ))

            # Enforce 1,000-entry retention per device
            cursor.execute('''
                DELETE FROM url_filtering_logs
                WHERE device_id = ?
                AND id NOT IN (
                    SELECT id FROM url_filtering_logs
                    WHERE device_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 1000
                )
            ''', (device_id, device_id))

            deleted_count = cursor.rowcount
            if deleted_count > 0:
                debug(f"Cleaned up {deleted_count} old URL filtering logs for device {device_id}")

            conn.commit()
            conn.close()

            debug(f"Successfully inserted {len(logs)} URL filtering logs for device {device_id}")
            return True

        except Exception as e:
            exception(f"Failed to insert URL filtering logs for device {device_id}: {str(e)}")
            return False

    def get_url_filtering_logs(self, device_id: str, limit: int = 50) -> List[Dict]:
        """
        Retrieve URL filtering logs from database.

        Args:
            device_id: Device identifier
            limit: Maximum number of logs to return (default: 50)

        Returns:
            List of URL filtering log dictionaries
        """
        debug(f"Retrieving URL filtering logs for device {device_id}, limit={limit}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM url_filtering_logs
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (device_id, limit))

            rows = cursor.fetchall()
            conn.close()

            logs = []
            for row in rows:
                logs.append({
                    'time': row['timestamp'],
                    'url': row['url'],
                    'threat': row['url'],  # Alias for compatibility
                    'category': row['category'],
                    'src': row['source_ip'],
                    'dst': row['dest_ip'],
                    'action': row['action']
                })

            debug(f"Retrieved {len(logs)} URL filtering logs")
            return logs

        except Exception as e:
            exception(f"Failed to retrieve URL filtering logs: {str(e)}")
            return []

    def insert_system_logs(self, device_id: str, logs: List[Dict]) -> bool:
        """
        Insert system event logs into database.
        Automatically enforces 1,000-entry retention per device.

        Args:
            device_id: Device identifier
            logs: List of system log dictionaries

        Returns:
            True if successful, False otherwise
        """
        if not logs:
            return True

        debug(f"Inserting {len(logs)} system logs for device {device_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert logs
            for log in logs:
                cursor.execute('''
                    INSERT INTO system_logs (
                        device_id, timestamp, severity, event_type,
                        message, user, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    log.get('time') or log.get('timestamp') or datetime.utcnow().isoformat(),
                    log.get('severity') or log.get('level'),
                    log.get('type') or log.get('event_type'),
                    log.get('message') or log.get('description'),
                    log.get('user'),
                    json.dumps(log) if log else None
                ))

            # Enforce 1,000-entry retention per device
            cursor.execute('''
                DELETE FROM system_logs
                WHERE device_id = ?
                AND id NOT IN (
                    SELECT id FROM system_logs
                    WHERE device_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 1000
                )
            ''', (device_id, device_id))

            deleted_count = cursor.rowcount
            if deleted_count > 0:
                debug(f"Cleaned up {deleted_count} old system logs for device {device_id}")

            conn.commit()
            conn.close()

            debug(f"Successfully inserted {len(logs)} system logs for device {device_id}")
            return True

        except Exception as e:
            exception(f"Failed to insert system logs for device {device_id}: {str(e)}")
            return False

    def get_system_logs(self, device_id: str, limit: int = 50) -> List[Dict]:
        """
        Retrieve system event logs from database.

        Args:
            device_id: Device identifier
            limit: Maximum number of logs to return (default: 50)

        Returns:
            List of system log dictionaries
        """
        debug(f"Retrieving system logs for device {device_id}, limit={limit}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM system_logs
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (device_id, limit))

            rows = cursor.fetchall()
            conn.close()

            logs = []
            for row in rows:
                logs.append({
                    'time': row['timestamp'],
                    'severity': row['severity'],
                    'type': row['event_type'],
                    'message': row['message'],
                    'user': row['user']
                })

            debug(f"Retrieved {len(logs)} system logs")
            return logs

        except Exception as e:
            exception(f"Failed to retrieve system logs: {str(e)}")
            return []

    def insert_traffic_logs(self, device_id: str, logs: List[Dict]) -> bool:
        """
        Insert traffic session logs into database.
        Automatically enforces 1,000-entry retention per device.

        Args:
            device_id: Device identifier
            logs: List of traffic log dictionaries

        Returns:
            True if successful, False otherwise
        """
        if not logs:
            return True

        debug(f"Inserting {len(logs)} traffic logs for device {device_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert logs
            for log in logs:
                cursor.execute('''
                    INSERT INTO traffic_logs (
                        device_id, timestamp, source_ip, dest_ip,
                        source_port, dest_port, app,
                        bytes_sent, bytes_received, action, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    log.get('time') or log.get('timestamp') or datetime.utcnow().isoformat(),
                    log.get('src') or log.get('source_ip'),
                    log.get('dst') or log.get('dest_ip'),
                    log.get('sport') or log.get('source_port'),
                    log.get('dport') or log.get('dest_port'),
                    log.get('app'),
                    log.get('bytes_sent') or log.get('sent_bytes'),
                    log.get('bytes_received') or log.get('received_bytes'),
                    log.get('action'),
                    json.dumps(log) if log else None
                ))

            # Enforce 1,000-entry retention per device
            cursor.execute('''
                DELETE FROM traffic_logs
                WHERE device_id = ?
                AND id NOT IN (
                    SELECT id FROM traffic_logs
                    WHERE device_id = ?
                    ORDER BY timestamp DESC
                    LIMIT 1000
                )
            ''', (device_id, device_id))

            deleted_count = cursor.rowcount
            if deleted_count > 0:
                debug(f"Cleaned up {deleted_count} old traffic logs for device {device_id}")

            conn.commit()
            conn.close()

            debug(f"Successfully inserted {len(logs)} traffic logs for device {device_id}")
            return True

        except Exception as e:
            exception(f"Failed to insert traffic logs for device {device_id}: {str(e)}")
            return False

    def get_traffic_logs(self, device_id: str, limit: int = 50) -> List[Dict]:
        """
        Retrieve traffic session logs from database.

        Args:
            device_id: Device identifier
            limit: Maximum number of logs to return (default: 50)

        Returns:
            List of traffic log dictionaries
        """
        debug(f"Retrieving traffic logs for device {device_id}, limit={limit}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM traffic_logs
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (device_id, limit))

            rows = cursor.fetchall()
            conn.close()

            logs = []
            for row in rows:
                logs.append({
                    'time': row['timestamp'],
                    'src': row['source_ip'],
                    'dst': row['dest_ip'],
                    'sport': row['source_port'],
                    'dport': row['dest_port'],
                    'app': row['app'],
                    'bytes_sent': row['bytes_sent'],
                    'bytes_received': row['bytes_received'],
                    'action': row['action'],
                    'details_json': row['details_json']
                })

            debug(f"Retrieved {len(logs)} traffic logs")
            return logs

        except Exception as e:
            exception(f"Failed to retrieve traffic logs: {str(e)}")
            return []

    def insert_application_statistics(self, device_id: str, apps: List[Dict], collection_time: Optional[datetime] = None) -> bool:
        """
        Insert application statistics into database.

        Args:
            device_id: Device identifier
            apps: List of application statistics dictionaries from get_application_statistics()
            collection_time: Collection timestamp (defaults to now)

        Returns:
            True if successful, False otherwise
        """
        if collection_time is None:
            collection_time = datetime.now()

        debug(f"Inserting {len(apps)} application statistics for device {device_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert each application's statistics
            for app in apps:
                cursor.execute('''
                    INSERT INTO application_statistics (
                        device_id, collection_time, app_name, category,
                        sessions, bytes_total, bytes_sent, bytes_received,
                        source_count, dest_count,
                        protocols_json, ports_json, vlans_json, zones_json,
                        source_details_json, dest_details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    collection_time.isoformat(),
                    app.get('app', 'unknown'),
                    app.get('category', ''),
                    app.get('sessions', 0),
                    app.get('bytes', 0),
                    app.get('bytes_sent', 0),
                    app.get('bytes_received', 0),
                    app.get('source_count', 0),
                    app.get('dest_count', 0),
                    json.dumps(app.get('protocols', [])),
                    json.dumps(app.get('ports', [])),
                    json.dumps(app.get('vlans', [])),
                    json.dumps(app.get('zones', [])),
                    json.dumps(app.get('source_details', [])),
                    json.dumps(app.get('destination_details', []))
                ))

            # Auto-cleanup: Keep only last 1000 collections per device
            # First, get the timestamp of the 1000th most recent collection
            cursor.execute('''
                SELECT collection_time FROM (
                    SELECT DISTINCT collection_time
                    FROM application_statistics
                    WHERE device_id = ?
                    ORDER BY collection_time DESC
                    LIMIT 1 OFFSET 999
                )
            ''', (device_id,))

            cutoff_row = cursor.fetchone()
            if cutoff_row:
                cutoff_time = cutoff_row[0]
                cursor.execute('''
                    DELETE FROM application_statistics
                    WHERE device_id = ? AND collection_time < ?
                ''', (device_id, cutoff_time))
                deleted = cursor.rowcount
                if deleted > 0:
                    debug(f"Auto-cleanup: Deleted {deleted} old application statistics for device {device_id}")

            conn.commit()
            conn.close()

            debug(f"Successfully inserted {len(apps)} application statistics")
            return True

        except Exception as e:
            exception(f"Failed to insert application statistics: {str(e)}")
            return False

    def get_application_statistics(self, device_id: str, limit: int = 100) -> List[Dict]:
        """
        Get application statistics from database (latest collection).

        Args:
            device_id: Device identifier
            limit: Max number of applications to return (default 100)

        Returns:
            List of application statistics dictionaries
        """
        debug(f"Retrieving application statistics for device {device_id}, limit={limit}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get the most recent collection time for this device
            cursor.execute('''
                SELECT MAX(collection_time) as latest_time
                FROM application_statistics
                WHERE device_id = ?
            ''', (device_id,))

            row = cursor.fetchone()
            if not row or not row['latest_time']:
                debug(f"No application statistics found for device {device_id}")
                conn.close()
                return []

            latest_time = row['latest_time']

            # Get all applications from that collection
            cursor.execute('''
                SELECT * FROM application_statistics
                WHERE device_id = ? AND collection_time = ?
                ORDER BY bytes_total DESC
                LIMIT ?
            ''', (device_id, latest_time, limit))

            rows = cursor.fetchall()
            conn.close()

            apps = []
            for row in rows:
                # Parse JSON fields
                source_details = json.loads(row['source_details_json']) if row['source_details_json'] else []
                destination_details = json.loads(row['dest_details_json']) if row['dest_details_json'] else []

                apps.append({
                    'name': row['app_name'],  # Frontend expects 'name' not 'app'
                    'category': row['category'],
                    'sessions': row['sessions'],
                    'bytes': row['bytes_total'],
                    'bytes_sent': row['bytes_sent'],
                    'bytes_received': row['bytes_received'],
                    'source_count': row['source_count'],
                    'dest_count': row['dest_count'],
                    'sources': source_details,  # Frontend expects this for app details modal
                    'destinations': destination_details,  # Frontend expects this for destinations modal
                    'protocols': json.loads(row['protocols_json']) if row['protocols_json'] else [],
                    'ports': json.loads(row['ports_json']) if row['ports_json'] else [],
                    'vlans': json.loads(row['vlans_json']) if row['vlans_json'] else [],
                    'zones': json.loads(row['zones_json']) if row['zones_json'] else []
                })

            debug(f"Retrieved {len(apps)} application statistics from collection at {latest_time}")
            return apps

        except Exception as e:
            exception(f"Failed to retrieve application statistics: {str(e)}")
            return []

    def get_application_summary(self, device_id: str) -> Dict:
        """
        Get summary statistics for applications page dashboard.

        Args:
            device_id: Device identifier

        Returns:
            Dict with total_applications, traffic_volume, vlans_detected, zones_detected
        """
        debug(f"Retrieving application summary for device {device_id}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get the most recent collection time
            cursor.execute('''
                SELECT MAX(collection_time) as latest_time
                FROM application_statistics
                WHERE device_id = ?
            ''', (device_id,))

            row = cursor.fetchone()
            if not row or not row['latest_time']:
                conn.close()
                return {
                    'total_applications': 0,
                    'traffic_volume': 0,
                    'vlans_detected': 0,
                    'zones_detected': 0
                }

            latest_time = row['latest_time']

            # Get summary statistics from latest collection
            cursor.execute('''
                SELECT
                    COUNT(DISTINCT app_name) as total_apps,
                    SUM(bytes_total) as total_bytes
                FROM application_statistics
                WHERE device_id = ? AND collection_time = ?
            ''', (device_id, latest_time))

            row = cursor.fetchone()
            total_apps = row['total_apps'] or 0
            total_bytes = row['total_bytes'] or 0

            # Get unique VLANs count
            cursor.execute('''
                SELECT vlans_json
                FROM application_statistics
                WHERE device_id = ? AND collection_time = ?
            ''', (device_id, latest_time))

            all_vlans = set()
            for row in cursor.fetchall():
                if row['vlans_json']:
                    vlans = json.loads(row['vlans_json'])
                    all_vlans.update(vlans)

            # Get unique zones count
            cursor.execute('''
                SELECT zones_json
                FROM application_statistics
                WHERE device_id = ? AND collection_time = ?
            ''', (device_id, latest_time))

            all_zones = set()
            for row in cursor.fetchall():
                if row['zones_json']:
                    zones = json.loads(row['zones_json'])
                    all_zones.update(zones)

            conn.close()

            summary = {
                'total_applications': total_apps,
                'total_bytes': total_bytes,  # Frontend expects 'total_bytes'
                'vlans_detected': len(all_vlans),
                'zones_detected': len(all_zones)
            }

            debug(f"Application summary: {summary}")
            return summary

        except Exception as e:
            exception(f"Failed to retrieve application summary: {str(e)}")
            return {
                'total_applications': 0,
                'total_bytes': 0,  # Frontend expects 'total_bytes'
                'vlans_detected': 0,
                'zones_detected': 0
            }
