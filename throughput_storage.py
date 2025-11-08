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

            conn.commit()
            conn.close()

            info("Database schema initialized successfully")

        except Exception as e:
            exception("Failed to initialize database schema: %s", str(e))
            raise

        # Run schema migration for Phase 2 (adds new columns)
        self._migrate_schema_phase2()

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
                    hostname, uptime_seconds, pan_os_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                sample_data.get('pan_os_version')
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
                    'memory_used_pct': row['memory_used_pct']
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
                    'critical_logs': [],  # Not stored in database, would need separate query
                    'medium_logs': [],  # Not stored in database
                    'blocked_url_logs': []  # Not stored in database
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
                'pan_os_version': row['pan_os_version']
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
