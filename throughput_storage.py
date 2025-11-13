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


def is_private_ip(ip):
    """
    Check if an IP address is a private (RFC 1918) address.

    Args:
        ip: IP address string (e.g., "192.168.1.1")

    Returns:
        bool: True if IP is private, False otherwise
    """
    if not ip or ip == 'N/A' or ip == '':
        return False

    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        first = int(parts[0])
        second = int(parts[1])

        # 10.0.0.0/8 (Class A private network)
        if first == 10:
            return True

        # 172.16.0.0/12 (Class B private network)
        if first == 172 and 16 <= second <= 31:
            return True

        # 192.168.0.0/16 (Class C private network)
        if first == 192 and second == 168:
            return True

        # Loopback 127.0.0.0/8
        if first == 127:
            return True

        # Link-local 169.254.0.0/16
        if first == 169 and second == 254:
            return True

        return False
    except (ValueError, IndexError):
        return False


def is_internet_traffic(src_ip, dst_ip):
    """
    Check if traffic is internet-bound (local to public or vice versa).

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address

    Returns:
        bool: True if one end is private and one is public (internet traffic)
    """
    src_private = is_private_ip(src_ip)
    dst_private = is_private_ip(dst_ip)

    # Internet traffic = one private, one public
    return (src_private and not dst_private) or (not src_private and dst_private)


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
                    memory_used_pct INTEGER,
                    top_bandwidth_client_json TEXT
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

            # Add UNIQUE constraint to prevent duplicate timestamps per device
            # This prevents race conditions and ensures data integrity
            cursor.execute('''
                CREATE UNIQUE INDEX IF NOT EXISTS idx_device_timestamp_unique
                ON throughput_samples(device_id, timestamp)
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

            # Create scheduler_stats table (Priority 2: Clock process health monitoring)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scheduler_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    state TEXT NOT NULL,
                    total_executions INTEGER DEFAULT 0,
                    total_errors INTEGER DEFAULT 0,
                    last_execution DATETIME,
                    last_error TEXT,
                    last_error_time DATETIME,
                    uptime_seconds INTEGER DEFAULT 0,
                    jobs_json TEXT,
                    execution_history_json TEXT
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_scheduler_timestamp
                ON scheduler_stats(timestamp DESC)
            ''')

            conn.commit()
            conn.close()

            info("Database schema initialized successfully (including Phase 3 log tables, Phase 4 application_statistics, and scheduler_stats)")

        except Exception as e:
            exception("Failed to initialize database schema: %s", str(e))
            raise

        # Run schema migration for Phase 2 (adds new columns)
        self._migrate_schema_phase2()

        # Run schema migration for Phase 3 (adds category support)
        self._migrate_schema_phase3()

        # Run schema migration for connected devices table
        self._migrate_schema_connected_devices()

        # Run schema migration for traffic separation (top clients split)
        self._migrate_schema_traffic_separation()

        # Run schema migration for category split (top category LAN/Internet)
        self._migrate_schema_category_split()

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
                ('pan_os_version', 'TEXT'),
                ('top_bandwidth_client_json', 'TEXT')
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

    def _migrate_schema_connected_devices(self):
        """
        Migrate database schema for connected devices storage.

        Creates connected_devices table for storing ARP entries with metadata.
        Safe to run multiple times (uses CREATE TABLE IF NOT EXISTS).
        """
        debug("Checking for connected_devices schema migration")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create connected_devices table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connected_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    collection_time DATETIME NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    hostname TEXT,
                    vlan TEXT,
                    interface TEXT,
                    ttl TEXT,
                    status TEXT,
                    port TEXT,
                    zone TEXT,
                    vendor TEXT,
                    is_virtual INTEGER DEFAULT 0,
                    virtual_type TEXT,
                    is_randomized INTEGER DEFAULT 0,
                    custom_name TEXT,
                    comment TEXT,
                    location TEXT,
                    tags_json TEXT,
                    original_hostname TEXT
                )
            ''')

            # Create indexes for efficient queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_connected_device_time
                ON connected_devices(device_id, collection_time DESC)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_connected_mac
                ON connected_devices(device_id, mac, collection_time DESC)
            ''')

            conn.commit()
            conn.close()

            info("Connected devices schema initialized successfully")

        except Exception as e:
            exception("Error during connected_devices schema migration: %s", str(e))
            # Don't raise - allow app to continue with existing schema

    def _migrate_schema_traffic_separation(self):
        """
        Migrate database schema for traffic separation feature.

        Adds columns for storing top internal client and top internet client separately.
        Safe to run multiple times (uses ALTER TABLE with error handling).
        """
        debug("Checking for traffic separation schema migration")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # List of new columns for traffic separation
            new_columns = [
                ('top_internal_client_json', 'TEXT'),  # Top client for internal-only traffic
                ('top_internet_client_json', 'TEXT')   # Top client for internet-bound traffic
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
                info(f"Traffic separation migration: added {columns_added} new columns")
            else:
                debug("Traffic separation migration: all columns already exist")

        except Exception as e:
            exception("Error during traffic separation schema migration: %s", str(e))
            # Don't raise - allow app to continue with existing schema

    def _migrate_schema_category_split(self):
        """
        Migrate database schema for split top categories (Local LAN vs Internet).

        Adds columns for storing top category split by traffic direction.
        Safe to run multiple times (uses ALTER TABLE with error handling).
        """
        debug("Checking for category split schema migration")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # List of new columns for split categories
            new_columns = [
                ('top_category_lan_json', 'TEXT'),  # Top category for local LAN traffic
                ('top_category_internet_json', 'TEXT')  # Top category for internet traffic
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
                info(f"Category split migration: added {columns_added} new columns")
            else:
                debug("Category split migration: all columns already exist")

        except Exception as e:
            exception("Error during category split schema migration: %s", str(e))
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

            # Duplicate prevention: Check if sample with same device_id and timestamp already exists
            cursor.execute('''
                SELECT COUNT(*) FROM throughput_samples
                WHERE device_id = ? AND timestamp = ?
            ''', (device_id, timestamp))

            existing_count = cursor.fetchone()[0]
            if existing_count > 0:
                debug("Duplicate sample detected for device %s at timestamp %s, skipping insert", device_id, timestamp)
                conn.close()
                return True  # Return True as data already exists

            # Serialize JSON fields
            top_apps_json = json.dumps(sample_data.get('top_applications', [])) if sample_data.get('top_applications') else None
            interface_stats_json = json.dumps(sample_data.get('interface_stats', [])) if sample_data.get('interface_stats') else None
            categories_json = json.dumps(sample_data.get('categories', {})) if sample_data.get('categories') else None
            top_bandwidth_client_json = json.dumps(sample_data.get('top_bandwidth_client', {})) if sample_data.get('top_bandwidth_client') else None
            top_internal_client_json = json.dumps(sample_data.get('top_internal_client', {})) if sample_data.get('top_internal_client') else None
            top_internet_client_json = json.dumps(sample_data.get('top_internet_client', {})) if sample_data.get('top_internet_client') else None
            top_category_lan_json = json.dumps(sample_data.get('top_category_lan', {})) if sample_data.get('top_category_lan') else None
            top_category_internet_json = json.dumps(sample_data.get('top_category_internet', {})) if sample_data.get('top_category_internet') else None

            cursor.execute('''
                INSERT OR IGNORE INTO throughput_samples (
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
                    categories_json,
                    top_bandwidth_client_json,
                    top_internal_client_json,
                    top_internet_client_json,
                    top_category_lan_json,
                    top_category_internet_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                categories_json,
                # Cyber Health: Top bandwidth client (JSON)
                top_bandwidth_client_json,
                # Traffic Separation: Top internal and internet clients (JSON)
                top_internal_client_json,
                top_internet_client_json,
                # Category Split: Top category for LAN and Internet (JSON)
                top_category_lan_json,
                top_category_internet_json
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

    def cleanup_old_traffic_logs(self, retention_days: int) -> int:
        """
        Delete traffic logs older than retention period.

        Args:
            retention_days: Number of days to retain data

        Returns:
            Number of logs deleted
        """
        debug("Cleaning up traffic logs older than %d days", retention_days)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            cursor.execute('''
                DELETE FROM traffic_logs
                WHERE timestamp < ?
            ''', (cutoff_date.isoformat(),))

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_count > 0:
                info("Cleaned up %d old traffic logs (cutoff: %s)", deleted_count, cutoff_date)
            else:
                debug("No old traffic logs to clean up")

            return deleted_count

        except Exception as e:
            exception("Failed to cleanup old traffic logs: %s", str(e))
            return 0

    def cleanup_old_system_logs(self, retention_days: int) -> int:
        """
        Delete system logs older than retention period.

        Args:
            retention_days: Number of days to retain data

        Returns:
            Number of logs deleted
        """
        debug("Cleaning up system logs older than %d days", retention_days)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            cursor.execute('''
                DELETE FROM system_logs
                WHERE timestamp < ?
            ''', (cutoff_date.isoformat(),))

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_count > 0:
                info("Cleaned up %d old system logs (cutoff: %s)", deleted_count, cutoff_date)
            else:
                debug("No old system logs to clean up")

            return deleted_count

        except Exception as e:
            exception("Failed to cleanup old system logs: %s", str(e))
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

            # Query most recent sample within time window (all Phase 1 + Phase 2 + Traffic Separation columns)
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
                    hostname, uptime_seconds, pan_os_version,
                    top_bandwidth_client_json,
                    top_internal_client_json,
                    top_internet_client_json,
                    top_category_lan_json,
                    top_category_internet_json
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
            top_bandwidth_client = json.loads(row['top_bandwidth_client_json']) if row['top_bandwidth_client_json'] else {}
            top_internal_client = json.loads(row['top_internal_client_json']) if row['top_internal_client_json'] else {}
            top_internet_client = json.loads(row['top_internet_client_json']) if row['top_internet_client_json'] else {}
            top_category_lan = json.loads(row['top_category_lan_json']) if row['top_category_lan_json'] else {}
            top_category_internet = json.loads(row['top_category_internet_json']) if row['top_category_internet_json'] else {}

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
                'panos_version': row['pan_os_version'],  # Dashboard UI expects 'panos_version'
                # Cyber Health: Top bandwidth client
                'top_bandwidth_client': top_bandwidth_client,
                # Traffic Separation: Internal and internet clients
                'top_internal_client': top_internal_client,
                'top_internet_client': top_internet_client,
                # Category Split: Top category for LAN and Internet
                'top_category_lan': top_category_lan,
                'top_category_internet': top_category_internet
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
                # Parse details_json if available
                details = {}
                if row['details_json']:
                    try:
                        details = json.loads(row['details_json'])
                    except:
                        pass

                # Map database fields to frontend-expected fields
                logs.append({
                    'time': row['timestamp'],
                    'eventid': details.get('eventid', 'undefined'),
                    'severity': row['severity'] or 'informational',
                    'module': details.get('module', 'undefined'),
                    'subtype': details.get('subtype', 'undefined'),
                    'description': row['message'] or 'undefined',
                    'result': details.get('result', 'undefined')
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

    def get_top_category_for_range(self, device_id: str, time_range: str = None) -> Dict:
        """
        Get top application category by volume for a time range.

        Args:
            device_id: Device identifier
            time_range: Time range string (1h, 6h, 24h, 7d, 30d) or None for latest

        Returns:
            Dict with 'category' name and 'bytes' volume, or empty dict if no data
        """
        debug(f"Getting top category for device {device_id}, range={time_range}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Calculate time window
            if time_range and time_range != 'realtime':
                # Parse time range
                range_minutes = self._parse_time_range(time_range)
                if range_minutes is None:
                    debug(f"Invalid time range: {time_range}, using latest snapshot")
                    time_range = None
                else:
                    cutoff_time = datetime.now() - timedelta(minutes=range_minutes)
                    cutoff_str = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')

            if time_range and time_range != 'realtime':
                # Aggregate over time range
                debug(f"Aggregating applications since {cutoff_str}")
                cursor.execute('''
                    SELECT category, SUM(bytes_total) as total_bytes
                    FROM application_statistics
                    WHERE device_id = ? AND collection_time >= ?
                    GROUP BY category
                    ORDER BY total_bytes DESC
                    LIMIT 1
                ''', (device_id, cutoff_str))
            else:
                # Get latest snapshot only
                debug(f"Getting top category from latest snapshot")
                cursor.execute('''
                    SELECT MAX(collection_time) as latest_time
                    FROM application_statistics
                    WHERE device_id = ?
                ''', (device_id,))

                row = cursor.fetchone()
                if not row or not row['latest_time']:
                    conn.close()
                    return {}

                latest_time = row['latest_time']

                cursor.execute('''
                    SELECT category, SUM(bytes_total) as total_bytes
                    FROM application_statistics
                    WHERE device_id = ? AND collection_time = ?
                    GROUP BY category
                    ORDER BY total_bytes DESC
                    LIMIT 1
                ''', (device_id, latest_time))

            row = cursor.fetchone()
            conn.close()

            if row and row['category']:
                result = {
                    'category': row['category'],
                    'bytes': row['total_bytes']
                }
                debug(f"Top category: {result['category']} with {result['bytes']} bytes")
                return result
            else:
                debug("No category data found")
                return {}

        except Exception as e:
            exception(f"Failed to get top category: {str(e)}")
            return {}

    # ========================================================================
    # Connected Devices Storage Methods
    # ========================================================================

    def insert_connected_devices(self, device_id: str, devices: List[Dict], collection_time: Optional[datetime] = None) -> bool:
        """
        Insert connected devices data into database.
        Automatically enforces 1,000-collection retention per device.

        Args:
            device_id: Firewall device identifier
            devices: List of device dictionaries from get_connected_devices()
            collection_time: Collection timestamp (defaults to now)

        Returns:
            True if successful, False otherwise
        """
        if not devices:
            debug(f"No devices to insert for device {device_id}")
            return True

        if collection_time is None:
            collection_time = datetime.utcnow()

        debug(f"Inserting {len(devices)} connected devices for device {device_id} at {collection_time.isoformat()}")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Insert each device
            for device in devices:
                cursor.execute('''
                    INSERT INTO connected_devices (
                        device_id, collection_time, ip, mac, hostname,
                        vlan, interface, ttl, status, port, zone,
                        vendor, is_virtual, virtual_type, is_randomized,
                        custom_name, comment, location, tags_json, original_hostname
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_id,
                    collection_time.isoformat(),
                    device.get('ip', '-'),
                    device.get('mac', '-'),
                    device.get('hostname', '-'),
                    device.get('vlan', '-'),
                    device.get('interface', '-'),
                    device.get('ttl', '-'),
                    device.get('status', '-'),
                    device.get('port', '-'),
                    device.get('zone', '-'),
                    device.get('vendor'),
                    1 if device.get('is_virtual') else 0,
                    device.get('virtual_type'),
                    1 if device.get('is_randomized') else 0,
                    device.get('custom_name'),
                    device.get('comment'),
                    device.get('location'),
                    json.dumps(device.get('tags', [])) if device.get('tags') else None,
                    device.get('original_hostname', '-')
                ))

            # Enforce 1,000-collection retention per device
            # Count distinct collection times
            cursor.execute('''
                SELECT COUNT(DISTINCT collection_time)
                FROM connected_devices
                WHERE device_id = ?
            ''', (device_id,))

            collection_count = cursor.fetchone()[0]

            if collection_count > 1000:
                # Get the 1000th most recent collection time
                cursor.execute('''
                    SELECT DISTINCT collection_time
                    FROM connected_devices
                    WHERE device_id = ?
                    ORDER BY collection_time DESC
                    LIMIT 1 OFFSET 999
                ''', (device_id,))

                cutoff_row = cursor.fetchone()
                if cutoff_row:
                    cutoff_time = cutoff_row[0]
                    cursor.execute('''
                        DELETE FROM connected_devices
                        WHERE device_id = ? AND collection_time < ?
                    ''', (device_id, cutoff_time))

                    deleted_count = cursor.rowcount
                    if deleted_count > 0:
                        debug(f"Auto-cleanup: Deleted {deleted_count} old connected device records for device {device_id}")

            conn.commit()
            conn.close()

            debug(f"Successfully inserted {len(devices)} connected devices for device {device_id}")
            return True

        except Exception as e:
            exception(f"Failed to insert connected devices for device {device_id}: {str(e)}")
            return False

    def get_connected_devices(self, device_id: str, max_age_seconds: int = 90) -> List[Dict]:
        """
        Get connected devices from most recent collection.

        Args:
            device_id: Firewall device identifier
            max_age_seconds: Maximum age of data in seconds (default: 90)

        Returns:
            List of device dictionaries in same format as firewall_api_devices.get_connected_devices()
        """
        debug(f"Retrieving connected devices for device {device_id} (max age: {max_age_seconds}s)")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Calculate cutoff time
            cutoff_time = datetime.utcnow() - timedelta(seconds=max_age_seconds)

            # Get the most recent collection time within the time window
            cursor.execute('''
                SELECT MAX(collection_time) as latest_time
                FROM connected_devices
                WHERE device_id = ? AND collection_time >= ?
            ''', (device_id, cutoff_time.isoformat()))

            row = cursor.fetchone()
            if not row or not row['latest_time']:
                debug(f"No recent connected devices data found for device {device_id}")
                conn.close()
                return []

            latest_time = row['latest_time']

            # Get all devices from that collection
            cursor.execute('''
                SELECT * FROM connected_devices
                WHERE device_id = ? AND collection_time = ?
                ORDER BY ip
            ''', (device_id, latest_time))

            rows = cursor.fetchall()
            conn.close()

            # Convert to dictionaries matching original format
            devices = []
            for row in rows:
                device = {
                    'ip': row['ip'],
                    'mac': row['mac'],
                    'hostname': row['hostname'],
                    'vlan': row['vlan'],
                    'interface': row['interface'],
                    'ttl': row['ttl'],
                    'status': row['status'],
                    'port': row['port'],
                    'zone': row['zone'],
                    'vendor': row['vendor'],
                    'is_virtual': bool(row['is_virtual']),
                    'virtual_type': row['virtual_type'],
                    'is_randomized': bool(row['is_randomized']),
                    'custom_name': row['custom_name'],
                    'comment': row['comment'],
                    'location': row['location'],
                    'tags': json.loads(row['tags_json']) if row['tags_json'] else [],
                    'original_hostname': row['original_hostname']
                }
                devices.append(device)

            debug(f"Retrieved {len(devices)} connected devices from collection at {latest_time}")
            return devices

        except Exception as e:
            exception(f"Failed to retrieve connected devices for device {device_id}: {str(e)}")
            return []

    def get_connected_device_history(self, device_id: str, mac: str, limit: int = 100) -> List[Dict]:
        """
        Get history for a specific device by MAC address.

        Args:
            device_id: Firewall device identifier
            mac: MAC address to track
            limit: Maximum number of historical records to return

        Returns:
            List of historical device records
        """
        debug(f"Retrieving device history for MAC {mac} on device {device_id}, limit={limit}")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM connected_devices
                WHERE device_id = ? AND mac = ?
                ORDER BY collection_time DESC
                LIMIT ?
            ''', (device_id, mac, limit))

            rows = cursor.fetchall()
            conn.close()

            history = []
            for row in rows:
                history.append({
                    'collection_time': row['collection_time'],
                    'ip': row['ip'],
                    'hostname': row['hostname'],
                    'interface': row['interface'],
                    'zone': row['zone'],
                    'status': row['status']
                })

            debug(f"Retrieved {len(history)} historical records for MAC {mac}")
            return history

        except Exception as e:
            exception(f"Failed to retrieve device history for MAC {mac}: {str(e)}")
            return []

    def get_per_ip_bandwidth_5min(self, device_id: str, threshold_bytes: int = 1_000_000_000) -> List[Dict]:
        """
        Query traffic logs to find IPs that downloaded/uploaded threshold bytes in last 5 minutes.

        Args:
            device_id: Firewall device identifier
            threshold_bytes: Minimum bytes to trigger (default: 1GB = 1,000,000,000)

        Returns:
            List of dicts: [{'ip': '192.168.1.100', 'total_bytes': 1500000000, 'direction': 'download', 'hostname': 'Johns-Laptop'}, ...]
        """
        debug(f"Querying per-IP bandwidth for device {device_id}, threshold={threshold_bytes} bytes")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Calculate 5-minute window
            cutoff_time = datetime.utcnow() - timedelta(minutes=5)

            # Query for downloads (bytes_received) - aggregate by source_ip
            cursor.execute('''
                SELECT
                    source_ip as ip,
                    SUM(bytes_received) as total_bytes,
                    'download' as direction
                FROM traffic_logs
                WHERE device_id = ?
                    AND timestamp >= ?
                    AND bytes_received IS NOT NULL
                GROUP BY source_ip
                HAVING SUM(bytes_received) >= ?
            ''', (device_id, cutoff_time.isoformat(), threshold_bytes))

            download_results = cursor.fetchall()

            # Query for uploads (bytes_sent) - aggregate by source_ip
            cursor.execute('''
                SELECT
                    source_ip as ip,
                    SUM(bytes_sent) as total_bytes,
                    'upload' as direction
                FROM traffic_logs
                WHERE device_id = ?
                    AND timestamp >= ?
                    AND bytes_sent IS NOT NULL
                GROUP BY source_ip
                HAVING SUM(bytes_sent) >= ?
            ''', (device_id, cutoff_time.isoformat(), threshold_bytes))

            upload_results = cursor.fetchall()

            conn.close()

            # Combine results and enrich with hostnames
            results = []

            for row in download_results:
                ip = row['ip']
                hostname = self.get_hostname_for_ip(device_id, ip)
                results.append({
                    'ip': ip,
                    'total_bytes': row['total_bytes'],
                    'direction': 'download',
                    'hostname': hostname
                })

            for row in upload_results:
                ip = row['ip']
                hostname = self.get_hostname_for_ip(device_id, ip)
                results.append({
                    'ip': ip,
                    'total_bytes': row['total_bytes'],
                    'direction': 'upload',
                    'hostname': hostname
                })

            debug(f"Found {len(results)} IPs exceeding {threshold_bytes} bytes in last 5 minutes")
            return results

        except Exception as e:
            exception(f"Failed to query per-IP bandwidth for device {device_id}: {str(e)}")
            return []

    def get_top_internal_client(self, device_id: str, minutes: int = 5) -> Optional[Dict]:
        """
        Get the top internal client (local-to-local traffic only) in the last N minutes.

        Args:
            device_id: Firewall device identifier
            minutes: Time window in minutes (default: 5)

        Returns:
            Dict with ip, hostname, custom_name, bytes_sent, bytes_received, total_bytes
            or None if no internal traffic found
        """
        debug(f"Getting top internal client for device {device_id} (last {minutes} min)")

        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)

            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Query for traffic where BOTH src and dst are private IPs
            # Aggregate by source_ip
            cursor.execute('''
                SELECT
                    source_ip as ip,
                    SUM(bytes_sent) as total_sent,
                    SUM(bytes_received) as total_received,
                    SUM(bytes_sent + bytes_received) as total_bytes
                FROM traffic_logs
                WHERE device_id = ?
                    AND timestamp >= ?
                    AND source_ip IS NOT NULL
                    AND dest_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY total_bytes DESC
                LIMIT 100
            ''', (device_id, cutoff_time.isoformat()))

            rows = cursor.fetchall()
            conn.close()

            # Filter for internal traffic only (both src and dst private)
            # Need to re-query to check destinations
            for row in rows:
                ip = row['ip']

                # Skip if source is not private
                if not is_private_ip(ip):
                    continue

                # Check if this IP's destinations are all private
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT dest_ip
                    FROM traffic_logs
                    WHERE device_id = ?
                        AND source_ip = ?
                        AND timestamp >= ?
                    LIMIT 100
                ''', (device_id, ip, cutoff_time.isoformat()))

                dest_rows = cursor.fetchall()
                conn.close()

                # Check if all destinations are private
                has_public_dest = False
                for dest_row in dest_rows:
                    if not is_private_ip(dest_row['dest_ip']):
                        has_public_dest = True
                        break

                # If this IP only talks to private destinations, it's pure internal
                if not has_public_dest and len(dest_rows) > 0:
                    hostname = self.get_hostname_for_ip(device_id, ip)
                    custom_name = self.get_custom_name_for_ip(device_id, ip)

                    result = {
                        'ip': ip,
                        'hostname': hostname,
                        'custom_name': custom_name,
                        'bytes_sent': row['total_sent'] or 0,
                        'bytes_received': row['total_received'] or 0,
                        'total_bytes': row['total_bytes'] or 0
                    }
                    debug(f"Top internal client: {ip} ({hostname}) - {result['total_bytes']} bytes")
                    return result

            debug("No internal-only traffic found")
            return None

        except Exception as e:
            exception(f"Failed to get top internal client: {str(e)}")
            return None

    def get_top_internet_client(self, device_id: str, minutes: int = 5) -> Optional[Dict]:
        """
        Get the top internet client (local IP with most traffic to/from public IPs) in the last N minutes.

        Args:
            device_id: Firewall device identifier
            minutes: Time window in minutes (default: 5)

        Returns:
            Dict with ip, hostname, custom_name, bytes_sent, bytes_received, total_bytes
            or None if no internet traffic found
        """
        debug(f"Getting top internet client for device {device_id} (last {minutes} min)")

        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)

            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Query all traffic
            cursor.execute('''
                SELECT
                    source_ip,
                    dest_ip,
                    bytes_sent,
                    bytes_received
                FROM traffic_logs
                WHERE device_id = ?
                    AND timestamp >= ?
                    AND source_ip IS NOT NULL
                    AND dest_ip IS NOT NULL
            ''', (device_id, cutoff_time.isoformat()))

            rows = cursor.fetchall()
            conn.close()

            # Aggregate internet traffic by local source IP
            ip_totals = {}

            for row in rows:
                src_ip = row['source_ip']
                dst_ip = row['dest_ip']

                # Only count if it's internet traffic (one private, one public)
                if is_internet_traffic(src_ip, dst_ip):
                    # Aggregate by the private IP (local client)
                    local_ip = src_ip if is_private_ip(src_ip) else dst_ip

                    if local_ip not in ip_totals:
                        ip_totals[local_ip] = {
                            'bytes_sent': 0,
                            'bytes_received': 0
                        }

                    ip_totals[local_ip]['bytes_sent'] += row['bytes_sent'] or 0
                    ip_totals[local_ip]['bytes_received'] += row['bytes_received'] or 0

            # Find top client by total bytes
            if not ip_totals:
                debug("No internet traffic found")
                return None

            top_ip = max(ip_totals.keys(), key=lambda ip: ip_totals[ip]['bytes_sent'] + ip_totals[ip]['bytes_received'])

            hostname = self.get_hostname_for_ip(device_id, top_ip)
            custom_name = self.get_custom_name_for_ip(device_id, top_ip)

            total_bytes = ip_totals[top_ip]['bytes_sent'] + ip_totals[top_ip]['bytes_received']

            result = {
                'ip': top_ip,
                'hostname': hostname,
                'custom_name': custom_name,
                'bytes_sent': ip_totals[top_ip]['bytes_sent'],
                'bytes_received': ip_totals[top_ip]['bytes_received'],
                'total_bytes': total_bytes
            }

            debug(f"Top internet client: {top_ip} ({hostname}) - {total_bytes} bytes")
            return result

        except Exception as e:
            exception(f"Failed to get top internet client: {str(e)}")
            return None

    def get_custom_name_for_ip(self, device_id: str, ip: str) -> Optional[str]:
        """
        Get custom name for an IP address from connected_devices table.

        Args:
            device_id: Firewall device identifier
            ip: IP address to lookup

        Returns:
            Custom name if found, otherwise None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT custom_name
                FROM connected_devices
                WHERE device_id = ? AND ip = ?
                ORDER BY collection_time DESC
                LIMIT 1
            ''', (device_id, ip))

            row = cursor.fetchone()
            conn.close()

            if row and row['custom_name']:
                return row['custom_name']
            return None

        except Exception as e:
            debug(f"Could not get custom name for {ip}: {str(e)}")
            return None

    def get_hostname_for_ip(self, device_id: str, ip: str) -> str:
        """
        Get hostname for an IP address from connected_devices table.

        Args:
            device_id: Firewall device identifier
            ip: IP address to lookup

        Returns:
            Hostname if found, otherwise IP address
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get most recent hostname for this IP
            cursor.execute('''
                SELECT hostname, custom_name
                FROM connected_devices
                WHERE device_id = ? AND ip = ?
                ORDER BY collection_time DESC
                LIMIT 1
            ''', (device_id, ip))

            row = cursor.fetchone()
            conn.close()

            if row:
                # Prefer custom_name if available, otherwise hostname
                if row['custom_name']:
                    return row['custom_name']
                elif row['hostname'] and row['hostname'] != '-':
                    return row['hostname']

            # Return IP if no hostname found
            return ip

        except Exception as e:
            exception(f"Failed to get hostname for IP {ip}: {str(e)}")
            return ip

    def insert_scheduler_stats(self, stats: Dict) -> bool:
        """
        Insert current scheduler statistics into database.

        Args:
            stats: Dictionary with scheduler stats (from clock.py)

        Returns:
            True if successful, False otherwise
        """
        debug("Inserting scheduler stats into database")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO scheduler_stats (
                    timestamp, state, total_executions, total_errors,
                    last_execution, last_error, last_error_time, uptime_seconds,
                    jobs_json, execution_history_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                stats.get('timestamp') or datetime.utcnow().isoformat(),
                stats.get('state', 'unknown'),
                stats.get('total_executions', 0),
                stats.get('total_errors', 0),
                stats.get('last_execution'),
                stats.get('last_error'),
                stats.get('last_error_time'),
                stats.get('uptime_seconds', 0),
                json.dumps(stats.get('jobs', {})),
                json.dumps(stats.get('execution_history', []))
            ))

            conn.commit()
            conn.close()

            debug("Successfully inserted scheduler stats")
            return True

        except Exception as e:
            exception(f"Failed to insert scheduler stats: {str(e)}")
            return False

    def get_latest_scheduler_stats(self) -> Optional[Dict]:
        """
        Retrieve the most recent scheduler statistics from database.

        Returns:
            Dictionary with scheduler stats or None if no data
        """
        debug("Retrieving latest scheduler stats")

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM scheduler_stats
                ORDER BY timestamp DESC
                LIMIT 1
            ''')

            row = cursor.fetchone()
            conn.close()

            if not row:
                debug("No scheduler stats found in database")
                return None

            # Parse JSON fields
            jobs = {}
            execution_history = []
            if row['jobs_json']:
                try:
                    jobs = json.loads(row['jobs_json'])
                except:
                    pass
            if row['execution_history_json']:
                try:
                    execution_history = json.loads(row['execution_history_json'])
                except:
                    pass

            stats = {
                'id': row['id'],
                'timestamp': row['timestamp'],
                'state': row['state'],
                'total_executions': row['total_executions'],
                'total_errors': row['total_errors'],
                'last_execution': row['last_execution'],
                'last_error': row['last_error'],
                'last_error_time': row['last_error_time'],
                'uptime_seconds': row['uptime_seconds'],
                'jobs': jobs,
                'execution_history': execution_history
            }

            debug(f"Retrieved scheduler stats: state={stats['state']}, executions={stats['total_executions']}")
            return stats

        except Exception as e:
            exception(f"Failed to retrieve scheduler stats: {str(e)}")
            return None

    def cleanup_old_scheduler_stats(self, retention_hours: int = 24) -> int:
        """
        Delete scheduler stats older than retention period.

        Args:
            retention_hours: Number of hours to retain data (default: 24)

        Returns:
            Number of records deleted
        """
        debug(f"Cleaning up scheduler stats older than {retention_hours} hours")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cutoff_time = datetime.utcnow() - timedelta(hours=retention_hours)

            cursor.execute('''
                DELETE FROM scheduler_stats
                WHERE timestamp < ?
            ''', (cutoff_time.isoformat(),))

            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()

            if deleted_count > 0:
                debug(f"Deleted {deleted_count} old scheduler stats records")

            return deleted_count

        except Exception as e:
            exception(f"Failed to cleanup scheduler stats: {str(e)}")
            return 0
