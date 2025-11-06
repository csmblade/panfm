"""
Throughput Collector Module

Background service for collecting and storing historical network throughput data.
Runs as scheduled job via APScheduler to periodically collect data from enabled devices.

Author: PANfm Development Team
Created: 2025-11-06
"""

from datetime import datetime
from typing import Dict, Optional
from logger import debug, info, warning, error, exception
from device_manager import device_manager
from firewall_api import get_throughput_data
from throughput_storage import ThroughputStorage


class ThroughputCollector:
    """Background collector for network throughput data."""

    def __init__(self, storage: ThroughputStorage, retention_days: int = 90):
        """
        Initialize the throughput collector.

        Args:
            storage: ThroughputStorage instance
            retention_days: Number of days to retain historical data
        """
        self.storage = storage
        self.retention_days = retention_days
        self.collection_count = 0
        self.last_cleanup = None
        debug("ThroughputCollector initialized with %d-day retention", retention_days)

    def collect_all_devices(self):
        """
        Collect throughput data from all enabled devices and store in database.

        This is the main collection function called by the APScheduler job.
        """
        debug("Starting throughput collection cycle #%d", self.collection_count + 1)

        try:
            # Get all devices
            devices_data = device_manager.load_devices()
            devices = devices_data.get('devices', [])

            if not devices:
                debug("No devices configured, skipping collection")
                return

            # Count enabled devices
            enabled_devices = [d for d in devices if d.get('enabled', True)]
            debug("Found %d enabled devices out of %d total", len(enabled_devices), len(devices))

            # Collect data from each enabled device
            success_count = 0
            for device in enabled_devices:
                device_id = device.get('id')
                device_name = device.get('name', 'Unknown')

                debug("Collecting data for device: %s (ID: %s)", device_name, device_id)

                try:
                    # Get throughput data
                    throughput_data = get_throughput_data(device_id)

                    if throughput_data and throughput_data.get('status') == 'success':
                        # Store in database
                        if self.storage.insert_sample(device_id, throughput_data):
                            success_count += 1
                            debug("Successfully stored data for device: %s", device_name)
                        else:
                            warning("Failed to store data for device: %s", device_name)
                    else:
                        warning("Failed to get throughput data for device: %s", device_name)

                except Exception as e:
                    exception("Error collecting data for device %s: %s", device_name, str(e))
                    continue

            self.collection_count += 1
            info("Collection cycle #%d complete: %d/%d devices successful",
                 self.collection_count, success_count, len(enabled_devices))

            # Run cleanup periodically (every 24 hours = ~5760 collections at 15s intervals)
            if self.collection_count % 5760 == 0:
                self._run_cleanup()

        except Exception as e:
            exception("Error in collection cycle: %s", str(e))

    def _run_cleanup(self):
        """Run database cleanup to remove old samples."""
        debug("Running scheduled cleanup of old samples")

        try:
            deleted_count = self.storage.cleanup_old_samples(self.retention_days)
            self.last_cleanup = datetime.utcnow()

            if deleted_count > 0:
                info("Cleanup complete: removed %d old samples (retention: %d days)",
                     deleted_count, self.retention_days)
            else:
                debug("Cleanup complete: no old samples to remove")

        except Exception as e:
            exception("Error during cleanup: %s", str(e))

    def force_cleanup(self) -> int:
        """
        Manually trigger cleanup of old samples.

        Returns:
            Number of samples deleted
        """
        info("Manual cleanup triggered")
        deleted_count = self.storage.cleanup_old_samples(self.retention_days)
        self.last_cleanup = datetime.utcnow()
        return deleted_count

    def get_collector_stats(self) -> Dict:
        """
        Get statistics about the collector.

        Returns:
            Dictionary with collector statistics
        """
        debug("Retrieving collector statistics")

        storage_stats = self.storage.get_storage_stats()

        stats = {
            'collection_count': self.collection_count,
            'last_cleanup': self.last_cleanup.isoformat() if self.last_cleanup else None,
            'retention_days': self.retention_days,
            'storage': storage_stats
        }

        return stats


# Global collector instance (initialized in app.py)
collector = None


def init_collector(db_path: str, retention_days: int = 90) -> ThroughputCollector:
    """
    Initialize the global throughput collector.

    Args:
        db_path: Path to SQLite database file
        retention_days: Number of days to retain historical data

    Returns:
        ThroughputCollector instance
    """
    global collector

    debug("Initializing global throughput collector (retention: %d days)", retention_days)

    storage = ThroughputStorage(db_path)
    collector = ThroughputCollector(storage, retention_days)

    info("Throughput collector initialized successfully")
    return collector


def get_collector() -> Optional[ThroughputCollector]:
    """
    Get the global collector instance.

    Returns:
        ThroughputCollector instance or None if not initialized
    """
    return collector
