"""
Backup & Restore Manager for PANfm
Handles comprehensive site-wide backup and restore of Settings, Devices, and Metadata.
All backups are encrypted and timestamped.
"""
import os
import json
from datetime import datetime
from config import load_settings, save_settings, SETTINGS_FILE
from device_manager import device_manager
from device_metadata import load_metadata, save_metadata, check_migration_needed, migrate_global_to_per_device
from logger import debug, info, warning, error, exception


def create_full_backup():
    """
    Create comprehensive backup of Settings, Devices, and Metadata.

    Returns:
        dict: Backup dictionary with structure:
              {
                  'version': '1.6.0',
                  'timestamp': 'ISO-8601 timestamp',
                  'settings': {...},
                  'devices': {...},
                  'metadata': {...}
              }
        None: On error
    """
    debug("Creating full site backup")
    try:
        # Load settings
        settings = load_settings()
        debug(f"Loaded settings: {len(settings)} keys")

        # Load devices with decrypted API keys
        devices_list = device_manager.load_devices(decrypt_api_keys=True)
        debug(f"Loaded devices: {len(devices_list)} devices")

        # Load full devices data structure to get groups (but use decrypted devices list)
        with open(device_manager.devices_file, 'r') as f:
            file_data = json.load(f)

        # Build devices_data with decrypted devices + groups from file
        devices_data = {
            'devices': devices_list,  # Use decrypted list
            'groups': file_data.get('groups', [])
        }

        # Load metadata (get all, regardless of format)
        metadata = load_metadata(use_cache=False)
        debug(f"Loaded metadata")

        # Create backup structure
        backup = {
            'version': '1.6.0',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'settings': settings,
            'devices': devices_data,
            'metadata': metadata
        }

        info("Successfully created full backup")
        return backup
    except Exception as e:
        exception(f"Failed to create backup: {str(e)}")
        return None


def restore_from_backup(backup_data, restore_settings=True, restore_devices=True, restore_metadata=True):
    """
    Restore site configuration from backup.

    Args:
        backup_data (dict): Backup dictionary from create_full_backup()
        restore_settings (bool): Whether to restore settings
        restore_devices (bool): Whether to restore devices
        restore_metadata (bool): Whether to restore metadata

    Returns:
        dict: Result with structure:
              {
                  'success': bool,
                  'restored': ['settings', 'devices', 'metadata'],
                  'errors': ['error messages if any']
              }
    """
    debug(f"Starting restore (settings={restore_settings}, devices={restore_devices}, metadata={restore_metadata})")

    result = {
        'success': True,
        'restored': [],
        'errors': []
    }

    try:
        # Validate backup structure
        if not isinstance(backup_data, dict):
            result['success'] = False
            result['errors'].append("Invalid backup format: not a dictionary")
            return result

        if 'version' not in backup_data or 'timestamp' not in backup_data:
            result['success'] = False
            result['errors'].append("Invalid backup format: missing version or timestamp")
            return result

        debug(f"Restoring from backup version {backup_data.get('version')} created at {backup_data.get('timestamp')}")

        # Restore settings
        if restore_settings and 'settings' in backup_data:
            try:
                settings = backup_data['settings']
                if save_settings(settings):
                    result['restored'].append('settings')
                    info("Successfully restored settings")
                else:
                    result['errors'].append("Failed to save settings")
            except Exception as e:
                result['errors'].append(f"Settings restore error: {str(e)}")
                exception(f"Failed to restore settings: {str(e)}")

        # Restore devices
        if restore_devices and 'devices' in backup_data:
            try:
                devices_data = backup_data['devices']
                # save_devices expects just the list, but we need to restore full structure with groups
                devices_list = devices_data.get('devices', []) if isinstance(devices_data, dict) else devices_data

                # Save devices list
                if device_manager.save_devices(devices_list):
                    # Also restore groups if present in backup
                    if isinstance(devices_data, dict) and 'groups' in devices_data:
                        with open(device_manager.devices_file, 'r') as f:
                            full_data = json.load(f)
                        full_data['groups'] = devices_data['groups']
                        with open(device_manager.devices_file, 'w') as f:
                            json.dump(full_data, f, indent=2)

                    result['restored'].append('devices')
                    info("Successfully restored devices")
                else:
                    result['errors'].append("Failed to save devices")
            except Exception as e:
                result['errors'].append(f"Devices restore error: {str(e)}")
                exception(f"Failed to restore devices: {str(e)}")

        # Restore metadata
        if restore_metadata and 'metadata' in backup_data:
            try:
                metadata = backup_data['metadata']
                if save_metadata(metadata):
                    result['restored'].append('metadata')
                    info("Successfully restored metadata")
                else:
                    result['errors'].append("Failed to save metadata")
            except Exception as e:
                result['errors'].append(f"Metadata restore error: {str(e)}")
                exception(f"Failed to restore metadata: {str(e)}")

        # Overall success if no errors
        if result['errors']:
            result['success'] = False
            error(f"Restore completed with errors: {result['errors']}")
        else:
            info(f"Restore completed successfully: {result['restored']}")

        return result
    except Exception as e:
        exception(f"Critical error during restore: {str(e)}")
        return {
            'success': False,
            'restored': result['restored'],
            'errors': result['errors'] + [f"Critical error: {str(e)}"]
        }


def export_backup_to_file(backup_data, filename=None):
    """
    Export backup data to JSON file.

    Args:
        backup_data (dict): Backup dictionary from create_full_backup()
        filename (str, optional): Custom filename. If None, auto-generates with timestamp.

    Returns:
        str: File path of exported backup, or None on error
    """
    debug("Exporting backup to file")
    try:
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"panfm_backup_{timestamp}.json"

        # Write to file
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        info(f"Exported backup to {filename}")
        return filename
    except Exception as e:
        exception(f"Failed to export backup: {str(e)}")
        return None


def import_backup_from_file(filename):
    """
    Import backup data from JSON file.

    Args:
        filename (str): Path to backup file

    Returns:
        dict: Backup data dictionary, or None on error
    """
    debug(f"Importing backup from {filename}")
    try:
        if not os.path.exists(filename):
            error(f"Backup file not found: {filename}")
            return None

        with open(filename, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)

        # Basic validation
        if not isinstance(backup_data, dict):
            error("Invalid backup file: not a valid JSON object")
            return None

        if 'version' not in backup_data:
            warning("Backup file missing version field")

        info(f"Successfully imported backup from {filename}")
        return backup_data
    except json.JSONDecodeError as e:
        error(f"Invalid JSON in backup file: {str(e)}")
        return None
    except Exception as e:
        exception(f"Failed to import backup: {str(e)}")
        return None


def get_backup_info(backup_data):
    """
    Get summary information about a backup.

    Args:
        backup_data (dict): Backup dictionary

    Returns:
        dict: Summary information:
              {
                  'version': str,
                  'timestamp': str,
                  'has_settings': bool,
                  'has_devices': bool,
                  'has_metadata': bool,
                  'device_count': int,
                  'metadata_count': int
              }
    """
    debug("Getting backup information")
    try:
        info_dict = {
            'version': backup_data.get('version', 'unknown'),
            'timestamp': backup_data.get('timestamp', 'unknown'),
            'has_settings': 'settings' in backup_data,
            'has_devices': 'devices' in backup_data,
            'has_metadata': 'metadata' in backup_data,
            'device_count': 0,
            'metadata_count': 0
        }

        # Count devices
        if 'devices' in backup_data and isinstance(backup_data['devices'], dict):
            devices = backup_data['devices'].get('devices', [])
            info_dict['device_count'] = len(devices) if isinstance(devices, list) else 0

        # Count metadata entries
        if 'metadata' in backup_data and isinstance(backup_data['metadata'], dict):
            metadata = backup_data['metadata']
            # Check if per-device format or global format
            if metadata:
                first_key = list(metadata.keys())[0]
                # Simple heuristic: if value is dict of dicts, it's per-device
                first_value = metadata[first_key]
                if isinstance(first_value, dict) and any(isinstance(v, dict) for v in first_value.values()):
                    # Per-device format
                    total = sum(len(device_meta) for device_meta in metadata.values() if isinstance(device_meta, dict))
                    info_dict['metadata_count'] = total
                else:
                    # Global format
                    info_dict['metadata_count'] = len(metadata)

        return info_dict
    except Exception as e:
        exception(f"Failed to get backup info: {str(e)}")
        return {
            'version': 'unknown',
            'timestamp': 'unknown',
            'has_settings': False,
            'has_devices': False,
            'has_metadata': False,
            'device_count': 0,
            'metadata_count': 0
        }
