"""
Device Manager for handling multiple firewall devices
"""
import json
import os
import uuid
from datetime import datetime
import requests
import xml.etree.ElementTree as ET
from config import DEVICES_FILE
from logger import debug, error, exception, warning
# Only import what we need: encrypt_string and decrypt_string for API keys only
from encryption import encrypt_string, decrypt_string

class DeviceManager:
    """Manages multiple firewall devices"""

    def __init__(self, devices_file=DEVICES_FILE):
        self.devices_file = devices_file
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        """Create devices.json if it doesn't exist"""
        if not os.path.exists(self.devices_file):
            default_data = {
                "devices": [],
                "groups": ["Headquarters", "Branch Office", "Remote", "Standalone"]
            }
            with open(self.devices_file, 'w') as f:
                json.dump(default_data, f, indent=2)

    def load_devices(self, decrypt_api_keys=True):
        """
        Load all devices from file.

        Args:
            decrypt_api_keys: If True, decrypts api_key field. If False, returns encrypted api_keys.
                             Default True for internal use, False for API responses.
        """
        try:
            with open(self.devices_file, 'r') as f:
                data = json.load(f)
                devices = data.get('devices', [])
                debug("Loaded %d devices from %s", len(devices), self.devices_file)

                if decrypt_api_keys:
                    # Decrypt ONLY the api_key field for internal use
                    decrypted_devices = []
                    for device in devices:
                        device_copy = device.copy()
                        if 'api_key' in device_copy and device_copy['api_key']:
                            try:
                                decrypted_key = decrypt_string(device_copy['api_key'])
                                device_copy['api_key'] = decrypted_key
                                debug(f"Successfully decrypted API key for device {device_copy.get('name', 'unknown')}")
                            except Exception as decrypt_err:
                                # Decryption failed - log the error and set empty key
                                error(f"Failed to decrypt API key for device {device_copy.get('name', 'unknown')}: {str(decrypt_err)}")
                                device_copy['api_key'] = ""  # Set to empty to prevent using corrupted key
                                warning(f"Device {device_copy.get('name', 'unknown')} API key could not be decrypted - authentication will fail")
                        decrypted_devices.append(device_copy)
                    debug("Decrypted api_key for %d device records", len(decrypted_devices))
                    return decrypted_devices
                else:
                    # Return with encrypted api_keys for API responses
                    debug("Returning %d devices with encrypted api_keys", len(devices))
                    return devices
        except Exception as e:
            exception("Error loading devices: %s", str(e))
            return []

    def save_devices(self, devices):
        """
        Save devices to file with encryption.
        Only the api_key field is encrypted, other fields remain plain text.
        """
        try:
            with open(self.devices_file, 'r') as f:
                data = json.load(f)

            # Encrypt ONLY the api_key field for each device
            # IMPORTANT: Check if already encrypted to prevent double encryption
            from encryption import is_encrypted
            encrypted_devices = []
            for device in devices:
                device_copy = device.copy()
                if 'api_key' in device_copy and device_copy['api_key']:
                    try:
                        # Only encrypt if not already encrypted (prevent double encryption)
                        if not is_encrypted(device_copy['api_key']):
                            device_copy['api_key'] = encrypt_string(device_copy['api_key'])
                            debug(f"Encrypted API key for device {device_copy.get('name', 'unknown')}")
                        else:
                            # Already encrypted, leave as-is
                            debug(f"API key already encrypted for device {device_copy.get('name', 'unknown')}, skipping encryption")
                    except Exception as encrypt_err:
                        # Encryption failed - log the error
                        error(f"Failed to encrypt API key for device {device_copy.get('name', 'unknown')}: {str(encrypt_err)}")
                        raise Exception(f"Cannot save device {device_copy.get('name', 'unknown')}: encryption failed")
                encrypted_devices.append(device_copy)

            data['devices'] = encrypted_devices
            with open(self.devices_file, 'w') as f:
                json.dump(data, f, indent=2)

            debug("Saved %d devices with encrypted api_keys to %s", len(devices), self.devices_file)
            return True
        except Exception as e:
            exception("Error saving devices: %s", str(e))
            return False

    def get_device(self, device_id):
        """Get a specific device by ID"""
        debug("get_device called for device_id: %s", device_id)
        devices = self.load_devices()
        for device in devices:
            if device.get('id') == device_id:
                debug("Found device: %s", device.get('name'))
                return device
        debug("Device not found: %s", device_id)
        return None

    def add_device(self, name, ip, api_key, group="Default", description="", monitored_interface="ethernet1/12", wan_interface=""):
        """Add a new device"""
        # Load devices WITH decryption so save_devices can re-encrypt all consistently
        devices = self.load_devices(decrypt_api_keys=True)

        new_device = {
            "id": str(uuid.uuid4()),
            "name": name,
            "ip": ip,
            "api_key": api_key,
            "enabled": True,
            "group": group,
            "description": description,
            "added_date": datetime.now().isoformat(),
            "last_seen": None,
            "monitored_interface": monitored_interface,
            "wan_interface": wan_interface
        }

        devices.append(new_device)
        self.save_devices(devices)
        return new_device

    def update_device(self, device_id, updates):
        """Update an existing device"""
        # Load devices WITH decryption so save_devices can re-encrypt all consistently
        devices = self.load_devices(decrypt_api_keys=True)
        for i, device in enumerate(devices):
            if device.get('id') == device_id:
                devices[i].update(updates)
                self.save_devices(devices)
                return devices[i]
        return None

    def delete_device(self, device_id):
        """Delete a device"""
        debug("delete_device called for device_id: %s", device_id)
        # Load devices WITH decryption so save_devices can re-encrypt all consistently
        devices = self.load_devices(decrypt_api_keys=True)
        initial_count = len(devices)
        devices = [d for d in devices if d.get('id') != device_id]
        debug("Deleted device. Device count: %d -> %d", initial_count, len(devices))
        return self.save_devices(devices)

    def get_groups(self):
        """Get list of device groups"""
        debug("get_groups called")
        try:
            with open(self.devices_file, 'r') as f:
                data = json.load(f)
                groups = data.get('groups', [])
                debug("Found %d device groups", len(groups))
                return groups
        except Exception as e:
            debug("Error loading groups, returning default: %s", str(e))
            return ["Default"]

    def test_connection(self, ip, api_key):
        """Test connection to a device"""
        try:
            base_url = f"https://{ip}/api/"
            params = {
                'type': 'op',
                'cmd': '<show><system><info></info></system></show>',
                'key': api_key
            }
            from utils import api_request_get
            response = api_request_get(base_url, params=params, verify=False, timeout=5)
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                # Check if we got a valid response
                if root.find('.//hostname') is not None:
                    return {"success": True, "message": "Connection successful"}
            return {"success": False, "message": "Invalid response from firewall"}
        except requests.exceptions.Timeout:
            return {"success": False, "message": "Connection timeout"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

    # Note: Device migration is handled by the standalone migrate_api_keys.py script
    # Only API keys need encryption, all other device fields remain in plain text

# Initialize device manager
device_manager = DeviceManager()
