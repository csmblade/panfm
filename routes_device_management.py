"""
Flask route handlers for device CRUD operations
Handles device list, create, read, update, delete, and connection testing
"""
from flask import jsonify, request
from auth import login_required
from config import load_settings, save_settings
from device_manager import device_manager
from firewall_api import get_device_uptime, get_device_version
from logger import debug, info, error, exception


def register_device_management_routes(app, csrf, limiter):
    """Register device management CRUD routes"""
    debug("Registering device management CRUD routes")

    # ============================================================================
    # Device Management API Endpoints
    # ============================================================================

    @app.route('/api/devices', methods=['GET'])
    @limiter.limit("600 per hour")  # Support frequent device list reads
    @login_required
    def get_devices():
        """Get all devices with encrypted API keys"""
        try:
            # Load devices with encrypted API keys for API response (security)
            devices = device_manager.load_devices(decrypt_api_keys=False)
            groups = device_manager.get_groups()

            # Fetch uptime and version for each enabled device
            for device in devices:
                if device.get('enabled', True):
                    try:
                        uptime = get_device_uptime(device['id'])
                        device['uptime'] = uptime if uptime else 'N/A'
                    except Exception as e:
                        debug(f"Error fetching uptime for device {device['id']}: {str(e)}")
                        device['uptime'] = 'N/A'

                    try:
                        version = get_device_version(device['id'])
                        device['version'] = version if version else 'N/A'
                    except Exception as e:
                        debug(f"Error fetching version for device {device['id']}: {str(e)}")
                        device['version'] = 'N/A'
                else:
                    device['uptime'] = 'Disabled'
                    device['version'] = 'N/A'

            return jsonify({
                'status': 'success',
                'devices': devices,
                'groups': groups
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices', methods=['POST'])
    @login_required
    @limiter.limit("100 per hour")
    def create_device():
        """Add a new device and manage selected_device_id"""
        debug("Create device request received")
        try:
            data = request.get_json()
            name = data.get('name', '').strip()
            ip = data.get('ip', '').strip()
            api_key = data.get('api_key', '').strip()
            group = data.get('group', 'Default')
            description = data.get('description', '')
            wan_interface = data.get('wan_interface', '').strip()

            debug(f"Adding new device: name={name}, ip={ip}, group={group}")

            # Validate required fields
            if not name or not ip or not api_key:
                debug("Validation failed: missing required fields")
                return jsonify({
                    'status': 'error',
                    'message': 'Name, IP, and API Key are required'
                }), 400

            # Get device count before adding
            existing_devices = device_manager.load_devices(decrypt_api_keys=False)
            was_first_device = len(existing_devices) == 0
            debug(f"Existing device count: {len(existing_devices)}, is_first_device: {was_first_device}")

            new_device = device_manager.add_device(name, ip, api_key, group, description, wan_interface=wan_interface)
            debug(f"Device added successfully: {new_device['name']} ({new_device['id']})")

            # Auto-select this device if it's the first device OR no device is currently selected
            settings = load_settings()
            current_selected = settings.get('selected_device_id', '')
            auto_selected = False

            # Check if current selection is valid
            if current_selected:
                # Verify the currently selected device still exists
                selected_device_exists = device_manager.get_device(current_selected) is not None
                debug(f"Current selected device {current_selected} exists: {selected_device_exists}")
                if not selected_device_exists:
                    current_selected = ''

            if not current_selected or was_first_device:
                settings['selected_device_id'] = new_device['id']
                save_settings(settings)
                auto_selected = True
                info(f"Auto-selected device {new_device['name']} ({new_device['id']}) - first_device={was_first_device}, no_selection={not current_selected}")
                debug(f"Updated selected_device_id to: {new_device['id']}")
            else:
                debug(f"Device not auto-selected. Current selection: {current_selected}")

            return jsonify({
                'status': 'success',
                'device': new_device,
                'auto_selected': auto_selected,
                'message': 'Device added successfully'
            })
        except Exception as e:
            exception(f"Error creating device: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>', methods=['GET'])
    @login_required
    def get_device(device_id):
        """Get a specific device with encrypted API key"""
        try:
            # Get all devices with encrypted keys, then find the specific one
            devices = device_manager.load_devices(decrypt_api_keys=False)
            device = next((d for d in devices if d.get('id') == device_id), None)
            if device:
                return jsonify({
                    'status': 'success',
                    'device': device
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Device not found'
                }), 404
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>', methods=['PUT'])
    @login_required
    @limiter.limit("100 per hour")
    def update_device(device_id):
        """Update a device"""
        try:
            data = request.get_json()

            # If api_key is empty or not provided, remove it from updates to preserve existing key
            if 'api_key' in data and not data['api_key']:
                debug("API key is empty, removing from updates to preserve existing key")
                del data['api_key']

            updated_device = device_manager.update_device(device_id, data)
            if updated_device:
                return jsonify({
                    'status': 'success',
                    'device': updated_device,
                    'message': 'Device updated successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Device not found'
                }), 404
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>', methods=['DELETE'])
    @login_required
    @limiter.limit("100 per hour")
    def delete_device(device_id):
        """Delete a device and manage selected_device_id"""
        debug(f"Delete device request for device_id: {device_id}")
        try:
            # Get device info before deleting for logging
            device_to_delete = device_manager.get_device(device_id)
            device_name = device_to_delete.get('name', 'unknown') if device_to_delete else 'unknown'

            success = device_manager.delete_device(device_id)
            if success:
                debug(f"Device {device_name} ({device_id}) deleted successfully")

                # Check if the deleted device was the selected one
                settings = load_settings()
                was_selected = settings.get('selected_device_id') == device_id
                debug(f"Deleted device was selected: {was_selected}")

                if was_selected:
                    # Get remaining devices (use load_devices, not decrypt for API responses)
                    remaining_devices = device_manager.load_devices(decrypt_api_keys=False)
                    debug(f"Remaining devices after deletion: {len(remaining_devices)}")

                    if remaining_devices:
                        # Select the first remaining device
                        new_selected_id = remaining_devices[0]['id']
                        new_selected_name = remaining_devices[0]['name']
                        settings['selected_device_id'] = new_selected_id
                        save_settings(settings)
                        info(f"Deleted device was selected. Auto-selected device {new_selected_name} ({new_selected_id})")
                        debug(f"Updated selected_device_id to: {new_selected_id}")
                    else:
                        # No devices left, clear selection
                        settings['selected_device_id'] = ''
                        save_settings(settings)
                        info("Deleted last device. Cleared device selection")
                        debug("Cleared selected_device_id (no devices remaining)")

                return jsonify({
                    'status': 'success',
                    'message': 'Device deleted successfully'
                })
            else:
                error(f"Failed to delete device {device_id}")
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to delete device'
                }), 500
        except Exception as e:
            exception(f"Error deleting device {device_id}: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/<device_id>/test', methods=['POST'])
    @login_required
    def test_device_connection(device_id):
        """Test connection to a device"""
        try:
            device = device_manager.get_device(device_id)
            if not device:
                return jsonify({
                    'status': 'error',
                    'message': 'Device not found'
                }), 404

            result = device_manager.test_connection(device['ip'], device['api_key'])
            return jsonify({
                'status': 'success' if result['success'] else 'error',
                'message': result['message']
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/devices/test-connection', methods=['POST'])
    @login_required
    def test_new_device_connection():
        """Test connection to a device (before saving)"""
        try:
            data = request.get_json()
            ip = data.get('ip', '').strip()
            api_key = data.get('api_key', '').strip()

            if not ip or not api_key:
                return jsonify({
                    'status': 'error',
                    'message': 'IP and API Key are required'
                }), 400

            result = device_manager.test_connection(ip, api_key)
            return jsonify({
                'status': 'success' if result['success'] else 'error',
                'message': result['message']
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
