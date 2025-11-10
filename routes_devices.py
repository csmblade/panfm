"""
Flask route handlers for device management
Handles device CRUD operations, device metadata, connected devices, DHCP leases,
vendor/service databases, reverse DNS, and backup/restore
"""
from flask import jsonify, request, send_file
from datetime import datetime
import json
from io import BytesIO
from auth import login_required
from config import (
    load_settings,
    save_settings,
    save_vendor_database,
    get_vendor_db_info,
    save_service_port_database,
    get_service_port_db_info,
    load_service_port_database
)
from device_manager import device_manager
from device_metadata import (
    load_metadata,
    get_device_metadata,
    update_device_metadata,
    delete_device_metadata,
    get_all_tags,
    get_all_locations,
    import_metadata,
    check_migration_needed,
    migrate_global_to_per_device,
    reload_metadata_cache
)
from backup_restore import (
    create_full_backup,
    restore_from_backup,
    get_backup_info
)
from firewall_api import (
    get_connected_devices,
    get_firewall_config,
    get_device_uptime,
    get_device_version
)
from utils import reverse_dns_lookup
from logger import debug, info, error, exception
import xml.etree.ElementTree as ET


def register_devices_routes(app, csrf, limiter):
    """Register device management and metadata-related routes"""
    debug("Registering device management routes")

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

    # ============================================================================
    # Connected Devices & DHCP Endpoints
    # ============================================================================

    @app.route('/api/connected-devices')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def connected_devices_api():
        """API endpoint for connected devices (ARP entries)"""
        debug("=== Connected Devices API endpoint called ===")
        try:
            firewall_config = get_firewall_config()
            devices = get_connected_devices(firewall_config)
            debug(f"Retrieved {len(devices)} devices from firewall")
            return jsonify({
                'status': 'success',
                'devices': devices,
                'total': len(devices),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            error(f"Error in connected devices API: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'devices': [],
                'total': 0
            })

    @app.route('/api/dhcp-leases')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def dhcp_leases_api():
        """API endpoint for DHCP lease information"""
        debug("=== DHCP Leases API endpoint called ===")
        try:
            firewall_config = get_firewall_config()

            # Import DHCP function
            from firewall_api_dhcp import get_dhcp_leases_detailed

            leases = get_dhcp_leases_detailed(firewall_config)
            debug(f"Retrieved {len(leases)} DHCP lease(s) from firewall")

            return jsonify({
                'status': 'success',
                'leases': leases,
                'total': len(leases),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            error(f"Error in DHCP leases API: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'leases': [],
                'total': 0
            })

    # ============================================================================
    # Device Metadata Endpoints
    # ============================================================================

    @app.route('/api/device-metadata', methods=['GET'])
    @limiter.limit("600 per hour")  # Support bulk loading on page load
    @login_required
    def get_all_device_metadata():
        """Get all device metadata (for bulk loading on page load)"""
        debug("=== Get all device metadata API endpoint called ===")
        try:
            metadata = load_metadata()
            debug(f"Retrieved metadata for {len(metadata)} devices")
            return jsonify({
                'status': 'success',
                'metadata': metadata
            })
        except Exception as e:
            error(f"Error loading device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'metadata': {}
            }), 500

    @app.route('/api/device-metadata/<mac>', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_single_device_metadata(mac):
        """Get metadata for a specific MAC address"""
        debug(f"=== Get device metadata for MAC: {mac} ===")
        try:
            metadata = get_device_metadata(mac)
            if metadata:
                return jsonify({
                    'status': 'success',
                    'metadata': metadata
                })
            else:
                return jsonify({
                    'status': 'success',
                    'metadata': None,
                    'message': 'No metadata found for this MAC address'
                })
        except Exception as e:
            error(f"Error getting device metadata for {mac}: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata', methods=['POST'])
    @login_required
    @limiter.limit("100 per hour")  # Device management category
    def create_or_update_device_metadata():
        """Create or update device metadata (requires CSRF token)"""
        debug("=== Create/update device metadata API endpoint called ===")
        try:
            data = request.get_json()

            if not data or 'mac' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'MAC address is required'
                }), 400

            mac = data.get('mac')
            name = data.get('name')
            comment = data.get('comment')
            location = data.get('location')
            tags = data.get('tags')

            # Validate tags is a list if provided
            if tags is not None and not isinstance(tags, list):
                return jsonify({
                    'status': 'error',
                    'message': 'Tags must be a list'
                }), 400

            success = update_device_metadata(mac, name=name, comment=comment, location=location, tags=tags)

            if success:
                # Force reload cache to ensure latest data
                reload_metadata_cache()

                # Return updated metadata
                updated_metadata = get_device_metadata(mac)
                return jsonify({
                    'status': 'success',
                    'metadata': updated_metadata,
                    'message': 'Metadata saved successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save metadata'
                }), 500
        except Exception as e:
            error(f"Error saving device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata/<mac>', methods=['DELETE'])
    @login_required
    @limiter.limit("100 per hour")  # Device management category
    def delete_device_metadata_endpoint(mac):
        """Delete device metadata (requires CSRF token)"""
        debug(f"=== Delete device metadata for MAC: {mac} ===")
        try:
            success = delete_device_metadata(mac)
            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Metadata deleted successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to delete metadata'
                }), 500
        except Exception as e:
            error(f"Error deleting device metadata for {mac}: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata/tags', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_all_device_tags():
        """Get all unique tags across all devices"""
        debug("=== Get all device tags API endpoint called ===")
        try:
            tags = get_all_tags()
            return jsonify({
                'status': 'success',
                'tags': tags
            })
        except Exception as e:
            error(f"Error getting device tags: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'tags': []
            }), 500

    @app.route('/api/device-metadata/locations', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_all_device_locations():
        """Get all unique locations across all devices"""
        debug("=== Get all device locations API endpoint called ===")
        try:
            locations = get_all_locations()
            return jsonify({
                'status': 'success',
                'locations': locations
            })
        except Exception as e:
            error(f"Error getting device locations: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'locations': []
            }), 500

    @app.route('/api/device-metadata/export', methods=['GET'])
    @limiter.limit("100 per hour")
    @login_required
    def export_device_metadata():
        """Export device metadata as JSON backup file"""
        debug("=== Device metadata export endpoint called ===")
        try:
            # Load decrypted metadata
            metadata = load_metadata(use_cache=False)  # Force reload to get latest

            # Add export metadata
            export_data = {
                'export_date': datetime.now().isoformat(),
                'version': '1.0',
                'total_devices': len(metadata),
                'metadata': metadata
            }

            json_str = json.dumps(export_data, indent=2)
            json_bytes = json_str.encode('utf-8')

            # Create BytesIO object for file download
            json_file = BytesIO(json_bytes)
            json_file.seek(0)

            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'device_metadata_backup_{timestamp}.json'

            return send_file(
                json_file,
                mimetype='application/json',
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            error(f"Error exporting device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/device-metadata/import', methods=['POST'])
    @login_required
    @limiter.limit("50 per hour")  # Limit imports to prevent abuse
    def import_device_metadata():
        """Import device metadata from JSON backup file"""
        debug("=== Device metadata import endpoint called ===")
        try:
            if 'file' not in request.files:
                return jsonify({
                    'status': 'error',
                    'message': 'No file provided'
                }), 400

            file = request.files['file']

            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'message': 'No file selected'
                }), 400

            if not file.filename.endswith('.json'):
                return jsonify({
                    'status': 'error',
                    'message': 'File must be a JSON file'
                }), 400

            # Read and parse JSON
            try:
                file_content = file.read().decode('utf-8')
                import_data = json.loads(file_content)
            except json.JSONDecodeError as e:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid JSON file: {str(e)}'
                }), 400

            # Extract metadata from import data
            # Support both old format (direct metadata dict) and new format (with export metadata)
            if 'metadata' in import_data:
                metadata_to_import = import_data['metadata']
                debug(f"Importing metadata from backup file (version: {import_data.get('version', 'unknown')}, export date: {import_data.get('export_date', 'unknown')})")
            elif isinstance(import_data, dict):
                # Assume it's a metadata dict directly
                metadata_to_import = import_data
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid metadata format in file'
                }), 400

            # Validate metadata structure
            if not isinstance(metadata_to_import, dict):
                return jsonify({
                    'status': 'error',
                    'message': 'Metadata must be a dictionary'
                }), 400

            # Import metadata (merges with existing)
            success = import_metadata(metadata_to_import)

            if success:
                # Reload cache
                reload_metadata_cache()

                info(f"Device metadata imported successfully: {len(metadata_to_import)} devices")
                return jsonify({
                    'status': 'success',
                    'message': f'Metadata imported successfully ({len(metadata_to_import)} devices)',
                    'devices_imported': len(metadata_to_import)
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to import metadata'
                }), 500

        except Exception as e:
            error(f"Error importing device metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    # ============================================================================
    # Vendor & Service Port Database Endpoints
    # ============================================================================

    @app.route('/api/vendor-db/info', methods=['GET'])
    @login_required
    def vendor_db_info():
        """API endpoint to get vendor database information"""
        debug("=== Vendor DB info endpoint called ===")
        try:
            db_info = get_vendor_db_info()
            return jsonify({
                'status': 'success',
                'info': db_info
            })
        except Exception as e:
            error(f"Error getting vendor DB info: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/vendor-db/upload', methods=['POST'])
    @login_required
    @limiter.limit("20 per hour")
    def vendor_db_upload():
        """API endpoint to upload vendor database"""
        debug("=== Vendor DB upload endpoint called ===")
        try:
            if 'file' not in request.files:
                return jsonify({
                    'status': 'error',
                    'message': 'No file provided'
                }), 400
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'message': 'No file selected'
                }), 400
            if not file.filename.endswith('.json'):
                return jsonify({
                    'status': 'error',
                    'message': 'File must be a JSON file'
                }), 400

            # Read and parse JSON
            content = file.read().decode('utf-8')
            vendor_data = json.loads(content)

            # Validate structure
            if not isinstance(vendor_data, list):
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid format: Expected JSON array'
                }), 400

            if len(vendor_data) == 0:
                return jsonify({
                    'status': 'error',
                    'message': 'Database is empty'
                }), 400

            # Check first entry has required fields
            first_entry = vendor_data[0]
            if 'macPrefix' not in first_entry or 'vendorName' not in first_entry:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid format: Entries must have "macPrefix" and "vendorName" fields'
                }), 400

            # Save to file
            if save_vendor_database(vendor_data):
                db_info = get_vendor_db_info()
                info(f"Vendor database uploaded successfully: {db_info['entries']} entries, {db_info['size_mb']} MB")
                return jsonify({
                    'status': 'success',
                    'message': f'Vendor database uploaded successfully ({db_info["entries"]} entries)',
                    'info': db_info
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save vendor database'
                }), 500

        except json.JSONDecodeError as e:
            error(f"Invalid JSON in vendor DB upload: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid JSON format'
            }), 400
        except Exception as e:
            error(f"Error uploading vendor DB: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/service-port-db/info', methods=['GET'])
    @login_required
    def service_port_db_info():
        """API endpoint to get service port database information"""
        debug("=== Service port DB info endpoint called ===")
        try:
            db_info = get_service_port_db_info()
            return jsonify({
                'status': 'success',
                'info': db_info
            })
        except Exception as e:
            error(f"Error getting service port DB info: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/service-port-db/upload', methods=['POST'])
    @login_required
    @limiter.limit("20 per hour")
    def service_port_db_upload():
        """API endpoint to upload service port database (IANA XML)"""
        debug("=== Service port DB upload endpoint called ===")
        try:
            if 'file' not in request.files:
                return jsonify({
                    'status': 'error',
                    'message': 'No file provided'
                }), 400
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'status': 'error',
                    'message': 'No file selected'
                }), 400
            if not file.filename.endswith('.xml'):
                return jsonify({
                    'status': 'error',
                    'message': 'File must be an XML file'
                }), 400

            # Read XML content
            content = file.read().decode('utf-8')

            # Parse XML and convert to JSON structure
            root = ET.fromstring(content)

            # Build service port dictionary
            # Format: {port: {'tcp': {'name': 'http', 'description': '...'}, 'udp': {...}}}
            service_dict = {}

            for record in root.findall('.//{http://www.iana.org/assignments}record'):
                name_elem = record.find('{http://www.iana.org/assignments}name')
                protocol_elem = record.find('{http://www.iana.org/assignments}protocol')
                number_elem = record.find('{http://www.iana.org/assignments}number')
                desc_elem = record.find('{http://www.iana.org/assignments}description')

                # Skip if missing required fields
                if protocol_elem is None or number_elem is None:
                    continue

                protocol = protocol_elem.text
                port_str = number_elem.text

                # Skip if protocol or port is None
                if protocol is None or port_str is None:
                    continue

                # Handle port ranges (e.g., "8000-8100")
                if '-' in port_str:
                    continue  # Skip ranges for now

                try:
                    port = int(port_str)
                except ValueError:
                    continue  # Skip invalid port numbers

                # Get service name and description
                service_name = name_elem.text if name_elem is not None and name_elem.text else ''
                description = desc_elem.text if desc_elem is not None and desc_elem.text else ''

                # Initialize port entry if it doesn't exist
                port_key = str(port)
                if port_key not in service_dict:
                    service_dict[port_key] = {}

                # Add protocol-specific info
                service_dict[port_key][protocol.lower()] = {
                    'name': service_name,
                    'description': description
                }

            if len(service_dict) == 0:
                return jsonify({
                    'status': 'error',
                    'message': 'No valid service port entries found in XML'
                }), 400

            # Save to file
            if save_service_port_database(service_dict):
                db_info = get_service_port_db_info()
                info(f"Service port database uploaded successfully: {db_info['entries']} port entries, {db_info['size_mb']} MB")
                return jsonify({
                    'status': 'success',
                    'message': f'Service port database uploaded successfully ({db_info["entries"]} ports)',
                    'info': db_info
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to save service port database'
                }), 500

        except ET.ParseError as e:
            error(f"Invalid XML in service port DB upload: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Invalid XML format'
            }), 400
        except Exception as e:
            error(f"Error uploading service port DB: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/service-port-db/data', methods=['GET'])
    @login_required
    def service_port_db_data():
        """API endpoint to get service port database data"""
        debug("=== Service port DB data endpoint called ===")
        try:
            service_data = load_service_port_database()
            return jsonify({
                'status': 'success',
                'data': service_data
            })
        except Exception as e:
            error(f"Error loading service port DB data: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'data': {}
            }), 500

    # ============================================================================
    # Utility Endpoints
    # ============================================================================

    @app.route('/api/reverse-dns', methods=['POST'])
    @login_required
    def reverse_dns_api():
        """
        Perform reverse DNS lookups on a list of IP addresses.

        Request body:
            {
                "ip_addresses": ["8.8.8.8", "1.1.1.1", ...],
                "timeout": 2  (optional, default: 2)
            }

        Response:
            {
                "status": "success",
                "results": {
                    "8.8.8.8": "dns.google",
                    "1.1.1.1": "one.one.one.one",
                    ...
                }
            }
        """
        debug("=== Reverse DNS API endpoint called ===")
        try:
            data = request.get_json()
            ip_addresses = data.get('ip_addresses', [])
            timeout = data.get('timeout', 2)

            # Validate input
            if not isinstance(ip_addresses, list):
                return jsonify({
                    'status': 'error',
                    'message': 'ip_addresses must be a list'
                }), 400

            if len(ip_addresses) == 0:
                return jsonify({
                    'status': 'success',
                    'results': {}
                })

            debug(f"Processing reverse DNS lookup for {len(ip_addresses)} IP addresses")

            # Perform reverse DNS lookups
            results = reverse_dns_lookup(ip_addresses, timeout)

            debug("Reverse DNS lookup completed successfully")
            return jsonify({
                'status': 'success',
                'results': results
            })

        except Exception as e:
            error(f"Error performing reverse DNS lookup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    # ============================================================================
    # Backup & Restore Routes (v1.6.0)
    # ============================================================================

    @app.route('/api/backup/create', methods=['POST'])
    @limiter.limit("20 per hour")
    @login_required
    def create_backup():
        """Create comprehensive site backup (Settings + Devices + Metadata)"""
        debug("=== Create Backup API endpoint called ===")
        try:
            backup_data = create_full_backup()

            if backup_data is None:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to create backup'
                }), 500

            return jsonify({
                'status': 'success',
                'message': 'Backup created successfully',
                'backup': backup_data
            })

        except Exception as e:
            error(f"Error creating backup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/backup/export', methods=['POST'])
    @limiter.limit("20 per hour")
    @login_required
    def export_backup():
        """Export backup to downloadable JSON file"""
        debug("=== Export Backup API endpoint called ===")
        try:
            # Create backup first
            backup_data = create_full_backup()

            if backup_data is None:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to create backup'
                }), 500

            # Generate timestamped filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"panfm_backup_{timestamp}.json"

            # Return as downloadable file
            return jsonify({
                'status': 'success',
                'message': 'Backup created successfully',
                'filename': filename,
                'data': backup_data
            })

        except Exception as e:
            error(f"Error exporting backup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/backup/restore', methods=['POST'])
    @limiter.limit("10 per hour")
    @login_required
    def restore_backup():
        """Restore site configuration from backup"""
        debug("=== Restore Backup API endpoint called ===")
        try:
            data = request.get_json()

            if not data or 'backup' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'No backup data provided'
                }), 400

            backup_data = data['backup']

            # Optional: selective restore
            restore_settings = data.get('restore_settings', True)
            restore_devices = data.get('restore_devices', True)
            restore_metadata = data.get('restore_metadata', True)

            result = restore_from_backup(
                backup_data,
                restore_settings=restore_settings,
                restore_devices=restore_devices,
                restore_metadata=restore_metadata
            )

            if result['success']:
                return jsonify({
                    'status': 'success',
                    'message': 'Restore completed successfully',
                    'restored': result['restored']
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Restore completed with errors',
                    'restored': result['restored'],
                    'errors': result['errors']
                }), 500

        except Exception as e:
            error(f"Error restoring backup: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/backup/info', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def backup_info():
        """Get information about a backup file"""
        debug("=== Backup Info API endpoint called ===")
        try:
            data = request.get_json()

            if not data or 'backup' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'No backup data provided'
                }), 400

            backup_data = data['backup']
            info = get_backup_info(backup_data)

            return jsonify({
                'status': 'success',
                'info': info
            })

        except Exception as e:
            error(f"Error getting backup info: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/metadata/migration/check', methods=['GET'])
    @limiter.limit("100 per hour")
    @login_required
    def check_metadata_migration():
        """Check if metadata needs migration from global to per-device format"""
        debug("=== Check Metadata Migration API endpoint called ===")
        try:
            needs_migration = check_migration_needed()

            return jsonify({
                'status': 'success',
                'needs_migration': needs_migration
            })

        except Exception as e:
            error(f"Error checking migration status: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    @app.route('/api/metadata/migration/migrate', methods=['POST'])
    @limiter.limit("10 per hour")
    @login_required
    def migrate_metadata():
        """Migrate metadata from global to per-device format"""
        debug("=== Migrate Metadata API endpoint called ===")
        try:
            data = request.get_json() or {}
            target_device_id = data.get('device_id')

            success = migrate_global_to_per_device(target_device_id)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Metadata migrated successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Migration failed'
                }), 500

        except Exception as e:
            error(f"Error migrating metadata: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    debug("Device management routes registered successfully")
