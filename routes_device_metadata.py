"""
Flask route handlers for device metadata and connected devices
Handles connected devices, DHCP leases, device metadata CRUD, migration, and reverse DNS
"""
from flask import jsonify, request, send_file
from datetime import datetime
import json
from io import BytesIO
from auth import login_required
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
from firewall_api import get_connected_devices, get_firewall_config
from utils import reverse_dns_lookup
from logger import debug, info, error, exception


def register_device_metadata_routes(app, csrf, limiter):
    """Register device metadata and connected devices routes"""
    debug("Registering device metadata and connected devices routes")

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
    # Metadata Migration Endpoints
    # ============================================================================

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

    debug("Device metadata and connected devices routes registered successfully")
