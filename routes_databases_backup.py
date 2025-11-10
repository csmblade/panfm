"""
Flask route handlers for vendor/service databases and backup/restore operations
Handles MAC vendor database, service port database, and comprehensive backup/restore
"""
from flask import jsonify, request
from datetime import datetime
import json
from auth import login_required
from config import (
    save_vendor_database,
    get_vendor_db_info,
    save_service_port_database,
    get_service_port_db_info,
    load_service_port_database
)
from backup_restore import (
    create_full_backup,
    restore_from_backup,
    get_backup_info
)
from logger import debug, info, error, exception
import xml.etree.ElementTree as ET


def register_databases_backup_routes(app, csrf, limiter):
    """Register vendor/service database and backup/restore routes"""
    debug("Registering databases and backup/restore routes")

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
            info_result = get_backup_info(backup_data)

            return jsonify({
                'status': 'success',
                'info': info_result
            })

        except Exception as e:
            error(f"Error getting backup info: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    debug("Databases and backup/restore routes registered successfully")
