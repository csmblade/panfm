"""
Flask route handlers for the Palo Alto Firewall Dashboard
"""
from flask import render_template, jsonify, request, send_from_directory, session
from datetime import datetime
import os
import json
from config import load_settings, save_settings, save_vendor_database, get_vendor_db_info, save_service_port_database, get_service_port_db_info, load_service_port_database
from device_manager import device_manager
from auth import login_required, verify_password, create_session, destroy_session, change_password, must_change_password
from device_metadata import (
    load_metadata,
    save_metadata,
    get_device_metadata,
    update_device_metadata,
    delete_device_metadata,
    get_all_tags
)
from firewall_api import (
    get_throughput_data,
    get_system_logs,
    get_traffic_logs,
    get_software_updates,
    get_license_info,
    get_connected_devices,
    get_firewall_config,
    get_device_uptime,
    get_device_version,
    get_application_statistics,
    generate_tech_support_file,
    check_tech_support_job_status,
    get_tech_support_file_url,
    get_interface_info,
    get_interface_traffic_counters,
    check_available_panos_versions,
    download_panos_version,
    install_panos_version,
    check_job_status,
    reboot_firewall,
    check_firewall_health,
    check_content_updates,
    download_content_update,
    install_content_update
)
from logger import debug, info, error
from utils import reverse_dns_lookup
from version import get_version_info, get_display_version

def register_routes(app, csrf, limiter):
    """Register all Flask routes with authentication, CSRF protection, and rate limiting"""

    # ============================================================================
    # Authentication Routes (no @login_required)
    # ============================================================================

    @app.route('/login')
    @csrf.exempt  # Exempt login page from CSRF (form has its own token)
    def login_page():
        """Serve the login page"""
        return render_template('login.html')

    @app.route('/api/login', methods=['POST'])
    @csrf.exempt  # Exempt login API from CSRF (not yet authenticated)
    @limiter.limit("5 per minute")  # Strict rate limit on login attempts
    def login():
        """Handle login authentication"""
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')

            if not username or not password:
                return jsonify({
                    'status': 'error',
                    'message': 'Username and password are required'
                }), 400

            if verify_password(username, password):
                create_session(username)

                # Check if password must be changed
                if must_change_password():
                    return jsonify({
                        'status': 'success',
                        'message': 'Login successful - password change required',
                        'must_change_password': True
                    })

                return jsonify({
                    'status': 'success',
                    'message': 'Login successful'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid username or password'
                }), 401
        except Exception as e:
            error(f"Login error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Login failed'
            }), 500

    @app.route('/api/logout', methods=['POST'])
    @login_required
    def logout():
        """Handle logout"""
        destroy_session()
        return jsonify({
            'status': 'success',
            'message': 'Logged out successfully'
        })

    @app.route('/api/session-keepalive', methods=['GET'])
    @limiter.limit("600 per hour")  # Support frequent keepalive pings
    @login_required
    def session_keepalive():
        """Session keepalive endpoint for Tony Mode - refreshes session expiry"""
        # Simply accessing this endpoint with @login_required refreshes the session
        # Flask automatically updates session.modified when accessed
        return jsonify({
            'status': 'success',
            'message': 'Session refreshed'
        })

    @app.route('/api/change-password', methods=['POST'])
    @login_required
    @limiter.limit("3 per hour")
    def change_password_route():
        """Handle password change"""
        try:
            data = request.get_json()
            old_password = data.get('old_password', '')
            new_password = data.get('new_password', '')

            if not old_password or not new_password:
                return jsonify({
                    'status': 'error',
                    'message': 'Old and new passwords are required'
                }), 400

            if len(new_password) < 8:
                return jsonify({
                    'status': 'error',
                    'message': 'New password must be at least 8 characters'
                }), 400

            username = session.get('username')
            success, message = change_password(username, old_password, new_password)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': message
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': message
                }), 400
        except Exception as e:
            error(f"Password change error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': 'Failed to change password'
            }), 500

    # ============================================================================
    # Protected Routes (require authentication)
    # ============================================================================

    @app.route('/')
    @login_required
    def index():
        """Serve the main dashboard"""
        return render_template('index.html')

    @app.route('/images/<path:filename>')
    @login_required
    def serve_images(filename):
        """Serve image files"""
        images_dir = os.path.join(os.path.dirname(__file__), 'images')
        return send_from_directory(images_dir, filename)

    @app.route('/api/throughput')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds (12/min = 720/hr)
    @login_required
    def throughput():
        """API endpoint for real-time throughput data"""
        debug("=== Throughput API endpoint called ===")
        settings = load_settings()
        debug(f"Selected device ID from settings: {settings.get('selected_device_id', 'NONE')}")
        data = get_throughput_data()
        return jsonify(data)

    @app.route('/api/health')
    @limiter.limit("600 per hour")  # Support frequent health checks
    @login_required
    def health():
        """Health check endpoint"""
        return jsonify({'status': 'ok', 'timestamp': datetime.now().isoformat()})

    @app.route('/api/firewall-health')
    @limiter.limit("300 per hour")  # 5/min for 15s polling during reboot monitoring
    @login_required
    def firewall_health_check():
        """Lightweight firewall health check - does NOT trigger update server connections"""
        debug("=== Firewall Health Check API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_firewall_health(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in firewall health check: {str(e)}")
            return jsonify({'status': 'offline', 'message': str(e)}), 500

    @app.route('/api/version')
    def version():
        """Version information endpoint (public - no auth required)"""
        return jsonify(get_version_info())

    @app.route('/api/system-logs')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def system_logs_api():
        """API endpoint for system logs"""
        debug("=== System Logs API endpoint called ===")
        try:
            settings = load_settings()
            debug(f"Selected device ID from settings: {settings.get('selected_device_id', 'NONE')}")
            firewall_config = get_firewall_config()
            logs = get_system_logs(firewall_config, max_logs=50)
            return jsonify({
                'status': 'success',
                'logs': logs,
                'total': len(logs),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e),
                'logs': []
            })

    @app.route('/api/traffic-logs')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def traffic_logs_api():
        """API endpoint for traffic logs"""
        debug("=== Traffic Logs API endpoint called ===")
        try:
            settings = load_settings()
            debug(f"Selected device ID from settings: {settings.get('selected_device_id', 'NONE')}")
            firewall_config = get_firewall_config()
            max_logs = request.args.get('max_logs', 50, type=int)
            logs = get_traffic_logs(firewall_config, max_logs)
            return jsonify({
                'status': 'success',
                'logs': logs,
                'total': len(logs),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e),
                'logs': []
            })


    @app.route('/api/software-updates')
    @limiter.limit("120 per minute")  # Higher limit for reboot monitoring (15s intervals = 4/min, +buffer)
    @login_required
    def software_updates():
        """API endpoint for software update information"""
        debug("=== Software Updates API endpoint called ===")
        settings = load_settings()
        debug(f"Selected device ID from settings: {settings.get('selected_device_id', 'NONE')}")
        firewall_config = get_firewall_config()
        data = get_software_updates(firewall_config)
        return jsonify(data)

    @app.route('/api/tech-support/generate', methods=['POST'])
    @login_required
    def tech_support_generate():
        """API endpoint to generate tech support file"""
        debug("=== Tech Support Generate API endpoint called ===")
        firewall_config = get_firewall_config()
        data = generate_tech_support_file(firewall_config)
        return jsonify(data)

    @app.route('/api/tech-support/status/<job_id>')
    @login_required
    def tech_support_status(job_id):
        """API endpoint to check tech support job status"""
        debug(f"=== Tech Support Status API endpoint called for job: {job_id} ===")
        firewall_config = get_firewall_config()
        data = check_tech_support_job_status(firewall_config, job_id)
        return jsonify(data)

    @app.route('/api/tech-support/download/<job_id>')
    @login_required
    def tech_support_download(job_id):
        """API endpoint to get tech support file download URL"""
        debug(f"=== Tech Support Download API endpoint called for job: {job_id} ===")
        firewall_config = get_firewall_config()
        data = get_tech_support_file_url(firewall_config, job_id)
        return jsonify(data)

    @app.route('/api/interfaces')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def interfaces_info():
        """API endpoint for interface information"""
        debug("=== Interfaces API endpoint called ===")
        firewall_config = get_firewall_config()
        data = get_interface_info(firewall_config)
        debug(f"Interfaces API returning {len(data.get('interfaces', []))} interfaces")
        return jsonify(data)

    @app.route('/api/interface-traffic')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def interface_traffic():
        """API endpoint for per-interface traffic counters"""
        debug("=== Interface Traffic API endpoint called ===")
        counters = get_interface_traffic_counters()
        return jsonify({'status': 'success', 'counters': counters})

    @app.route('/api/license')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def license_info():
        """API endpoint for license information"""
        firewall_config = get_firewall_config()
        data = get_license_info(firewall_config)
        return jsonify(data)

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
            tags = data.get('tags')
            
            # Validate tags is a list if provided
            if tags is not None and not isinstance(tags, list):
                return jsonify({
                    'status': 'error',
                    'message': 'Tags must be a list'
                }), 400
            
            success = update_device_metadata(mac, name=name, comment=comment, tags=tags)
            
            if success:
                # Force reload cache to ensure latest data
                from device_metadata import reload_metadata_cache
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

    @app.route('/api/applications')
    @limiter.limit("600 per hour")  # Support auto-refresh every 5 seconds
    @login_required
    def applications_api():
        """API endpoint for application statistics"""
        debug("=== Applications API endpoint called ===")
        try:
            firewall_config = get_firewall_config()
            max_logs = request.args.get('max_logs', 5000, type=int)
            data = get_application_statistics(firewall_config, max_logs)
            applications = data.get('applications', [])
            summary = data.get('summary', {})
            debug(f"Retrieved {len(applications)} applications from firewall")
            return jsonify({
                'status': 'success',
                'applications': applications,
                'summary': summary,
                'total': len(applications),
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            error(f"Error in applications API: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': str(e),
                'applications': [],
                'summary': {
                    'total_applications': 0,
                    'total_sessions': 0,
                    'total_bytes': 0,
                    'vlans_detected': 0,
                    'zones_detected': 0
                },
                'total': 0
            })

    @app.route('/api/settings', methods=['GET', 'POST'])
    @limiter.limit("600 per hour")  # Support frequent settings reads
    @login_required
    def settings():
        """API endpoint for settings"""
        if request.method == 'GET':
            # Return current settings
            settings_data = load_settings()
            return jsonify({
                'status': 'success',
                'settings': settings_data
            })
        elif request.method == 'POST':
            # Save new settings
            try:
                new_settings = request.get_json()
                debug(f"=== POST /api/settings called ===")
                debug(f"Received settings: {new_settings}")

                # Validate settings
                refresh_interval = int(new_settings.get('refresh_interval', 5))
                match_count = int(new_settings.get('match_count', 5))
                top_apps_count = int(new_settings.get('top_apps_count', 5))

                # Ensure values are within valid ranges
                refresh_interval = max(1, min(60, refresh_interval))
                match_count = max(1, min(20, match_count))
                top_apps_count = max(1, min(10, top_apps_count))

                # Get debug logging setting
                debug_logging = new_settings.get('debug_logging', False)

                # Get selected device ID (for multi-device support)
                selected_device_id = new_settings.get('selected_device_id', '')
                debug(f"selected_device_id to save: {selected_device_id}")

                # Get monitored interface
                monitored_interface = new_settings.get('monitored_interface', 'ethernet1/12')
                debug(f"monitored_interface to save: {monitored_interface}")

                # Get Tony Mode setting (disable session timeout)
                tony_mode = new_settings.get('tony_mode', False)
                debug(f"tony_mode to save: {tony_mode}")

                # Get timezone setting
                timezone = new_settings.get('timezone', 'UTC')
                debug(f"timezone to save: {timezone}")

                settings_data = {
                    'refresh_interval': refresh_interval,
                    'match_count': match_count,
                    'top_apps_count': top_apps_count,
                    'debug_logging': debug_logging,
                    'selected_device_id': selected_device_id,
                    'monitored_interface': monitored_interface,
                    'tony_mode': tony_mode,
                    'timezone': timezone
                }

                if save_settings(settings_data):
                    return jsonify({
                        'status': 'success',
                        'message': 'Settings saved successfully',
                        'settings': settings_data
                    })
                else:
                    return jsonify({
                        'status': 'error',
                        'message': 'Failed to save settings'
                    }), 500
            except Exception as e:
                debug(f"Error in settings endpoint: {e}")
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 400

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
    @csrf.exempt
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
    @csrf.exempt
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
    @csrf.exempt
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
    @csrf.exempt
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
            import xml.etree.ElementTree as ET
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

    @app.route('/api/reverse-dns', methods=['POST'])
    @csrf.exempt
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

            debug("Processing reverse DNS lookup for %d IP addresses", len(ip_addresses))

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

    # PAN-OS Upgrade API Routes
    @app.route('/api/panos-versions', methods=['GET'])
    @limiter.limit("100 per hour")  # Allow reasonable number of version checks
    @login_required
    def get_panos_versions():
        """Get available PAN-OS versions"""
        debug("=== PAN-OS Versions API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_available_panos_versions(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error checking PAN-OS versions: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/download', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow retries and multiple download operations
    @login_required
    def download_panos():
        """Download a specific PAN-OS version"""
        debug("=== PAN-OS Download API endpoint called ===")
        try:
            data = request.get_json()
            version = data.get('version')

            if not version:
                return jsonify({'status': 'error', 'message': 'Version parameter required'}), 400

            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = download_panos_version(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error downloading PAN-OS: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/install', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow retries and testing
    @login_required
    def install_panos():
        """Install a downloaded PAN-OS version"""
        debug("=== PAN-OS Install API endpoint called ===")
        try:
            data = request.get_json()
            version = data.get('version')

            if not version:
                return jsonify({'status': 'error', 'message': 'Version parameter required'}), 400

            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = install_panos_version(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error installing PAN-OS: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/job-status/<job_id>', methods=['GET'])
    @limiter.limit("2000 per hour")  # Very high limit for continuous job polling (4/min sustained = 240/hr, set 8x buffer)
    @login_required
    def get_panos_job_status(job_id):
        """Check the status of a PAN-OS upgrade job"""
        debug(f"=== PAN-OS Job Status API endpoint called for job {job_id} ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                error("No firewall configured for job status check")
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            debug(f"Checking job status for job_id={job_id} on {firewall_ip}")
            result = check_job_status(firewall_ip, api_key, job_id)
            debug(f"Job status result: {result}")
            return jsonify(result)

        except Exception as e:
            error(f"Error checking job status for job {job_id}: {str(e)}")
            import traceback
            error(f"Traceback: {traceback.format_exc()}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/reboot', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow multiple reboots for testing
    @login_required
    def reboot_panos():
        """Reboot the firewall after upgrade"""
        debug("=== PAN-OS Reboot API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = reboot_firewall(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error rebooting firewall: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ============================================================================
    # Content Update API Routes (App & Threat, Antivirus, WildFire)
    # ============================================================================

    @app.route('/api/content-updates/check', methods=['GET'])
    @limiter.limit("100 per hour")
    @login_required
    def check_content_updates_api():
        """Check for available content updates (App & Threat, AV, WildFire)"""
        debug("=== Content Updates Check API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_content_updates(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content updates check: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/content-updates/download', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def download_content_api():
        """Download latest content update"""
        debug("=== Content Update Download API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = download_content_update(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content download: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500


    @app.route('/api/content-updates/install', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def install_content_api():
        """Install downloaded content update"""
        debug("=== Content Update Install API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            data = request.get_json() or {}
            version = data.get('version', 'latest')

            result = install_content_update(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content install: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
