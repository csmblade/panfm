"""
Firewall API health check, software updates, and license management
Handles firewall health checks, software version information, and license data
"""
import xml.etree.ElementTree as ET
from datetime import datetime
from utils import api_request_get
from logger import debug


def check_firewall_health(firewall_ip, api_key):
    """
    Lightweight health check for firewall - does NOT trigger update server connections
    Used for reboot monitoring and connection testing

    Verifies firewall is fully operational by checking:
    1. API responds to system info query
    2. Auto-commit status indicates system is ready
    """
    try:
        base_url = f"https://{firewall_ip}/api/"

        # First check: Simple system info query - no update checks
        cmd = "<show><system><info></info></system></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        if response.status_code == 200:
            # Parse to verify it's valid XML
            root = ET.fromstring(response.text)
            status = root.get('status')

            if status == 'success':
                # Extract basic info
                hostname = root.find('.//hostname')
                sw_version = root.find('.//sw-version')

                # Check auto-commit status to verify system is fully booted
                # During boot, auto-commit will be in progress or not available
                auto_commit = root.find('.//auto-commit-status')

                # If we can get system info AND auto-commit status is available,
                # the firewall is likely fully operational
                # Note: auto-commit might be None on some models, which is fine

                return {
                    'status': 'online',
                    'ip': firewall_ip,
                    'hostname': hostname.text if hostname is not None else 'Unknown',
                    'version': sw_version.text if sw_version is not None else 'Unknown',
                    'ready': True
                }
            else:
                return {'status': 'error', 'message': 'Firewall returned error status'}
        else:
            return {'status': 'error', 'message': f'HTTP {response.status_code}'}

    except Exception as e:
        debug(f"Health check failed: {str(e)}")
        return {'status': 'offline', 'message': str(e)}


def get_software_updates(firewall_config):
    """Fetch system software version information from Palo Alto firewall"""
    try:
        firewall_ip, api_key, base_url = firewall_config

        # Query for system information
        cmd = "<show><system><info></info></system></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"\n=== System Info API Response ===")
        debug(f"Status: {response.status_code}")

        software_info = []

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            debug(f"Response XML (first 2000 chars):\n{response.text[:2000]}")

            # Helper function to check for updates using specific commands
            def get_update_status(cmd_xml):
                """Execute update check command and return downloaded/current/latest status"""
                try:
                    check_params = {
                        'type': 'op',
                        'cmd': cmd_xml,
                        'key': api_key
                    }
                    check_response = api_request_get(base_url, params=check_params, verify=False, timeout=10)

                    if check_response.status_code == 200:
                        check_root = ET.fromstring(check_response.text)
                        debug(f"Update check response (first 1500 chars):\n{check_response.text[:1500]}")

                        # Export full XML for inspection
                        try:
                            with open('software_update_check.xml', 'w') as f:
                                f.write(check_response.text)
                            debug("Exported full update check XML to software_update_check.xml")
                        except Exception as e:
                            debug(f"Error exporting update check XML: {e}")

                        # Find all entries with version information
                        entries = check_root.findall('.//entry')
                        current_version = None
                        latest_available = None
                        all_versions = []

                        for entry in entries:
                            version_elem = entry.find('.//version')
                            downloaded_elem = entry.find('.//downloaded')
                            current_elem = entry.find('.//current')
                            latest_elem = entry.find('.//latest')

                            version_num = version_elem.text if version_elem is not None and version_elem.text else None
                            is_downloaded = downloaded_elem.text if downloaded_elem is not None and downloaded_elem.text else 'no'
                            is_current = current_elem.text if current_elem is not None and current_elem.text else 'no'
                            is_latest = latest_elem.text if latest_elem is not None and latest_elem.text else 'no'

                            debug(f"  Entry: version={version_num}, current={is_current}, latest={is_latest}, downloaded={is_downloaded}")

                            if version_num:
                                all_versions.append({
                                    'version': version_num,
                                    'current': is_current,
                                    'latest': is_latest,
                                    'downloaded': is_downloaded
                                })

                            # Track the current version
                            if is_current == 'yes' and version_num:
                                current_version = version_num

                            # Track latest available version (marked as latest='yes', regardless of current status)
                            if is_latest == 'yes' and version_num:
                                # If this is also current, no update; otherwise it's the update
                                if is_current != 'yes':
                                    latest_available = version_num

                        debug(f"  All versions found: {all_versions}")
                        debug(f"  Current version: {current_version}, Latest available: {latest_available}")

                        # Return status
                        if latest_available:
                            # There's a newer version available
                            return {
                                'downloaded': 'N/A',
                                'current': 'no',
                                'latest': latest_available
                            }
                        else:
                            # No update available
                            return {
                                'downloaded': 'N/A',
                                'current': 'yes',
                                'latest': 'yes'
                            }

                except Exception as e:
                    debug(f"Error checking update status: {e}")

                return {'downloaded': 'N/A', 'current': 'yes', 'latest': 'yes'}

            # Helper function to add software entry
            def add_software_entry(name, version_elem, update_cmd=None):
                if version_elem is not None and version_elem.text:
                    # Get update status if command provided
                    if update_cmd:
                        status = get_update_status(update_cmd)
                    else:
                        status = {'downloaded': 'N/A', 'current': 'N/A', 'latest': 'N/A'}

                    software_info.append({
                        'name': name,
                        'version': version_elem.text,
                        'downloaded': status['downloaded'],
                        'current': status['current'],
                        'latest': status['latest']
                    })

            # Extract specific version fields
            # PAN-OS version - always available from system info
            sw_version = root.find('.//sw-version')
            add_software_entry('PAN-OS', sw_version)

            # Application and threat signatures - NO auto update check (user clicks "Check for Updates")
            app_version = root.find('.//app-version')
            add_software_entry('Application & Threat', app_version)

            debug(f"Software versions found: {software_info}")

        return {
            'status': 'success',
            'software': software_info,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        debug(f"Software updates error: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'software': []
        }


def get_license_info(firewall_config):
    """Fetch license information from Palo Alto firewall"""
    try:
        firewall_ip, api_key, base_url = firewall_config

        # Query for license information
        cmd = "<request><license><info></info></license></request>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"\n=== License API Response ===")
        debug(f"Status: {response.status_code}")

        license_data = {
            'expired': 0,
            'licensed': 0,
            'licenses': []
        }

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            debug(f"Response XML (first 3000 chars):\n{response.text[:3000]}")

            # Try multiple XPath patterns to find license entries
            entries = root.findall('.//entry')
            if not entries:
                entries = root.findall('.//licenses/entry')
            if not entries:
                entries = root.findall('.//result/entry')

            debug(f"Found {len(entries)} license entries using XPath")

            # Parse license entries
            for entry in entries:
                # Try different field names
                feature = entry.find('.//feature') or entry.find('feature')
                description = entry.find('.//description') or entry.find('description')
                expires = entry.find('.//expires') or entry.find('expires')
                expired = entry.find('.//expired') or entry.find('expired')
                authcode = entry.find('.//authcode') or entry.find('authcode')

                feature_name = feature.text if feature is not None and feature.text else 'Unknown'
                description_text = description.text if description is not None and description.text else ''
                expires_text = expires.text if expires is not None and expires.text else 'N/A'
                expired_text = expired.text if expired is not None and expired.text else 'no'

                debug(f"License entry - Feature: {feature_name}, Expired: {expired_text}, Expires: {expires_text}")

                # Count expired and licensed
                if expired_text.lower() == 'yes':
                    license_data['expired'] += 1
                else:
                    license_data['licensed'] += 1

                license_data['licenses'].append({
                    'feature': feature_name,
                    'description': description_text,
                    'expires': expires_text,
                    'expired': expired_text
                })

            debug(f"License info - Expired: {license_data['expired']}, Licensed: {license_data['licensed']}")

        return {
            'status': 'success',
            'license': license_data,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        debug(f"License info error: {str(e)}")
        import traceback
        debug(f"Traceback: {traceback.format_exc()}")
        return {
            'status': 'error',
            'message': str(e),
            'license': {
                'expired': 0,
                'licensed': 0,
                'licenses': []
            }
        }
