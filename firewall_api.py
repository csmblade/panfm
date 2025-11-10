"""
Firewall API interaction functions for fetching data from Palo Alto firewalls
This module serves as the main entry point and aggregator for firewall API calls.
Individual functions are organized into specialized modules:
- firewall_api_logs.py: Log retrieval functions
- firewall_api_health.py: Health checks, software updates, and license management
- firewall_api_mac.py: MAC vendor lookups and virtual MAC detection
- firewall_api_network.py: Interface information, zones, and transceiver details
- firewall_api_devices.py: DHCP leases, connected devices, and tech support
- firewall_api_upgrades.py: PAN-OS upgrade automation
- firewall_api_content.py: Content update management
- firewall_api_dhcp.py: DHCP server management
"""
import xml.etree.ElementTree as ET
import time
import sys
from datetime import datetime
from config import load_settings, DEFAULT_FIREWALL_IP, DEFAULT_API_KEY
from utils import api_request_get, get_api_stats
from logger import debug, info, warning, error, exception
from device_manager import device_manager

# Import functions from specialized modules
from firewall_api_logs import (
    get_system_logs,
    get_threat_stats,
    get_traffic_logs,
    get_top_applications,
    get_application_statistics
)
from firewall_api_health import (
    check_firewall_health,
    get_software_updates,
    get_license_info
)
from firewall_api_mac import (
    is_virtual_mac,
    lookup_mac_vendor
)
from firewall_api_network import (
    get_interface_zones,
    get_interface_info
)
from firewall_api_devices import (
    get_dhcp_leases,
    get_connected_devices,
    generate_tech_support_file,
    check_tech_support_job_status,
    get_tech_support_file_url
)
from firewall_api_upgrades import (
    check_available_panos_versions,
    download_panos_version,
    install_panos_version,
    check_job_status,
    reboot_firewall
)
from firewall_api_content import (
    check_content_updates,
    download_content_update,
    install_content_update
)
from firewall_api_dhcp import (
    get_dhcp_servers,
    get_dhcp_leases_detailed,
    get_dhcp_summary
)
from firewall_api_metrics import (
    get_system_resources,
    get_interface_stats,
    get_interface_traffic_counters,
    get_session_count
)
from firewall_api_applications import (
    get_top_applications,
    get_application_statistics
)
from firewall_api_throughput import (
    get_throughput_data,
    get_wan_interface_ip
)


def get_firewall_config(device_id=None):
    """Get firewall IP and API key from settings or from a specific device

    Returns:
        tuple: (firewall_ip, api_key, base_url) or (None, None, None) if no device configured
    """
    debug("get_firewall_config called with device_id: %s", device_id)

    if device_id:
        # Get configuration for a specific device
        device = device_manager.get_device(device_id)
        if device:
            firewall_ip = device['ip']
            api_key = device['api_key']
            debug(f"get_firewall_config: Using device {device.get('name')} - API key starts with: {api_key[:20] if api_key else 'NONE'}...")
            base_url = f"https://{firewall_ip}/api/"
            return firewall_ip, api_key, base_url

    # Fall back to settings (legacy single-device mode)
    settings = load_settings()
    firewall_ip = settings.get('firewall_ip', DEFAULT_FIREWALL_IP)
    api_key = settings.get('api_key', DEFAULT_API_KEY)
    debug(f"get_firewall_config: Loaded from settings - firewall_ip={firewall_ip}, API key starts with: {api_key[:20] if api_key else 'NONE'}...")

    # Check if we have a selected device in settings
    selected_device_id = settings.get('selected_device_id')
    if selected_device_id:
        device = device_manager.get_device(selected_device_id)
        if device and device.get('enabled', True):
            firewall_ip = device['ip']
            api_key = device['api_key']
            debug(f"get_firewall_config: Using selected device {device.get('name')} - API key starts with: {api_key[:20] if api_key else 'NONE'}...")

    # If no device is configured or selected, return None values
    if not firewall_ip or not api_key:
        debug("get_firewall_config: No device configured or selected - returning None")
        return None, None, None

    base_url = f"https://{firewall_ip}/api/"
    debug(f"get_firewall_config: Final API key starts with: {api_key[:20] if api_key else 'NONE'}...")
    return firewall_ip, api_key, base_url


def get_device_uptime(device_id):
    """Fetch uptime for a specific device"""
    try:
        firewall_ip, api_key, base_url = get_firewall_config(device_id)

        cmd = "<show><system><info></info></system></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=5)
        if response.status_code == 200:
            root = ET.fromstring(response.text)
            uptime_elem = root.find('.//uptime')
            if uptime_elem is not None and uptime_elem.text:
                return uptime_elem.text

        return None
    except Exception as e:
        debug(f"Error fetching uptime for device {device_id}: {str(e)}")
        return None


def get_device_version(device_id):
    """Fetch PAN-OS version for a specific device"""
    try:
        firewall_ip, api_key, base_url = get_firewall_config(device_id)

        cmd = "<show><system><info></info></system></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=5)
        if response.status_code == 200:
            root = ET.fromstring(response.text)
            version_elem = root.find('.//sw-version')
            if version_elem is not None and version_elem.text:
                return version_elem.text

        return None
    except Exception as e:
        debug(f"Error fetching version for device {device_id}: {str(e)}")
        return None


# Export all functions for backward compatibility
__all__ = [
    # Core functions (defined in this module)
    'get_firewall_config',
    'get_device_uptime',
    'get_device_version',
    # Re-exported from firewall_api_metrics
    'get_system_resources',
    'get_interface_stats',
    'get_interface_traffic_counters',
    'get_session_count',
    # Re-exported from firewall_api_throughput
    'get_throughput_data',
    'get_wan_interface_ip',
    # Re-exported from firewall_api_logs
    'get_system_logs',
    'get_threat_stats',
    'get_traffic_logs',
    # Re-exported from firewall_api_applications
    'get_top_applications',
    'get_application_statistics',
    # Re-exported from firewall_api_health
    'check_firewall_health',
    'get_software_updates',
    'get_license_info',
    # Re-exported from firewall_api_mac
    'is_virtual_mac',
    'lookup_mac_vendor',
    # Re-exported from firewall_api_network
    'get_interface_zones',
    'get_interface_info',
    # Re-exported from firewall_api_devices
    'get_dhcp_leases',
    'get_connected_devices',
    'generate_tech_support_file',
    'check_tech_support_job_status',
    'get_tech_support_file_url',
    # Re-exported from firewall_api_upgrades
    'check_available_panos_versions',
    'download_panos_version',
    'install_panos_version',
    'check_job_status',
    'reboot_firewall',
    # Re-exported from firewall_api_content
    'check_content_updates',
    'download_content_update',
    'install_content_update',
    # Re-exported from firewall_api_dhcp
    'get_dhcp_servers',
    'get_dhcp_leases_detailed',
    'get_dhcp_summary'
]
