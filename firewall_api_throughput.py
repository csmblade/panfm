"""
Firewall API throughput calculation and aggregation for Palo Alto firewalls
Handles throughput rate calculation, WAN interface IP extraction, and dashboard data aggregation
"""
import xml.etree.ElementTree as ET
import time
import sys
from datetime import datetime
from config import load_settings
from utils import api_request_get, get_api_stats
from logger import debug, exception
from device_manager import device_manager

# Store per-device statistics for rate calculation
previous_stats = {}


def get_firewall_config(device_id=None):
    """Import get_firewall_config from firewall_api to avoid circular import"""
    from firewall_api import get_firewall_config as _get_firewall_config
    return _get_firewall_config(device_id)


def get_wan_interface_ip(wan_interface):
    """
    Get the IP address and speed of a specific WAN interface

    Args:
        wan_interface: Interface name (e.g., 'ethernet1/1')

    Returns:
        Dictionary with 'ip' and 'speed' keys, or None if interface not found
        Example: {'ip': '87.121.248.146', 'speed': '1000'}
    """
    try:
        if not wan_interface:
            return None

        _, api_key, base_url = get_firewall_config()

        # Get interface information
        cmd = f"<show><interface>{wan_interface}</interface></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"WAN interface IP API Status: {response.status_code}")

        if response.status_code == 200:
            # Export XML for debugging
            try:
                with open(f'wan_interface_{wan_interface.replace("/", "_")}_output.xml', 'w') as f:
                    f.write(response.text)
                debug(f"Exported WAN interface XML to wan_interface_{wan_interface.replace('/', '_')}_output.xml")
            except Exception as e:
                debug(f"Error exporting WAN interface XML: {e}")

            root = ET.fromstring(response.text)

            ip_address = None
            speed = None

            # Try to find IP address in the response
            # First try <dyn-addr><member> for dynamic IPs (DHCP, PPPoE, etc.)
            dyn_addr_elem = root.find('.//dyn-addr/member')
            if dyn_addr_elem is not None and dyn_addr_elem.text:
                # Dynamic address includes CIDR notation (e.g., "87.121.248.146/22")
                # Strip the CIDR to get just the IP
                ip_with_cidr = dyn_addr_elem.text
                ip_address = ip_with_cidr.split('/')[0] if '/' in ip_with_cidr else ip_with_cidr
                debug(f"Found WAN interface {wan_interface} dynamic IP: {ip_address} (from {ip_with_cidr})")

            # Fallback: try <ip> tag for static IPs
            if not ip_address:
                ip_elem = root.find('.//ip')
                if ip_elem is not None and ip_elem.text:
                    ip_address = ip_elem.text.split('/')[0] if '/' in ip_elem.text else ip_elem.text
                    debug(f"Found WAN interface {wan_interface} static IP: {ip_address}")

            # Extract interface speed and format it
            speed_elem = root.find('.//speed')
            speed_raw = speed_elem.text if speed_elem is not None and speed_elem.text else None

            # Import format_interface_speed from firewall_api_network
            from firewall_api_network import format_interface_speed
            speed = format_interface_speed(speed_raw)
            debug(f"Found WAN interface {wan_interface} speed: {speed}")

            if ip_address:
                return {'ip': ip_address, 'speed': speed}

            debug(f"No IP found for interface {wan_interface}")
            return None
        else:
            debug(f"Failed to get WAN interface IP, status: {response.status_code}")
            return None

    except Exception as e:
        debug(f"WAN interface IP error: {str(e)}")
        return None


def get_throughput_data(device_id=None):
    """Fetch throughput data from Palo Alto firewall

    This is the main dashboard aggregator function that collects:
    - Interface throughput (Mbps and PPS)
    - Session counts
    - System resources (CPU, memory, uptime)
    - Threat statistics
    - System logs
    - Interface errors/drops
    - Top applications
    - License information
    - Software version
    - WAN interface IP and speed

    Args:
        device_id (str, optional): Specific device ID to query. If None, uses selected_device_id from settings.

    Returns:
        dict: Comprehensive dashboard data with status 'success' or 'error'
    """
    debug("=== get_throughput_data called (device_id=%s) ===", device_id)

    try:
        # Load settings to get match count and firewall config
        settings = load_settings()
        max_logs = settings.get('match_count', 5)

        # Use provided device_id or fall back to settings
        if device_id is None:
            device_id = settings.get('selected_device_id', '')
            debug(f"No device_id provided, using selected device from settings: {device_id}")
        else:
            debug(f"Using provided device_id: {device_id}")

        firewall_ip, api_key, base_url = get_firewall_config(device_id)

        # Check if no device is configured
        if not firewall_ip or not api_key or not base_url:
            debug("No device configured or selected - returning empty data")
            return {
                'status': 'error',
                'message': 'No device configured. Please add a device in the Managed Devices page.',
                'data': {}
            }

        # Get monitored interface and WAN interface from the device, not from settings
        monitored_interface = 'ethernet1/12'  # default
        wan_interface = ''  # default
        if device_id:
            device = device_manager.get_device(device_id)
            if device:
                if device.get('monitored_interface'):
                    monitored_interface = device['monitored_interface']
                if device.get('wan_interface'):
                    wan_interface = device['wan_interface']

        debug(f"Fetching throughput data from device: {firewall_ip}")
        debug(f"Monitored interface: {monitored_interface}")
        debug(f"WAN interface: {wan_interface}")

        # Use device ID as key for per-device stats, fallback to IP if no device ID
        device_key = device_id if device_id else firewall_ip

        # Query for interface statistics
        cmd = f"<show><counter><interface>{monitored_interface}</interface></counter></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        debug(f"Interface counter API response: HTTP {response.status_code}")
        if response.status_code != 200:
            debug(f"Interface counter request URL length: {len(response.url)} chars")
            debug(f"Interface counter request URL: {response.url}")
            debug(f"Interface counter error response: {response.text[:500]}")

        if response.status_code == 200:
            # Export XML for debugging
            try:
                with open('interface_counter_output.xml', 'w') as f:
                    f.write(response.text)
                debug("Exported interface counter XML to interface_counter_output.xml")
            except Exception as e:
                debug(f"Error exporting interface counter XML: {e}")

            # Parse XML response
            root = ET.fromstring(response.text)

            total_ibytes = 0
            total_obytes = 0
            total_ipkts = 0
            total_opkts = 0

            # Extract interface statistics - find the main interface entry only
            hw_entry = root.find(f".//entry[name='{monitored_interface}']")
            if hw_entry is not None:
                ibytes = hw_entry.find('ibytes')
                obytes = hw_entry.find('obytes')
                ipackets = hw_entry.find('ipackets')
                opackets = hw_entry.find('opackets')

                debug(f"Packet fields found - ipackets: {ipackets is not None}, opackets: {opackets is not None}")

                if ibytes is not None and ibytes.text:
                    total_ibytes = int(ibytes.text)
                if obytes is not None and obytes.text:
                    total_obytes = int(obytes.text)
                if ipackets is not None and ipackets.text:
                    total_ipkts = int(ipackets.text)
                    debug(f"Extracted ipackets: {total_ipkts}")
                if opackets is not None and opackets.text:
                    total_opkts = int(opackets.text)
                    debug(f"Extracted opackets: {total_opkts}")
            else:
                debug(f"WARNING: Could not find {monitored_interface} entry in interface counter XML")

            # Initialize device stats if not exists
            global previous_stats
            if device_key not in previous_stats:
                previous_stats[device_key] = {
                    'ibytes': 0,
                    'obytes': 0,
                    'ipkts': 0,
                    'opkts': 0,
                    'timestamp': time.time()
                }

            # Calculate throughput rate (bytes per second)
            current_time = time.time()
            device_stats = previous_stats[device_key]
            time_delta = current_time - device_stats['timestamp']

            if time_delta > 0 and device_stats['ibytes'] > 0:
                # Calculate bytes per second, then convert to Mbps
                ibytes_delta = total_ibytes - device_stats['ibytes']
                obytes_delta = total_obytes - device_stats['obytes']
                ipkts_delta = total_ipkts - device_stats['ipkts']
                opkts_delta = total_opkts - device_stats['opkts']

                # Avoid negative deltas from counter resets
                if ibytes_delta < 0:
                    ibytes_delta = 0
                if obytes_delta < 0:
                    obytes_delta = 0
                if ipkts_delta < 0:
                    ipkts_delta = 0
                if opkts_delta < 0:
                    opkts_delta = 0

                # Bytes per second
                inbound_bps = ibytes_delta / time_delta
                outbound_bps = obytes_delta / time_delta

                # Packets per second
                inbound_pps = ipkts_delta / time_delta
                outbound_pps = opkts_delta / time_delta
                total_pps = inbound_pps + outbound_pps

                # Log to help debug
                sys.stderr.write(f"\nDEBUG: ibytes_delta={ibytes_delta:,}, obytes_delta={obytes_delta:,}, time={time_delta:.2f}s\n")
                sys.stderr.write(f"DEBUG: inbound_bps={inbound_bps:,.0f}, outbound_bps={outbound_bps:,.0f}\n")
                sys.stderr.write(f"DEBUG: inbound_pps={inbound_pps:,.0f}, outbound_pps={outbound_pps:,.0f}, total_pps={total_pps:,.0f}\n")
                sys.stderr.flush()

                # Convert bytes/sec to Mbps
                inbound_mbps = inbound_bps / 125000
                outbound_mbps = outbound_bps / 125000
                total_mbps = inbound_mbps + outbound_mbps

                sys.stderr.write(f"DEBUG: Result: inbound={inbound_mbps:.2f} Mbps, outbound={outbound_mbps:.2f} Mbps\n\n")
                sys.stderr.flush()
            else:
                # First run or invalid delta
                inbound_mbps = 0
                outbound_mbps = 0
                total_mbps = 0
                inbound_pps = 0
                outbound_pps = 0
                total_pps = 0

            # Update device stats for this device
            device_stats['ibytes'] = total_ibytes
            device_stats['obytes'] = total_obytes
            device_stats['ipkts'] = total_ipkts
            device_stats['opkts'] = total_opkts
            device_stats['timestamp'] = current_time

            # Import functions from other modules
            from firewall_api_metrics import get_session_count, get_system_resources, get_interface_stats
            from firewall_api_logs import get_threat_stats, get_system_logs
            from firewall_api_applications import get_top_applications
            from firewall_api_health import get_license_info, get_software_updates

            # Get session count data
            session_data = get_session_count()

            # Get system resource data
            resource_data = get_system_resources()

            # Use top 10 for all modal displays
            max_logs = 10
            top_apps_count = 10

            # Build firewall config tuple to pass to imported functions
            firewall_config = (firewall_ip, api_key, base_url)

            # Get threat statistics (from firewall_api_logs module)
            threat_data = get_threat_stats(firewall_config, max_logs)

            # Get system logs (limit to max_logs) (from firewall_api_logs module)
            system_logs = get_system_logs(firewall_config, max_logs)

            # Get interface statistics
            interface_stats_data = get_interface_stats()
            interface_stats_list = interface_stats_data.get('interfaces', [])
            interface_errors = interface_stats_data.get('total_errors', 0)
            interface_drops = interface_stats_data.get('total_drops', 0)

            # Get top applications (from firewall_api_applications module)
            top_apps = get_top_applications(firewall_config, top_apps_count)

            # Get license information (from firewall_api_health module)
            license_info = get_license_info(firewall_config)

            # Get software version information (from firewall_api_health module)
            software_info = get_software_updates(firewall_config)
            panos_version = None

            if software_info.get('status') == 'success':
                # Find PAN-OS version from software list
                for sw in software_info.get('software', []):
                    if sw['name'] == 'PAN-OS':
                        panos_version = sw['version']
                        break

            # Get WAN interface IP and speed if wan_interface is configured
            wan_ip = None
            wan_speed = None
            if wan_interface:
                wan_data = get_wan_interface_ip(wan_interface)
                if wan_data:
                    wan_ip = wan_data.get('ip')
                    wan_speed = wan_data.get('speed')
                    debug(f"WAN IP for interface {wan_interface}: {wan_ip}, Speed: {wan_speed}")

            # Get hostname and uptime (Phase 2 fields)
            hostname = None
            uptime_seconds = None
            try:
                cmd = "<show><system><info></info></system></show>"
                params = {
                    'type': 'op',
                    'cmd': cmd,
                    'key': api_key
                }
                response = api_request_get(base_url, params=params, verify=False, timeout=5)
                if response.status_code == 200:
                    root = ET.fromstring(response.text)
                    hostname_elem = root.find('.//hostname')
                    uptime_elem = root.find('.//uptime')
                    if hostname_elem is not None and hostname_elem.text:
                        hostname = hostname_elem.text
                    if uptime_elem is not None and uptime_elem.text:
                        # Parse uptime string (format: "X days, HH:MM:SS") into seconds
                        uptime_str = uptime_elem.text
                        try:
                            # Example: "5 days, 12:34:56"
                            parts = uptime_str.split(',')
                            days = 0
                            time_part = uptime_str
                            if len(parts) == 2:
                                # Has days
                                days = int(parts[0].split()[0])
                                time_part = parts[1].strip()
                            # Parse HH:MM:SS
                            time_parts = time_part.split(':')
                            if len(time_parts) == 3:
                                hours, minutes, seconds = map(int, time_parts)
                                uptime_seconds = (days * 86400) + (hours * 3600) + (minutes * 60) + seconds
                        except Exception as e:
                            debug(f"Error parsing uptime string '{uptime_str}': {e}")
            except Exception as e:
                debug(f"Error fetching hostname/uptime: {e}")

            return {
                'timestamp': datetime.utcnow().isoformat() + 'Z',  # Use UTC and add 'Z' suffix
                'inbound_mbps': round(max(0, inbound_mbps), 2),
                'outbound_mbps': round(max(0, outbound_mbps), 2),
                'total_mbps': round(max(0, total_mbps), 2),
                'inbound_pps': round(max(0, inbound_pps), 0),
                'outbound_pps': round(max(0, outbound_pps), 0),
                'total_pps': round(max(0, total_pps), 0),
                'sessions': session_data,
                'cpu': resource_data,
                'threats': threat_data,
                'system_logs': system_logs,
                'interfaces': interface_stats_list,  # For backward compatibility (UI uses this)
                'top_applications': top_apps,
                'license': license_info.get('license', {'expired': 0, 'licensed': 0}),
                'api_stats': get_api_stats(),
                'pan_os_version': panos_version,  # Changed from 'panos_version' to match Phase 2 schema
                'wan_ip': wan_ip,
                'wan_speed': wan_speed,
                # Phase 2 fields for database storage
                'interface_errors': interface_errors,
                'interface_drops': interface_drops,
                'interface_stats': interface_stats_list,
                'hostname': hostname,
                'uptime_seconds': uptime_seconds,
                'status': 'success'
            }
        else:
            return {'status': 'error', 'message': f'HTTP {response.status_code}'}

    except Exception as e:
        exception(f"Throughput data error: {str(e)}")
        return {'status': 'error', 'message': f'Error: {str(e)}'}
