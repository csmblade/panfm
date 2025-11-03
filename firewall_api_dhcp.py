"""
Firewall API - DHCP Functions
Handles DHCP server information and lease management for Palo Alto firewalls.
"""

import xml.etree.ElementTree as ET
from logger import debug, info, warning, error, exception
from utils import api_request_get


def get_dhcp_servers(firewall_config):
    """
    Fetch DHCP server configuration from Palo Alto firewall.

    Args:
        firewall_config: Tuple of (firewall_ip, api_key, base_url)

    Returns:
        list: List of DHCP server configurations

    Example return:
        [
            {
                'interface': 'ethernet1/1',
                'enabled': True,
                'ip_pool_start': '192.168.1.100',
                'ip_pool_end': '192.168.1.200',
                'subnet': '192.168.1.0/24'
            }
        ]
    """
    debug("=== Starting get_dhcp_servers ===")
    servers = []

    try:
        firewall_ip, api_key, base_url = firewall_config
        debug(f"Fetching DHCP server configuration from {firewall_ip}")

        # API command to get DHCP server configuration
        params = {
            'type': 'op',
            'cmd': '<show><dhcp><server></server></dhcp></show>',
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"DHCP server API response status: {response.status_code}")

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            status = root.get('status')

            if status == 'success':
                # Parse DHCP server entries
                for interface_elem in root.findall('.//interface'):
                    interface_name = interface_elem.get('name', 'Unknown')

                    server_info = {
                        'interface': interface_name,
                        'enabled': True,
                        'lease_count': 0
                    }

                    # Extract server details if available
                    pool_elem = interface_elem.find('.//pool')
                    if pool_elem is not None:
                        start_elem = pool_elem.find('start')
                        end_elem = pool_elem.find('end')
                        if start_elem is not None:
                            server_info['ip_pool_start'] = start_elem.text
                        if end_elem is not None:
                            server_info['ip_pool_end'] = end_elem.text

                    # Count active leases for this interface
                    lease_entries = interface_elem.findall('.//entry')
                    server_info['lease_count'] = len(lease_entries)

                    servers.append(server_info)
                    debug(f"Found DHCP server on {interface_name} with {server_info['lease_count']} leases")
            else:
                # Check for error message
                msg_elem = root.find('.//msg')
                if msg_elem is not None:
                    warning(f"DHCP server query returned error: {msg_elem.text}")
                else:
                    warning("DHCP server query returned non-success status")

        debug(f"Found {len(servers)} DHCP server(s)")
        return servers

    except ET.ParseError as e:
        exception(f"XML parsing error in get_dhcp_servers: {str(e)}")
        return []
    except Exception as e:
        exception(f"Error fetching DHCP servers: {str(e)}")
        return []


def get_dhcp_leases_detailed(firewall_config):
    """
    Fetch detailed DHCP lease information from Palo Alto firewall.

    This function retrieves comprehensive DHCP lease data including IP address,
    MAC address, hostname, lease state, expiration time, and interface.

    Args:
        firewall_config: Tuple of (firewall_ip, api_key, base_url)

    Returns:
        list: List of DHCP lease dictionaries with detailed information

    Example return:
        [
            {
                'ip': '192.168.1.100',
                'mac': 'aa:bb:cc:dd:ee:ff',
                'hostname': 'laptop-finance',
                'state': 'BOUND',
                'expiration': '2025-11-03 15:30:00',
                'interface': 'ethernet1/1'
            }
        ]
    """
    debug("=== Starting get_dhcp_leases_detailed ===")
    leases = []

    try:
        firewall_ip, api_key, base_url = firewall_config
        debug(f"Fetching DHCP lease information from {firewall_ip}")

        # API command to get DHCP leases
        params = {
            'type': 'op',
            'cmd': '<show><dhcp><server><lease></lease></server></dhcp></show>',
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"DHCP leases API response status: {response.status_code}")

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            status = root.get('status')

            if status == 'success':
                # Parse DHCP lease entries
                # Structure: <interface name="..."><entry>...</entry></interface>
                for interface_elem in root.findall('.//interface'):
                    interface_name = interface_elem.get('name', 'Unknown')

                    for entry in interface_elem.findall('.//entry'):
                        lease = parse_dhcp_entry(entry, interface_name)
                        if lease:
                            leases.append(lease)

                debug(f"Successfully parsed {len(leases)} DHCP lease(s)")
            else:
                # Check for error message
                msg_elem = root.find('.//msg')
                if msg_elem is not None:
                    warning(f"DHCP leases query returned error: {msg_elem.text}")
                    debug(f"This may indicate DHCP server is not configured on the firewall")
                else:
                    warning("DHCP leases query returned non-success status")
        else:
            warning(f"DHCP leases API returned status code: {response.status_code}")

        debug(f"Returning {len(leases)} total DHCP lease(s)")
        return leases

    except ET.ParseError as e:
        exception(f"XML parsing error in get_dhcp_leases_detailed: {str(e)}")
        return []
    except Exception as e:
        exception(f"Error fetching DHCP leases: {str(e)}")
        return []


def parse_dhcp_entry(entry, interface_name):
    """
    Parse a single DHCP lease entry from XML.

    Args:
        entry: XML element containing DHCP lease data
        interface_name: Name of the interface this lease is on

    Returns:
        dict: Parsed lease information, or None if parsing fails
    """
    try:
        lease = {
            'interface': interface_name
        }

        # Extract IP address (required)
        ip_elem = entry.find('ip')
        if ip_elem is not None and ip_elem.text:
            lease['ip'] = ip_elem.text.strip()
        else:
            debug("Skipping entry with no IP address")
            return None

        # Extract MAC address (required)
        mac_elem = entry.find('mac')
        if mac_elem is not None and mac_elem.text:
            lease['mac'] = mac_elem.text.strip().lower()
        else:
            lease['mac'] = 'N/A'

        # Extract hostname (optional)
        hostname_elem = entry.find('hostname')
        if hostname_elem is not None and hostname_elem.text:
            lease['hostname'] = hostname_elem.text.strip()
        else:
            lease['hostname'] = 'Unknown'

        # Extract state (optional)
        state_elem = entry.find('state')
        if state_elem is not None and state_elem.text:
            lease['state'] = state_elem.text.strip().upper()
        else:
            lease['state'] = 'UNKNOWN'

        # Extract expiration time (optional)
        expiration_elem = entry.find('expiration')
        if expiration_elem is not None and expiration_elem.text:
            lease['expiration'] = expiration_elem.text.strip()
        else:
            # Try alternative field names
            lease_time_elem = entry.find('lease-time')
            if lease_time_elem is not None and lease_time_elem.text:
                lease['expiration'] = lease_time_elem.text.strip()
            else:
                lease['expiration'] = 'N/A'

        debug(f"Parsed DHCP lease: IP={lease['ip']}, MAC={lease['mac']}, Hostname={lease['hostname']}")
        return lease

    except Exception as e:
        exception(f"Error parsing DHCP entry: {str(e)}")
        return None


def get_dhcp_summary(firewall_config):
    """
    Get a summary of DHCP server status and lease information.

    Args:
        firewall_config: Tuple of (firewall_ip, api_key, base_url)

    Returns:
        dict: Summary containing server count, total leases, and servers list

    Example return:
        {
            'server_count': 1,
            'total_leases': 15,
            'servers': [
                {
                    'interface': 'ethernet1/1',
                    'lease_count': 15,
                    'enabled': True
                }
            ]
        }
    """
    debug("=== Starting get_dhcp_summary ===")

    try:
        servers = get_dhcp_servers(firewall_config)
        leases = get_dhcp_leases_detailed(firewall_config)

        summary = {
            'server_count': len(servers),
            'total_leases': len(leases),
            'servers': servers
        }

        debug(f"DHCP summary: {summary['server_count']} server(s), {summary['total_leases']} lease(s)")
        return summary

    except Exception as e:
        exception(f"Error generating DHCP summary: {str(e)}")
        return {
            'server_count': 0,
            'total_leases': 0,
            'servers': []
        }
