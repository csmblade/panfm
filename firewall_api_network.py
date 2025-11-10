"""
Firewall API network and interface management
Handles interface information, zones, transceivers/SFP details
"""
import xml.etree.ElementTree as ET
from datetime import datetime
from utils import api_request_get
from logger import debug, error, exception


def get_interface_zones(firewall_config):
    """Get mapping of interfaces to security zones by querying the firewall"""
    debug("=== Getting interface-to-zone mappings ===")
    interface_zones = {}

    try:
        firewall_ip, api_key, base_url = firewall_config

        # Query for zone configuration using the config API
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': '/config/devices/entry[@name="localhost.localdomain"]/vsys/entry[@name="vsys1"]/zone',
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            debug(f"Zone config response (first 2000 chars):\n{response.text[:2000]}")

            # Parse zone entries to get interface-to-zone mappings
            # Structure: <response><result><zone><entry name="zone-name"><network><layer3><member>interface</member>...
            for zone_entry in root.findall('.//zone/entry'):
                zone_name = zone_entry.get('name')
                if not zone_name:
                    continue

                debug(f"Processing zone: {zone_name}")

                # Look for member interfaces in the network section
                network = zone_entry.find('.//network')
                if network is not None:
                    # Check for layer3 interfaces
                    layer3 = network.find('.//layer3')
                    if layer3 is not None:
                        for member in layer3.findall('.//member'):
                            if member.text:
                                interface_name = member.text
                                interface_zones[interface_name] = zone_name
                                debug(f"  Mapped L3 interface {interface_name} -> {zone_name}")

                                # Also map base interface if this is a subinterface
                                if '.' in interface_name:
                                    base_interface = interface_name.split('.')[0]
                                    if base_interface not in interface_zones:
                                        interface_zones[base_interface] = zone_name
                                        debug(f"  Mapped base interface {base_interface} -> {zone_name}")

                    # Check for layer2 interfaces
                    layer2 = network.find('.//layer2')
                    if layer2 is not None:
                        for member in layer2.findall('.//member'):
                            if member.text:
                                interface_name = member.text
                                interface_zones[interface_name] = zone_name
                                debug(f"  Mapped L2 interface {interface_name} -> {zone_name}")

                                # Also map base interface if this is a subinterface
                                if '.' in interface_name:
                                    base_interface = interface_name.split('.')[0]
                                    if base_interface not in interface_zones:
                                        interface_zones[base_interface] = zone_name
                                        debug(f"  Mapped base interface {base_interface} -> {zone_name}")

            debug(f"Found {len(interface_zones)} interface-to-zone mappings")
            if interface_zones:
                debug(f"Zone mappings: {interface_zones}")
            else:
                debug("WARNING: No zone mappings found!")

    except Exception as e:
        exception(f"Error getting interface zones: {str(e)}")

    return interface_zones


def get_interface_info(firewall_config):
    """
    Fetch comprehensive interface information from Palo Alto firewall
    Including: interface name, IP address, VLAN, speed, duplex, state, and transceiver (SFP) info
    """
    debug("\n=== Getting interface information ===")

    try:
        firewall_ip, api_key, base_url = firewall_config
        interfaces = []

        # Step 1: Get all transceiver info first (single API call)
        debug("Fetching all transceiver information")
        transceiver_map = get_all_transceiver_info(firewall_config)
        debug(f"Retrieved transceiver info for {len(transceiver_map)} interfaces")

        # Step 2: Get all interfaces with basic info
        debug("Fetching all interfaces")
        cmd = "<show><interface>all</interface></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=15)
        debug(f"Interface API Status: {response.status_code}")

        if response.status_code != 200:
            error(f"Failed to fetch interface info: HTTP {response.status_code}")
            return {
                'status': 'error',
                'message': f'API returned status {response.status_code}',
                'interfaces': []
            }

        debug(f"Interface response XML (first 2000 chars):\n{response.text[:2000]}")

        # Export XML for debugging
        try:
            with open('interface_info_output.xml', 'w', encoding='utf-8') as f:
                f.write(response.text)
            debug("Exported interface info XML to interface_info_output.xml")
        except Exception as e:
            debug(f"Error exporting interface XML: {e}")

        root = ET.fromstring(response.text)

        # Parse hardware interfaces (ethernet, aggregate, loopback, tunnel, vlan)
        # Store in a dictionary for merging with ifnet data
        hw_interfaces = {}
        for hw_entry in root.findall('.//hw/entry'):
            interface_data = parse_interface_entry(hw_entry, firewall_config, transceiver_map)
            if interface_data:
                hw_interfaces[interface_data['name']] = interface_data
                debug(f"Parsed HW interface: {interface_data['name']}")

        # Parse logical interfaces (ifnet - has IP, zone, VLAN info)
        # Merge with hardware data
        for ifnet_entry in root.findall('.//ifnet/entry'):
            name_elem = ifnet_entry.find('name')
            if name_elem is not None and name_elem.text:
                interface_name = name_elem.text

                # Get IP, zone, vlan from ifnet
                ip_elem = ifnet_entry.find('ip')
                zone_elem = ifnet_entry.find('zone')
                tag_elem = ifnet_entry.find('tag')
                dyn_addr_elem = ifnet_entry.find('dyn-addr/member')

                # Extract IP address
                ip_address = '-'
                # Check dynamic IP first
                if dyn_addr_elem is not None and dyn_addr_elem.text:
                    ip_with_cidr = dyn_addr_elem.text
                    ip_address = ip_with_cidr.split('/')[0] if '/' in ip_with_cidr else ip_with_cidr
                    debug(f"Found dynamic IP for {interface_name}: {ip_address}")
                # Check static IP
                elif ip_elem is not None and ip_elem.text and ip_elem.text not in ['N/A', 'n/a']:
                    ip_address = ip_elem.text.split('/')[0] if '/' in ip_elem.text else ip_elem.text
                    debug(f"Found static IP for {interface_name}: {ip_address}")

                # Extract zone
                zone = zone_elem.text if zone_elem is not None and zone_elem.text else '-'

                # Extract VLAN tag (replace 0 with -)
                vlan = tag_elem.text if tag_elem is not None and tag_elem.text else '-'
                if vlan == '0':
                    vlan = '-'

                # If we have HW data for this interface, merge it
                if interface_name in hw_interfaces:
                    hw_interfaces[interface_name]['ip'] = ip_address
                    hw_interfaces[interface_name]['zone'] = zone
                    hw_interfaces[interface_name]['vlan'] = vlan
                    debug(f"Merged ifnet data for: {interface_name} (IP: {ip_address}, Zone: {zone})")
                else:
                    # Interface only exists in ifnet (e.g., subinterface)
                    interface_data = parse_interface_entry(ifnet_entry, firewall_config, transceiver_map, is_logical=True)
                    if interface_data:
                        hw_interfaces[interface_name] = interface_data
                        debug(f"Added logical-only interface: {interface_name}")

        # Convert dictionary to list
        interfaces = list(hw_interfaces.values())

        debug(f"Total interfaces found before state inheritance: {len(interfaces)}")

        # Step 3: Inherit state from parent interfaces for subinterfaces
        # Build a map of interface names to their state
        interface_state_map = {iface['name']: iface['state'] for iface in interfaces}

        for interface in interfaces:
            if interface['type'] == 'Subinterface':
                parent_name = get_parent_interface_name(interface['name'])
                parent_state = interface_state_map.get(parent_name, None)

                # If parent interface is up, subinterface should also be considered up
                if parent_state and parent_state.lower() == 'up' and interface['state'].lower() != 'up':
                    debug(f"Inheriting 'up' state from parent {parent_name} to subinterface {interface['name']}")
                    interface['state'] = 'up'
                # If parent is down, subinterface should be down
                elif parent_state and parent_state.lower() == 'down':
                    debug(f"Inheriting 'down' state from parent {parent_name} to subinterface {interface['name']}")
                    interface['state'] = 'down'

        debug(f"Total interfaces found: {len(interfaces)}")

        return {
            'status': 'success',
            'interfaces': interfaces,
            'timestamp': datetime.now().isoformat()
        }

    except Exception as e:
        exception(f"Error fetching interface information: {str(e)}")
        return {
            'status': 'error',
            'message': str(e),
            'interfaces': []
        }


def format_interface_speed(speed_raw):
    """
    Format interface speed value to a readable string with Mbps/Gbps suffix

    Args:
        speed_raw: Raw speed value from firewall (e.g., "10000", "1000", "ukn", "[n/a]")

    Returns:
        Formatted speed string (e.g., "10 Gbps", "1000 Mbps", "-")
    """
    debug("format_interface_speed called with: %s", speed_raw)
    if not speed_raw or speed_raw in ['ukn', '[n/a]', '-']:
        return '-'

    try:
        speed_mbps = int(speed_raw)

        # Convert to Gbps if >= 1000 Mbps
        if speed_mbps >= 1000 and speed_mbps % 1000 == 0:
            speed_gbps = speed_mbps // 1000
            return f"{speed_gbps} Gbps"
        else:
            return f"{speed_mbps} Mbps"
    except (ValueError, TypeError):
        # If it's not a number, return as-is or '-'
        return '-'


def parse_interface_entry(entry, firewall_config, transceiver_map, is_logical=False):
    """
    Parse a single interface entry from XML
    Returns dict with interface details or None if parsing fails

    Args:
        entry: XML entry element
        firewall_config: Firewall configuration tuple
        transceiver_map: Dictionary mapping interface names to transceiver info
        is_logical: Whether this is a logical interface
    """
    try:
        # Extract interface name
        name_elem = entry.find('name')
        if name_elem is None or not name_elem.text:
            return None

        interface_name = name_elem.text
        debug(f"Parsing interface: {interface_name}")

        # Extract basic info
        # Note: Using './/' searches all descendants, but we need direct children in some cases
        ip_elem = entry.find('ip')  # Direct child for ifnet section
        state_elem = entry.find('state')  # Direct child
        speed_elem = entry.find('speed')  # Direct child
        duplex_elem = entry.find('duplex')  # Direct child
        zone_elem = entry.find('zone')  # Direct child
        tag_elem = entry.find('tag')  # Direct child
        mac_elem = entry.find('mac')  # Direct child

        # Get IP address (check dynamic/DHCP first, then static)
        ip_address = '-'

        # First, try to find dynamic IP address (DHCP, PPPoE, etc.) in <dyn-addr><member>
        dyn_addr_elem = entry.find('dyn-addr/member')  # Direct path
        if dyn_addr_elem is not None and dyn_addr_elem.text:
            # Dynamic address includes CIDR notation (e.g., "87.121.248.146/22")
            # Strip the CIDR to get just the IP
            ip_with_cidr = dyn_addr_elem.text
            ip_address = ip_with_cidr.split('/')[0] if '/' in ip_with_cidr else ip_with_cidr
            debug(f"Found dynamic IP for {interface_name}: {ip_address} (from {ip_with_cidr})")
        # Fallback: try <ip> tag for static IPs
        elif ip_elem is not None and ip_elem.text and ip_elem.text not in ['N/A', 'n/a']:
            ip_address = ip_elem.text.split('/')[0] if '/' in ip_elem.text else ip_elem.text
            debug(f"Found static IP for {interface_name}: {ip_address}")
        else:
            # Try to find IP in member elements (multiple static IPs)
            ip_members = entry.findall('.//ip/member')
            if ip_members:
                ips = [member.text.split('/')[0] if '/' in member.text else member.text
                       for member in ip_members if member.text]
                ip_address = ', '.join(ips) if ips else '-'
                if ip_address != '-':
                    debug(f"Found multiple static IPs for {interface_name}: {ip_address}")

        # Get state
        state = state_elem.text if state_elem is not None and state_elem.text else '-'

        # Get speed and format it
        speed_raw = speed_elem.text if speed_elem is not None and speed_elem.text else None
        speed = format_interface_speed(speed_raw)

        # Get duplex
        duplex = duplex_elem.text if duplex_elem is not None and duplex_elem.text else '-'

        # Get zone
        zone = zone_elem.text if zone_elem is not None and zone_elem.text else '-'

        # Get VLAN tag
        vlan = tag_elem.text if tag_elem is not None and tag_elem.text else '-'

        # Get MAC address
        mac = mac_elem.text if mac_elem is not None and mac_elem.text else '-'

        # Determine interface type
        interface_type = determine_interface_type(interface_name)

        # Get transceiver info from the pre-fetched map
        transceiver_info = transceiver_map.get(interface_name, None)

        interface_data = {
            'name': interface_name,
            'ip': ip_address,
            'vlan': vlan,
            'speed': speed,
            'duplex': duplex,
            'state': state,
            'zone': zone,
            'mac': mac,
            'type': interface_type,
            'transceiver': transceiver_info
        }

        debug(f"Interface {interface_name}: IP={ip_address}, VLAN={vlan}, Speed={speed}, State={state}")

        return interface_data

    except Exception as e:
        debug(f"Error parsing interface entry: {str(e)}")
        return None


def determine_interface_type(interface_name):
    """Determine the type of interface based on its name"""
    debug("determine_interface_type called for: %s", interface_name)
    # Check for subinterface first (has a dot)
    if '.' in interface_name:
        return 'Subinterface'
    elif interface_name.startswith('ethernet'):
        return 'Ethernet'
    elif interface_name.startswith('ae'):
        return 'Aggregate'
    elif interface_name.startswith('loopback'):
        return 'Loopback'
    elif interface_name.startswith('tunnel'):
        return 'Tunnel'
    elif interface_name.startswith('vlan'):
        return 'VLAN'
    else:
        return 'Other'


def get_parent_interface_name(interface_name):
    """
    Extract parent interface name from a subinterface name
    e.g., 'ethernet1/1.100' -> 'ethernet1/1'
    """
    debug("get_parent_interface_name called for: %s", interface_name)
    if '.' in interface_name:
        return interface_name.split('.')[0]
    return interface_name


def get_all_transceiver_info(firewall_config):
    """
    Get all SFP/transceiver information from the firewall
    Returns dict mapping interface names to transceiver details
    """
    debug("=== Fetching all transceiver information ===")

    try:
        firewall_ip, api_key, base_url = firewall_config

        # Query for all transceiver details
        cmd = "<show><transceiver-detail></transceiver-detail></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=15)
        debug(f"Transceiver detail API Status: {response.status_code}")

        if response.status_code != 200:
            error(f"Failed to fetch transceiver info: HTTP {response.status_code}")
            return {}

        debug(f"Transceiver response XML (first 3000 chars):\n{response.text[:3000]}")

        # Export XML for debugging
        try:
            with open('transceiver_detail_output.xml', 'w', encoding='utf-8') as f:
                f.write(response.text)
            debug("Exported transceiver detail XML to transceiver_detail_output.xml")
        except Exception as e:
            debug(f"Error exporting transceiver XML: {e}")

        root = ET.fromstring(response.text)

        # Dictionary to store transceiver info by interface name
        transceiver_map = {}

        # Parse transceiver entries - try multiple possible paths
        possible_paths = [
            './/result/entry',
            './/entry',
            './/transceiver/entry',
            './/result/transceiver/entry'
        ]

        entries = []
        for path in possible_paths:
            entries = root.findall(path)
            if entries:
                debug(f"Found {len(entries)} transceiver entries using path: {path}")
                break

        if not entries:
            debug("No transceiver entries found. Dumping XML structure for debugging...")
            for child in root:
                debug(f"Root child tag: {child.tag}, attrib: {child.attrib}")
                for subchild in list(child)[:5]:  # First 5 only
                    debug(f"  Subchild tag: {subchild.tag}")
            return {}

        for entry in entries:
            try:
                # Debug: Print all elements in this entry (first entry only)
                if not transceiver_map:  # Only for first entry
                    debug(f"First entry elements: {[elem.tag for elem in entry]}")

                # Extract interface name - try multiple possible element names
                name_elem = entry.find('name') or entry.find('interface') or entry.find('port')
                if name_elem is None or not name_elem.text:
                    # Sometimes the name is in an attribute
                    interface_name = entry.attrib.get('name', None)
                    if not interface_name:
                        continue
                else:
                    interface_name = name_elem.text

                debug(f"Processing transceiver for interface: {interface_name}")

                # Extract transceiver details
                transceiver_data = {}

                # Common field mappings - expanded with more variants
                field_mappings = {
                    'vendor': ['vendor', 'vendor-name', 'mfg-name', 'manufacturer'],
                    'part_number': ['part-number', 'part-num', 'pn', 'partnumber', 'part_number'],
                    'serial_number': ['serial-number', 'serial-num', 'sn', 'serialnumber', 'serial_number'],
                    'type': ['type', 'connector-type', 'sfp-type', 'transceiver-type'],
                    'wavelength': ['wavelength', 'wave-length', 'wave_length'],
                    'tx_power': ['tx-power', 'txpower', 'tx-pwr', 'tx_power'],
                    'rx_power': ['rx-power', 'rxpower', 'rx-pwr', 'rx_power'],
                    'temperature': ['temperature', 'temp'],
                    'voltage': ['voltage', 'volt'],
                    'tx_bias': ['tx-bias', 'txbias', 'bias-current', 'tx_bias'],
                    'digital_diagnostic': ['digital-diagnostic', 'ddm', 'digital_diagnostic']
                }

                # Try to find each field using various possible element names
                for key, possible_names in field_mappings.items():
                    for name in possible_names:
                        elem = entry.find(f'.//{name}')
                        if elem is None:
                            elem = entry.find(name)
                        if elem is not None and elem.text and elem.text.strip():
                            transceiver_data[key] = elem.text.strip()
                            if not transceiver_map:  # Debug for first interface only
                                debug(f"  Found {key}={elem.text.strip()} using element '{name}'")
                            break

                if transceiver_data:
                    transceiver_map[interface_name] = transceiver_data
                    debug(f"Successfully added transceiver for {interface_name}: {list(transceiver_data.keys())}")
                else:
                    debug(f"No transceiver data found for {interface_name}. Entry elements: {[elem.tag for elem in list(entry)[:10]]}")
                    # Log first few element values for debugging
                    for elem in list(entry)[:8]:
                        if elem.text and elem.text.strip():
                            debug(f"    {elem.tag} = {elem.text[:50]}")

            except Exception as e:
                exception(f"Error parsing transceiver entry: {str(e)}")
                continue

        debug(f"Total transceivers with data found: {len(transceiver_map)}")
        if transceiver_map:
            debug(f"Sample transceiver interfaces: {list(transceiver_map.keys())[:5]}")

        return transceiver_map

    except Exception as e:
        exception(f"Error fetching transceiver information: {str(e)}")
        return {}
