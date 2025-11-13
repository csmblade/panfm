"""
Firewall API system resource metrics for Palo Alto firewalls
Handles CPU, memory, sessions, and interface statistics
"""
import xml.etree.ElementTree as ET
from utils import api_request_get
from logger import debug, exception


def get_firewall_config(device_id=None):
    """Import get_firewall_config from firewall_api to avoid circular import"""
    from firewall_api import get_firewall_config as _get_firewall_config
    return _get_firewall_config(device_id)


def get_system_resources(device_id=None):
    """Fetch system resource usage (CPU, memory, uptime) from Palo Alto firewall

    Args:
        device_id (str, optional): Specific device ID to query. If None, uses selected_device_id from settings.

    Returns:
        dict: Resource metrics including:
            - data_plane_cpu: Data plane CPU percentage
            - mgmt_plane_cpu: Management plane CPU percentage
            - uptime: System uptime string
            - memory_used_pct: Memory usage percentage
            - memory_used_mb: Memory used in MB
            - memory_total_mb: Total memory in MB
    """
    debug("get_system_resources called (device_id=%s)", device_id)
    try:
        _, api_key, base_url = get_firewall_config(device_id)

        # Check if no device is configured
        if not api_key or not base_url:
            debug("No device configured - returning 0 CPU values")
            return {'data_plane_cpu': 0, 'mgmt_plane_cpu': 0, 'uptime': None, 'memory_used_pct': 0, 'memory_used_mb': 0, 'memory_total_mb': 0}

        # Query for dataplane CPU load
        cmd = "<show><running><resource-monitor></resource-monitor></running></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        debug(f"\n=== CPU API Response ===")
        debug(f"Status: {response.status_code}")
        if response.status_code == 200:
            debug(f"Response XML (first 1000 chars):\n{response.text[:1000]}")

        data_plane_cpu = 0
        mgmt_plane_cpu = 0

        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Try to find data-plane CPU from resource monitor - look for minute average across all data processors
            # This will average across all dp0, dp1, dp2, etc. and all their cores
            all_cpu_values = []

            # Find all data processor entries (dp0, dp1, etc.)
            dp_processors = root.findall('.//data-processors/*')
            for dp in dp_processors:
                dp_entries = dp.findall('.//minute/cpu-load-average/entry')
                for entry in dp_entries:
                    value_elem = entry.find('value')
                    if value_elem is not None and value_elem.text:
                        # Value is a comma-separated list of CPU values for different cores
                        try:
                            values = [int(v) for v in value_elem.text.strip().split(',') if v.strip()]
                            all_cpu_values.extend(values)  # Add all core values to the list
                        except:
                            pass

            if all_cpu_values:
                data_plane_cpu = int(sum(all_cpu_values) / len(all_cpu_values))
                debug(f"Found data-plane CPU (1-min avg across {len(all_cpu_values)} cores): {data_plane_cpu}%")

            # If minute average not found, try second average
            if data_plane_cpu == 0:
                dp_entries = root.findall('.//data-processors/dp0/second/cpu-load-average/entry')
                if dp_entries:
                    total_cpu = 0
                    count = 0
                    for entry in dp_entries:
                        value_elem = entry.find('value')
                        if value_elem is not None and value_elem.text:
                            try:
                                values = [int(v) for v in value_elem.text.strip().split(',') if v.strip()]
                                if values:
                                    avg = sum(values) / len(values)
                                    total_cpu += avg
                                    count += 1
                            except:
                                pass
                    if count > 0:
                        data_plane_cpu = int(total_cpu / count)
                        debug(f"Found data-plane CPU (second avg from {count} entries): {data_plane_cpu}%")

        # Try the system resources command for management CPU and memory
        cmd2 = "<show><system><resources></resources></system></show>"
        params2 = {
            'type': 'op',
            'cmd': cmd2,
            'key': api_key
        }
        response2 = api_request_get(base_url, params=params2, verify=False, timeout=10)
        debug(f"Trying system resources command, status: {response2.status_code}")

        memory_used_pct = 0
        memory_total_mb = 0
        memory_used_mb = 0

        if response2.status_code == 200:
                # Export the XML response to a file for inspection
                try:
                    with open('system_resources_output.xml', 'w') as f:
                        f.write(response2.text)
                    debug("Exported system resources XML to system_resources_output.xml")
                except Exception as e:
                    debug(f"Error exporting XML: {e}")

                root2 = ET.fromstring(response2.text)

                # Try to get data plane CPU from XML field
                dp_cpu_elem = root2.find('.//dp-cpu-utilization')

                # Use data plane CPU from XML if not already found from resource monitor
                if dp_cpu_elem is not None and dp_cpu_elem.text and data_plane_cpu == 0:
                    data_plane_cpu = int(dp_cpu_elem.text)
                    debug(f"Data Plane CPU from XML: {data_plane_cpu}%")

                result_text = root2.find('.//result')

                if result_text is not None and result_text.text:
                    lines = result_text.text.strip().split('\n')
                    debug(f"System resources output (first 500 chars):\n{result_text.text[:500]}")

                    for line in lines:
                        # Parse CPU line from top command
                        if '%Cpu(s):' in line or 'Cpu(s):' in line:
                            debug(f"Found CPU line: {line}")
                            try:
                                # Extract all CPU components
                                parts = line.split(':')[1].split(',')  # Get part after ':'
                                user_cpu = 0
                                sys_cpu = 0
                                idle_cpu = 0

                                for part in parts:
                                    part = part.strip()
                                    if 'us' in part:  # user CPU
                                        user_cpu = float(part.split()[0])
                                    elif 'sy' in part:  # system CPU
                                        sys_cpu = float(part.split()[0])
                                    elif 'id' in part:  # idle CPU
                                        idle_cpu = float(part.split()[0])

                                # Always use aggregate CPU from %Cpu(s) line (average across all cores)
                                # Management plane CPU shows usage percentage (user + system)
                                mgmt_plane_cpu = int(user_cpu + sys_cpu)
                                debug(f"Management CPU from system resources (aggregate): {mgmt_plane_cpu}% (user: {user_cpu}% + system: {sys_cpu}%)")

                                debug(f"Parsed CPU - User: {user_cpu}%, System: {sys_cpu}%, Idle: {idle_cpu}%")
                            except Exception as e:
                                debug(f"Error parsing CPU line: {e}")

                        # Parse memory information
                        if 'Mem' in line and 'total' in line:
                            debug(f"Found memory line: {line}")
                            try:
                                parts = line.split(',')
                                for part in parts:
                                    if 'total' in part:
                                        total_str = part.split('total')[0].strip().split()[-1]
                                        memory_total_mb = float(total_str)
                                    if 'used' in part and 'buff/cache' not in part:
                                        used_str = part.split('used')[0].strip().split()[-1]
                                        memory_used_mb = float(used_str)

                                if memory_total_mb > 0:
                                    memory_used_pct = int((memory_used_mb / memory_total_mb) * 100)
                                    debug(f"Memory: {memory_used_mb:.1f}MB / {memory_total_mb:.1f}MB ({memory_used_pct}%)")
                            except Exception as e:
                                debug(f"Error calculating memory: {e}")

        debug(f"Final CPU - Data plane: {data_plane_cpu}%, Mgmt plane: {mgmt_plane_cpu}%")

        # Get system uptime
        uptime = None
        uptime_cmd = "<show><system><info></info></system></show>"
        uptime_params = {
            'type': 'op',
            'cmd': uptime_cmd,
            'key': api_key
        }
        uptime_response = api_request_get(base_url, params=uptime_params, verify=False, timeout=10)
        if uptime_response.status_code == 200:
            uptime_root = ET.fromstring(uptime_response.text)
            uptime_elem = uptime_root.find('.//uptime')
            if uptime_elem is not None and uptime_elem.text:
                uptime = uptime_elem.text

        return {
            'data_plane_cpu': data_plane_cpu,
            'mgmt_plane_cpu': mgmt_plane_cpu,
            'uptime': uptime,
            'memory_used_pct': memory_used_pct,
            'memory_used_mb': int(memory_used_mb),
            'memory_total_mb': int(memory_total_mb)
        }

    except Exception as e:
        exception(f"CPU Error: {str(e)}")
        return {'data_plane_cpu': 0, 'mgmt_plane_cpu': 0, 'uptime': None, 'memory_used_pct': 0, 'memory_used_mb': 0, 'memory_total_mb': 0}


def get_interface_stats(device_id=None):
    """Fetch interface statistics from Palo Alto firewall

    Args:
        device_id (str, optional): Specific device ID to query. If None, uses selected_device_id from settings.

    Returns:
        dict: Interface statistics including:
            - interfaces: List of interfaces with errors/drops
            - total_errors: Sum of all input/output errors
            - total_drops: Sum of all input drops
    """
    debug("get_interface_stats called (device_id=%s)", device_id)
    try:
        _, api_key, base_url = get_firewall_config(device_id)

        # Check if no device is configured
        if not api_key or not base_url:
            debug("No device configured - returning empty interface stats")
            return {'interfaces': [], 'total_errors': 0, 'total_drops': 0}

        # Get interface statistics
        cmd = "<show><counter><interface>all</interface></counter></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"Interface stats API Status: {response.status_code}")

        interfaces = []
        total_errors = 0
        total_drops = 0

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            debug(f"Interface stats XML (first 2000 chars):\n{response.text[:2000]}")

            # Parse interface entries
            for ifentry in root.findall('.//ifnet/entry'):
                name_elem = ifentry.find('name')
                ierrors_elem = ifentry.find('ierrors')
                oerrors_elem = ifentry.find('oerrors')
                idrops_elem = ifentry.find('idrops')

                if name_elem is not None:
                    interface_name = name_elem.text
                    ierrors = int(ierrors_elem.text) if ierrors_elem is not None and ierrors_elem.text else 0
                    oerrors = int(oerrors_elem.text) if oerrors_elem is not None and oerrors_elem.text else 0
                    idrops = int(idrops_elem.text) if idrops_elem is not None and idrops_elem.text else 0

                    total_errors += ierrors + oerrors
                    total_drops += idrops

                    # Only include interfaces with errors or drops
                    if ierrors > 0 or oerrors > 0 or idrops > 0:
                        interfaces.append({
                            'name': interface_name,
                            'ierrors': ierrors,
                            'oerrors': oerrors,
                            'idrops': idrops,
                            'total_errors': ierrors + oerrors
                        })

            debug(f"Found {len(interfaces)} interfaces with errors/drops")
            debug(f"Total errors: {total_errors}, Total drops: {total_drops}")

        return {
            'interfaces': interfaces,
            'total_errors': total_errors,
            'total_drops': total_drops
        }

    except Exception as e:
        debug(f"Interface stats error: {str(e)}")
        return {'interfaces': [], 'total_errors': 0, 'total_drops': 0}


def get_interface_traffic_counters():
    """
    Fetch per-interface traffic counters (bytes in/out) from Palo Alto firewall

    Returns:
        dict: Interface name mapped to traffic stats
        Example: {'ethernet1/1': {'ibytes': 12345, 'obytes': 67890, 'total_bytes': 80235}, ...}
    """
    debug("get_interface_traffic_counters called")
    try:
        _, api_key, base_url = get_firewall_config()

        # Check if no device is configured
        if not api_key or not base_url:
            debug("No device configured - returning empty traffic counters")
            return {}

        # Get interface counters
        cmd = "<show><counter><interface>all</interface></counter></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"Interface traffic counters API Status: {response.status_code}")

        interface_counters = {}

        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Parse hardware entries for byte counters (physical interfaces)
            for hw_entry in root.findall('.//hw/entry'):
                name_elem = hw_entry.find('name')
                ibytes_elem = hw_entry.find('ibytes')
                obytes_elem = hw_entry.find('obytes')

                if name_elem is not None and name_elem.text:
                    interface_name = name_elem.text
                    ibytes = int(ibytes_elem.text) if ibytes_elem is not None and ibytes_elem.text else 0
                    obytes = int(obytes_elem.text) if obytes_elem is not None and obytes_elem.text else 0

                    interface_counters[interface_name] = {
                        'ibytes': ibytes,
                        'obytes': obytes,
                        'total_bytes': ibytes + obytes
                    }

            # Parse ifnet entries for subinterfaces (logical interfaces like ethernet1/1.100)
            for ifnet_entry in root.findall('.//ifnet/entry'):
                name_elem = ifnet_entry.find('name')
                ibytes_elem = ifnet_entry.find('ibytes')
                obytes_elem = ifnet_entry.find('obytes')

                if name_elem is not None and name_elem.text:
                    interface_name = name_elem.text
                    # Only process if this is a subinterface (contains a dot) or not already in counters
                    if '.' in interface_name or interface_name not in interface_counters:
                        ibytes = int(ibytes_elem.text) if ibytes_elem is not None and ibytes_elem.text else 0
                        obytes = int(obytes_elem.text) if obytes_elem is not None and obytes_elem.text else 0

                        interface_counters[interface_name] = {
                            'ibytes': ibytes,
                            'obytes': obytes,
                            'total_bytes': ibytes + obytes
                        }

            debug(f"Found traffic counters for {len(interface_counters)} interfaces (including subinterfaces)")

        return interface_counters

    except Exception as e:
        debug(f"Interface traffic counters error: {str(e)}")
        return {}


def get_session_count(device_id=None):
    """Fetch session count from Palo Alto firewall

    Args:
        device_id (str, optional): Specific device ID to query. If None, uses selected_device_id from settings.

    Returns:
        dict: Session counts including:
            - active: Total active sessions
            - tcp: TCP sessions
            - udp: UDP sessions
            - icmp: ICMP sessions
    """
    debug("get_session_count called (device_id=%s)", device_id)
    try:
        _, api_key, base_url = get_firewall_config(device_id)

        # Check if no device is configured
        if not api_key or not base_url:
            debug("No device configured - returning 0 session counts")
            return {'active': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}

        cmd = "<show><session><info></info></session></show>"
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Extract session counts
            num_active = root.find('.//num-active')
            num_tcp = root.find('.//num-tcp')
            num_udp = root.find('.//num-udp')
            num_icmp = root.find('.//num-icmp')

            return {
                'active': int(num_active.text) if num_active is not None and num_active.text else 0,
                'tcp': int(num_tcp.text) if num_tcp is not None and num_tcp.text else 0,
                'udp': int(num_udp.text) if num_udp is not None and num_udp.text else 0,
                'icmp': int(num_icmp.text) if num_icmp is not None and num_icmp.text else 0
            }
        else:
            return {'active': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}

    except Exception as e:
        exception(f"Session count error: {str(e)}")
        return {'active': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
