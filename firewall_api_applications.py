"""
Firewall API application traffic analysis for Palo Alto firewalls
Handles application statistics, top applications, and traffic aggregation
"""
import xml.etree.ElementTree as ET
import time
from utils import api_request_get
from logger import debug, exception
from firewall_api_logs import get_traffic_logs
from firewall_api_devices import get_dhcp_leases, get_connected_devices


def is_private_ip(ip):
    """
    Check if an IP address is a private (RFC 1918) address.

    Args:
        ip: IP address string (e.g., "192.168.1.1")

    Returns:
        bool: True if IP is private, False otherwise
    """
    if not ip or ip == 'N/A' or ip == '':
        return False

    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        first = int(parts[0])
        second = int(parts[1])

        # 10.0.0.0/8 (Class A private network)
        if first == 10:
            return True

        # 172.16.0.0/12 (Class B private network)
        if first == 172 and 16 <= second <= 31:
            return True

        # 192.168.0.0/16 (Class C private network)
        if first == 192 and second == 168:
            return True

        # Loopback 127.0.0.0/8
        if first == 127:
            return True

        # Link-local 169.254.0.0/16
        if first == 169 and second == 254:
            return True

        return False
    except (ValueError, IndexError):
        return False


def classify_traffic_direction(sources, destinations, zones, category):
    """
    Classify traffic direction as local, internet, mixed, or unknown.

    Uses multiple signals in priority order:
    1. Security zones (trust→untrust = internet, trust→trust = local)
    2. IP address analysis (RFC 1918 detection)
    3. Firewall category (fallback if zones/IPs inconclusive)

    Args:
        sources: List of source dicts with 'ip' key
        destinations: List of destination dicts with 'ip' key
        zones: List of zone strings (e.g., ["trust", "untrust"])
        category: Application category from firewall (e.g., "private-ip-addresses")

    Returns:
        str: "internet", "local", "mixed", or "unknown"
    """
    # Strategy 1: Use security zones if available
    if zones and len(zones) > 0:
        zone_set = set(z.lower() for z in zones if z)

        # Check for typical zone patterns
        has_untrust = 'untrust' in zone_set or 'internet' in zone_set or 'external' in zone_set
        has_trust_only = 'trust' in zone_set and len(zone_set) == 1

        if has_untrust:
            # Traffic involving untrust zone = internet traffic
            return 'internet'
        elif has_trust_only:
            # Traffic entirely within trust zone = local traffic
            return 'local'
        elif len(zone_set) > 1:
            # Multiple zones (not just untrust) = mixed
            return 'mixed'

    # Strategy 2: Analyze source and destination IPs
    if sources or destinations:
        has_private_src = False
        has_public_src = False
        has_private_dst = False
        has_public_dst = False

        # Check sources
        for src in sources:
            src_ip = src.get('ip', '')
            if src_ip and src_ip != 'N/A':
                if is_private_ip(src_ip):
                    has_private_src = True
                else:
                    has_public_src = True

        # Check destinations
        for dst in destinations:
            dst_ip = dst.get('ip', '')
            if dst_ip and dst_ip != 'N/A':
                if is_private_ip(dst_ip):
                    has_private_dst = True
                else:
                    has_public_dst = True

        # Classify based on IP analysis
        if has_public_dst or has_public_src:
            # Any public IP involvement = internet traffic
            if has_private_src or has_private_dst:
                # Mix of public and private = mixed (less common)
                return 'internet'  # Treat as internet since it touches public IPs
            else:
                return 'internet'
        elif has_private_src and has_private_dst:
            # All IPs are private = local traffic
            return 'local'
        elif has_private_src or has_private_dst:
            # Only one side analyzed and it's private
            return 'local'

    # Strategy 3: Use firewall category as fallback
    if category:
        cat_lower = category.lower()
        if 'private-ip' in cat_lower or 'internal' in cat_lower or 'local' in cat_lower:
            return 'local'
        elif 'internet' in cat_lower or 'cloud' in cat_lower or 'web' in cat_lower:
            return 'internet'

    # Unable to determine
    return 'unknown'


def get_top_applications(firewall_config, top_count=5):
    """Fetch top applications from traffic logs

    Args:
        firewall_config: Tuple of (firewall_ip, api_key, base_url)
        top_count: Number of top applications to return (default: 5)

    Returns:
        dict: Top applications with:
            - apps: List of {'name': app_name, 'count': session_count}
            - total_count: Total unique applications
    """
    try:
        firewall_ip, api_key, base_url = firewall_config

        # Query traffic logs
        log_query = "(subtype eq end)"
        params = {
            'type': 'log',
            'log-type': 'traffic',
            'query': log_query,
            'nlogs': '1000',
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"Top apps traffic log query status: {response.status_code}")

        app_counts = {}

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            job_id = root.find('.//job')

            if job_id is not None and job_id.text:
                debug(f"Top apps job ID: {job_id.text}")
                time.sleep(1)

                result_params = {
                    'type': 'log',
                    'action': 'get',
                    'job-id': job_id.text,
                    'key': api_key
                }

                result_response = api_request_get(base_url, params=result_params, verify=False, timeout=10)

                if result_response.status_code == 200:
                    result_root = ET.fromstring(result_response.text)

                    # Count applications
                    for entry in result_root.findall('.//entry'):
                        app_elem = entry.find('.//app')
                        if app_elem is not None and app_elem.text:
                            app_name = app_elem.text
                            if app_name not in app_counts:
                                app_counts[app_name] = 0
                            app_counts[app_name] += 1

        # Sort by count and get top N
        top_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:top_count]
        debug(f"Top {top_count} applications: {top_apps}")

        # Calculate total unique applications
        total_apps = len(app_counts)

        return {
            'apps': [{'name': app[0], 'count': app[1]} for app in top_apps],
            'total_count': total_apps
        }

    except Exception as e:
        debug(f"Top applications error: {str(e)}")
        return {'apps': [], 'total_count': 0}


def extract_vlan_from_interface(interface_name):
    """
    Extract VLAN ID from interface name

    Common formats: ethernet1/1.10, ae1.100, vlan.100, etc.

    Args:
        interface_name: Interface name string

    Returns:
        VLAN ID formatted as "VLAN X" or None if not found
    """
    if not interface_name:
        return None

    # Check for sub-interface format (e.g., ethernet1/1.10, ae1.100)
    if '.' in interface_name:
        parts = interface_name.split('.')
        if len(parts) >= 2 and parts[-1].isdigit():
            return f"VLAN {parts[-1]}"

    # Check for vlan interface format (e.g., vlan.100)
    if interface_name.lower().startswith('vlan'):
        parts = interface_name.split('.')
        if len(parts) >= 2 and parts[-1].isdigit():
            return f"VLAN {parts[-1]}"

    return None


def get_application_statistics(firewall_config, max_logs=5000):
    """
    Fetch application statistics from traffic logs

    Returns aggregated data by application name with sessions, bytes, source IPs, destinations, etc.
    Also returns summary statistics for the dashboard.

    VLAN information is extracted from inbound_if and outbound_if fields (not zones).

    Args:
        firewall_config: Tuple of (firewall_ip, api_key, base_url)
        max_logs: Maximum number of logs to retrieve (default: 5000)

    Returns:
        dict: Application statistics with:
            - applications: List of app stats including sessions, bytes, sources, destinations
            - summary: Aggregate statistics (total apps, sessions, bytes, VLANs, zones, timespan)
    """
    debug("=== get_application_statistics called ===")
    try:
        traffic_logs_data = get_traffic_logs(firewall_config, max_logs)
        traffic_logs = traffic_logs_data.get('logs', [])
        debug(f"Retrieved {len(traffic_logs)} traffic logs for application analysis")

        # Get DHCP leases for hostname resolution
        dhcp_hostnames = get_dhcp_leases(firewall_config)
        debug(f"Retrieved {len(dhcp_hostnames)} DHCP hostname mappings for source IP enrichment")

        # Get connected devices for custom name enrichment
        # This gives us IP -> {custom_name, original_hostname} mapping
        debug("Fetching connected devices for custom name enrichment")
        connected_devices = get_connected_devices(firewall_config)
        # Create IP-to-device mapping for quick lookups
        ip_to_device = {}
        if isinstance(connected_devices, list):
            for device in connected_devices:
                if device.get('ip') and device['ip'] != '-':
                    ip_to_device[device['ip']] = {
                        'custom_name': device.get('custom_name'),
                        'original_hostname': device.get('original_hostname', device.get('hostname', '-'))
                    }
        debug(f"Created IP-to-device mapping for {len(ip_to_device)} devices")

        # Aggregate by application
        app_stats = {}
        total_sessions = 0
        total_bytes = 0
        vlans = set()
        zones = set()
        earliest_time = None
        latest_time = None

        for log in traffic_logs:
            app = log.get('app', 'unknown')
            category = log.get('category', 'unknown')
            src = log.get('src', '')
            dst = log.get('dst', '')
            log_time = log.get('time', '')

            # Track earliest and latest timestamps
            if log_time:
                if earliest_time is None or log_time < earliest_time:
                    earliest_time = log_time
                if latest_time is None or log_time > latest_time:
                    latest_time = log_time

            # Calculate total bytes (sent + received)
            bytes_sent = int(log.get('bytes_sent', 0))
            bytes_received = int(log.get('bytes_received', 0))
            bytes_val = bytes_sent + bytes_received
            proto = log.get('proto', '')
            dport = log.get('dport', '')
            from_zone = log.get('from_zone', '')
            to_zone = log.get('to_zone', '')
            inbound_if = log.get('inbound_if', '')
            outbound_if = log.get('outbound_if', '')

            # Extract VLANs from interface names (not zones)
            inbound_vlan = extract_vlan_from_interface(inbound_if)
            outbound_vlan = extract_vlan_from_interface(outbound_if)

            if inbound_vlan:
                vlans.add(inbound_vlan)
            if outbound_vlan:
                vlans.add(outbound_vlan)

            # Track security zones
            if from_zone:
                zones.add(from_zone)
            if to_zone:
                zones.add(to_zone)

            # Update summary totals
            total_sessions += 1
            total_bytes += bytes_val

            if app not in app_stats:
                app_stats[app] = {
                    'name': app,
                    'category': category,
                    'sessions': 0,
                    'bytes': 0,
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'source_ips': set(),
                    'dest_ips': set(),
                    'source_details': {},  # Track bytes per source IP
                    'dest_details': {},  # Track bytes per destination
                    'protocols': set(),
                    'ports': set(),
                    'vlans': set(),
                    'zones': set()
                }

            app_stats[app]['sessions'] += 1
            app_stats[app]['bytes'] += bytes_val
            app_stats[app]['bytes_sent'] += bytes_sent
            app_stats[app]['bytes_received'] += bytes_received
            if src:
                app_stats[app]['source_ips'].add(src)
                # Track bytes per source IP
                if src not in app_stats[app]['source_details']:
                    app_stats[app]['source_details'][src] = {
                        'ip': src,
                        'bytes': 0
                    }
                app_stats[app]['source_details'][src]['bytes'] += bytes_val
            if dst:
                app_stats[app]['dest_ips'].add(dst)
                # Track bytes per destination with port
                dest_key = f"{dst}:{dport}" if dport else dst
                if dest_key not in app_stats[app]['dest_details']:
                    app_stats[app]['dest_details'][dest_key] = {
                        'ip': dst,
                        'port': dport,
                        'bytes': 0
                    }
                app_stats[app]['dest_details'][dest_key]['bytes'] += bytes_val
            if proto: app_stats[app]['protocols'].add(proto)
            if dport: app_stats[app]['ports'].add(dport)
            # Track VLANs from interfaces (not zones)
            if inbound_vlan: app_stats[app]['vlans'].add(inbound_vlan)
            if outbound_vlan: app_stats[app]['vlans'].add(outbound_vlan)
            # Track security zones
            if from_zone: app_stats[app]['zones'].add(from_zone)
            if to_zone: app_stats[app]['zones'].add(to_zone)

        # Log VLAN and zone detection summary
        debug(f"Detected {len(vlans)} unique VLANs from interface data: {sorted(vlans)}")
        debug(f"Detected {len(zones)} unique security zones: {sorted(zones)}")

        # Convert sets to lists and format result
        result = []
        for app_name, stats in app_stats.items():
            # Convert source_details dict to sorted list with hostname enrichment
            source_list = []
            for src_ip, src_info in stats['source_details'].items():
                # Look up device info from connected devices (includes custom_name and original_hostname)
                device_info = ip_to_device.get(src_ip)

                # Determine display name: custom_name -> original_hostname -> DHCP hostname -> IP
                custom_name = None
                original_hostname = None
                hostname = dhcp_hostnames.get(src_ip, '')

                if device_info:
                    custom_name = device_info.get('custom_name')
                    original_hostname = device_info.get('original_hostname', hostname)

                source_list.append({
                    'ip': src_info['ip'],
                    'bytes': src_info['bytes'],
                    'hostname': hostname,  # DHCP hostname (fallback)
                    'custom_name': custom_name,  # Custom name from metadata (highest priority)
                    'original_hostname': original_hostname  # Original hostname (fallback if no custom_name)
                })
            # Sort sources by bytes descending
            source_list.sort(key=lambda x: x['bytes'], reverse=True)

            # Convert dest_details dict to sorted list
            dest_list = []
            for dest_key, dest_info in stats['dest_details'].items():
                dest_list.append({
                    'ip': dest_info['ip'],
                    'port': dest_info['port'],
                    'bytes': dest_info['bytes']
                })
            # Sort destinations by bytes descending
            dest_list.sort(key=lambda x: x['bytes'], reverse=True)

            # Classify traffic direction using multiple signals
            traffic_direction = classify_traffic_direction(
                sources=source_list,
                destinations=dest_list,
                zones=list(stats['zones']),
                category=stats['category']
            )

            result.append({
                'name': app_name,
                'category': stats['category'],
                'sessions': stats['sessions'],
                'bytes': stats['bytes'],
                'bytes_sent': stats['bytes_sent'],
                'bytes_received': stats['bytes_received'],
                'source_count': len(stats['source_ips']),
                'dest_count': len(stats['dest_ips']),
                'source_ips': list(stats['source_ips'])[:50],  # Limit to 50 (legacy, for backward compatibility)
                'sources': source_list[:50],  # Top 50 sources with bytes
                'dest_ips': list(stats['dest_ips'])[:50],
                'destinations': dest_list[:50],  # Top 50 destinations with details
                'protocols': list(stats['protocols']),
                'ports': list(stats['ports'])[:20],  # Limit to 20
                'vlans': list(stats['vlans']),
                'zones': list(stats['zones']),
                'traffic_direction': traffic_direction  # NEW: local, internet, mixed, or unknown
            })

        # Sort by bytes (volume) descending by default
        result.sort(key=lambda x: x['bytes'], reverse=True)

        debug(f"Aggregated {len(result)} unique applications")

        # Aggregate bytes by category for alerting
        category_stats = {}
        category_stats_lan = {}  # Local LAN only
        category_stats_internet = {}  # Internet only

        for app in result:
            category = app.get('category', 'unknown')
            traffic_dir = app.get('traffic_direction', 'unknown')

            # Overall category stats (for backward compatibility)
            if category not in category_stats:
                category_stats[category] = {
                    'bytes': 0,
                    'sessions': 0,
                    'bytes_sent': 0,
                    'bytes_received': 0
                }
            category_stats[category]['bytes'] += app['bytes']
            category_stats[category]['sessions'] += app['sessions']
            category_stats[category]['bytes_sent'] += app['bytes_sent']
            category_stats[category]['bytes_received'] += app['bytes_received']

            # Split by traffic direction
            if traffic_dir == 'local':
                if category not in category_stats_lan:
                    category_stats_lan[category] = {
                        'bytes': 0,
                        'sessions': 0,
                        'bytes_sent': 0,
                        'bytes_received': 0
                    }
                category_stats_lan[category]['bytes'] += app['bytes']
                category_stats_lan[category]['sessions'] += app['sessions']
                category_stats_lan[category]['bytes_sent'] += app['bytes_sent']
                category_stats_lan[category]['bytes_received'] += app['bytes_received']
            elif traffic_dir == 'internet':
                if category not in category_stats_internet:
                    category_stats_internet[category] = {
                        'bytes': 0,
                        'sessions': 0,
                        'bytes_sent': 0,
                        'bytes_received': 0
                    }
                category_stats_internet[category]['bytes'] += app['bytes']
                category_stats_internet[category]['sessions'] += app['sessions']
                category_stats_internet[category]['bytes_sent'] += app['bytes_sent']
                category_stats_internet[category]['bytes_received'] += app['bytes_received']

        debug(f"Aggregated {len(category_stats)} unique categories (overall), {len(category_stats_lan)} LAN, {len(category_stats_internet)} Internet")

        # Return both applications list, category stats, and summary statistics
        return {
            'applications': result,
            'categories': category_stats,
            'categories_lan': category_stats_lan,
            'categories_internet': category_stats_internet,
            'summary': {
                'total_applications': len(result),
                'total_sessions': total_sessions,
                'total_bytes': total_bytes,
                'vlans_detected': len(vlans),
                'zones_detected': len(zones),
                'earliest_time': earliest_time,
                'latest_time': latest_time
            }
        }

    except Exception as e:
        exception(f"Error getting application statistics: {str(e)}")
        return {
            'applications': [],
            'categories': {},
            'summary': {
                'total_applications': 0,
                'total_sessions': 0,
                'total_bytes': 0,
                'vlans_detected': 0,
                'zones_detected': 0,
                'earliest_time': None,
                'latest_time': None
            }
        }
