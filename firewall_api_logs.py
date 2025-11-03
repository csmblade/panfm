"""
Firewall API log retrieval functions for Palo Alto firewalls
Handles system logs, threat logs, traffic logs, and application logs
"""
import xml.etree.ElementTree as ET
import time
import sys
from utils import api_request_get
from logger import debug, info, warning, error, exception
from firewall_api_devices import get_dhcp_leases, get_connected_devices


def get_system_logs(firewall_config, max_logs=50):
    """Fetch system logs from Palo Alto firewall"""
    try:
        firewall_ip, api_key, base_url = firewall_config

        # Query for system logs using log query API
        params = {
            'type': 'log',
            'log-type': 'system',
            'nlogs': str(max_logs * 2),  # Request more to ensure we get enough
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        debug(f"\n=== SYSTEM LOG API Response ===")
        debug(f"Status: {response.status_code}")

        system_logs = []

        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Check if this is a job response (async log query)
            job_id = root.find('.//job')
            if job_id is not None and job_id.text:
                debug(f"System log job ID: {job_id.text}")

                # Wait briefly and fetch job results
                time.sleep(0.5)
                result_params = {
                    'type': 'log',
                    'action': 'get',
                    'job-id': job_id.text,
                    'key': api_key
                }

                result_response = api_request_get(base_url, params=result_params, verify=False, timeout=10)
                if result_response.status_code == 200:
                    root = ET.fromstring(result_response.text)
                    debug(f"System log job result fetched")

            # Parse system log entries with all fields
            for entry in root.findall('.//entry'):
                eventid = entry.find('.//eventid')
                description = entry.find('.//opaque') or entry.find('.//description')
                severity = entry.find('.//severity')
                receive_time = entry.find('.//receive_time') or entry.find('.//time_generated')
                module = entry.find('.//module')
                subtype = entry.find('.//subtype')
                result_elem = entry.find('.//result')

                # Create full log entry with all fields
                log_entry = {
                    'eventid': eventid.text if eventid is not None and eventid.text else 'N/A',
                    'description': description.text if description is not None and description.text else 'System Event',
                    'severity': severity.text if severity is not None and severity.text else 'N/A',
                    'module': module.text if module is not None and module.text else 'N/A',
                    'subtype': subtype.text if subtype is not None and subtype.text else 'N/A',
                    'result': result_elem.text if result_elem is not None and result_elem.text else 'N/A',
                    'time': receive_time.text if receive_time is not None and receive_time.text else 'N/A',
                    # Keep old format for homepage tile
                    'threat': description.text[:50] + '...' if description is not None and description.text and len(description.text) > 50 else (description.text if description is not None and description.text else 'System Event'),
                    'src': module.text if module is not None and module.text else 'N/A',
                    'dst': severity.text if severity is not None and severity.text else 'N/A',
                    'dport': eventid.text if eventid is not None and eventid.text else 'N/A',
                    'action': 'system'
                }

                if len(system_logs) < max_logs:
                    system_logs.append(log_entry)

            debug(f"Total system logs collected: {len(system_logs)}")

        return system_logs

    except Exception as e:
        debug(f"Error fetching system logs: {str(e)}")
        return []


def get_threat_stats(firewall_config, max_logs=5):
    """Fetch threat and URL filtering statistics from Palo Alto firewall"""
    try:
        firewall_ip, api_key, base_url = firewall_config
        debug(f"=== get_threat_stats called ===")
        debug(f"Fetching threat stats from device: {firewall_ip}")

        # Query for threat logs using log query API
        params = {
            'type': 'log',
            'log-type': 'threat',
            'nlogs': '500',
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        sys.stderr.write(f"\n=== THREAT API Response ===\nStatus: {response.status_code}\n")
        if response.status_code == 200:
            sys.stderr.write(f"Response XML (first 1000 chars):\n{response.text[:1000]}...\n")
        sys.stderr.flush()

        medium_count = 0
        critical_count = 0
        url_blocked = 0

        critical_logs = []
        medium_logs = []
        blocked_url_logs = []

        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Check if this is a job response (async log query)
            job_id = root.find('.//job')
            if job_id is not None and job_id.text:
                sys.stderr.write(f"Job ID received: {job_id.text}, fetching results...\n")
                sys.stderr.flush()

                # Wait briefly and fetch job results
                time.sleep(0.5)
                result_params = {
                    'type': 'log',
                    'action': 'get',
                    'job-id': job_id.text,
                    'key': api_key
                }

                result_response = api_request_get(base_url, params=result_params, verify=False, timeout=10)
                if result_response.status_code == 200:
                    root = ET.fromstring(result_response.text)
                    sys.stderr.write(f"Job result fetched, parsing logs...\n")
                    sys.stderr.flush()

            # Count total entries found
            entries = root.findall('.//entry')
            sys.stderr.write(f"Total threat entries found: {len(entries)}\n")
            sys.stderr.flush()

            # Count threats by severity and collect details
            for entry in root.findall('.//entry'):
                severity = entry.find('.//severity')
                threat_type = entry.find('.//type')
                subtype = entry.find('.//subtype')
                action = entry.find('.//action')
                threat_name = entry.find('.//threat-name') or entry.find('.//threatid')
                src = entry.find('.//src')
                dst = entry.find('.//dst')
                sport = entry.find('.//sport')
                dport = entry.find('.//dport')
                receive_time = entry.find('.//receive_time') or entry.find('.//time_generated')
                category = entry.find('.//category')
                url_field = entry.find('.//url') or entry.find('.//misc')
                app = entry.find('.//app')

                # Try to find threat information from various fields
                threat_display = 'Unknown'
                if threat_name is not None and threat_name.text:
                    threat_display = threat_name.text
                elif category is not None and category.text:
                    threat_display = category.text

                # Create log entry
                log_entry = {
                    'threat': threat_display,
                    'src': src.text if src is not None and src.text else 'N/A',
                    'dst': dst.text if dst is not None and dst.text else 'N/A',
                    'sport': sport.text if sport is not None and sport.text else 'N/A',
                    'dport': dport.text if dport is not None and dport.text else 'N/A',
                    'time': receive_time.text if receive_time is not None and receive_time.text else 'N/A',
                    'action': action.text if action is not None and action.text else 'N/A',
                    'app': app.text if app is not None and app.text else 'N/A',
                    'category': category.text if category is not None and category.text else 'N/A',
                    'severity': severity.text if severity is not None and severity.text else 'N/A'
                }

                # Check severity (try different common severity values)
                if severity is not None and severity.text:
                    sev_lower = severity.text.lower()

                    if sev_lower in ['medium', 'med']:
                        medium_count += 1
                        if len(medium_logs) < max_logs:
                            medium_logs.append(log_entry)
                    elif sev_lower in ['critical', 'high', 'crit']:
                        critical_count += 1
                        if len(critical_logs) < max_logs:
                            critical_logs.append(log_entry)

            # Query URL filtering logs for blocked URLs
            url_params = {
                'type': 'log',
                'log-type': 'url',
                'nlogs': '500',
                'key': api_key
            }

            url_response = api_request_get(base_url, params=url_params, verify=False, timeout=10)
            if url_response.status_code == 200:
                url_root = ET.fromstring(url_response.text)
                job_id = url_root.find('.//job')

                if job_id is not None and job_id.text:
                    debug(f"URL filtering log job ID: {job_id.text}")
                    time.sleep(0.5)

                    result_params = {
                        'type': 'log',
                        'action': 'get',
                        'job-id': job_id.text,
                        'key': api_key
                    }

                    result_response = api_request_get(base_url, params=result_params, verify=False, timeout=10)
                    if result_response.status_code == 200:
                        url_root = ET.fromstring(result_response.text)

                        # Get blocked URLs from URL filtering logs
                        all_entries = url_root.findall('.//entry')
                        debug(f"Total URL filtering entries found: {len(all_entries)}")

                        # Iterate through entries and collect blocked URLs
                        for idx, entry in enumerate(all_entries):
                            action = entry.find('.//action')
                            url_category = entry.find('.//category') or entry.find('.//url-category')
                            url_field = entry.find('.//url') or entry.find('.//misc')
                            src = entry.find('.//src')
                            dst = entry.find('.//dst')
                            sport = entry.find('.//sport')
                            dport = entry.find('.//dport')
                            receive_time = entry.find('.//receive_time') or entry.find('.//time_generated')
                            app = entry.find('.//app')

                            # Debug: Log first few entries to understand the data
                            if idx < 10:
                                debug(f"\n=== URL Filtering Entry {idx} ===")
                                debug(f"Action: {action.text if action is not None and action.text else 'None'}")
                                debug(f"URL: {url_field.text if url_field is not None and url_field.text else 'None'}")
                                debug(f"Category: {url_category.text if url_category is not None and url_category.text else 'None'}")
                                debug(f"Source: {src.text if src is not None and src.text else 'None'}")

                            # Check if this is a blocked/denied entry
                            is_blocked = False
                            if action is not None and action.text:
                                action_lower = action.text.lower()
                                # URL filtering logs typically have 'block-url', 'block-continue', 'alert', etc.
                                if 'block' in action_lower or 'deny' in action_lower or 'drop' in action_lower:
                                    is_blocked = True
                                    debug(f"Found blocked URL by action: {action.text}")

                            if is_blocked and len(blocked_url_logs) < max_logs:
                                # Try to get meaningful description
                                url_display = 'Blocked URL'
                                if url_field is not None and url_field.text:
                                    url_display = url_field.text[:50]
                                elif url_category is not None and url_category.text:
                                    url_display = f"Category: {url_category.text}"

                                url_log = {
                                    'threat': url_display,
                                    'url': url_field.text if url_field is not None and url_field.text else 'N/A',
                                    'src': src.text if src is not None and src.text else 'N/A',
                                    'dst': dst.text if dst is not None and dst.text else 'N/A',
                                    'sport': sport.text if sport is not None and sport.text else 'N/A',
                                    'dport': dport.text if dport is not None and dport.text else 'N/A',
                                    'time': receive_time.text if receive_time is not None and receive_time.text else 'N/A',
                                    'action': action.text if action is not None and action.text else 'N/A',
                                    'app': app.text if app is not None and app.text else 'N/A',
                                    'category': url_category.text if url_category is not None and url_category.text else 'N/A',
                                    'severity': 'N/A'
                                }
                                blocked_url_logs.append(url_log)
                                url_blocked += 1

                        debug(f"Total blocked URLs found: {url_blocked}")

            # Get total URL filtering count (all events, not just blocked)
            url_filtering_total = 0
            if url_response.status_code == 200:
                url_root_all = ET.fromstring(url_response.text)
                job_id_all = url_root_all.find('.//job')

                if job_id_all is not None and job_id_all.text:
                    # Already fetched above, count all entries
                    all_url_entries = url_root.findall('.//entry')
                    url_filtering_total = len(all_url_entries)
                    debug(f"Total URL filtering events: {url_filtering_total}")

            # Calculate days since last critical threat and blocked URL
            critical_last_seen = None
            medium_last_seen = None
            blocked_url_last_seen = None

            if critical_logs:
                # Get the most recent critical threat time
                latest_critical = critical_logs[0]
                if latest_critical.get('time'):
                    critical_last_seen = latest_critical['time']

            if medium_logs:
                # Get the most recent medium threat time
                latest_medium = medium_logs[0]
                if latest_medium.get('time'):
                    medium_last_seen = latest_medium['time']

            if blocked_url_logs:
                # Get the most recent blocked URL time
                latest_blocked = blocked_url_logs[0]
                if latest_blocked.get('time'):
                    blocked_url_last_seen = latest_blocked['time']

            return {
                'medium_threats': medium_count,
                'critical_threats': critical_count,
                'blocked_urls': url_blocked,
                'url_filtering_total': url_filtering_total,
                'critical_logs': critical_logs,
                'medium_logs': medium_logs,
                'blocked_url_logs': blocked_url_logs,
                'critical_last_seen': critical_last_seen,
                'medium_last_seen': medium_last_seen,
                'blocked_url_last_seen': blocked_url_last_seen
            }
        else:
            return {
                'medium_threats': 0,
                'critical_threats': 0,
                'blocked_urls': 0,
                'url_filtering_total': 0,
                'critical_logs': [],
                'medium_logs': [],
                'blocked_url_logs': [],
                'critical_last_seen': None,
                'blocked_url_last_seen': None
            }

    except Exception as e:
        return {
            'medium_threats': 0,
            'critical_threats': 0,
            'blocked_urls': 0,
            'url_filtering_total': 0,
            'critical_logs': [],
            'medium_logs': [],
            'blocked_url_logs': [],
            'critical_last_seen': None,
            'blocked_url_last_seen': None
        }


def get_traffic_logs(firewall_config, max_logs=50):
    """Fetch traffic logs from Palo Alto firewall"""
    try:
        firewall_ip, api_key, base_url = firewall_config

        # Query traffic logs
        log_query = "(subtype eq end)"
        params = {
            'type': 'log',
            'log-type': 'traffic',
            'query': log_query,
            'nlogs': str(max_logs),
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"Traffic logs query status: {response.status_code}")

        traffic_logs = []

        if response.status_code == 200:
            root = ET.fromstring(response.text)

            # Check if this is a job response (async log query)
            job_id = root.find('.//job')
            if job_id is not None and job_id.text:
                debug(f"Job ID received: {job_id.text}, fetching traffic log results...")

                # Wait briefly and fetch job results
                time.sleep(0.5)
                result_params = {
                    'type': 'log',
                    'action': 'get',
                    'job-id': job_id.text,
                    'key': api_key
                }

                result_response = api_request_get(base_url, params=result_params, verify=False, timeout=10)
                if result_response.status_code == 200:
                    root = ET.fromstring(result_response.text)

            # Find all log entries
            for entry in root.findall('.//entry'):
                time_generated = entry.get('time_generated', '')
                src = entry.find('src')
                dst = entry.find('dst')
                sport = entry.find('sport')
                dport = entry.find('dport')
                app = entry.find('app')
                category = entry.find('category')
                proto = entry.find('proto')
                action = entry.find('action')
                bytes_sent = entry.find('bytes_sent')
                bytes_received = entry.find('bytes')
                packets = entry.find('packets')
                session_end_reason = entry.find('session_end_reason')
                from_zone = entry.find('from')
                to_zone = entry.find('to')
                # Extract VLAN interface information
                inbound_if = entry.find('inbound_if')
                outbound_if = entry.find('outbound_if')

                traffic_logs.append({
                    'time': time_generated,
                    'src': src.text if src is not None else '',
                    'dst': dst.text if dst is not None else '',
                    'sport': sport.text if sport is not None else '',
                    'dport': dport.text if dport is not None else '',
                    'app': app.text if app is not None else '',
                    'category': category.text if category is not None else 'unknown',
                    'proto': proto.text if proto is not None else '',
                    'action': action.text if action is not None else '',
                    'bytes_sent': bytes_sent.text if bytes_sent is not None else '0',
                    'bytes_received': bytes_received.text if bytes_received is not None else '0',
                    'packets': packets.text if packets is not None else '0',
                    'session_end_reason': session_end_reason.text if session_end_reason is not None else '',
                    'from_zone': from_zone.text if from_zone is not None else '',
                    'to_zone': to_zone.text if to_zone is not None else '',
                    'inbound_if': inbound_if.text if inbound_if is not None else '',
                    'outbound_if': outbound_if.text if outbound_if is not None else ''
                })

            debug(f"Found {len(traffic_logs)} traffic log entries")

        return traffic_logs

    except Exception as e:
        debug(f"Error fetching traffic logs: {e}")
        return []


def get_top_applications(firewall_config, top_count=5):
    """Fetch top applications from traffic logs"""
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
    Returns VLAN ID as string or None if not found
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
    Also returns summary statistics for the dashboard

    VLAN information is extracted from inbound_if and outbound_if fields (not zones)
    """
    debug("=== get_application_statistics called ===")
    try:
        traffic_logs = get_traffic_logs(firewall_config, max_logs)
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
                'zones': list(stats['zones'])
            })

        # Sort by bytes (volume) descending by default
        result.sort(key=lambda x: x['bytes'], reverse=True)

        debug(f"Aggregated {len(result)} unique applications")

        # Return both applications list and summary statistics
        return {
            'applications': result,
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
