"""
Firewall API device, license, and software management functions for Palo Alto firewalls
Handles DHCP leases, connected devices, and tech support file generation
"""
import xml.etree.ElementTree as ET
from datetime import datetime
from utils import api_request_get
from logger import debug, info, warning, error, exception

# Import functions from specialized modules
from firewall_api_health import check_firewall_health, get_software_updates, get_license_info
from firewall_api_mac import is_virtual_mac, lookup_mac_vendor
from firewall_api_network import get_interface_zones, get_interface_info


def get_dhcp_leases(firewall_config):
    """Fetch DHCP lease information from Palo Alto firewall

    Returns:
        dict: Dictionary mapping IP addresses to hostnames from DHCP leases
              Format: {'192.168.1.10': 'hostname1', '192.168.1.11': 'hostname2', ...}
    """
    debug("=== Starting get_dhcp_leases ===")
    dhcp_hostnames = {}

    try:
        firewall_ip, api_key, base_url = firewall_config
        debug(f"Fetching DHCP leases from: {base_url}")

        # Query for DHCP server lease information
        params = {
            'type': 'op',
            'cmd': '<show><dhcp><server><lease></lease></server></dhcp></show>',
            'key': api_key
        }

        debug("Making API request for DHCP leases")
        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        debug(f"DHCP lease API Response Status: {response.status_code}")

        if response.status_code == 200:
            debug(f"Response length: {len(response.text)} characters")
            debug(f"Response preview (first 500 chars): {response.text[:500]}")

            # Export full XML for debugging
            try:
                with open('/app/dhcp_leases_output.xml', 'w') as f:
                    f.write(response.text)
                info("Exported DHCP leases XML to /app/dhcp_leases_output.xml for debugging")
            except Exception as export_err:
                debug(f"Could not export DHCP XML: {export_err}")

            root = ET.fromstring(response.text)

            # Check for error response
            status = root.get('status')
            if status == 'error':
                error_msg = root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else 'Unknown error'
                warning(f"DHCP lease query returned error: {error_text}")
                return dhcp_hostnames

            # Parse DHCP lease entries
            # Structure: <result><interface><entry><ip><hostname>...
            lease_count = 0
            entry_count = 0

            # Use .// to find all entry elements regardless of nesting
            for entry in root.findall('.//entry'):
                entry_count += 1
                ip_elem = entry.find('ip')
                mac_elem = entry.find('mac')

                # Try to find hostname element (try multiple possible names)
                hostname_elem = None
                for possible_name in ['hostname', 'host-name', 'name']:
                    hostname_elem = entry.find(possible_name)
                    if hostname_elem is not None:
                        break

                # Debug: Show all child elements for first entry
                if entry_count == 1:
                    child_names = [child.tag for child in entry]
                    info(f"DHCP entry structure (first entry): tags={child_names}")
                    if hostname_elem is not None:
                        info(f"Found hostname element: tag='{hostname_elem.tag}', value='{hostname_elem.text}'")
                    else:
                        info("WARNING: No hostname element found in first entry!")

                if ip_elem is not None and ip_elem.text:
                    ip_address = ip_elem.text.strip()

                    # Get hostname if available
                    if hostname_elem is not None and hostname_elem.text:
                        hostname = hostname_elem.text.strip()
                        if hostname:  # Only add if hostname is not empty
                            dhcp_hostnames[ip_address] = hostname
                            lease_count += 1
                            info(f"✓ DHCP match: IP={ip_address} → Hostname={hostname} (MAC={mac_elem.text if mac_elem is not None else 'N/A'})")
                    else:
                        # Log entries without hostnames for debugging (first 3 only)
                        if entry_count <= 3:
                            info(f"✗ DHCP entry missing hostname: IP={ip_address}, MAC={mac_elem.text if mac_elem is not None else 'N/A'}")

            info(f"DHCP Summary: Processed {entry_count} total entries, found {lease_count} with hostnames")
            if lease_count > 0:
                info(f"Sample DHCP hostname mappings (first 5): {dict(list(dhcp_hostnames.items())[:5])}")
            else:
                info("No DHCP leases with hostnames found - this may be normal if DHCP is not configured on this firewall")

        else:
            warning(f"Failed to fetch DHCP leases: HTTP {response.status_code}")
            debug(f"Response text: {response.text[:500]}")

    except Exception as e:
        exception(f"Error fetching DHCP leases: {str(e)}")

    debug(f"=== Completed get_dhcp_leases with {len(dhcp_hostnames)} entries ===")
    return dhcp_hostnames


def get_connected_devices(firewall_config):
    """Fetch ARP entries from all interfaces on the firewall and enrich with DHCP hostnames"""
    debug("=== Starting get_connected_devices ===")
    try:
        firewall_ip, api_key, base_url = firewall_config
        debug(f"Using firewall API: {base_url}")

        # Get interface-to-zone mappings first
        interface_zones = get_interface_zones(firewall_config)

        # Get DHCP leases for hostname lookups
        debug("Fetching DHCP leases for hostname resolution")
        dhcp_hostnames = get_dhcp_leases(firewall_config)
        debug(f"Retrieved {len(dhcp_hostnames)} DHCP hostname mappings")

        # Load device metadata for enrichment
        debug("Loading device metadata for enrichment")
        from device_metadata import load_metadata
        device_metadata = load_metadata()
        debug(f"Loaded metadata for {len(device_metadata)} devices")

        # Query for ARP table entries
        params = {
            'type': 'op',
            'cmd': '<show><arp><entry name="all"/></arp></show>',
            'key': api_key
        }

        debug(f"Making API request for ARP entries")
        response = api_request_get(base_url, params=params, verify=False, timeout=10)

        debug(f"ARP API Response Status: {response.status_code}")

        devices = []

        if response.status_code == 200:
            debug(f"Response length: {len(response.text)} characters")
            debug(f"Response preview (first 500 chars): {response.text[:500]}")

            root = ET.fromstring(response.text)

            # Parse ARP entries
            for entry in root.findall('.//entry'):
                status = entry.find('.//status')
                ip = entry.find('.//ip')
                mac = entry.find('.//mac')
                ttl = entry.find('.//ttl')
                interface = entry.find('.//interface')
                port = entry.find('.//port')

                # Extract values with fallbacks
                mac_address = mac.text if mac is not None and mac.text else '-'
                interface_name = interface.text if interface is not None and interface.text else '-'

                # Convert TTL from seconds to minutes
                ttl_seconds = ttl.text if ttl is not None and ttl.text else None
                ttl_minutes = '-'
                if ttl_seconds and ttl_seconds.isdigit():
                    ttl_minutes = str(round(int(ttl_seconds) / 60, 1))

                # Get security zone for this interface
                zone = '-'
                if interface_name != '-':
                    # Try exact match first
                    if interface_name in interface_zones:
                        zone = interface_zones[interface_name]
                    else:
                        # Try base interface (e.g., ethernet1/1 from ethernet1/1.100)
                        base_interface = interface_name.split('.')[0]
                        if base_interface in interface_zones:
                            zone = interface_zones[base_interface]

                # Get IP address for hostname lookup
                ip_address = ip.text if ip is not None and ip.text else '-'

                # Lookup hostname from DHCP leases if available
                hostname = dhcp_hostnames.get(ip_address, '-')
                if hostname != '-':
                    debug(f"Matched hostname '{hostname}' for IP {ip_address}")

                # Store original hostname before metadata merge
                original_hostname = hostname

                device_entry = {
                    'hostname': hostname,  # From DHCP leases if available (may be overridden by custom name)
                    'ip': ip_address,
                    'mac': mac_address,
                    'vlan': '-',  # Will be extracted from interface if available
                    'interface': interface_name,
                    'ttl': ttl_minutes,
                    'status': status.text if status is not None and status.text else '-',
                    'port': port.text if port is not None and port.text else '-',
                    'zone': zone,  # Security zone
                    'vendor': None,  # Will be looked up from vendor database
                    'is_virtual': False,  # Will be determined by MAC analysis
                    'virtual_type': None,  # Type of virtual MAC if detected
                    'original_hostname': original_hostname,  # Always preserve original hostname
                    'custom_name': None,  # Will be set from metadata if available
                    'comment': None,  # Will be set from metadata if available
                    'location': None,  # Will be set from metadata if available
                    'tags': []  # Will be set from metadata if available
                }

                # Try to extract VLAN from interface name (e.g., "ethernet1/1.100" -> VLAN 100)
                if device_entry['interface'] != '-' and '.' in device_entry['interface']:
                    try:
                        vlan_id = device_entry['interface'].split('.')[-1]
                        if vlan_id.isdigit():
                            device_entry['vlan'] = vlan_id
                    except:
                        pass

                # Lookup vendor name for MAC address first
                vendor_name = lookup_mac_vendor(mac_address)
                if vendor_name:
                    device_entry['vendor'] = vendor_name

                # Check if MAC is virtual/locally administered
                # Pass vendor name to help detect randomized Apple/Android devices
                virtual_info = is_virtual_mac(mac_address, vendor_name)
                device_entry['is_virtual'] = virtual_info['is_virtual']
                device_entry['virtual_type'] = virtual_info['reason']
                device_entry['is_randomized'] = virtual_info.get('is_randomized', False)

                # Merge device metadata if available (normalize MAC to lowercase for lookup)
                normalized_mac = mac_address.lower()
                if normalized_mac in device_metadata:
                    meta = device_metadata[normalized_mac]
                    debug(f"Found metadata for MAC {normalized_mac}")

                    # Set custom name if available (display prominently, hostname as subtitle)
                    if 'name' in meta and meta['name']:
                        device_entry['custom_name'] = meta['name']
                        # Keep original hostname in device_entry['hostname'] for subtitle display

                    # Set comment if available
                    if 'comment' in meta and meta['comment']:
                        device_entry['comment'] = meta['comment']

                    # Set location if available
                    if 'location' in meta and meta['location']:
                        device_entry['location'] = meta['location']

                    # Set tags if available
                    if 'tags' in meta and meta['tags']:
                        device_entry['tags'] = meta['tags']

                devices.append(device_entry)

            debug(f"Total devices found: {len(devices)}")
            debug(f"Sample device entries (first 3): {devices[:3]}")

            # Perform reverse DNS lookups for ALL devices without hostnames
            # This includes both:
            # 1. Routed devices (no MAC address) - typically 1+ hops away
            # 2. Local devices with static IPs (have MAC but no DHCP hostname)
            devices_without_hostname = [d for d in devices if d['hostname'] == '-' and d['ip'] != '-']

            if devices_without_hostname:
                debug(f"Found {len(devices_without_hostname)} devices without hostnames, performing reverse DNS lookup")
                from utils import reverse_dns_lookup

                # Extract IPs for lookup
                ips_to_lookup = [d['ip'] for d in devices_without_hostname]
                debug(f"Looking up hostnames for IPs: {ips_to_lookup[:5]}{'...' if len(ips_to_lookup) > 5 else ''}")

                # Perform DNS lookups
                dns_results = reverse_dns_lookup(ips_to_lookup, timeout=3)

                # Update devices with DNS results (only if different from IP)
                updated_count = 0
                for device in devices_without_hostname:
                    ip = device['ip']
                    if ip in dns_results and dns_results[ip] != ip:
                        device['hostname'] = dns_results[ip]
                        updated_count += 1
                        mac_info = f" (MAC: {device['mac'][:17]})" if device['mac'] != '-' else " (routed)"
                        debug(f"✓ DNS resolved: {ip} → {dns_results[ip]}{mac_info}")
                    else:
                        debug(f"✗ No PTR record: {ip}")

                info(f"Reverse DNS lookup completed: {updated_count}/{len(devices_without_hostname)} hostnames resolved")
        else:
            error(f"Failed to fetch ARP entries. Status code: {response.status_code}")
            debug(f"Error response: {response.text[:500]}")

        return devices

    except Exception as e:
        exception(f"Error fetching connected devices: {str(e)}")
        return []


def generate_tech_support_file(firewall_config):
    """
    Generate a tech support file on the Palo Alto firewall
    This is an asynchronous operation that returns a job ID
    """
    try:
        firewall_ip, api_key, base_url = firewall_config

        debug("=== Requesting tech support file generation ===")

        # Request tech support file generation
        params = {
            'type': 'export',
            'category': 'tech-support',
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=30)
        debug(f"Tech support request status: {response.status_code}")

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            status = root.get('status')

            if status == 'success':
                # Extract job ID
                job_elem = root.find('.//job')
                if job_elem is not None and job_elem.text:
                    job_id = job_elem.text
                    debug(f"Tech support job ID: {job_id}")

                    return {
                        'status': 'success',
                        'job_id': job_id,
                        'message': 'Tech support file generation started'
                    }
                else:
                    error("No job ID found in response")
                    return {
                        'status': 'error',
                        'message': 'No job ID returned from firewall'
                    }
            else:
                msg_elem = root.find('.//msg')
                error_msg = msg_elem.text if msg_elem is not None else 'Unknown error'
                error(f"Tech support request failed: {error_msg}")
                return {
                    'status': 'error',
                    'message': error_msg
                }
        else:
            error(f"Failed to request tech support file. Status: {response.status_code}")
            return {
                'status': 'error',
                'message': f'HTTP error: {response.status_code}'
            }

    except Exception as e:
        exception(f"Error generating tech support file: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }


def check_tech_support_job_status(firewall_config, job_id):
    """
    Check the status of a tech support file generation job
    """
    try:
        firewall_ip, api_key, base_url = firewall_config

        debug(f"=== Checking tech support job status: {job_id} ===")

        params = {
            'type': 'export',
            'category': 'tech-support',
            'action': 'status',
            'job-id': job_id,
            'key': api_key
        }

        response = api_request_get(base_url, params=params, verify=False, timeout=10)
        debug(f"Status check response code: {response.status_code}")

        if response.status_code == 200:
            root = ET.fromstring(response.text)
            status = root.get('status')

            if status == 'success':
                # Check job status
                job_status_elem = root.find('.//status')
                job_progress_elem = root.find('.//progress')

                job_status = job_status_elem.text if job_status_elem is not None else 'Unknown'
                job_progress = job_progress_elem.text if job_progress_elem is not None else '0'

                debug(f"Job status: {job_status}, Progress: {job_progress}%")

                return {
                    'status': 'success',
                    'job_status': job_status,
                    'progress': job_progress,
                    'ready': job_status == 'FIN'
                }
            else:
                return {
                    'status': 'error',
                    'message': 'Failed to check job status'
                }
        else:
            return {
                'status': 'error',
                'message': f'HTTP error: {response.status_code}'
            }

    except Exception as e:
        exception(f"Error checking tech support job status: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }


def get_tech_support_file_url(firewall_config, job_id):
    """
    Get the download URL for a completed tech support file
    """
    try:
        firewall_ip, api_key, _ = firewall_config

        # Construct download URL
        download_url = f"https://{firewall_ip}/api/?type=export&category=tech-support&action=get&job-id={job_id}&key={api_key}"

        return {
            'status': 'success',
            'download_url': download_url,
            'filename': f'tech-support-{job_id}.tgz'
        }

    except Exception as e:
        exception(f"Error getting tech support file URL: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }
