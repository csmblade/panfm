"""
Firewall API MAC address utilities
Handles MAC vendor lookups and virtual MAC detection
"""
from logger import debug


def is_virtual_mac(mac_address, vendor_name=None):
    """
    Determine if a MAC address is virtual/locally administered.

    Returns dict with:
    - is_virtual: bool
    - reason: string explaining why (if virtual)
    - is_randomized: bool (for privacy features like iOS/Android)
    """
    debug("is_virtual_mac called for MAC: %s, vendor: %s", mac_address, vendor_name)
    if not mac_address or mac_address == 'N/A':
        return {'is_virtual': False, 'reason': None, 'is_randomized': False}

    try:
        # Normalize MAC address
        mac_clean = mac_address.upper().replace(':', '').replace('-', '')

        if len(mac_clean) < 2:
            return {'is_virtual': False, 'reason': None, 'is_randomized': False}

        # Check locally administered bit (2nd bit of 1st octet)
        first_octet = int(mac_clean[:2], 16)
        is_locally_administered = bool(first_octet & 0x02)

        # Known virtual MAC prefixes
        virtual_prefixes = {
            '005056': 'VMware',
            '000C29': 'VMware',
            '000569': 'VMware',
            '00155D': 'Microsoft Hyper-V',
            '0242': 'Docker',
            '080027': 'VirtualBox',
            '00163E': 'Xen',
            'DEADBE': 'Test/Virtual',
            '525400': 'QEMU/KVM'
        }

        # Check for known virtual prefixes
        for prefix, vm_type in virtual_prefixes.items():
            if mac_clean.startswith(prefix):
                return {
                    'is_virtual': True,
                    'reason': f'{vm_type} virtual MAC',
                    'is_randomized': False
                }

        # Check for randomized MAC addresses (privacy features)
        # iOS (iPhone/iPad), Android, Windows 10+ use randomization
        if is_locally_administered:
            # If vendor shows Apple but MAC is locally administered = randomized iPhone/iPad/Mac
            if vendor_name and 'Apple' in vendor_name:
                return {
                    'is_virtual': True,
                    'reason': 'Apple device with randomized MAC (Privacy)',
                    'is_randomized': True
                }
            # Generic randomized MAC detection
            elif vendor_name and any(brand in vendor_name for brand in ['Samsung', 'Google', 'Xiaomi', 'OnePlus']):
                return {
                    'is_virtual': True,
                    'reason': 'Android device with randomized MAC (Privacy)',
                    'is_randomized': True
                }
            # Windows randomization
            elif vendor_name and 'Microsoft' in vendor_name:
                return {
                    'is_virtual': True,
                    'reason': 'Windows device with randomized MAC (Privacy)',
                    'is_randomized': True
                }
            else:
                # Unknown locally administered - could be iPhone without vendor match
                # Check for common randomized MAC patterns
                # Randomized MACs often have specific patterns in 2nd-3rd octets
                return {
                    'is_virtual': True,
                    'reason': 'Randomised MAC address',
                    'is_randomized': True
                }

        return {'is_virtual': False, 'reason': None, 'is_randomized': False}

    except Exception as e:
        debug(f"Error checking if MAC is virtual: {str(e)}")
        return {'is_virtual': False, 'reason': None, 'is_randomized': False}


def lookup_mac_vendor(mac_address):
    """
    Lookup vendor name for a MAC address.
    Returns vendor name or None if not found.
    """
    debug("lookup_mac_vendor called for MAC: %s", mac_address)
    if not mac_address or mac_address == 'N/A':
        return None

    try:
        from config import load_vendor_database
        vendor_db = load_vendor_database()

        if not vendor_db:
            return None

        # Normalize MAC address (remove colons/dashes, uppercase)
        mac_clean = mac_address.upper().replace(':', '').replace('-', '')

        # Try matching with progressively shorter prefixes
        # MA-L: 6 chars (00:00:0C -> 00000C)
        # MA-M: 7 chars
        # MA-S: 9 chars
        for prefix_len in [6, 7, 9]:
            if len(mac_clean) >= prefix_len:
                prefix = mac_clean[:prefix_len]
                if prefix in vendor_db:
                    return vendor_db[prefix]

        return None

    except Exception as e:
        debug(f"Error looking up MAC vendor: {str(e)}")
        return None
