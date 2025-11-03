"""
Device Metadata Manager for PANfm
Manages custom names, comments, and tags for connected devices keyed by MAC address.
Metadata is stored encrypted at rest in device_metadata.json.
"""
import os
import json
from config import METADATA_FILE
from encryption import encrypt_dict, decrypt_dict
from logger import debug, info, warning, error, exception

# Global cache for metadata (loaded at startup, updated on changes)
_metadata_cache = None
_cache_loaded = False


def init_metadata_file():
    """
    Initialize device_metadata.json with empty structure if it doesn't exist.
    Sets file permissions to 600 (owner read/write only) for security.
    
    Returns:
        bool: True on success, False on error
    """
    debug("Checking if metadata file exists")
    if not os.path.exists(METADATA_FILE):
        debug("Metadata file not found, creating with empty structure")
        empty_data = {}
        
        try:
            # Encrypt empty structure (following encryption pattern)
            encrypted_data = encrypt_dict(empty_data)
            with open(METADATA_FILE, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
            
            # Set file permissions to 600
            os.chmod(METADATA_FILE, 0o600)
            
            info("Created empty device metadata file")
            return True
        except Exception as e:
            error(f"Failed to create metadata file: {str(e)}")
            return False
    else:
        debug("Metadata file exists")
        return True


def load_metadata(use_cache=True):
    """
    Load and decrypt device metadata from JSON file.
    Uses global cache if available and use_cache=True to avoid repeated file I/O.
    
    Args:
        use_cache: If True, returns cached metadata if available. If False, forces reload from disk.
    
    Returns:
        dict: Metadata dictionary keyed by MAC address (normalized to lowercase)
              Returns empty dict on error
    """
    global _metadata_cache, _cache_loaded
    
    # Return cached data if available and cache is enabled
    if use_cache and _cache_loaded and _metadata_cache is not None:
        debug("Returning cached device metadata")
        return _metadata_cache.copy()
    
    debug("Loading device metadata from disk")
    try:
        # Check if file exists
        if not os.path.exists(METADATA_FILE):
            debug("Metadata file does not exist, initializing")
            init_metadata_file()
            return {}
        
        # Check if file is empty
        if os.path.getsize(METADATA_FILE) == 0:
            debug("Metadata file is empty, initializing")
            init_metadata_file()
            return {}
        
        # Load data
        with open(METADATA_FILE, 'r') as f:
            data = json.load(f)
        
        # Try to decrypt
        try:
            decrypted_data = decrypt_dict(data)
            debug("Successfully loaded and decrypted metadata")
            
            # Normalize MAC addresses to lowercase for consistent lookup
            normalized_data = {}
            for mac, metadata in decrypted_data.items():
                normalized_mac = mac.lower()
                normalized_data[normalized_mac] = metadata
            
            # Update global cache
            _metadata_cache = normalized_data.copy()
            _cache_loaded = True
            
            debug(f"Loaded metadata for {len(normalized_data)} devices")
            return normalized_data
        except Exception as decrypt_error:
            # Decryption failed - check if it's unencrypted data
            debug(f"Decryption failed: {decrypt_error}")
            debug("Checking if metadata file is unencrypted...")
            
            # If it has the expected structure (MAC addresses as keys), it's unencrypted
            if isinstance(data, dict) and all(isinstance(k, str) for k in data.keys()):
                debug("Metadata file appears to be unencrypted, encrypting and saving...")
                # Encrypt and save
                encrypted_data = encrypt_dict(data)
                with open(METADATA_FILE, 'w') as f:
                    json.dump(encrypted_data, f, indent=2)
                os.chmod(METADATA_FILE, 0o600)
                debug("Metadata file encrypted and saved")
                
                # Normalize MAC addresses
                normalized_data = {}
                for mac, metadata in data.items():
                    normalized_mac = mac.lower()
                    normalized_data[normalized_mac] = metadata
                
                # Update global cache
                _metadata_cache = normalized_data.copy()
                _cache_loaded = True
                
                return normalized_data
            else:
                # Unknown format
                raise decrypt_error
    except (json.JSONDecodeError, ValueError) as e:
        # JSON parsing error - file is corrupted
        error(f"Metadata file is corrupted: {str(e)}")
        debug("Reinitializing metadata file due to corruption")
        init_metadata_file()
        return {}
    except Exception as e:
        exception(f"Failed to load metadata: {str(e)}")
        return {}


def save_metadata(metadata_dict):
    """
    Encrypt and save device metadata to JSON file.
    MAC addresses are normalized to lowercase before saving.
    Updates global cache after successful save.
    
    Args:
        metadata_dict (dict): Metadata dictionary keyed by MAC address
    
    Returns:
        bool: True on success, False on error
    """
    global _metadata_cache, _cache_loaded
    
    debug("Saving device metadata")
    try:
        # Normalize MAC addresses to lowercase
        normalized_dict = {}
        for mac, metadata in metadata_dict.items():
            normalized_mac = mac.lower()
            normalized_dict[normalized_mac] = metadata
        
        # Encrypt and save
        encrypted_data = encrypt_dict(normalized_dict)
        with open(METADATA_FILE, 'w') as f:
            json.dump(encrypted_data, f, indent=2)
            f.flush()  # Ensure data is written to disk
            os.fsync(f.fileno())  # Force OS to write to disk
        
        # Set file permissions to 600
        os.chmod(METADATA_FILE, 0o600)
        
        # Update global cache
        _metadata_cache = normalized_dict.copy()
        _cache_loaded = True
        
        debug(f"Successfully saved metadata for {len(normalized_dict)} devices")
        return True
    except Exception as e:
        exception(f"Failed to save metadata: {str(e)}")
        return False


def get_device_metadata(mac_address):
    """
    Get metadata for a specific MAC address.
    
    Args:
        mac_address (str): MAC address (will be normalized to lowercase)
    
    Returns:
        dict: Metadata dict with 'name', 'comment', 'tags' keys, or None if not found
    """
    debug(f"Getting metadata for MAC: {mac_address}")
    metadata = load_metadata()
    normalized_mac = mac_address.lower()
    
    result = metadata.get(normalized_mac)
    if result:
        debug(f"Found metadata for MAC {normalized_mac}")
    else:
        debug(f"No metadata found for MAC {normalized_mac}")
    
    return result


def update_device_metadata(mac_address, name=None, comment=None, tags=None, location=None):
    """
    Update metadata for a specific MAC address.
    Only provided fields are updated; others remain unchanged.
    
    Args:
        mac_address (str): MAC address (will be normalized to lowercase)
        name (str, optional): Custom device name
        comment (str, optional): Device comment
        tags (list, optional): List of tag strings
        location (str, optional): Device location/room/building
    
    Returns:
        bool: True on success, False on error
    """
    debug(f"Updating metadata for MAC: {mac_address}")
    metadata = load_metadata()
    normalized_mac = mac_address.lower()
    
    # Get existing metadata or create new entry
    if normalized_mac not in metadata:
        metadata[normalized_mac] = {}
    
    # Update only provided fields
    if name is not None:
        metadata[normalized_mac]['name'] = name
        debug(f"Updated name to: {name}")
    
    if comment is not None:
        metadata[normalized_mac]['comment'] = comment
        debug(f"Updated comment")
    
    if location is not None:
        metadata[normalized_mac]['location'] = location
        debug(f"Updated location to: {location}")
    
    if tags is not None:
        # Ensure tags is a list and filter out empty strings
        if isinstance(tags, list):
            metadata[normalized_mac]['tags'] = [tag.strip() for tag in tags if tag and tag.strip()]
        else:
            metadata[normalized_mac]['tags'] = []
        debug(f"Updated tags: {metadata[normalized_mac]['tags']}")
    
    return save_metadata(metadata)


def delete_device_metadata(mac_address):
    """
    Remove metadata entry for a specific MAC address.
    
    Args:
        mac_address (str): MAC address (will be normalized to lowercase)
    
    Returns:
        bool: True on success, False on error
    """
    debug(f"Deleting metadata for MAC: {mac_address}")
    metadata = load_metadata()
    normalized_mac = mac_address.lower()
    
    if normalized_mac in metadata:
        del metadata[normalized_mac]
        debug(f"Deleted metadata for MAC {normalized_mac}")
        return save_metadata(metadata)
    else:
        debug(f"No metadata found for MAC {normalized_mac}, nothing to delete")
        return True


def get_all_tags():
    """
    Get a list of all unique tags across all devices.
    Uses cached metadata if available.
    
    Returns:
        list: Sorted list of unique tag strings
    """
    debug("Getting all unique tags")
    metadata = load_metadata(use_cache=True)  # Use cache for performance
    all_tags = set()
    
    for mac, device_meta in metadata.items():
        if 'tags' in device_meta and isinstance(device_meta['tags'], list):
            all_tags.update(device_meta['tags'])
    
    unique_tags = sorted(list(all_tags))
    debug(f"Found {len(unique_tags)} unique tags")
    return unique_tags

def get_all_locations():
    """
    Get a list of all unique locations across all devices.
    Uses cached metadata if available.
    
    Returns:
        list: Sorted list of unique location strings
    """
    debug("Getting all unique locations")
    metadata = load_metadata(use_cache=True)  # Use cache for performance
    all_locations = set()
    
    for mac, device_meta in metadata.items():
        if 'location' in device_meta and device_meta['location']:
            location = device_meta['location'].strip()
            if location:
                all_locations.add(location)
    
    unique_locations = sorted(list(all_locations))
    debug(f"Found {len(unique_locations)} unique locations")
    return unique_locations

def reload_metadata_cache():
    """
    Force reload metadata from disk, updating the global cache.
    Call this when you know metadata has been modified externally.
    
    Returns:
        dict: Reloaded metadata dictionary
    """
    global _cache_loaded
    _cache_loaded = False  # Force reload
    return load_metadata(use_cache=False)

def import_metadata(metadata_dict):
    """
    Import metadata dictionary, merging with existing metadata.
    This is used for importing backup metadata files.
    Merges imported data with existing data (imported data takes precedence).
    
    Args:
        metadata_dict (dict): Metadata dictionary keyed by MAC address (may be unnormalized)
    
    Returns:
        bool: True on success, False on error
    """
    debug("Importing device metadata")
    try:
        # Load existing metadata
        existing_metadata = load_metadata(use_cache=False)  # Force reload to get latest
        
        # Normalize MAC addresses in imported data
        normalized_import = {}
        for mac, metadata in metadata_dict.items():
            normalized_mac = mac.lower()
            normalized_import[normalized_mac] = metadata
        
        # Merge: imported data takes precedence over existing
        merged_metadata = existing_metadata.copy()
        merged_metadata.update(normalized_import)
        
        # Save merged metadata
        return save_metadata(merged_metadata)
    except Exception as e:
        exception(f"Failed to import metadata: {str(e)}")
        return False

