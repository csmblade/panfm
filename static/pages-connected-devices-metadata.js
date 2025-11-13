/**
 * PANfm - Connected Devices Metadata Module
 *
 * Purpose: Device metadata modal, autocomplete UI, and API operations
 * Part of: Phase 6 JavaScript Refactoring (v1.8.2)
 *
 * Dependencies:
 * - pages-connected-devices-core.js (for state access and reload functions)
 *
 * Exports (via window):
 * - openDeviceEditModal(mac) - Open modal for device editing
 * - saveDeviceMetadata(mac, name, location, comment, tags) - Save metadata
 * - exportDeviceMetadata() - Export metadata backup
 * - importDeviceMetadata() - Import metadata backup
 */

// ============================================================================
// MODAL MANAGEMENT
// ============================================================================

/**
 * Open edit modal for device metadata
 *
 * @param {string} mac - MAC address of device to edit
 */
function openDeviceEditModal(mac) {
    // Find the device data from the row
    const normalizedMac = mac.toLowerCase();
    const device = window.ConnectedDevices.allDevices.find(d => d.mac.toLowerCase() === normalizedMac);

    if (!device) {
        console.error('Device not found:', mac);
        return;
    }

    // Get existing metadata
    const metadataCache = window.ConnectedDevices.metadataCache;
    const metadata = metadataCache[normalizedMac] || {};
    const currentName = device.custom_name || metadata.name || '';
    const currentComment = device.comment || metadata.comment || '';
    const currentLocation = device.location || metadata.location || '';
    const currentTags = device.tags || metadata.tags || [];

    // Populate modal fields
    const modal = document.getElementById('deviceMetadataModal');
    if (!modal) {
        console.error('Modal not found');
        return;
    }

    document.getElementById('deviceMetadataMac').textContent = device.mac;
    document.getElementById('deviceMetadataIp').textContent = device.ip;
    document.getElementById('deviceMetadataName').value = currentName;
    document.getElementById('deviceMetadataLocation').value = currentLocation;
    document.getElementById('deviceMetadataComment').value = currentComment;

    // Populate tags input
    const tagsInput = document.getElementById('deviceMetadataTags');
    tagsInput.value = currentTags.join(', ');

    // Show modal
    modal.style.display = 'flex';

    // Store current MAC for save handler
    modal.dataset.currentMac = mac;

    // Set up tag autocomplete
    setupTagAutocomplete();

    // Set up location autocomplete
    setupLocationAutocomplete();
}

// ============================================================================
// TAG AUTOCOMPLETE
// ============================================================================

/**
 * Set up tag autocomplete for tags input field
 * Supports multi-tag input with comma separation
 */
function setupTagAutocomplete() {
    const tagsInput = document.getElementById('deviceMetadataTags');
    const dropdown = document.getElementById('tagAutocompleteDropdown');

    if (!tagsInput || !dropdown) {
        return;
    }

    // Clear existing event listeners by removing and re-adding
    const newInput = tagsInput.cloneNode(true);
    tagsInput.parentNode.replaceChild(newInput, tagsInput);
    const newDropdown = dropdown.cloneNode(true);
    dropdown.parentNode.replaceChild(newDropdown, dropdown);

    const input = document.getElementById('deviceMetadataTags');
    const suggestions = document.getElementById('tagAutocompleteDropdown');

    let hideTimeout = null;

    input.addEventListener('input', function() {
        const value = this.value;
        const cursorPos = this.selectionStart;

        // Get the current word being typed (everything after the last comma)
        const lastCommaIndex = value.lastIndexOf(',', cursorPos - 1);
        const currentWord = value.substring(lastCommaIndex + 1, cursorPos).trim();

        // Clear hide timeout
        if (hideTimeout) {
            clearTimeout(hideTimeout);
        }

        // Filter tags based on current word
        if (currentWord.length > 0) {
            const allTags = window.ConnectedDevices.tagsCache;
            const matches = allTags.filter(tag =>
                tag.toLowerCase().includes(currentWord.toLowerCase()) &&
                !value.toLowerCase().includes(tag.toLowerCase() + ',') &&
                !value.toLowerCase().endsWith(tag.toLowerCase())
            ).slice(0, 10); // Limit to 10 suggestions

            if (matches.length > 0) {
                suggestions.innerHTML = '';
                matches.forEach(tag => {
                    const item = document.createElement('div');
                    item.className = 'tag-suggestion';
                    item.style.cssText = 'padding: 8px 12px; cursor: pointer; border-bottom: 1px solid #e0e0e0; transition: background 0.2s;';
                    item.textContent = tag;
                    item.onmouseover = () => item.style.background = '#f0f0f0';
                    item.onmouseout = () => item.style.background = 'white';
                    item.onclick = () => {
                        selectTag(tag, input);
                    };
                    suggestions.appendChild(item);
                });
                suggestions.style.display = 'block';
            } else {
                suggestions.style.display = 'none';
            }
        } else {
            suggestions.style.display = 'none';
        }
    });

    input.addEventListener('blur', function() {
        // Delay hiding to allow clicks on suggestions
        hideTimeout = setTimeout(() => {
            suggestions.style.display = 'none';
        }, 200);
    });

    input.addEventListener('focus', function() {
        if (hideTimeout) {
            clearTimeout(hideTimeout);
        }
    });

    // Prevent dropdown from closing when clicking on it
    suggestions.addEventListener('mousedown', function(e) {
        e.preventDefault();
    });
}

/**
 * Select a tag from autocomplete and add it to input
 *
 * @param {string} tag - Tag to insert
 * @param {HTMLElement} input - Input element
 */
function selectTag(tag, input) {
    const value = input.value;
    const cursorPos = input.selectionStart;

    // Find the current word being typed
    const lastCommaIndex = value.lastIndexOf(',', cursorPos - 1);
    const beforeWord = value.substring(0, lastCommaIndex + 1);
    const afterWord = value.substring(cursorPos);

    // Insert the selected tag
    const newValue = beforeWord + (beforeWord.trim() ? ', ' : '') + tag + (afterWord.trim() ? ', ' : '') + afterWord;
    input.value = newValue;

    // Position cursor after the inserted tag
    const newCursorPos = beforeWord.length + (beforeWord.trim() ? 2 : 0) + tag.length;
    input.setSelectionRange(newCursorPos, newCursorPos);
    input.focus();

    // Hide dropdown
    document.getElementById('tagAutocompleteDropdown').style.display = 'none';

    // Trigger input event to update any dependent logic
    input.dispatchEvent(new Event('input'));
}

// ============================================================================
// LOCATION AUTOCOMPLETE
// ============================================================================

/**
 * Setup location autocomplete for location input field
 */
function setupLocationAutocomplete() {
    const input = document.getElementById('deviceMetadataLocation');
    const dropdown = document.getElementById('locationAutocompleteDropdown');

    if (!input || !dropdown) {
        console.warn('Location autocomplete elements not found');
        return;
    }

    let hideTimeout = null;

    input.addEventListener('input', function() {
        const value = this.value.toLowerCase().trim();

        // Clear hide timeout
        if (hideTimeout) {
            clearTimeout(hideTimeout);
        }

        // Filter locations based on current input
        if (value.length > 0) {
            const allLocations = window.ConnectedDevices.locationsCache;
            const matches = allLocations.filter(location =>
                location.toLowerCase().includes(value) &&
                location.toLowerCase() !== value
            ).slice(0, 10); // Limit to 10 suggestions

            if (matches.length > 0) {
                dropdown.innerHTML = '';
                matches.forEach(location => {
                    const item = document.createElement('div');
                    item.className = 'location-suggestion';
                    item.style.cssText = 'padding: 8px 12px; cursor: pointer; border-bottom: 1px solid #e0e0e0; transition: background 0.2s;';
                    item.textContent = location;
                    item.onmouseover = () => item.style.background = '#f0f0f0';
                    item.onmouseout = () => item.style.background = 'white';
                    item.onclick = () => {
                        input.value = location;
                        dropdown.style.display = 'none';
                        input.focus();
                    };
                    dropdown.appendChild(item);
                });
                dropdown.style.display = 'block';
            } else {
                dropdown.style.display = 'none';
            }
        } else {
            dropdown.style.display = 'none';
        }
    });

    input.addEventListener('blur', function() {
        // Delay hiding to allow clicks on suggestions
        hideTimeout = setTimeout(() => {
            dropdown.style.display = 'none';
        }, 200);
    });

    input.addEventListener('focus', function() {
        if (hideTimeout) {
            clearTimeout(hideTimeout);
        }
        // Show suggestions if there's a value
        const value = this.value.toLowerCase().trim();
        if (value.length > 0) {
            const allLocations = window.ConnectedDevices.locationsCache;
            const matches = allLocations.filter(location =>
                location.toLowerCase().includes(value) &&
                location.toLowerCase() !== value
            ).slice(0, 10);

            if (matches.length > 0) {
                dropdown.innerHTML = '';
                matches.forEach(location => {
                    const item = document.createElement('div');
                    item.className = 'location-suggestion';
                    item.style.cssText = 'padding: 8px 12px; cursor: pointer; border-bottom: 1px solid #e0e0e0; transition: background 0.2s;';
                    item.textContent = location;
                    item.onmouseover = () => item.style.background = '#f0f0f0';
                    item.onmouseout = () => item.style.background = 'white';
                    item.onclick = () => {
                        input.value = location;
                        dropdown.style.display = 'none';
                        input.focus();
                    };
                    dropdown.appendChild(item);
                });
                dropdown.style.display = 'block';
            }
        }
    });

    // Prevent dropdown from closing when clicking on it
    dropdown.addEventListener('mousedown', function(e) {
        e.preventDefault();
    });

    // Hide dropdown initially
    dropdown.style.display = 'none';
}

// ============================================================================
// METADATA API OPERATIONS
// ============================================================================

/**
 * Save device metadata via API
 *
 * @param {string} mac - MAC address
 * @param {string} name - Custom device name
 * @param {string} location - Device location
 * @param {string} comment - Device comment
 * @param {Array} tags - Array of tags
 * @returns {Promise<boolean>} - Success status
 */
async function saveDeviceMetadata(mac, name, location, comment, tags) {
    try {
        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (!csrfToken) {
            alert('CSRF token not found. Please refresh the page.');
            return false;
        }

        const response = await fetch('/api/device-metadata', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                mac: mac,
                name: name || null,
                location: location || null,
                comment: comment || null,
                tags: tags || []
            })
        });

        const data = await response.json();

        if (data.status === 'success') {
            console.log('Metadata saved successfully, updating cache and reloading devices...');

            // Update cache
            const normalizedMac = mac.toLowerCase();
            const metadataCache = window.ConnectedDevices.metadataCache;
            if (name || location || comment || (tags && tags.length > 0)) {
                metadataCache[normalizedMac] = data.metadata;
                console.log('Updated metadata cache for', normalizedMac, ':', data.metadata);
            } else {
                delete metadataCache[normalizedMac];
                console.log('Removed metadata cache for', normalizedMac);
            }

            // Reload devices to refresh display
            console.log('Calling window.loadConnectedDevices()...');
            if (typeof window.loadConnectedDevices === 'function') {
                await window.loadConnectedDevices();
                console.log('Device list reloaded successfully');
            } else {
                console.error('window.loadConnectedDevices is not a function!', typeof window.loadConnectedDevices);
            }

            return true;
        } else {
            alert('Failed to save metadata: ' + (data.message || 'Unknown error'));
            return false;
        }
    } catch (error) {
        console.error('Error saving device metadata:', error);
        alert('Error saving metadata: ' + error.message);
        return false;
    }
}

/**
 * Export device metadata as JSON backup
 */
async function exportDeviceMetadata() {
    try {
        const response = await fetch('/api/device-metadata/export');

        if (!response.ok) {
            const errorData = await response.json();
            alert('Failed to export metadata: ' + (errorData.message || 'Unknown error'));
            return;
        }

        // Get filename from Content-Disposition header or use default
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = 'device_metadata_backup.json';
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (filenameMatch && filenameMatch[1]) {
                filename = filenameMatch[1].replace(/['"]/g, '');
            }
        }

        // Download file
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        console.log('Metadata exported successfully');
    } catch (error) {
        console.error('Error exporting metadata:', error);
        alert('Error exporting metadata: ' + error.message);
    }
}

/**
 * Import device metadata from JSON backup file
 */
async function importDeviceMetadata() {
    const fileInput = document.getElementById('importMetadataFile');
    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        return;
    }

    const file = fileInput.files[0];

    if (!file.name.endsWith('.json')) {
        alert('File must be a JSON file');
        fileInput.value = '';
        return;
    }

    // Confirm import
    const confirmMessage = `Are you sure you want to import metadata from "${file.name}"?\n\nThis will merge the imported metadata with existing metadata. Devices with the same MAC address will be updated.`;
    if (!confirm(confirmMessage)) {
        fileInput.value = '';
        return;
    }

    try {
        const formData = new FormData();
        formData.append('file', file);

        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

        const response = await fetch('/api/device-metadata/import', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            },
            body: formData
        });

        const data = await response.json();

        if (data.status === 'success') {
            alert(`Metadata imported successfully!\n\n${data.message}\n\nReloading devices...`);

            // Clear file input
            fileInput.value = '';

            // Reload devices and metadata
            await window.loadConnectedDevices();
        } else {
            alert('Failed to import metadata: ' + (data.message || 'Unknown error'));
            fileInput.value = '';
        }
    } catch (error) {
        console.error('Error importing metadata:', error);
        alert('Error importing metadata: ' + error.message);
        fileInput.value = '';
    }
}

// ============================================================================
// EXPORTS TO GLOBAL NAMESPACE
// ============================================================================

// Export functions to window for inline event handlers and module access
window.openDeviceEditModal = openDeviceEditModal;
window.saveDeviceMetadata = saveDeviceMetadata;
window.exportDeviceMetadata = exportDeviceMetadata;
window.importDeviceMetadata = importDeviceMetadata;
