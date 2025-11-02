/**
 * pages-connected-devices.js - Connected Devices Page Module
 *
 * Handles Connected Devices page functionality including:
 * - Loading and displaying ARP table data
 * - Filtering by VLAN, status, and search
 * - Sorting by multiple columns (hostname, IP, MAC, VLAN, zone, interface, age)
 * - Default sort: age (lowest to highest)
 * - Exporting to CSV and XML formats
 * - MAC vendor lookup integration
 */

// Connected Devices functionality
let allConnectedDevices = [];
let connectedDevicesMetadata = {};
let connectedDevicesSortBy = 'age'; // Default sort by age
let connectedDevicesSortDesc = false; // Default ascending (lowest to highest)
let deviceMetadataCache = {}; // Cache metadata keyed by MAC address (normalized lowercase)
let expandedRows = new Set(); // Track which rows are expanded for comments

async function loadDeviceMetadata() {
    console.log('Loading device metadata...');
    try {
        const response = await fetch('/api/device-metadata');
        const data = await response.json();

        if (data.status === 'success' && data.metadata) {
            // Normalize MAC addresses to lowercase for consistent lookup
            deviceMetadataCache = {};
            for (const [mac, metadata] of Object.entries(data.metadata)) {
                deviceMetadataCache[mac.toLowerCase()] = metadata;
            }
            console.log(`Loaded metadata for ${Object.keys(deviceMetadataCache).length} devices`);
        } else {
            console.warn('Failed to load device metadata:', data.message);
            deviceMetadataCache = {};
        }
    } catch (error) {
        console.error('Error loading device metadata:', error);
        deviceMetadataCache = {};
    }
}

async function loadConnectedDevices() {
    console.log('Loading connected devices...');
    try {
        // Load metadata first (in parallel with devices)
        const [devicesResponse, metadataResponse] = await Promise.all([
            fetch('/api/connected-devices'),
            fetch('/api/device-metadata')
        ]);

        const data = await devicesResponse.json();
        const metadataData = await metadataResponse.json();

        // Cache metadata
        if (metadataData.status === 'success' && metadataData.metadata) {
            deviceMetadataCache = {};
            for (const [mac, metadata] of Object.entries(metadataData.metadata)) {
                deviceMetadataCache[mac.toLowerCase()] = metadata;
            }
        }

        const tableDiv = document.getElementById('connectedDevicesTable');
        const errorDiv = document.getElementById('connectedDevicesErrorMessage');

        if (data.status === 'success' && data.devices.length > 0) {
            errorDiv.style.display = 'none';

            // Store devices for filtering/searching
            allConnectedDevices = data.devices;
            connectedDevicesMetadata = {
                total: data.total,
                timestamp: data.timestamp
            };

            console.log(`Loaded ${data.devices.length} connected devices`);

            // Set up event listeners
            setupConnectedDevicesEventListeners();

            // Render the table
            renderConnectedDevicesTable();
        } else {
            errorDiv.textContent = data.message || 'No connected devices found';
            errorDiv.style.display = 'block';
            tableDiv.innerHTML = '';
        }
    } catch (error) {
        console.error('Error loading connected devices:', error);
        document.getElementById('connectedDevicesErrorMessage').textContent = 'Failed to load connected devices: ' + error.message;
        document.getElementById('connectedDevicesErrorMessage').style.display = 'block';
    }
}

function setupConnectedDevicesEventListeners() {
    // Search input
    const searchInput = document.getElementById('connectedDevicesSearchInput');
    if (searchInput && !searchInput.hasAttribute('data-listener')) {
        searchInput.addEventListener('input', () => renderConnectedDevicesTable());
        searchInput.setAttribute('data-listener', 'true');
    }

    // VLAN filter
    const vlanFilter = document.getElementById('connectedDevicesVlanFilter');
    if (vlanFilter && !vlanFilter.hasAttribute('data-listener')) {
        vlanFilter.addEventListener('change', () => renderConnectedDevicesTable());
        vlanFilter.setAttribute('data-listener', 'true');
    }

    // Zone filter
    const zoneFilter = document.getElementById('connectedDevicesZoneFilter');
    if (zoneFilter && !zoneFilter.hasAttribute('data-listener')) {
        zoneFilter.addEventListener('change', () => renderConnectedDevicesTable());
        zoneFilter.setAttribute('data-listener', 'true');
    }

    // Limit selector
    const limitSelect = document.getElementById('connectedDevicesLimit');
    if (limitSelect && !limitSelect.hasAttribute('data-listener')) {
        limitSelect.addEventListener('change', () => renderConnectedDevicesTable());
        limitSelect.setAttribute('data-listener', 'true');
    }

    // Refresh button
    const refreshBtn = document.getElementById('refreshConnectedDevicesBtn');
    if (refreshBtn && !refreshBtn.hasAttribute('data-listener')) {
        refreshBtn.addEventListener('click', () => loadConnectedDevices());
        refreshBtn.setAttribute('data-listener', 'true');
    }

    // Export buttons
    const exportCSVBtn = document.getElementById('exportDevicesCSV');
    if (exportCSVBtn && !exportCSVBtn.hasAttribute('data-listener')) {
        exportCSVBtn.addEventListener('click', () => exportDevices('csv'));
        exportCSVBtn.setAttribute('data-listener', 'true');
    }

    const exportXMLBtn = document.getElementById('exportDevicesXML');
    if (exportXMLBtn && !exportXMLBtn.hasAttribute('data-listener')) {
        exportXMLBtn.addEventListener('click', () => exportDevices('xml'));
        exportXMLBtn.setAttribute('data-listener', 'true');
    }

    // Populate VLAN and Zone filters with unique values
    populateVLANFilter();
    populateZoneFilter();
}

function sortConnectedDevices(field) {
    // Toggle sort direction if clicking the same field
    if (connectedDevicesSortBy === field) {
        connectedDevicesSortDesc = !connectedDevicesSortDesc;
    } else {
        connectedDevicesSortBy = field;
        // Default direction based on field type
        if (field === 'age') {
            connectedDevicesSortDesc = false; // Ascending for age (lowest first)
        } else {
            connectedDevicesSortDesc = true; // Descending for others
        }
    }
    renderConnectedDevicesTable();
}

function populateVLANFilter() {
    const vlanFilter = document.getElementById('connectedDevicesVlanFilter');
    if (!vlanFilter) return;

    // Get unique VLANs
    const vlans = new Set();
    allConnectedDevices.forEach(device => {
        if (device.vlan && device.vlan !== '-') {
            vlans.add(device.vlan);
        }
    });

    // Clear existing options (except "All VLANs")
    while (vlanFilter.options.length > 1) {
        vlanFilter.remove(1);
    }

    // Add VLAN options sorted
    Array.from(vlans).sort((a, b) => {
        const numA = parseInt(a);
        const numB = parseInt(b);
        if (!isNaN(numA) && !isNaN(numB)) {
            return numA - numB;
        }
        return a.localeCompare(b);
    }).forEach(vlan => {
        const option = document.createElement('option');
        option.value = vlan;
        option.textContent = `VLAN ${vlan}`;
        vlanFilter.appendChild(option);
    });
}

function populateZoneFilter() {
    const zoneFilter = document.getElementById('connectedDevicesZoneFilter');
    if (!zoneFilter) return;

    // Get unique zones
    const zones = new Set();
    allConnectedDevices.forEach(device => {
        if (device.zone && device.zone !== '-') {
            zones.add(device.zone);
        }
    });

    // Clear existing options (except "All Zones")
    while (zoneFilter.options.length > 1) {
        zoneFilter.remove(1);
    }

    // Add zone options sorted alphabetically
    Array.from(zones).sort().forEach(zone => {
        const option = document.createElement('option');
        option.value = zone;
        option.textContent = zone;
        zoneFilter.appendChild(option);
    });
}

function renderConnectedDevicesTable() {
    const tableDiv = document.getElementById('connectedDevicesTable');
    const searchTerm = (document.getElementById('connectedDevicesSearchInput')?.value || '').toLowerCase().trim();
    const vlanFilter = document.getElementById('connectedDevicesVlanFilter')?.value || '';
    const zoneFilter = document.getElementById('connectedDevicesZoneFilter')?.value || '';
    const limit = parseInt(document.getElementById('connectedDevicesLimit')?.value || '50');

    // Filter devices
    let filteredDevices = allConnectedDevices.filter(device => {
        // Search filter (includes tags automatically)
        if (searchTerm) {
            // Build searchable text including tags
            const tagsText = (device.tags && Array.isArray(device.tags)) ? device.tags.join(' ') : '';
            const customNameText = device.custom_name || '';
            const commentText = device.comment || '';
            const searchableText = `${device.hostname} ${device.original_hostname || device.hostname} ${customNameText} ${device.ip} ${device.mac} ${device.interface} ${tagsText} ${commentText}`.toLowerCase();
            if (!searchableText.includes(searchTerm)) {
                return false;
            }
        }

        // VLAN filter
        if (vlanFilter && device.vlan !== vlanFilter) {
            return false;
        }

        // Zone filter
        if (zoneFilter && device.zone !== zoneFilter) {
            return false;
        }

        return true;
    });

    // Apply sorting
    filteredDevices.sort((a, b) => {
        let aVal = a[connectedDevicesSortBy];
        let bVal = b[connectedDevicesSortBy];

        // Handle missing values
        if (aVal === undefined || aVal === null) aVal = '';
        if (bVal === undefined || bVal === null) bVal = '';

        // For string fields, use locale compare
        if (typeof aVal === 'string') {
            return connectedDevicesSortDesc ?
                bVal.localeCompare(aVal) :
                aVal.localeCompare(bVal);
        }

        // For numeric fields (age, vlan)
        return connectedDevicesSortDesc ? bVal - aVal : aVal - bVal;
    });

    // Apply limit (unless "All" is selected)
    const displayDevices = limit === -1 ? filteredDevices : filteredDevices.slice(0, limit);

    // Helper function for sort indicators
    const getSortIndicator = (field) => {
        if (connectedDevicesSortBy === field) {
            return connectedDevicesSortDesc ? ' ▼' : ' ▲';
        }
        return '';
    };

    // Create table HTML
    let html = `
        <div style="background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="padding: 15px 20px; background: linear-gradient(135deg, #FA582D 0%, #FF7A55 100%); color: white; display: flex; justify-content: space-between; align-items: center; font-family: var(--font-primary);">
                <div>
                    <strong style="font-size: 1.1em;">Connected Devices</strong>
                    <span style="margin-left: 15px; opacity: 0.9; font-family: var(--font-secondary);">Showing ${displayDevices.length} of ${filteredDevices.length} devices</span>
                </div>
                <div style="font-size: 0.9em; opacity: 0.9; font-family: var(--font-secondary);">
                    Total: ${allConnectedDevices.length}
                </div>
            </div>
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-family: var(--font-secondary); font-size: 0.9em;">
                    <thead>
                        <tr style="background: #f8f9fa; border-bottom: 2px solid #dee2e6;">
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary); width: 30px;"></th>
                            <th onclick="sortConnectedDevices('hostname')" style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary); cursor: pointer; user-select: none;">Hostname${getSortIndicator('hostname')}</th>
                            <th onclick="sortConnectedDevices('ip')" style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary); cursor: pointer; user-select: none;">IP Address${getSortIndicator('ip')}</th>
                            <th onclick="sortConnectedDevices('mac')" style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary); cursor: pointer; user-select: none;">MAC Address${getSortIndicator('mac')}</th>
                            <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary);">Tags</th>
                            <th onclick="sortConnectedDevices('vlan')" style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary); cursor: pointer; user-select: none;">VLAN${getSortIndicator('vlan')}</th>
                            <th onclick="sortConnectedDevices('zone')" style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary); cursor: pointer; user-select: none;">Security Zone${getSortIndicator('zone')}</th>
                            <th onclick="sortConnectedDevices('interface')" style="padding: 12px; text-align: left; font-weight: 600; color: #333; white-space: nowrap; font-family: var(--font-primary); cursor: pointer; user-select: none;">Interface${getSortIndicator('interface')}</th>
                            <th onclick="sortConnectedDevices('age')" style="padding: 12px; text-align: left; font-weight: 600; color: #FA582D; white-space: nowrap; font-family: var(--font-primary); cursor: pointer; user-select: none;">Age (minutes)${getSortIndicator('age')}</th>
                        </tr>
                    </thead>
                    <tbody>`;

    displayDevices.forEach((device, index) => {
        const rowStyle = index % 2 === 0 ? 'background: #ffffff;' : 'background: #f8f9fa;';
        const normalizedMac = device.mac.toLowerCase();
        const isExpanded = expandedRows.has(normalizedMac);
        const hasComment = device.comment && device.comment.trim();

        // Format hostname cell - show custom name prominently, hostname as subtitle
        let hostnameCell = '';
        if (device.custom_name) {
            hostnameCell = `<div style="font-weight: 600; color: #333;">${escapeHtml(device.custom_name)}</div>`;
            const originalHostname = device.original_hostname || device.hostname || '-';
            if (originalHostname !== '-') {
                hostnameCell += `<div style="font-size: 0.85em; color: #666; margin-top: 2px;">${escapeHtml(originalHostname)}</div>`;
            }
        } else {
            hostnameCell = `<div style="color: #666;">${escapeHtml(device.hostname || '-')}</div>`;
        }

        // Format tags cell - show as colored badge chips
        let tagsCell = '';
        if (device.tags && Array.isArray(device.tags) && device.tags.length > 0) {
            tagsCell = device.tags.map(tag => {
                return `<span style="display: inline-block; background: #FA582D; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: 500; margin: 2px 2px 2px 0; white-space: nowrap;">${escapeHtml(tag)}</span>`;
            }).join('');
        } else {
            tagsCell = '<span style="color: #999;">-</span>';
        }

        // Chevron icon for expand/collapse (only shown if comment exists)
        let chevronCell = '';
        if (hasComment) {
            const chevron = isExpanded ? '▼' : '▶';
            chevronCell = `<div onclick="toggleDeviceRowExpansion('${normalizedMac}'); event.stopPropagation();" style="cursor: pointer; color: #FA582D; font-size: 0.9em; user-select: none; padding: 4px; text-align: center;" title="${isExpanded ? 'Collapse' : 'Expand'} comment">${chevron}</div>`;
        } else {
            chevronCell = '<div style="padding: 4px; text-align: center;"></div>';
        }

        // Format MAC address cell with vendor name and virtual indicator
        let macCell = `<div style="font-family: monospace; color: #333;">${device.mac}</div>`;

        // Add badge for virtual/randomized MACs on a new line
        if (device.is_virtual) {
            // Different badge for privacy/randomized MACs (iPhone, Android, Windows)
            if (device.is_randomized) {
                macCell += `<div style="margin-top: 4px;"><span style="background: #FA582D; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; font-weight: 600;" title="${device.virtual_type || 'Randomized MAC for Privacy'}">PRIVATE</span></div>`;
            } else {
                // Regular virtual MAC (VMs, containers)
                macCell += `<div style="margin-top: 4px;"><span style="background: #FA582D; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; font-weight: 600;" title="${device.virtual_type || 'Virtual/Locally Administered MAC'}">VIRTUAL</span></div>`;
            }
        }

        // Add vendor name underneath if available
        if (device.vendor) {
            macCell += `<div style="font-size: 0.85em; color: #666; margin-top: 2px;">${device.vendor}</div>`;
        }

        // Add virtual type detail if available
        if (device.is_virtual && device.virtual_type) {
            const detailColor = device.is_randomized ? '#C44520' : '#C44520';
            macCell += `<div style="font-size: 0.75em; color: ${detailColor}; margin-top: 2px;">${device.virtual_type}</div>`;
        }

        // Make row clickable to open edit modal
        const rowId = `device-row-${normalizedMac.replace(/:/g, '-')}`;
        const deviceDataAttr = escapeHtml(JSON.stringify(device).replace(/"/g, '&quot;'));
        html += `
            <tr id="${rowId}" onclick="openDeviceEditModal('${escapeHtml(device.mac)}')" data-device='${deviceDataAttr}' style="${rowStyle} border-bottom: 1px solid #dee2e6; cursor: pointer;" onmouseover="this.style.backgroundColor='#f0f0f0'" onmouseout="this.style.backgroundColor='${index % 2 === 0 ? '#ffffff' : '#f8f9fa'}'">
                <td style="padding: 8px 12px;">${chevronCell}</td>
                <td style="padding: 12px;">${hostnameCell}</td>
                <td style="padding: 12px; color: #666; font-family: monospace;">${device.ip}</td>
                <td style="padding: 12px;">${macCell}</td>
                <td style="padding: 12px;">${tagsCell}</td>
                <td style="padding: 12px; color: #666;">${device.vlan}</td>
                <td style="padding: 12px; color: #666;">${device.zone || '-'}</td>
                <td style="padding: 12px; color: #666; font-family: monospace;">${device.interface}</td>
                <td style="padding: 12px; color: #666;">${device.ttl}</td>
            </tr>`;
        
        // Add expandable row detail for comments (if comment exists)
        if (hasComment) {
            const commentRowId = `device-comment-${normalizedMac.replace(/:/g, '-')}`;
            const displayStyle = isExpanded ? '' : 'display: none;';
            html += `
            <tr id="${commentRowId}" style="${displayStyle} background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                <td colspan="9" style="padding: 12px 12px 12px 48px; color: #666; font-size: 0.9em; border-top: 1px solid #e0e0e0;">
                    <div style="font-weight: 600; color: #333; margin-bottom: 4px;">Comment:</div>
                    <div style="white-space: pre-wrap;">${escapeHtml(device.comment)}</div>
                </td>
            </tr>`;
        }
    });

    html += `
                    </tbody>
                </table>
            </div>
        </div>`;

    tableDiv.innerHTML = html;
}

function exportDevices(format) {
    const vlanFilter = document.getElementById('connectedDevicesVlanFilter')?.value || '';
    const statusFilter = document.getElementById('connectedDevicesStatusFilter')?.value || '';
    const searchTerm = (document.getElementById('connectedDevicesSearchInput')?.value || '').toLowerCase().trim();

    // Filter devices (same as table)
    let filteredDevices = allConnectedDevices.filter(device => {
        if (searchTerm) {
            const searchableText = `${device.hostname} ${device.ip} ${device.mac} ${device.interface}`.toLowerCase();
            if (!searchableText.includes(searchTerm)) return false;
        }
        if (vlanFilter && device.vlan !== vlanFilter) return false;
        if (statusFilter && device.status !== statusFilter) return false;
        return true;
    });

    if (format === 'csv') {
        exportDevicesCSV(filteredDevices);
    } else if (format === 'xml') {
        exportDevicesXML(filteredDevices);
    }
}

function exportDevicesCSV(devices) {
    const headers = ['Hostname', 'IP Address', 'MAC Address', 'VLAN', 'Security Zone', 'Interface', 'TTL (minutes)', 'Status'];
    let csv = headers.join(',') + '\n';

    devices.forEach(device => {
        const row = [
            device.hostname,
            device.ip,
            device.mac,
            device.vlan,
            device.zone || '-',
            device.interface,
            device.ttl,
            device.status
        ];
        csv += row.map(field => `"${field}"`).join(',') + '\n';
    });

    downloadFile(csv, 'connected-devices.csv', 'text/csv');
}

function exportDevicesXML(devices) {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<connected-devices>\n';

    devices.forEach(device => {
        xml += '  <device>\n';
        xml += `    <hostname>${escapeXML(device.hostname)}</hostname>\n`;
        xml += `    <ip>${escapeXML(device.ip)}</ip>\n`;
        xml += `    <mac>${escapeXML(device.mac)}</mac>\n`;
        xml += `    <vlan>${escapeXML(device.vlan)}</vlan>\n`;
        xml += `    <zone>${escapeXML(device.zone || '-')}</zone>\n`;
        xml += `    <interface>${escapeXML(device.interface)}</interface>\n`;
        xml += `    <ttl>${escapeXML(device.ttl)}</ttl>\n`;
        xml += `    <status>${escapeXML(device.status)}</status>\n`;
        xml += '  </device>\n';
    });

    xml += '</connected-devices>';

    downloadFile(xml, 'connected-devices.xml', 'application/xml');
}

function escapeXML(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// Helper function to escape HTML
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Toggle row expansion for comments
function toggleDeviceRowExpansion(mac) {
    const normalizedMac = mac.toLowerCase();
    if (expandedRows.has(normalizedMac)) {
        expandedRows.delete(normalizedMac);
    } else {
        expandedRows.add(normalizedMac);
    }
    renderConnectedDevicesTable();
}

// Open edit modal for device
function openDeviceEditModal(mac) {
    // Find the device data from the row
    const normalizedMac = mac.toLowerCase();
    const device = allConnectedDevices.find(d => d.mac.toLowerCase() === normalizedMac);
    
    if (!device) {
        console.error('Device not found:', mac);
        return;
    }

    // Get existing metadata
    const metadata = deviceMetadataCache[normalizedMac] || {};
    const currentName = device.custom_name || metadata.name || '';
    const currentComment = device.comment || metadata.comment || '';
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
    document.getElementById('deviceMetadataComment').value = currentComment;
    
    // Populate tags input
    const tagsInput = document.getElementById('deviceMetadataTags');
    tagsInput.value = currentTags.join(', ');

    // Show modal
    modal.style.display = 'flex';

    // Store current MAC for save handler
    modal.dataset.currentMac = mac;
}

// Save device metadata via API
async function saveDeviceMetadata(mac, name, comment, tags) {
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
                comment: comment || null,
                tags: tags || []
            })
        });

        const data = await response.json();
        
        if (data.status === 'success') {
            // Update cache
            const normalizedMac = mac.toLowerCase();
            if (name || comment || (tags && tags.length > 0)) {
                deviceMetadataCache[normalizedMac] = data.metadata;
            } else {
                delete deviceMetadataCache[normalizedMac];
            }
            
            // Reload devices to refresh display
            await loadConnectedDevices();
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
