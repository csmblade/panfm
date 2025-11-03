/**
 * pages-applications.js - Applications Page Module
 *
 * Handles Applications page functionality including:
 * - Loading and displaying application traffic statistics
 * - Summary statistics tiles and category chart
 * - Filtering by VLAN, category, and search
 * - Sorting by multiple columns
 * - Exporting to CSV and JSON formats
 * - Application details and destinations modals
 */

// ============================================================================
// Applications Page Functions
// ============================================================================

let allApplications = [];
let applicationsSortBy = 'bytes'; // Default sort by volume
let applicationsSortDesc = true;
let categoryChart = null;
let servicePortDb = {}; // Service port database for port-to-service name lookups

async function loadApplications() {
    console.log('=== loadApplications called ===');
    try {
        // OPTIMIZATION: Reduced from 5000 to 1000 logs for faster loading
        const response = await fetch('/api/applications?max_logs=1000');
        const data = await response.json();

        console.log('Applications API response:', data);

        if (data.status === 'success') {
            allApplications = data.applications || [];

            // Update summary statistics tiles
            const summary = data.summary || {};
            document.getElementById('appStatTotalApps').textContent = summary.total_applications || 0;
            document.getElementById('appStatTotalVolume').textContent = formatBytesHuman(summary.total_bytes || 0);
            document.getElementById('appStatVlans').textContent = summary.vlans_detected || 0;
            document.getElementById('appStatZones').textContent = summary.zones_detected || 0;

            // Populate filter dropdowns
            populateApplicationFilters();

            // Render Traffic by Category chart
            renderCategoryChart();

            renderApplicationsTable();
            document.getElementById('applicationsCount').textContent = `Total: ${allApplications.length} applications`;
        } else {
            showApplicationsError(data.message || 'Failed to load applications');
        }
    } catch (error) {
        console.error('Error loading applications:', error);
        showApplicationsError('Connection error: ' + error.message);
    }

    // Load service port database
    await loadServicePortDatabase();
}

async function loadServicePortDatabase() {
    console.log('Loading service port database...');
    try {
        const response = await fetch('/api/service-port-db/info');
        const data = await response.json();

        if (data.status === 'success' && data.info.exists) {
            // Database exists, load it
            const dbResponse = await fetch('/api/service-port-db/data');
            const dbData = await dbResponse.json();

            if (dbData.status === 'success') {
                servicePortDb = dbData.data || {};
                console.log(`Service port database loaded: ${Object.keys(servicePortDb).length} ports`);
            } else {
                console.log('Service port database not available');
                servicePortDb = {};
            }
        } else {
            console.log('Service port database not uploaded yet');
            servicePortDb = {};
        }
    } catch (error) {
        console.error('Error loading service port database:', error);
        servicePortDb = {};
    }
}

function getServiceName(port, protocol = 'tcp') {
    /**
     * Lookup service name and description for a given port and protocol
     * Returns object with {name, description} or null if not found
     */
    if (!servicePortDb || !port) return null;

    const portKey = String(port);
    if (servicePortDb[portKey] && servicePortDb[portKey][protocol.toLowerCase()]) {
        return servicePortDb[portKey][protocol.toLowerCase()];
    }
    return null;
}

function formatPortDisplay(port) {
    /**
     * Format port number with service name if available
     * Returns HTML string with port and service name
     */
    if (!port || port === 'N/A') return 'Port: N/A';

    // Try to get service name for TCP first (most common)
    let serviceInfo = getServiceName(port, 'tcp');
    let protocol = 'tcp';

    // If not found for TCP, try UDP
    if (!serviceInfo) {
        serviceInfo = getServiceName(port, 'udp');
        protocol = 'udp';
    }

    if (serviceInfo && serviceInfo.name) {
        // Format: "Port: 443 (https)"  with description as title
        const serviceName = serviceInfo.name;
        const description = serviceInfo.description || '';
        return `Port: ${port} <span style="color: #FA582D; font-weight: 600;" title="${description}">(${serviceName})</span>`;
    }

    // No service name found - just show port
    return `Port: ${port}`;
}

function populateApplicationFilters() {
    // Get unique VLANs, Zones, and Categories
    const vlans = new Set();
    const zones = new Set();
    const categories = new Set();

    allApplications.forEach(app => {
        if (app.vlans && app.vlans.length > 0) {
            app.vlans.forEach(vlan => vlans.add(vlan));
        }
        if (app.zones && app.zones.length > 0) {
            app.zones.forEach(zone => zones.add(zone));
        }
        if (app.category) {
            categories.add(app.category);
        }
    });

    // Populate VLAN filter
    const vlanFilter = document.getElementById('applicationsVlanFilter');
    const currentVlan = vlanFilter.value;
    vlanFilter.innerHTML = '<option value="">All VLANs</option>';
    Array.from(vlans).sort().forEach(vlan => {
        const option = document.createElement('option');
        option.value = vlan;
        option.textContent = vlan;
        vlanFilter.appendChild(option);
    });
    vlanFilter.value = currentVlan;

    // Populate Security Zone filter
    const zoneFilter = document.getElementById('applicationsZoneFilter');
    const currentZone = zoneFilter.value;
    zoneFilter.innerHTML = '<option value="">All Zones</option>';
    Array.from(zones).sort().forEach(zone => {
        const option = document.createElement('option');
        option.value = zone;
        option.textContent = zone;
        zoneFilter.appendChild(option);
    });
    zoneFilter.value = currentZone;

    // Populate Category filter
    const categoryFilter = document.getElementById('applicationsCategoryFilter');
    const currentCategory = categoryFilter.value;
    categoryFilter.innerHTML = '<option value="">All Categories</option>';
    Array.from(categories).sort().forEach(category => {
        const option = document.createElement('option');
        option.value = category;
        option.textContent = category;
        categoryFilter.appendChild(option);
    });
    categoryFilter.value = currentCategory;
}

function renderCategoryChart() {
    // Aggregate traffic by category
    const categoryData = {};
    allApplications.forEach(app => {
        const category = app.category || 'unknown';
        if (!categoryData[category]) {
            categoryData[category] = 0;
        }
        categoryData[category] += app.bytes;
    });

    // Convert to sorted array (top 10 categories by volume)
    const sortedCategories = Object.entries(categoryData)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    const labels = sortedCategories.map(([category]) => category);
    const dataValues = sortedCategories.map(([, bytes]) => bytes / (1024 * 1024)); // Convert to MB

    // Destroy previous chart if it exists
    if (categoryChart) {
        categoryChart.destroy();
    }

    // Create chart
    const ctx = document.getElementById('trafficByCategoryChart');
    categoryChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Traffic Volume (MB)',
                data: dataValues,
                backgroundColor: 'rgba(250, 88, 45, 0.8)',
                borderColor: '#FA582D',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y', // Horizontal bar chart
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return formatBytesHuman(context.raw * 1024 * 1024);
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return value.toFixed(0) + ' MB';
                        }
                    },
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                y: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

function sortApplications(field) {
    // Toggle sort direction if clicking the same field
    if (applicationsSortBy === field) {
        applicationsSortDesc = !applicationsSortDesc;
    } else {
        applicationsSortBy = field;
        applicationsSortDesc = true; // Default to descending for new field
    }
    renderApplicationsTable();
}

function renderApplicationsTable() {
    const container = document.getElementById('applicationsTable');
    const searchTerm = document.getElementById('applicationsSearchInput').value.toLowerCase();
    const limit = parseInt(document.getElementById('applicationsLimit').value);
    const vlanFilter = document.getElementById('applicationsVlanFilter').value;
    const zoneFilter = document.getElementById('applicationsZoneFilter').value;
    const categoryFilter = document.getElementById('applicationsCategoryFilter').value;

    // Filter applications
    let filtered = allApplications.filter(app => {
        // Search filter
        if (searchTerm && !app.name.toLowerCase().includes(searchTerm)) {
            return false;
        }

        // VLAN filter
        if (vlanFilter && (!app.vlans || !app.vlans.includes(vlanFilter))) {
            return false;
        }

        // Security Zone filter
        if (zoneFilter && (!app.zones || !app.zones.includes(zoneFilter))) {
            return false;
        }

        // Category filter
        if (categoryFilter && app.category !== categoryFilter) {
            return false;
        }

        return true;
    });

    // Apply sorting
    filtered.sort((a, b) => {
        let aVal = a[applicationsSortBy];
        let bVal = b[applicationsSortBy];

        // For string fields, use locale compare
        if (typeof aVal === 'string') {
            return applicationsSortDesc ?
                bVal.localeCompare(aVal) :
                aVal.localeCompare(bVal);
        }

        // For numeric fields
        return applicationsSortDesc ? bVal - aVal : aVal - bVal;
    });

    // Apply limit
    const displayed = limit === -1 ? filtered : filtered.slice(0, limit);

    if (displayed.length === 0) {
        container.innerHTML = `
            <div style="background: white; border-radius: 12px; padding: 40px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <p style="color: #999; font-size: 1.1em;">No applications found</p>
            </div>
        `;
        return;
    }

    const getSortIndicator = (field) => {
        if (applicationsSortBy === field) {
            return applicationsSortDesc ? ' ▼' : ' ▲';
        }
        return '';
    };

    let html = `
        <div style="background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-top: 3px solid #FA582D; overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; font-family: var(--font-secondary); font-size: 0.9em; min-width: 1400px;">
                <thead>
                    <tr style="border-bottom: 2px solid #FA582D;">
                        <th onclick="sortApplications('name')" style="padding: 12px; text-align: left; color: #333; font-weight: 600; cursor: pointer; user-select: none; font-family: var(--font-primary);">
                            Application${getSortIndicator('name')}
                        </th>
                        <th onclick="sortApplications('category')" style="padding: 12px; text-align: left; color: #333; font-weight: 600; cursor: pointer; user-select: none; font-family: var(--font-primary);">
                            Category${getSortIndicator('category')}
                        </th>
                        <th onclick="sortApplications('bytes_sent')" style="padding: 12px; text-align: right; color: #333; font-weight: 600; cursor: pointer; user-select: none; font-family: var(--font-primary);">
                            Bytes Sent${getSortIndicator('bytes_sent')}
                        </th>
                        <th onclick="sortApplications('bytes_received')" style="padding: 12px; text-align: right; color: #333; font-weight: 600; cursor: pointer; user-select: none; font-family: var(--font-primary);">
                            Bytes Received${getSortIndicator('bytes_received')}
                        </th>
                        <th onclick="sortApplications('bytes')" style="padding: 12px; text-align: right; color: #FA582D; font-weight: 600; cursor: pointer; user-select: none; font-family: var(--font-primary);">
                            Total Volume${getSortIndicator('bytes')}
                        </th>
                        <th onclick="sortApplications('source_count')" style="padding: 12px; text-align: right; color: #333; font-weight: 600; cursor: pointer; user-select: none; font-family: var(--font-primary);">
                            Sources${getSortIndicator('source_count')}
                        </th>
                        <th onclick="sortApplications('dest_count')" style="padding: 12px; text-align: right; color: #333; font-weight: 600; cursor: pointer; user-select: none; font-family: var(--font-primary);">
                            Destinations${getSortIndicator('dest_count')}
                        </th>
                        <th style="padding: 12px; text-align: left; color: #333; font-weight: 600; font-family: var(--font-primary);">Protocols</th>
                        <th style="padding: 12px; text-align: left; color: #333; font-weight: 600; font-family: var(--font-primary);">Top Ports</th>
                        <th style="padding: 12px; text-align: left; color: #333; font-weight: 600; font-family: var(--font-primary);">VLANs</th>
                    </tr>
                </thead>
                <tbody>
    `;

    displayed.forEach((app, index) => {
        const totalVolume = formatBytesHuman(app.bytes);
        const bytesSent = formatBytesHuman(app.bytes_sent || 0);
        const bytesReceived = formatBytesHuman(app.bytes_received || 0);
        const protocols = app.protocols.slice(0, 3).join(', ') || 'N/A';
        const ports = app.ports.slice(0, 5).join(', ') || 'N/A';
        const vlans = (app.vlans || []).join(', ') || 'N/A';
        const category = app.category || 'unknown';

        // Category badge colors
        const categoryColors = {
            'networking': '#3498db',
            'general-internet': '#2ecc71',
            'business-systems': '#9b59b6',
            'cloud-services': '#e74c3c',
            'other': '#FA582D',
            'unknown': '#95a5a6'
        };
        const categoryColor = categoryColors[category.toLowerCase()] || categoryColors['other'];

        html += `
            <tr style="border-bottom: 1px solid #eee; transition: background 0.2s;" onmouseover="this.style.background='#f9f9f9'" onmouseout="this.style.background='white'">
                <td onclick="showAppDetails(${index})" style="padding: 12px; color: #FA582D; font-weight: 600; cursor: pointer; text-decoration: underline; transition: color 0.2s;" onmouseover="this.style.color='#C64620'" onmouseout="this.style.color='#FA582D'">${app.name}</td>
                <td onclick="showAppDestinations(${index})" style="padding: 12px; cursor: pointer;">
                    <span style="background: ${categoryColor}; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.8em; font-weight: 600; display: inline-block; transition: opacity 0.2s;" onmouseover="this.style.opacity='0.8'" onmouseout="this.style.opacity='1'">
                        ${category}
                    </span>
                </td>
                <td style="padding: 12px; color: #666; text-align: right;">${bytesSent}</td>
                <td style="padding: 12px; color: #666; text-align: right;">${bytesReceived}</td>
                <td style="padding: 12px; color: #FA582D; text-align: right; font-weight: 600;">${totalVolume}</td>
                <td style="padding: 12px; color: #666; text-align: right;">${app.source_count}</td>
                <td style="padding: 12px; color: #666; text-align: right;">${app.dest_count}</td>
                <td style="padding: 12px; color: #666;">${protocols}</td>
                <td style="padding: 12px; color: #666; font-family: monospace;">${ports}</td>
                <td style="padding: 12px; color: #666;">${vlans}</td>
            </tr>
        `;
    });

    html += `
                </tbody>
            </table>
        </div>
    `;

    container.innerHTML = html;
}

function formatBytesHuman(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showApplicationsError(message) {
    const errorDiv = document.getElementById('applicationsErrorMessage');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

function exportApplicationsCSV() {
    // Get filtered applications (same logic as table rendering)
    const searchTerm = document.getElementById('applicationsSearchInput').value.toLowerCase();
    const vlanFilter = document.getElementById('applicationsVlanFilter').value;
    const categoryFilter = document.getElementById('applicationsCategoryFilter').value;

    let filtered = allApplications.filter(app => {
        if (searchTerm && !app.name.toLowerCase().includes(searchTerm)) return false;
        if (vlanFilter && (!app.vlans || !app.vlans.includes(vlanFilter))) return false;
        if (categoryFilter && app.category !== categoryFilter) return false;
        return true;
    });

    // CSV Headers
    const headers = ['Application', 'Category', 'Bytes Sent', 'Bytes Received', 'Total Volume', 'Sources', 'Destinations', 'Protocols', 'Top Ports', 'VLANs'];
    let csv = headers.join(',') + '\n';

    // CSV Rows
    filtered.forEach(app => {
        const row = [
            `"${app.name}"`,
            `"${app.category || 'unknown'}"`,
            app.bytes_sent || 0,
            app.bytes_received || 0,
            app.bytes,
            app.source_count,
            app.dest_count,
            `"${(app.protocols || []).join(', ')}"`,
            `"${(app.ports || []).slice(0, 5).join(', ')}"`,
            `"${(app.vlans || []).join(', ')}"`
        ];
        csv += row.join(',') + '\n';
    });

    // Download file
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `applications-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function exportApplicationsJSON() {
    // Get filtered applications (same logic as table rendering)
    const searchTerm = document.getElementById('applicationsSearchInput').value.toLowerCase();
    const vlanFilter = document.getElementById('applicationsVlanFilter').value;
    const categoryFilter = document.getElementById('applicationsCategoryFilter').value;

    let filtered = allApplications.filter(app => {
        if (searchTerm && !app.name.toLowerCase().includes(searchTerm)) return false;
        if (vlanFilter && (!app.vlans || !app.vlans.includes(vlanFilter))) return false;
        if (categoryFilter && app.category !== categoryFilter) return false;
        return true;
    });

    // Create JSON export data
    const exportData = {
        export_date: new Date().toISOString(),
        total_applications: filtered.length,
        applications: filtered.map(app => ({
            name: app.name,
            category: app.category || 'unknown',
            bytes_sent: app.bytes_sent || 0,
            bytes_received: app.bytes_received || 0,
            total_bytes: app.bytes,
            source_count: app.source_count,
            dest_count: app.dest_count,
            protocols: app.protocols || [],
            top_ports: (app.ports || []).slice(0, 10),
            vlans: app.vlans || []
        }))
    };

    // Download file
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `applications-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// Event listeners for Applications page
function setupApplicationsEventListeners() {
    const searchInput = document.getElementById('applicationsSearchInput');
    const limitSelect = document.getElementById('applicationsLimit');
    const vlanFilter = document.getElementById('applicationsVlanFilter');
    const zoneFilter = document.getElementById('applicationsZoneFilter');
    const categoryFilter = document.getElementById('applicationsCategoryFilter');
    const refreshBtn = document.getElementById('refreshApplicationsBtn');

    if (searchInput) {
        searchInput.addEventListener('input', () => {
            renderApplicationsTable();
        });
    }

    if (limitSelect) {
        limitSelect.addEventListener('change', () => {
            renderApplicationsTable();
        });
    }

    if (vlanFilter) {
        vlanFilter.addEventListener('change', () => {
            renderApplicationsTable();
        });
    }

    if (zoneFilter) {
        zoneFilter.addEventListener('change', () => {
            renderApplicationsTable();
        });
    }

    if (categoryFilter) {
        categoryFilter.addEventListener('change', () => {
            renderApplicationsTable();
        });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadApplications();
        });
    }

    // Export buttons
    const exportCSVBtn = document.getElementById('exportAppsCSVBtn');
    const exportJSONBtn = document.getElementById('exportAppsJSONBtn');

    if (exportCSVBtn) {
        exportCSVBtn.addEventListener('click', exportApplicationsCSV);
    }

    if (exportJSONBtn) {
        exportJSONBtn.addEventListener('click', exportApplicationsJSON);
    }

    // Destinations modal close button
    const closeDestModalBtn = document.getElementById('closeAppDestModalBtn');
    if (closeDestModalBtn) {
        closeDestModalBtn.addEventListener('click', hideAppDestinations);
    }

    // Application details modal close button
    const closeAppDetailsBtn = document.getElementById('closeAppDetailsModalBtn');
    if (closeAppDetailsBtn) {
        closeAppDetailsBtn.addEventListener('click', hideAppDetails);
    }

    // Close modals when clicking outside
    const destModal = document.getElementById('appDestinationsModal');
    if (destModal) {
        destModal.addEventListener('click', (e) => {
            if (e.target === destModal) {
                hideAppDestinations();
            }
        });
    }

    const detailsModal = document.getElementById('appDetailsModal');
    if (detailsModal) {
        detailsModal.addEventListener('click', (e) => {
            if (e.target === detailsModal) {
                hideAppDetails();
            }
        });
    }
}

async function showAppDestinations(appIndex) {
    const searchTerm = document.getElementById('applicationsSearchInput').value.toLowerCase();
    const limit = parseInt(document.getElementById('applicationsLimit').value);

    // Get the filtered and sorted list
    let filtered = allApplications.filter(app =>
        app.name.toLowerCase().includes(searchTerm)
    );

    filtered.sort((a, b) => {
        let aVal = a[applicationsSortBy];
        let bVal = b[applicationsSortBy];
        if (typeof aVal === 'string') {
            return applicationsSortDesc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
        }
        return applicationsSortDesc ? bVal - aVal : aVal - bVal;
    });

    const displayed = limit === -1 ? filtered : filtered.slice(0, limit);
    const app = displayed[appIndex];

    if (!app) {
        console.error('Application not found at index:', appIndex);
        return;
    }

    // Populate modal with app data
    document.getElementById('appDestApp').textContent = app.name;
    document.getElementById('appDestCount').textContent = app.dest_count;
    document.getElementById('appDestVolume').textContent = formatBytesHuman(app.bytes);
    document.getElementById('appDestModalSubtitle').textContent = `Category: ${app.category}`;

    // Sort destinations by bytes (descending) - ensure they're sorted even if backend already sorted them
    if (app.destinations && app.destinations.length > 0) {
        app.destinations.sort((a, b) => (b.bytes || 0) - (a.bytes || 0));
    }

    // Populate destinations list
    const destinationsList = document.getElementById('appDestinationsList');
    if (app.destinations && app.destinations.length > 0) {
        // Check if reverse DNS lookup is enabled
        const reverseDnsEnabled = document.getElementById('enableReverseDnsCheckbox').checked;

        if (reverseDnsEnabled) {
            // Show loading indicator
            destinationsList.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;"><i class="fas fa-spinner fa-spin"></i> Performing reverse DNS lookups...</div>';

            // Show modal immediately with loading state
            const modal = document.getElementById('appDestinationsModal');
            modal.style.display = 'flex';

            try {
                // Extract IP addresses from destinations
                const ipAddresses = app.destinations.map(dest => dest.ip);

                // Get CSRF token
                const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

                // Call reverse DNS API
                const response = await fetch('/api/reverse-dns', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({
                        ip_addresses: ipAddresses,
                        timeout: 2
                    })
                });

                const data = await response.json();
                console.log('Reverse DNS API response:', data);

                if (data.status === 'success') {
                    // Render destinations with hostnames
                    let destHtml = '';
                    app.destinations.forEach(dest => {
                        const hostname = data.results[dest.ip];
                        const showHostname = hostname && hostname !== dest.ip;
                        const portDisplay = formatPortDisplay(dest.port);
                        const bytesDisplay = formatBytesHuman(dest.bytes || 0);
                        console.log(`IP: ${dest.ip}, Hostname: ${hostname}, Show: ${showHostname}`);

                        destHtml += `
                            <div style="background: white; border: 1px solid #ddd; border-left: 3px solid #FA582D; border-radius: 4px; padding: 10px;">
                                ${showHostname ? `<div style="color: #333; font-weight: 600; margin-bottom: 3px;">${hostname}</div>` : ''}
                                <div style="font-family: monospace; color: #FA582D; font-weight: 600; margin-bottom: 3px;">${dest.ip}</div>
                                <div style="font-size: 0.85em; color: #666; margin-bottom: 2px;">${portDisplay}</div>
                                <div style="font-size: 0.8em; color: #FA582D; font-weight: 600;">${bytesDisplay}</div>
                            </div>
                        `;
                    });
                    destinationsList.innerHTML = destHtml;
                } else {
                    throw new Error(data.message || 'Failed to perform reverse DNS lookup');
                }
            } catch (error) {
                console.error('Error performing reverse DNS lookup:', error);
                // Fall back to showing IPs without hostnames
                let destHtml = '';
                app.destinations.forEach(dest => {
                    const portDisplay = formatPortDisplay(dest.port);
                    const bytesDisplay = formatBytesHuman(dest.bytes || 0);
                    destHtml += `
                        <div style="background: white; border: 1px solid #ddd; border-left: 3px solid #FA582D; border-radius: 4px; padding: 10px;">
                            <div style="font-family: monospace; color: #FA582D; font-weight: 600; margin-bottom: 3px;">${dest.ip}</div>
                            <div style="font-size: 0.85em; color: #666; margin-bottom: 2px;">${portDisplay}</div>
                            <div style="font-size: 0.8em; color: #FA582D; font-weight: 600; margin-bottom: 2px;">${bytesDisplay}</div>
                            <div style="font-size: 0.8em; color: #d9534f;">DNS lookup failed</div>
                        </div>
                    `;
                });
                destinationsList.innerHTML = destHtml;
            }
        } else {
            // Render destinations without hostnames (original behavior)
            let destHtml = '';
            app.destinations.forEach(dest => {
                const portDisplay = formatPortDisplay(dest.port);
                const bytesDisplay = formatBytesHuman(dest.bytes || 0);
                destHtml += `
                    <div style="background: white; border: 1px solid #ddd; border-left: 3px solid #FA582D; border-radius: 4px; padding: 10px;">
                        <div style="font-family: monospace; color: #FA582D; font-weight: 600; margin-bottom: 3px;">${dest.ip}</div>
                        <div style="font-size: 0.85em; color: #666; margin-bottom: 2px;">${portDisplay}</div>
                        <div style="font-size: 0.8em; color: #FA582D; font-weight: 600;">${bytesDisplay}</div>
                    </div>
                `;
            });
            destinationsList.innerHTML = destHtml;

            // Show modal
            const modal = document.getElementById('appDestinationsModal');
            modal.style.display = 'flex';
        }

        // Update note
        const totalDests = app.dest_count;
        const showingDests = app.destinations.length;
        document.getElementById('appDestNote').textContent =
            showingDests < totalDests ?
            `Showing top ${showingDests} of ${totalDests} total destinations` :
            `Showing all ${totalDests} destinations`;
    } else {
        destinationsList.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No destination data available</div>';
        document.getElementById('appDestNote').textContent = 'No destinations found';

        // Show modal
        const modal = document.getElementById('appDestinationsModal');
        modal.style.display = 'flex';
    }
}

function hideAppDestinations() {
    const modal = document.getElementById('appDestinationsModal');
    modal.style.display = 'none';
}

function showAppDetails(appIndex) {
    const searchTerm = document.getElementById('applicationsSearchInput').value.toLowerCase();
    const vlanFilter = document.getElementById('applicationsVlanFilter').value;
    const categoryFilter = document.getElementById('applicationsCategoryFilter').value;
    const limit = parseInt(document.getElementById('applicationsLimit').value);

    // Get the filtered and sorted list (same logic as table rendering)
    let filtered = allApplications.filter(app => {
        if (searchTerm && !app.name.toLowerCase().includes(searchTerm)) return false;
        if (vlanFilter && (!app.vlans || !app.vlans.includes(vlanFilter))) return false;
        if (categoryFilter && app.category !== categoryFilter) return false;
        return true;
    });

    filtered.sort((a, b) => {
        let aVal = a[applicationsSortBy];
        let bVal = b[applicationsSortBy];
        if (typeof aVal === 'string') {
            return applicationsSortDesc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
        }
        return applicationsSortDesc ? bVal - aVal : aVal - bVal;
    });

    const displayed = limit === -1 ? filtered : filtered.slice(0, limit);
    const app = displayed[appIndex];

    if (!app) {
        console.error('Application not found at index:', appIndex);
        return;
    }

    // Populate modal header
    document.getElementById('appDetailsName').textContent = app.name;
    document.getElementById('appDetailsCategory').textContent = app.category || 'unknown';

    // Populate summary stats
    document.getElementById('appDetailsVolume').textContent = formatBytesHuman(app.bytes);
    document.getElementById('appDetailsSourceIPs').textContent = app.source_count;
    document.getElementById('appDetailsDestinations').textContent = app.dest_count;

    // Populate source IP addresses
    const sourceList = document.getElementById('appDetailsSourceList');
    if (app.source_ips && app.source_ips.length > 0) {
        let sourceHtml = '';
        app.source_ips.forEach(ip => {
            sourceHtml += `
                <div style="background: white; border: 2px solid #FA582D; border-radius: 6px; padding: 8px 12px; font-family: monospace; color: #333; font-size: 0.9em; font-weight: 500;">
                    ${ip}
                </div>
            `;
        });
        sourceList.innerHTML = sourceHtml;
    } else {
        sourceList.innerHTML = '<div style="padding: 10px; color: #999;">-</div>';
    }

    // Populate protocols
    const protocolsDiv = document.getElementById('appDetailsProtocols');
    if (app.protocols && app.protocols.length > 0) {
        protocolsDiv.textContent = app.protocols.join(', ');
    } else {
        protocolsDiv.textContent = '-';
    }

    // Populate top ports
    const topPortsDiv = document.getElementById('appDetailsTopPorts');
    if (app.ports && app.ports.length > 0) {
        // Format ports with protocol hints
        const portLabels = app.ports.map(port => {
            if (port === '443') return '443 (https)';
            if (port === '80') return '80 (http)';
            if (port === '22') return '22 (ssh)';
            if (port === '3389') return '3389 (rdp)';
            return port;
        });
        topPortsDiv.textContent = portLabels.join(', ');
    } else {
        topPortsDiv.textContent = '-';
    }

    // Populate VLANs
    const vlansDiv = document.getElementById('appDetailsVLANs');
    if (app.vlans && app.vlans.length > 0) {
        vlansDiv.textContent = app.vlans.join(', ');
    } else {
        vlansDiv.textContent = '-';
    }

    // Show modal
    const modal = document.getElementById('appDetailsModal');
    modal.style.display = 'flex';
}

function hideAppDetails() {
    const modal = document.getElementById('appDetailsModal');
    modal.style.display = 'none';
}

