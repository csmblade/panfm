/**
 * pages.js - Page-Specific Functions Module
 *
 * Handles page-specific functionality including:
 * - Software updates page
 * - Connected devices page
 * - Homepage modals (threat logs, top applications)
 * - Export functionality (CSV, XML)
 */

// Format timestamp for display (YYYY-MM-DD HH:MM:SS) with timezone conversion
function formatTimestamp(timestamp) {
    if (!timestamp || timestamp === 'Never' || timestamp === 'N/A') {
        return 'N/A';
    }

    try {
        // Handle Palo Alto timestamp format: "YYYY/MM/DD HH:MM:SS"
        let dateStr = timestamp;
        if (typeof timestamp === 'string' && timestamp.includes('/')) {
            // Convert YYYY/MM/DD to YYYY-MM-DD for parsing
            dateStr = timestamp.replace(/\//g, '-');
        }

        const date = new Date(dateStr);
        if (isNaN(date.getTime())) {
            return 'N/A';
        }

        // Get user's timezone preference (default to UTC if not set)
        const userTz = window.userTimezone || 'UTC';

        // Format using user's timezone
        const formatted = date.toLocaleString('en-US', {
            timeZone: userTz,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });

        // Convert from "MM/DD/YYYY, HH:MM:SS" to "YYYY-MM-DD HH:MM:SS"
        const parts = formatted.split(', ');
        if (parts.length === 2) {
            const datePart = parts[0].split('/'); // MM/DD/YYYY
            const timePart = parts[1]; // HH:MM:SS
            return `${datePart[2]}-${datePart[0]}-${datePart[1]} ${timePart}`;
        }

        return formatted;
    } catch (e) {
        return 'N/A';
    }
}

// Format timestamp to show how long ago (for threat last seen)
function formatDaysAgo(timestamp) {
    if (!timestamp || timestamp === 'N/A' || timestamp === 'Never') {
        return 'Never';
    }

    try {
        // Parse the timestamp - Palo Alto format is typically YYYY/MM/DD HH:MM:SS
        const dateStr = timestamp.replace(/\//g, '-');
        const date = new Date(dateStr);

        if (isNaN(date.getTime())) {
            return 'Never';
        }

        const now = new Date();
        const diffMs = now - date;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffMinutes = Math.floor(diffMs / (1000 * 60));

        if (diffDays > 0) {
            return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
        } else if (diffHours > 0) {
            return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
        } else if (diffMinutes > 0) {
            return `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
        } else {
            return 'Just now';
        }
    } catch (e) {
        return 'Never';
    }
}

// Sort system logs based on criteria
function sortSystemLogs(logs, sortBy) {
    const severityOrder = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'informational': 0
    };

    return logs.sort((a, b) => {
        switch(sortBy) {
            case 'time':
                // Newest first
                return new Date(b.time) - new Date(a.time);

            case 'time-asc':
                // Oldest first
                return new Date(a.time) - new Date(b.time);

            case 'severity':
                // High to Low
                const severityA = severityOrder[a.severity.toLowerCase()] || 0;
                const severityB = severityOrder[b.severity.toLowerCase()] || 0;
                return severityB - severityA;

            case 'severity-asc':
                // Low to High
                const severityA2 = severityOrder[a.severity.toLowerCase()] || 0;
                const severityB2 = severityOrder[b.severity.toLowerCase()] || 0;
                return severityA2 - severityB2;

            case 'module':
                // Module A-Z
                return (a.module || '').localeCompare(b.module || '');

            case 'eventid':
                // Event ID numeric
                return (a.eventid || '').localeCompare(b.eventid || '');

            default:
                return 0;
        }
    });
}

// ============================================================================
// DHCP Leases Functions
// ============================================================================

/**
 * Load DHCP leases from the firewall
 */
async function loadDhcpLeases() {
    const loadingDiv = document.getElementById('dhcpLoading');
    const contentDiv = document.getElementById('dhcpContent');
    const errorDiv = document.getElementById('dhcpErrorMessage');

    // Show loading animation
    loadingDiv.style.display = 'block';
    contentDiv.style.display = 'none';
    errorDiv.style.display = 'none';

    try {
        const response = await fetch('/api/dhcp-leases');
        const data = await response.json();

        // Hide loading animation
        loadingDiv.style.display = 'none';

        if (data.status === 'success') {
            if (data.leases && data.leases.length > 0) {
                errorDiv.style.display = 'none';
                contentDiv.style.display = 'block';

                // Update summary
                document.getElementById('dhcpTotalLeases').textContent = data.total || data.leases.length;

                // Render the DHCP leases table
                renderDhcpTable(data.leases);
            } else {
                // No leases found - show empty state
                contentDiv.style.display = 'block';
                document.getElementById('dhcpTotalLeases').textContent = '0';
                document.getElementById('dhcpLeasesTable').style.display = 'none';
                document.getElementById('dhcpEmptyState').style.display = 'block';
            }
        } else if (data.status === 'error') {
            errorDiv.textContent = `Error: ${data.message || 'Failed to fetch DHCP leases'}`;
            errorDiv.style.display = 'block';
        } else {
            errorDiv.textContent = 'No DHCP leases found';
            errorDiv.style.display = 'block';
        }

    } catch (error) {
        console.error('Error loading DHCP leases:', error);
        loadingDiv.style.display = 'none';
        errorDiv.textContent = `Error: ${error.message}`;
        errorDiv.style.display = 'block';
    }
}

/**
 * Render the DHCP leases table
 * @param {Array} leases - Array of DHCP lease objects
 */
function renderDhcpTable(leases) {
    const tableBody = document.getElementById('dhcpLeasesTableBody');
    const emptyState = document.getElementById('dhcpEmptyState');
    const table = document.getElementById('dhcpLeasesTable');

    if (!leases || leases.length === 0) {
        table.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }

    // Show table, hide empty state
    table.style.display = 'table';
    emptyState.style.display = 'none';

    // Build table rows
    let tableHTML = '';
    leases.forEach(lease => {
        const ip = escapeHtml(lease.ip || 'N/A');
        const mac = escapeHtml(lease.mac || 'N/A');
        const hostname = escapeHtml(lease.hostname || 'Unknown');
        const state = escapeHtml(lease.state || 'UNKNOWN');
        const expiration = escapeHtml(lease.expiration || 'N/A');
        const iface = escapeHtml(lease.interface || 'N/A');

        // Color code the state
        let stateColor = '#666';
        if (state === 'BOUND') {
            stateColor = '#28a745'; // Green
        } else if (state === 'EXPIRED') {
            stateColor = '#dc3545'; // Red
        } else if (state === 'OFFERED') {
            stateColor = '#ffc107'; // Yellow
        }

        tableHTML += `
            <tr style="border-bottom: 1px solid #eee;">
                <td style="padding: 12px; font-family: 'Courier New', monospace; color: #FA582D; font-weight: 600;">${ip}</td>
                <td style="padding: 12px; font-family: 'Courier New', monospace; color: #666;">${mac}</td>
                <td style="padding: 12px; color: #333; font-weight: 500;">${hostname}</td>
                <td style="padding: 12px;">
                    <span style="background: ${stateColor}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; font-family: var(--font-primary);">
                        ${state}
                    </span>
                </td>
                <td style="padding: 12px; color: #666; font-family: var(--font-secondary);">${expiration}</td>
                <td style="padding: 12px; color: #666; font-family: var(--font-secondary);">${iface}</td>
            </tr>
        `;
    });

    tableBody.innerHTML = tableHTML;
}

// Load system logs data
// Load software updates data
async function loadSoftwareUpdates() {
    const loadingDiv = document.getElementById('softwareLoading');
    const panosTableDiv = document.getElementById('panosTable');
    const componentsTableDiv = document.getElementById('componentsTable');
    const errorDiv = document.getElementById('softwareErrorMessage');

    // Hide loading - PAN-OS has its own upgrade UI, we only load components
    loadingDiv.style.display = 'none';
    panosTableDiv.style.display = 'none';
    componentsTableDiv.style.display = 'none';
    errorDiv.style.display = 'none';

    try {
        const response = await fetch('/api/software-updates');
        const data = await response.json();

        // Show components table
        componentsTableDiv.style.display = 'block';

        if (data.status === 'success' && data.software.length > 0) {
            errorDiv.style.display = 'none';

            // Filter out PAN-OS (it has dedicated upgrade UI)
            const componentItems = data.software.filter(item => !item.name.toLowerCase().includes('panos'));

            // Render Components table
            if (componentItems.length > 0) {
                let componentsHtml = renderSoftwareTable(componentItems, data.timestamp);
                componentsTableDiv.innerHTML = componentsHtml;
            } else {
                componentsTableDiv.innerHTML = '<p style="color: #999; text-align: center; padding: 40px;">No component information available</p>';
            }
        } else {
            errorDiv.textContent = data.message || 'No software version information available';
            errorDiv.style.display = 'block';
            componentsTableDiv.innerHTML = '';
        }
    } catch (error) {
        console.error('Error loading software updates:', error);
        componentsTableDiv.style.display = 'none';
        errorDiv.textContent = 'Failed to load software updates: ' + error.message;
        errorDiv.style.display = 'block';
    }

    // Initialize content updates UI when Components tab is loaded
    if (typeof initContentUpdates === 'function') {
        initContentUpdates();
    }
}

/**
 * Render software table HTML for given items
 */
function renderSoftwareTable(items, timestamp) {
    let tableHtml = `
        <table style="width: 100%; border-collapse: collapse; font-family: var(--font-secondary); font-size: 0.9em;">
            <thead>
                <tr style="background: linear-gradient(135deg, #FA582D 0%, #FF7A55 100%); color: white;">
                    <th style="padding: 12px; text-align: left; font-family: var(--font-primary);">Component</th>
                    <th style="padding: 12px; text-align: left; font-family: var(--font-primary);">Version</th>
                    <th style="padding: 12px; text-align: center; font-family: var(--font-primary);">Downloaded</th>
                    <th style="padding: 12px; text-align: center; font-family: var(--font-primary);">Current</th>
                    <th style="padding: 12px; text-align: center; font-family: var(--font-primary);">Latest</th>
                </tr>
            </thead>
            <tbody>
    `;

    // Add rows for each software component
    items.forEach((item, index) => {
        const bgColor = index % 2 === 0 ? '#f9f9f9' : '#ffffff';
        tableHtml += `
            <tr style="background: ${bgColor}; border-bottom: 1px solid #e0e0e0;">
                <td style="padding: 12px; font-weight: 600; color: #333; font-family: var(--font-primary);">${item.name}</td>
                <td style="padding: 12px; color: #666; font-family: monospace;">${item.version}</td>
                <td style="padding: 12px; text-align: center; color: ${item.downloaded === 'yes' ? '#28a745' : '#999'}; font-weight: 600;">${item.downloaded}</td>
                <td style="padding: 12px; text-align: center; color: ${item.current === 'yes' ? '#28a745' : '#999'}; font-weight: 600;">${item.current}</td>
                <td style="padding: 12px; text-align: center; color: ${item.latest === 'yes' ? '#28a745' : '#999'}; font-weight: 600;">${item.latest}</td>
            </tr>
        `;
    });

    tableHtml += `
            </tbody>
        </table>
        <div style="margin-top: 15px; padding: 10px; background: #f0f0f0; border-radius: 8px; color: #666; font-size: 0.9em; font-family: var(--font-secondary);">
            Last updated: ${new Date(timestamp).toLocaleString()}
        </div>
    `;

    return tableHtml;
}

// ============================================================================
// HOMEPAGE MODAL FUNCTIONS
// ============================================================================

// Critical Threats Modal
function showCriticalThreatsModal() {
    const modal = document.getElementById('criticalThreatsModal');
    const container = document.getElementById('criticalThreatsTableContainer');
    const countElement = document.getElementById('criticalModalCount');

    // Update count
    countElement.textContent = currentCriticalLogs.length;

    // Build table
    if (currentCriticalLogs.length === 0) {
        container.innerHTML = '<div style="color: #999; text-align: center; padding: 20px;">No critical threats detected</div>';
    } else {
        let tableHtml = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: linear-gradient(135deg, #FA582D 0%, #FF7A55 100%); color: white;">
                        <th style="padding: 12px; text-align: left;">Threat</th>
                        <th style="padding: 12px; text-align: left;">Source</th>
                        <th style="padding: 12px; text-align: left;">Destination</th>
                        <th style="padding: 12px; text-align: left;">App</th>
                        <th style="padding: 12px; text-align: left;">Action</th>
                        <th style="padding: 12px; text-align: left;">Time</th>
                    </tr>
                </thead>
                <tbody>
        `;

        currentCriticalLogs.forEach((log, index) => {
            const bgColor = index % 2 === 0 ? '#f9f9f9' : '#ffffff';
            const threat = log.threat || 'Unknown';
            const src = log.src || 'N/A';
            const dst = log.dst || 'N/A';
            const app = log.app || 'N/A';
            const action = log.action || 'N/A';
            const datetime = log.time ? new Date(log.time) : null;
            const time = datetime ? datetime.toLocaleString() : 'N/A';

            tableHtml += `
                <tr style="background: ${bgColor}; border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px; color: #333; font-weight: 600;">${threat}</td>
                    <td style="padding: 12px; color: #666; font-family: monospace; font-size: 0.9em;">${src}</td>
                    <td style="padding: 12px; color: #666; font-family: monospace; font-size: 0.9em;">${dst}</td>
                    <td style="padding: 12px; color: #666;">${app}</td>
                    <td style="padding: 12px; color: #FA582D; font-weight: 600;">${action}</td>
                    <td style="padding: 12px; color: #999; font-size: 0.9em;">${time}</td>
                </tr>
            `;
        });

        tableHtml += `
                </tbody>
            </table>
        `;
        container.innerHTML = tableHtml;
    }

    modal.style.display = 'flex';
}

function closeCriticalThreatsModal() {
    document.getElementById('criticalThreatsModal').style.display = 'none';
}

// Medium Threats Modal
function showMediumThreatsModal() {
    const modal = document.getElementById('mediumThreatsModal');
    const container = document.getElementById('mediumThreatsTableContainer');
    const countElement = document.getElementById('mediumModalCount');

    // Update count
    countElement.textContent = currentMediumLogs.length;

    // Build table
    if (currentMediumLogs.length === 0) {
        container.innerHTML = '<div style="color: #999; text-align: center; padding: 20px;">No medium threats detected</div>';
    } else {
        let tableHtml = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: linear-gradient(135deg, #E04F26 0%, #FF6B3D 100%); color: white;">
                        <th style="padding: 12px; text-align: left;">Threat</th>
                        <th style="padding: 12px; text-align: left;">Source</th>
                        <th style="padding: 12px; text-align: left;">Destination</th>
                        <th style="padding: 12px; text-align: left;">App</th>
                        <th style="padding: 12px; text-align: left;">Action</th>
                        <th style="padding: 12px; text-align: left;">Time</th>
                    </tr>
                </thead>
                <tbody>
        `;

        currentMediumLogs.forEach((log, index) => {
            const bgColor = index % 2 === 0 ? '#f9f9f9' : '#ffffff';
            const threat = log.threat || 'Unknown';
            const src = log.src || 'N/A';
            const dst = log.dst || 'N/A';
            const app = log.app || 'N/A';
            const action = log.action || 'N/A';
            const datetime = log.time ? new Date(log.time) : null;
            const time = datetime ? datetime.toLocaleString() : 'N/A';

            tableHtml += `
                <tr style="background: ${bgColor}; border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px; color: #333; font-weight: 600;">${threat}</td>
                    <td style="padding: 12px; color: #666; font-family: monospace; font-size: 0.9em;">${src}</td>
                    <td style="padding: 12px; color: #666; font-family: monospace; font-size: 0.9em;">${dst}</td>
                    <td style="padding: 12px; color: #666;">${app}</td>
                    <td style="padding: 12px; color: #E04F26; font-weight: 600;">${action}</td>
                    <td style="padding: 12px; color: #999; font-size: 0.9em;">${time}</td>
                </tr>
            `;
        });

        tableHtml += `
                </tbody>
            </table>
        `;
        container.innerHTML = tableHtml;
    }

    modal.style.display = 'flex';
}

function closeMediumThreatsModal() {
    document.getElementById('mediumThreatsModal').style.display = 'none';
}

// Blocked URLs Modal
function showBlockedUrlsModal() {
    const modal = document.getElementById('blockedUrlsModal');
    const container = document.getElementById('blockedUrlsTableContainer');
    const countElement = document.getElementById('blockedUrlsModalCount');

    // Update count
    countElement.textContent = currentBlockedUrlLogs.length;

    // Build table
    if (currentBlockedUrlLogs.length === 0) {
        container.innerHTML = '<div style="color: #999; text-align: center; padding: 20px;">No blocked URLs</div>';
    } else {
        let tableHtml = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: linear-gradient(135deg, #C64620 0%, #E85A31 100%); color: white;">
                        <th style="padding: 12px; text-align: left;">URL</th>
                        <th style="padding: 12px; text-align: left;">Category</th>
                        <th style="padding: 12px; text-align: left;">Source</th>
                        <th style="padding: 12px; text-align: left;">Destination</th>
                        <th style="padding: 12px; text-align: left;">Action</th>
                        <th style="padding: 12px; text-align: left;">Time</th>
                    </tr>
                </thead>
                <tbody>
        `;

        currentBlockedUrlLogs.forEach((log, index) => {
            const bgColor = index % 2 === 0 ? '#f9f9f9' : '#ffffff';
            const url = log.url || log.threat || 'Unknown';
            const category = log.category || 'N/A';
            const src = log.src || 'N/A';
            const dst = log.dst || 'N/A';
            const action = log.action || 'N/A';
            const datetime = log.time ? new Date(log.time) : null;
            const time = datetime ? datetime.toLocaleString() : 'N/A';

            tableHtml += `
                <tr style="background: ${bgColor}; border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px; color: #333; font-weight: 600; word-break: break-all;">${url}</td>
                    <td style="padding: 12px; color: #666;">${category}</td>
                    <td style="padding: 12px; color: #666; font-family: monospace; font-size: 0.9em;">${src}</td>
                    <td style="padding: 12px; color: #666; font-family: monospace; font-size: 0.9em;">${dst}</td>
                    <td style="padding: 12px; color: #C64620; font-weight: 600;">${action}</td>
                    <td style="padding: 12px; color: #999; font-size: 0.9em;">${time}</td>
                </tr>
            `;
        });

        tableHtml += `
                </tbody>
            </table>
        `;
        container.innerHTML = tableHtml;
    }

    modal.style.display = 'flex';
}

function closeBlockedUrlsModal() {
    document.getElementById('blockedUrlsModal').style.display = 'none';
}

// Top Applications Modal
function showTopAppsModal() {
    const modal = document.getElementById('topAppsModal');
    const container = document.getElementById('topAppsTableContainer');
    const countElement = document.getElementById('topAppsModalCount');

    // Update count
    countElement.textContent = currentTopApps.length;

    // Build table
    if (currentTopApps.length === 0) {
        container.innerHTML = '<div style="color: #999; text-align: center; padding: 20px;">No application data</div>';
    } else {
        let tableHtml = `
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="background: linear-gradient(135deg, #AD3D1A 0%, #D14925 100%); color: white;">
                        <th style="padding: 12px; text-align: left;">Rank</th>
                        <th style="padding: 12px; text-align: left;">Application</th>
                        <th style="padding: 12px; text-align: right;">Sessions</th>
                        <th style="padding: 12px; text-align: left;">Usage Bar</th>
                    </tr>
                </thead>
                <tbody>
        `;

        const maxCount = currentTopApps[0]?.count || 1;

        currentTopApps.forEach((app, index) => {
            const bgColor = index % 2 === 0 ? '#f9f9f9' : '#ffffff';
            const barWidth = maxCount > 0 ? (app.count / maxCount * 100) : 0;

            tableHtml += `
                <tr style="background: ${bgColor}; border-bottom: 1px solid #e0e0e0;">
                    <td style="padding: 12px; color: #AD3D1A; font-weight: 700; font-size: 1.2em;">${index + 1}</td>
                    <td style="padding: 12px; color: #333; font-weight: 600;">${app.name}</td>
                    <td style="padding: 12px; text-align: right; color: #AD3D1A; font-weight: 700; font-size: 1.1em;">${app.count.toLocaleString()}</td>
                    <td style="padding: 12px;">
                        <div style="background: #e0e0e0; border-radius: 4px; height: 20px; overflow: hidden; min-width: 200px;">
                            <div style="background: linear-gradient(135deg, #AD3D1A 0%, #D14925 100%); height: 100%; width: ${barWidth}%; transition: width 0.3s ease;"></div>
                        </div>
                    </td>
                </tr>
            `;
        });

        tableHtml += `
                </tbody>
            </table>
        `;
        container.innerHTML = tableHtml;
    }

    modal.style.display = 'flex';
}

function closeTopAppsModal() {
    document.getElementById('topAppsModal').style.display = 'none';
}

// Close modals when clicking outside
window.addEventListener('click', function(event) {
    const criticalModal = document.getElementById('criticalThreatsModal');
    const mediumModal = document.getElementById('mediumThreatsModal');
    const blockedModal = document.getElementById('blockedUrlsModal');
    const topAppsModal = document.getElementById('topAppsModal');

    if (event.target === criticalModal) {
        closeCriticalThreatsModal();
    } else if (event.target === mediumModal) {
        closeMediumThreatsModal();
    } else if (event.target === blockedModal) {
        closeBlockedUrlsModal();
    } else if (event.target === topAppsModal) {
        closeTopAppsModal();
    }
});

// ============================================================================
// TECH SUPPORT FUNCTIONS
// ============================================================================

// Store job ID for polling
let techSupportJobId = null;
let techSupportPollingInterval = null;

async function generateTechSupport() {
    const statusDiv = document.getElementById('techSupportStatus');
    const downloadDiv = document.getElementById('techSupportDownload');
    const generateBtn = document.getElementById('generateTechSupportBtn');
    const statusText = document.getElementById('techSupportStatusText');
    const progressText = document.getElementById('techSupportProgressText');

    // Reset UI
    downloadDiv.style.display = 'none';
    statusDiv.style.display = 'block';
    generateBtn.disabled = true;
    generateBtn.style.opacity = '0.5';
    generateBtn.style.cursor = 'not-allowed';

    statusText.textContent = 'Generating tech support file...';
    progressText.textContent = 'Please wait, this may take several minutes.';

    try {
        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

        // Request tech support file generation
        const response = await fetch('/api/tech-support/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });

        const data = await response.json();

        console.log('Tech support generation response:', data);

        if (data.status === 'success' && data.job_id) {
            techSupportJobId = data.job_id;
            statusText.textContent = 'Tech support file generation in progress...';
            progressText.textContent = `Job ID: ${data.job_id} - Checking status...`;

            // Start polling for job status
            startTechSupportPolling();
        } else {
            const errorMsg = data.message || 'Failed to generate tech support file';
            console.error('Tech support generation failed:', errorMsg, data);
            throw new Error(errorMsg);
        }
    } catch (error) {
        console.error('Error generating tech support file:', error);
        statusDiv.style.display = 'none';
        generateBtn.disabled = false;
        generateBtn.style.opacity = '1';
        generateBtn.style.cursor = 'pointer';

        const errorDiv = document.getElementById('techSupportErrorMessage');
        errorDiv.textContent = `Error: ${error.message}`;
        errorDiv.style.display = 'block';

        setTimeout(() => {
            errorDiv.style.display = 'none';
        }, 5000);
    }
}

function startTechSupportPolling() {
    // Poll every 5 seconds
    techSupportPollingInterval = setInterval(checkTechSupportStatus, 5000);

    // Check immediately
    checkTechSupportStatus();
}

async function checkTechSupportStatus() {
    if (!techSupportJobId) return;

    const progressText = document.getElementById('techSupportProgressText');

    try {
        const response = await fetch(`/api/tech-support/status/${techSupportJobId}`);
        const data = await response.json();

        if (data.status === 'success') {
            const jobStatus = data.job_status;
            const progress = data.progress;

            progressText.textContent = `Status: ${jobStatus} - Progress: ${progress}%`;

            // Check if job is complete
            if (data.ready) {
                clearInterval(techSupportPollingInterval);
                techSupportPollingInterval = null;

                // Job is complete, get download URL
                getTechSupportDownloadUrl();
            }
        } else {
            throw new Error(data.message || 'Failed to check job status');
        }
    } catch (error) {
        console.error('Error checking tech support status:', error);
        clearInterval(techSupportPollingInterval);
        techSupportPollingInterval = null;

        const statusDiv = document.getElementById('techSupportStatus');
        const generateBtn = document.getElementById('generateTechSupportBtn');

        statusDiv.style.display = 'none';
        generateBtn.disabled = false;
        generateBtn.style.opacity = '1';
        generateBtn.style.cursor = 'pointer';

        const errorDiv = document.getElementById('techSupportErrorMessage');
        errorDiv.textContent = `Error: ${error.message}`;
        errorDiv.style.display = 'block';
    }
}

async function getTechSupportDownloadUrl() {
    const statusDiv = document.getElementById('techSupportStatus');
    const downloadDiv = document.getElementById('techSupportDownload');
    const generateBtn = document.getElementById('generateTechSupportBtn');
    const fileNameText = document.getElementById('techSupportFileName');
    const downloadLink = document.getElementById('techSupportDownloadLink');

    try {
        const response = await fetch(`/api/tech-support/download/${techSupportJobId}`);
        const data = await response.json();

        if (data.status === 'success' && data.download_url) {
            // Hide status, show download
            statusDiv.style.display = 'none';
            downloadDiv.style.display = 'block';

            // Set download link and filename
            fileNameText.textContent = data.filename;
            downloadLink.href = data.download_url;

            // Re-enable generate button
            generateBtn.disabled = false;
            generateBtn.style.opacity = '1';
            generateBtn.style.cursor = 'pointer';
        } else {
            throw new Error(data.message || 'Failed to get download URL');
        }
    } catch (error) {
        console.error('Error getting download URL:', error);

        statusDiv.style.display = 'none';
        generateBtn.disabled = false;
        generateBtn.style.opacity = '1';
        generateBtn.style.cursor = 'pointer';

        const errorDiv = document.getElementById('techSupportErrorMessage');
        errorDiv.textContent = `Error: ${error.message}`;
        errorDiv.style.display = 'block';
    }
}

/**
 * Load and display firewall interface information
 */
// Global variables for interface sorting and filtering
let interfacesData = [];
let interfacesSortColumn = 'state'; // Default sort column
let interfacesSortDirection = 'asc'; // Default sort direction
let interfacesStateFilter = 'up'; // Default filter: show only up interfaces

// Global variables for interface traffic monitoring
let interfaceTrafficData = {}; // Stores historical traffic data for each interface
let interfaceTrafficCharts = {}; // Stores Chart.js instances for each interface
let interfaceTrafficInterval = null; // Interval ID for traffic updates
const MAX_INTERFACE_TRAFFIC_POINTS = 20; // Number of data points to show in traffic graphs

async function loadInterfaces() {
    const loadingDiv = document.getElementById('interfacesLoading');
    const contentDiv = document.getElementById('interfacesContent');
    const errorDiv = document.getElementById('interfacesErrorMessage');
    const tableDiv = document.getElementById('interfacesTable');

    // Show loading animation
    loadingDiv.style.display = 'block';
    contentDiv.style.display = 'none';
    errorDiv.style.display = 'none';

    try {
        const response = await fetch('/api/interfaces');
        const data = await response.json();

        // Hide loading animation
        loadingDiv.style.display = 'none';

        if (data.status === 'success' && data.interfaces && data.interfaces.length > 0) {
            errorDiv.style.display = 'none';
            contentDiv.style.display = 'block';

            // Store interfaces data globally for sorting
            interfacesData = data.interfaces;

            // Reset filter to "up" (default) on fresh load
            interfacesStateFilter = 'up';
            const filterSelect = document.getElementById('interfaceStateFilter');
            if (filterSelect) {
                filterSelect.value = 'up';
            }

            // Render the table with default sort and filter (state, then interface number)
            // renderInterfacesTable will update statistics
            renderInterfacesTable();

            // Start traffic monitoring
            startInterfaceTrafficMonitoring();

        } else if (data.status === 'error') {
            errorDiv.textContent = `Error: ${data.message || 'Failed to fetch interface information'}`;
            errorDiv.style.display = 'block';
        } else {
            errorDiv.textContent = 'No interfaces found';
            errorDiv.style.display = 'block';
        }

    } catch (error) {
        console.error('Error loading interfaces:', error);
        loadingDiv.style.display = 'none';
        errorDiv.textContent = `Error: ${error.message}`;
        errorDiv.style.display = 'block';
    }
}

/**
 * Render the interfaces table with current sort and filter settings
 */
function renderInterfacesTable() {
    const tableDiv = document.getElementById('interfacesTable');

    // Apply state filter first
    let filteredInterfaces = interfacesData;
    if (interfacesStateFilter === 'up') {
        filteredInterfaces = interfacesData.filter(iface => iface.state && iface.state.toLowerCase() === 'up');
    } else if (interfacesStateFilter === 'down') {
        filteredInterfaces = interfacesData.filter(iface => iface.state && iface.state.toLowerCase() === 'down');
    }

    // Sort the filtered interfaces
    const sortedInterfaces = sortInterfaces(filteredInterfaces, interfacesSortColumn, interfacesSortDirection);

    // Update statistics based on filtered data
    updateInterfaceStatistics(sortedInterfaces);

    // Build table HTML with sortable headers
    let tableHTML = `
        <table style="width: 100%; border-collapse: collapse; font-family: var(--font-secondary);">
            <thead>
                <tr style="background: #f5f5f5; border-bottom: 2px solid #FA582D;">
                    ${renderSortableHeader('name', 'Interface')}
                    ${renderSortableHeader('type', 'Type')}
                    ${renderSortableHeader('state', 'State')}
                    ${renderSortableHeader('ip', 'IP Address')}
                    ${renderSortableHeader('vlan', 'VLAN')}
                    ${renderSortableHeader('speed', 'Speed')}
                    ${renderSortableHeader('zone', 'Zone')}
                    <th style="padding: 12px; text-align: left; font-family: var(--font-primary); color: #333;">Traffic</th>
                </tr>
            </thead>
            <tbody>
    `;

    sortedInterfaces.forEach((iface, index) => {
        const rowBg = index % 2 === 0 ? '#fff' : '#f9f9f9';
        const stateColor = iface.state && iface.state.toLowerCase() === 'up' ? '#28a745' : '#dc3545';
        const stateIcon = iface.state && iface.state.toLowerCase() === 'up' ? '●' : '●';

        tableHTML += `
            <tr style="background: ${rowBg}; border-bottom: 1px solid #eee;">
                <td style="padding: 12px; font-weight: 600; color: #333; font-family: var(--font-primary);">${iface.name}</td>
                <td style="padding: 12px; color: #666;">${iface.type}</td>
                <td style="padding: 12px;"><span style="color: ${stateColor}; font-weight: 600;">${stateIcon} ${iface.state}</span></td>
                <td style="padding: 12px; color: #666;">${iface.ip}</td>
                <td style="padding: 12px; color: #666;">${iface.vlan}</td>
                <td style="padding: 12px; color: #666;">${iface.speed}</td>
                <td style="padding: 12px; color: #666;">${iface.zone}</td>
                <td style="padding: 12px;">
                    <div style="text-align: center; margin-bottom: 5px;">
                        <span id="traffic-rate-${iface.name.replace(/[\/\.]/g, '-')}" style="font-size: 0.85em; color: #FA582D; font-weight: 600; font-family: var(--font-primary);">0 Mbps</span>
                    </div>
                    <canvas id="traffic-chart-${iface.name.replace(/[\/\.]/g, '-')}" width="120" height="40" style="display: block;"></canvas>
                </td>
            </tr>
        `;
    });

    tableHTML += `
            </tbody>
        </table>
    `;

    tableDiv.innerHTML = tableHTML;

    // Initialize/update traffic charts for all visible interfaces
    requestAnimationFrame(() => {
        sortedInterfaces.forEach(iface => {
            initializeInterfaceTrafficChart(iface.name);
        });
    });
}

/**
 * Initialize traffic chart for a specific interface
 */
function initializeInterfaceTrafficChart(interfaceName) {
    const chartId = `traffic-chart-${interfaceName.replace(/[\/\.]/g, '-')}`;
    const canvas = document.getElementById(chartId);

    if (!canvas) return;

    // Initialize traffic data storage if not exists
    if (!interfaceTrafficData[interfaceName]) {
        interfaceTrafficData[interfaceName] = {
            data: [],
            previousBytes: null
        };
    }

    // Destroy existing chart if it exists
    if (interfaceTrafficCharts[interfaceName]) {
        interfaceTrafficCharts[interfaceName].destroy();
    }

    // Create new mini chart
    const ctx = canvas.getContext('2d');
    interfaceTrafficCharts[interfaceName] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(MAX_INTERFACE_TRAFFIC_POINTS).fill(''),
            datasets: [{
                data: Array(MAX_INTERFACE_TRAFFIC_POINTS).fill(0),
                borderColor: '#FA582D',
                backgroundColor: 'rgba(250, 88, 45, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            },
            scales: {
                x: { display: false },
                y: {
                    display: false,
                    beginAtZero: true
                }
            },
            animation: { duration: 0 }
        }
    });
}

/**
 * Update interface traffic charts with new data
 */
async function updateInterfaceTraffic() {
    try {
        const response = await fetch('/api/interface-traffic');
        const data = await response.json();

        if (data.status === 'success' && data.counters) {
            const currentTime = Date.now();

            // Update each interface's traffic data
            for (const [interfaceName, counters] of Object.entries(data.counters)) {
                if (!interfaceTrafficData[interfaceName]) {
                    interfaceTrafficData[interfaceName] = {
                        data: [],
                        previousBytes: null,
                        previousTime: null
                    };
                }

                const ifaceData = interfaceTrafficData[interfaceName];
                const totalBytes = counters.total_bytes;

                // Calculate rate (bytes per second)
                let rate = 0;
                if (ifaceData.previousBytes !== null && ifaceData.previousTime !== null) {
                    const byteDiff = totalBytes - ifaceData.previousBytes;
                    const timeDiff = (currentTime - ifaceData.previousTime) / 1000; // Convert to seconds

                    if (timeDiff > 0 && byteDiff >= 0) {
                        // Convert to Mbps
                        rate = (byteDiff * 8) / (timeDiff * 1000000);
                    }
                }

                // Store current values for next calculation
                ifaceData.previousBytes = totalBytes;
                ifaceData.previousTime = currentTime;

                // Add rate to data array
                ifaceData.data.push(rate);
                if (ifaceData.data.length > MAX_INTERFACE_TRAFFIC_POINTS) {
                    ifaceData.data.shift();
                }

                // Update chart if it exists
                const chart = interfaceTrafficCharts[interfaceName];
                if (chart) {
                    chart.data.datasets[0].data = [...ifaceData.data];
                    // Pad with zeros if not enough data points yet
                    while (chart.data.datasets[0].data.length < MAX_INTERFACE_TRAFFIC_POINTS) {
                        chart.data.datasets[0].data.unshift(0);
                    }
                    chart.update('none');
                }

                // Update traffic rate text display
                const rateId = `traffic-rate-${interfaceName.replace(/[\/\.]/g, '-')}`;
                const rateElement = document.getElementById(rateId);
                if (rateElement) {
                    // Format the rate nicely
                    let rateText;
                    if (rate >= 1000) {
                        // Show in Gbps if >= 1000 Mbps
                        rateText = `${(rate / 1000).toFixed(2)} Gbps`;
                    } else if (rate >= 1) {
                        // Show in Mbps with 2 decimal places
                        rateText = `${rate.toFixed(2)} Mbps`;
                    } else if (rate > 0) {
                        // Show in Kbps if less than 1 Mbps
                        rateText = `${(rate * 1000).toFixed(0)} Kbps`;
                    } else {
                        rateText = '0 Mbps';
                    }
                    rateElement.textContent = rateText;
                }
            }
        }
    } catch (error) {
        console.error('Error updating interface traffic:', error);
    }
}

/**
 * Start interface traffic monitoring
 */
function startInterfaceTrafficMonitoring() {
    // Clear existing interval if any
    if (interfaceTrafficInterval) {
        clearInterval(interfaceTrafficInterval);
    }

    // Initial update
    updateInterfaceTraffic();

    // Update every 15 seconds
    interfaceTrafficInterval = setInterval(updateInterfaceTraffic, 15000);
}

/**
 * Stop interface traffic monitoring
 */
function stopInterfaceTrafficMonitoring() {
    if (interfaceTrafficInterval) {
        clearInterval(interfaceTrafficInterval);
        interfaceTrafficInterval = null;
    }
}

/**
 * Update interface statistics display
 */
function updateInterfaceStatistics(interfaces) {
    const totalInterfaces = interfaces.length;
    const upInterfaces = interfaces.filter(iface => iface.state && iface.state.toLowerCase() === 'up').length;
    const downInterfaces = interfaces.filter(iface => iface.state && iface.state.toLowerCase() === 'down').length;

    document.getElementById('interfacesTotalCount').textContent = totalInterfaces;
    document.getElementById('interfacesUpCount').textContent = upInterfaces;
    document.getElementById('interfacesDownCount').textContent = downInterfaces;
}

/**
 * Apply interface state filter
 */
function applyInterfaceFilter() {
    const filterSelect = document.getElementById('interfaceStateFilter');
    interfacesStateFilter = filterSelect.value;
    renderInterfacesTable();
}

/**
 * Render a sortable table header
 */
function renderSortableHeader(column, label) {
    const isCurrentSort = interfacesSortColumn === column;
    const arrow = isCurrentSort ? (interfacesSortDirection === 'asc' ? ' ▲' : ' ▼') : '';
    const cursorStyle = 'cursor: pointer;';
    const hoverEffect = 'onmouseover="this.style.backgroundColor=\'#e8e8e8\'" onmouseout="this.style.backgroundColor=\'#f5f5f5\'"';

    return `<th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary); ${cursorStyle}"
                onclick="sortInterfacesBy('${column}')"
                ${hoverEffect}
                title="Click to sort by ${label}">
                ${label}${arrow}
            </th>`;
}

/**
 * Sort interfaces by column
 */
function sortInterfacesBy(column) {
    // Toggle direction if clicking the same column, otherwise default to ascending
    if (interfacesSortColumn === column) {
        interfacesSortDirection = interfacesSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        interfacesSortColumn = column;
        interfacesSortDirection = 'asc';
    }

    renderInterfacesTable();
}

/**
 * Sort interfaces array by column and direction
 */
function sortInterfaces(interfaces, column, direction) {
    const sorted = [...interfaces].sort((a, b) => {
        let aVal = a[column];
        let bVal = b[column];

        // Special handling for different columns
        if (column === 'state') {
            // State: up comes before down
            const stateOrder = { 'up': 1, 'down': 2, 'n/a': 3, '-': 3 };
            aVal = stateOrder[aVal?.toLowerCase()] || 999;
            bVal = stateOrder[bVal?.toLowerCase()] || 999;

            // Secondary sort by interface number if states are equal
            if (aVal === bVal) {
                return extractInterfaceNumber(a.name) - extractInterfaceNumber(b.name);
            }
        } else if (column === 'name') {
            // Interface name: sort by number extracted from name
            return extractInterfaceNumber(a.name) - extractInterfaceNumber(b.name);
        } else if (column === 'vlan') {
            // VLAN: sort numerically if possible
            const aNum = parseInt(aVal);
            const bNum = parseInt(bVal);
            if (!isNaN(aNum) && !isNaN(bNum)) {
                aVal = aNum;
                bVal = bNum;
            }
        }

        // Handle null/undefined values
        if (aVal === null || aVal === undefined || aVal === '-') aVal = '';
        if (bVal === null || bVal === undefined || bVal === '-') bVal = '';

        // Numeric comparison
        if (typeof aVal === 'number' && typeof bVal === 'number') {
            return direction === 'asc' ? aVal - bVal : bVal - aVal;
        }

        // String comparison
        const aStr = String(aVal).toLowerCase();
        const bStr = String(bVal).toLowerCase();

        if (direction === 'asc') {
            return aStr < bStr ? -1 : aStr > bStr ? 1 : 0;
        } else {
            return aStr > bStr ? -1 : aStr < bStr ? 1 : 0;
        }
    });

    return sorted;
}

/**
 * Extract numeric portion from interface name for natural sorting
 * Handles subinterfaces to keep them grouped with parent
 * e.g., "ethernet1/1" -> 1.001000, "ethernet1/1.100" -> 1.001100, "ethernet1/12" -> 1.012000
 */
function extractInterfaceNumber(interfaceName) {
    if (!interfaceName) return 0;

    // Check if this is a subinterface (has a dot)
    let subinterfaceNum = 0;
    let baseName = interfaceName;

    if (interfaceName.includes('.')) {
        const parts = interfaceName.split('.');
        baseName = parts[0];
        subinterfaceNum = parseInt(parts[1]) || 0;
    }

    // Match patterns like ethernet1/1, ae0, etc.
    const match = baseName.match(/(\d+)\/(\d+)|(\d+)/);
    if (match) {
        if (match[1] && match[2]) {
            // Pattern: ethernet1/1
            const major = parseInt(match[1]) || 0;
            const minor = parseInt(match[2]) || 0;
            // Combine: major.minorSUB (e.g., 1.001000 for ethernet1/1, 1.001100 for ethernet1/1.100)
            return major + (minor / 1000) + (subinterfaceNum / 1000000);
        } else if (match[3]) {
            // Pattern: ae0, vlan100, etc.
            const num = parseInt(match[3]) || 0;
            return num + (subinterfaceNum / 1000000);
        }
    }
    return 0;
}

/**
 * Initiate firewall reboot (standalone reboot tab)
 * Uses same modal and workflow as PAN-OS upgrade reboot
 */
async function initiateReboot() {
    // Show confirmation dialog
    if (!confirm('WARNING: This will reboot the firewall!\n\nAll network traffic will be interrupted and the firewall will be unavailable for 5-10 minutes.\n\nAre you sure you want to continue?')) {
        return;
    }

    // Show the PAN-OS upgrade modal with custom title for standalone reboot
    showUpgradeModal('Firewall Reboot in Progress');

    // Update modal to show reboot progress
    updateUpgradeProgress('Rebooting', 'Initiating firewall reboot...', 0, false);

    try {
        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

        // Wait a moment before initiating reboot
        await new Promise(resolve => setTimeout(resolve, 1500));

        // Send reboot request
        const response = await fetch('/api/panos-upgrade/reboot', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });

        const data = await response.json();

        if (data.status === 'success') {
            // Wait a moment to show reboot was initiated
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Start monitoring the reboot process using PAN-OS upgrade monitoring
            startRebootMonitoring();

        } else {
            // Show error in modal
            updateUpgradeProgress('Failed', `Reboot failed: ${data.message}`, 0, true);

            // Close modal after 3 seconds
            setTimeout(() => {
                hideUpgradeModal();
            }, 3000);
        }

    } catch (error) {
        // Show error in modal
        updateUpgradeProgress('Failed', `Error initiating reboot: ${error.message}`, 0, true);

        // Close modal after 3 seconds
        setTimeout(() => {
            hideUpgradeModal();
        }, 3000);
    }
}

// Reboot monitoring now handled by PAN-OS upgrade module (startRebootMonitoring)

