// Configuration (will be loaded from settings)
let UPDATE_INTERVAL = 60000; // Update every 60 seconds (Phase 2: database-first architecture)
const MAX_DATA_POINTS = 30; // Show last 30 data points
const MAX_MINI_POINTS = 20; // Mini charts show last 20 points

let updateIntervalId = null; // Store interval ID for updates
let sessionKeepaliveIntervalId = null; // Store interval ID for session keepalive (Tony Mode)

// Data storage
// Make chartData globally accessible
window.chartData = {
    labels: [],
    inbound: [],
    outbound: [],
    total: []
};
const chartData = window.chartData; // Create local alias for convenience

let miniChartData = {
    sessions: [],
    tcp: [],
    udp: [],
    pps: []
};

// Historical data for trend calculation (last 5 minutes worth of data)
let historicalData = {
    inbound: [],
    outbound: [],
    total: [],
    sessions: [],
    tcp: [],
    udp: [],
    icmp: [],
    criticalThreats: [],
    mediumThreats: [],
    blockedUrls: [],
    urlFiltering: [],
    interfaceErrors: []
};

// Storage for modal data
let currentCriticalLogs = [];
let currentMediumLogs = [];
let currentBlockedUrlLogs = [];
let currentTopApps = [];

// Mini chart instances
let sessionChart = null;
let tcpChart = null;
let udpChart = null;
let ppsChart = null;

// Initialize Chart.js
const ctx = document.getElementById('throughputChart').getContext('2d');
// Make chart globally accessible
const chart = window.chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: chartData.labels,
        datasets: [
            {
                label: 'Inbound',
                data: chartData.inbound,
                borderColor: '#ff6600',
                backgroundColor: 'rgba(255, 102, 0, 0.1)',
                borderWidth: 3,
                tension: 0.4,
                fill: true,
                pointRadius: 4,
                pointHoverRadius: 6
            },
            {
                label: 'Outbound',
                data: chartData.outbound,
                borderColor: '#ff9933',
                backgroundColor: 'rgba(255, 153, 51, 0.1)',
                borderWidth: 3,
                tension: 0.4,
                fill: true,
                pointRadius: 4,
                pointHoverRadius: 6
            },
            {
                label: 'Total',
                data: chartData.total,
                borderColor: '#333333',
                backgroundColor: 'rgba(51, 51, 51, 0.1)',
                borderWidth: 3,
                tension: 0.4,
                fill: true,
                pointRadius: 4,
                pointHoverRadius: 6
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
            mode: 'index',
            intersect: false,
        },
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                padding: 12,
                titleFont: {
                    size: 14
                },
                bodyFont: {
                    size: 13
                },
                callbacks: {
                    label: function(context) {
                        let label = context.dataset.label || '';
                        if (label) {
                            label += ': ';
                        }
                        label += context.parsed.y.toFixed(2) + ' MB';
                        return label;
                    }
                }
            }
        },
        scales: {
            x: {
                display: true,
                grid: {
                    display: false
                },
                ticks: {
                    font: {
                        size: 10
                    },
                    maxRotation: 0,
                    minRotation: 0,
                    maxTicksLimit: 10,
                    autoSkip: true,
                    autoSkipPadding: 10
                }
            },
            y: {
                display: true,
                beginAtZero: true,
                grid: {
                    color: 'rgba(0, 0, 0, 0.05)'
                },
                ticks: {
                    font: {
                        size: 12
                    },
                    callback: function(value) {
                        return value.toFixed(1) + ' Mbps';
                    }
                }
            }
        },
        animation: {
            duration: 750,
            easing: 'easeInOutQuart'
        }
    }
});

// Calculate trend from historical data
function calculateTrend(dataArray) {
    if (dataArray.length < 2) return ''; // Not enough data

    // Get first half and second half averages
    const halfPoint = Math.floor(dataArray.length / 2);
    const firstHalf = dataArray.slice(0, halfPoint);
    const secondHalf = dataArray.slice(halfPoint);

    const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    const percentChange = ((secondAvg - firstAvg) / firstAvg) * 100;

    if (percentChange > 5) {
        return '<span style="color: #ffffff; font-size: 0.8em; margin-left: 5px; opacity: 0.8;">▲</span>';
    } else if (percentChange < -5) {
        return '<span style="color: #ffffff; font-size: 0.8em; margin-left: 5px; opacity: 0.8;">▼</span>';
    } else {
        return '<span style="color: #ffffff; font-size: 0.8em; margin-left: 5px; opacity: 0.8;">━</span>';
    }
}

/**
 * Calculate average of data array (for 5-minute averages)
 * @param {Array} dataArray - Array of numeric values
 * @returns {number} - Average value, rounded to 2 decimal places
 */
function calculateAverage(dataArray) {
    if (!dataArray || dataArray.length === 0) return 0;
    const sum = dataArray.reduce((a, b) => a + b, 0);
    const avg = sum / dataArray.length;
    return Math.round(avg * 100) / 100; // Round to 2 decimal places
}

// Update the chart with new data
function updateChart(data) {
    const timestamp = new Date(data.timestamp);

    // Get user's timezone preference (default to UTC if not set)
    const userTz = window.userTimezone || 'UTC';

    // Format time using user's timezone
    const timeLabel = timestamp.toLocaleTimeString('en-US', {
        timeZone: userTz,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });

    // Add new data (backend already returns Mbps rates)
    chartData.labels.push(timeLabel);
    chartData.inbound.push(data.inbound_mbps);
    chartData.outbound.push(data.outbound_mbps);
    chartData.total.push(data.total_mbps);

    // Keep only the last MAX_DATA_POINTS
    if (chartData.labels.length > MAX_DATA_POINTS) {
        chartData.labels.shift();
        chartData.inbound.shift();
        chartData.outbound.shift();
        chartData.total.shift();
    }

    // Update chart datasets directly
    chart.data.labels = chartData.labels.slice();
    chart.data.datasets[0].data = chartData.inbound.slice();
    chart.data.datasets[1].data = chartData.outbound.slice();
    chart.data.datasets[2].data = chartData.total.slice();

    // Update chart
    chart.update('none'); // No animation for smoother updates
}

// Update stat cards
function updateStats(data) {
    // Store historical data for trends (keep last 30 data points = 30 minutes at 60 second intervals)
    historicalData.inbound.push(data.inbound_mbps);
    historicalData.outbound.push(data.outbound_mbps);
    historicalData.total.push(data.total_mbps);
    if (historicalData.inbound.length > 30) {
        historicalData.inbound.shift();
        historicalData.outbound.shift();
        historicalData.total.shift();
    }

    document.getElementById('inboundValue').innerHTML = data.inbound_mbps.toLocaleString() + calculateTrend(historicalData.inbound);
    document.getElementById('outboundValue').innerHTML = data.outbound_mbps.toLocaleString() + calculateTrend(historicalData.outbound);
    document.getElementById('totalValue').innerHTML = data.total_mbps.toLocaleString() + calculateTrend(historicalData.total);

    // Calculate 5-minute averages (last 5 samples at 60-second intervals = 300 seconds = 5 minutes)
    const last5Inbound = historicalData.inbound.slice(-5);
    const last5Outbound = historicalData.outbound.slice(-5);
    const last5Total = historicalData.total.slice(-5);

    const inboundAvg = calculateAverage(last5Inbound);
    const outboundAvg = calculateAverage(last5Outbound);
    const totalAvg = calculateAverage(last5Total);

    document.getElementById('inboundAvg').textContent = inboundAvg.toLocaleString();
    document.getElementById('outboundAvg').textContent = outboundAvg.toLocaleString();
    document.getElementById('totalAvg').textContent = totalAvg.toLocaleString();

    // Update session counts and mini chart
    if (data.sessions) {
        // Store historical data (keep last 30 data points = 30 minutes at 60 second intervals)
        historicalData.sessions.push(data.sessions.active);
        historicalData.tcp.push(data.sessions.tcp);
        historicalData.udp.push(data.sessions.udp);
        historicalData.icmp.push(data.sessions.icmp);
        if (historicalData.sessions.length > 30) {
            historicalData.sessions.shift();
            historicalData.tcp.shift();
            historicalData.udp.shift();
            historicalData.icmp.shift();
        }

        document.getElementById('sessionValue').innerHTML = data.sessions.active.toLocaleString() + calculateTrend(historicalData.sessions);
        document.getElementById('tcpValue').innerHTML = data.sessions.tcp.toLocaleString() + calculateTrend(historicalData.tcp);
        document.getElementById('udpValue').innerHTML = data.sessions.udp.toLocaleString() + calculateTrend(historicalData.udp);
        document.getElementById('icmpValue').innerHTML = data.sessions.icmp.toLocaleString() + calculateTrend(historicalData.icmp);

        miniChartData.sessions.push(data.sessions.active);
        if (miniChartData.sessions.length > MAX_MINI_POINTS) {
            miniChartData.sessions.shift();
        }
        updateMiniChart(sessionChart, miniChartData.sessions, '#ff6600');

        miniChartData.tcp.push(data.sessions.tcp);
        if (miniChartData.tcp.length > MAX_MINI_POINTS) {
            miniChartData.tcp.shift();
        }
        updateMiniChart(tcpChart, miniChartData.tcp, '#3b82f6');

        miniChartData.udp.push(data.sessions.udp);
        if (miniChartData.udp.length > MAX_MINI_POINTS) {
            miniChartData.udp.shift();
        }
        updateMiniChart(udpChart, miniChartData.udp, '#8b5cf6');
    }

    // Update CPU metrics and mini charts
    if (data.cpu) {
        // Store historical data
        // Update uptime display in sidebar
        const sidebarUptimeElement = document.getElementById('sidebarUptime');
        if (data.cpu.uptime && sidebarUptimeElement) {
            sidebarUptimeElement.textContent = data.cpu.uptime;
        }

        // Update PPS display in Network Traffic tile
        const totalPpsElement = document.getElementById('totalPps');
        const inboundPpsElement = document.getElementById('inboundPps');
        const outboundPpsElement = document.getElementById('outboundPps');

        if (data.total_pps !== undefined && totalPpsElement) {
            totalPpsElement.textContent = data.total_pps.toLocaleString();
        }
        if (data.inbound_pps !== undefined && inboundPpsElement) {
            inboundPpsElement.textContent = data.inbound_pps.toLocaleString();
        }
        if (data.outbound_pps !== undefined && outboundPpsElement) {
            outboundPpsElement.textContent = data.outbound_pps.toLocaleString();
        }

        // Update PPS mini chart
        if (data.total_pps !== undefined) {
            miniChartData.pps.push(data.total_pps);
            if (miniChartData.pps.length > MAX_MINI_POINTS) {
                miniChartData.pps.shift();
            }
            updateMiniChart(ppsChart, miniChartData.pps, '#ffffff');
        }

    }

    // Update PAN-OS version in sidebar
    if (data.panos_version !== undefined) {
        const versionElement = document.getElementById('sidebarPanosVersion');
        if (versionElement) {
            versionElement.textContent = data.panos_version || 'N/A';
        }
    }

    // Update WAN IP in sidebar
    if (data.wan_ip !== undefined) {
        const wanIpElement = document.getElementById('sidebarWanIp');
        if (wanIpElement) {
            wanIpElement.textContent = data.wan_ip || '-';
        }
    }

    // Update WAN speed in sidebar
    if (data.wan_speed !== undefined) {
        const wanSpeedElement = document.getElementById('sidebarWanSpeed');
        if (wanSpeedElement) {
            // Speed is already formatted with Mbps/Gbps suffix from backend
            wanSpeedElement.textContent = data.wan_speed || '-';
        }
    }

    // Update interface stats
    if (data.interfaces) {
        const interfaceErrorsElement = document.getElementById('interfaceErrorsValue');
        const interfaceDetailsElement = document.getElementById('interfaceDetails');

        if (interfaceErrorsElement) {
            const totalIssues = data.interfaces.total_errors + data.interfaces.total_drops;

            // Store historical data
            historicalData.interfaceErrors.push(totalIssues);
            if (historicalData.interfaceErrors.length > 30) {
                historicalData.interfaceErrors.shift();
            }

            interfaceErrorsElement.innerHTML = totalIssues.toLocaleString() + calculateTrend(historicalData.interfaceErrors);

            if (interfaceDetailsElement) {
                interfaceDetailsElement.textContent = `${data.interfaces.total_errors.toLocaleString()} errors, ${data.interfaces.total_drops.toLocaleString()} drops`;
            }
        }
    }

    // Update top applications
    if (data.top_applications) {
        const topAppsValueElement = document.getElementById('topAppsValue');
        const topAppsContainer = document.getElementById('topAppsContainer');
        const topAppNameElement = document.getElementById('topAppName');

        // Store for modals
        currentTopApps = data.top_applications.apps || [];

        // Update total count
        if (topAppsValueElement) {
            topAppsValueElement.textContent = data.top_applications.total_count || 0;
        }

        // Update top application name
        if (topAppNameElement) {
            if (data.top_applications.apps && data.top_applications.apps.length > 0) {
                topAppNameElement.textContent = data.top_applications.apps[0].name;
            } else {
                topAppNameElement.textContent = 'N/A';
            }
        }

        // Update the list of apps
        if (topAppsContainer && data.top_applications.apps && data.top_applications.apps.length > 0) {
            let appsHtml = '';
            data.top_applications.apps.forEach((app) => {
                const barWidth = data.top_applications.apps[0].count > 0 ? (app.count / data.top_applications.apps[0].count * 100) : 0;
                appsHtml += `
                    <div style="margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                            <span style="color: #ffffff; font-size: 0.85em;">${app.name}</span>
                            <span style="color: #ffcc99; font-size: 0.85em; font-weight: 600;">${app.count}</span>
                        </div>
                        <div style="background: rgba(255,255,255,0.2); border-radius: 4px; height: 6px; overflow: hidden;">
                            <div style="background: #ffffff; height: 100%; width: ${barWidth}%; transition: width 0.3s ease;"></div>
                        </div>
                    </div>
                `;
            });
            topAppsContainer.innerHTML = appsHtml;
        } else if (topAppsContainer) {
            topAppsContainer.innerHTML = '<div style="color: rgba(255,255,255,0.7); font-size: 0.85em; text-align: center;">No data</div>';
        }
    }

    // Update threat statistics and logs
    if (data.threats) {
        // Store historical data
        historicalData.criticalThreats.push(data.threats.critical_threats);
        historicalData.mediumThreats.push(data.threats.medium_threats);
        historicalData.blockedUrls.push(data.threats.blocked_urls);
        historicalData.urlFiltering.push(data.threats.url_filtering_total);
        if (historicalData.criticalThreats.length > 30) {
            historicalData.criticalThreats.shift();
            historicalData.mediumThreats.shift();
            historicalData.blockedUrls.shift();
            historicalData.urlFiltering.shift();
        }

        document.getElementById('criticalValue').innerHTML = data.threats.critical_threats.toLocaleString();
        document.getElementById('mediumValue').innerHTML = data.threats.medium_threats.toLocaleString();
        document.getElementById('blockedUrlValue').innerHTML = data.threats.blocked_urls.toLocaleString();

        // Store threat logs for modals
        currentCriticalLogs = data.threats.critical_logs || [];
        currentMediumLogs = data.threats.medium_logs || [];
        currentBlockedUrlLogs = data.threats.blocked_url_logs || [];

        // Update last seen stats in tiles
        const criticalLastSeen = document.getElementById('criticalLastSeen');
        const mediumLastSeen = document.getElementById('mediumLastSeen');
        const blockedUrlLastSeen = document.getElementById('blockedUrlLastSeen');

        if (criticalLastSeen) {
            criticalLastSeen.textContent = formatDaysAgo(data.threats.critical_last_seen);
        }
        if (mediumLastSeen) {
            mediumLastSeen.textContent = formatDaysAgo(data.threats.medium_last_seen);
        }
        if (blockedUrlLastSeen) {
            blockedUrlLastSeen.textContent = formatDaysAgo(data.threats.blocked_url_last_seen);
        }
    }

    // System logs are now on their own page, no need to update here

    // Update license information in sidebar
    if (data.license) {
        const expiredElement = document.getElementById('sidebarLicenseExpired');
        const licensedElement = document.getElementById('sidebarLicenseLicensed');

        if (expiredElement) {
            expiredElement.textContent = data.license.expired || 0;
            // Use brand theme color
            expiredElement.style.color = '#FA582D';
        }

        if (licensedElement) {
            licensedElement.textContent = data.license.licensed || 0;
            // Use brand theme color
            licensedElement.style.color = '#FA582D';
        }
    }
}

function updateThreatLogs(elementId, logs, borderColor) {
    const container = document.getElementById(elementId);
    container.innerHTML = '';

    if (logs.length === 0) {
        container.innerHTML = '<div style="font-size: 0.7em; color: #999; padding: 5px;">No recent matches</div>';
        return;
    }

    // Create table
    const table = document.createElement('table');
    table.className = 'threat-log-table';

    // Create header
    const thead = document.createElement('thead');
    thead.innerHTML = `
        <tr>
            <th style="width: 60%;">Threat/URL</th>
            <th style="width: 40%;">Time</th>
        </tr>
    `;
    table.appendChild(thead);

    // Create body
    const tbody = document.createElement('tbody');

    logs.forEach(log => {
        const row = document.createElement('tr');
        row.style.borderLeftColor = borderColor;

        const threat = log.threat || log.url || 'Unknown';
        const src = log.src || 'N/A';
        const dst = log.dst || 'N/A';
        const dport = log.dport || 'N/A';
        const sport = log.sport || 'N/A';
        const action = log.action || 'N/A';
        const app = log.app || 'N/A';
        const category = log.category || 'N/A';
        const severity = log.severity || 'N/A';
        const datetime = log.time ? new Date(log.time) : null;

        // Get user's timezone preference (default to UTC if not set)
        const userTz = window.userTimezone || 'UTC';

        const time = datetime ? datetime.toLocaleTimeString('en-US', {
            timeZone: userTz,
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        }) : 'N/A';
        const fullTime = datetime ? datetime.toLocaleString('en-US', {
            timeZone: userTz,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        }) : 'N/A';

        // Build comprehensive tooltip
        let tooltipParts = [
            `Threat/URL: ${threat}`,
            `Time: ${fullTime}`,
            `Source: ${src}:${sport}`,
            `Destination: ${dst}:${dport}`,
            `Action: ${action}`,
            `Application: ${app}`
        ];

        if (severity !== 'N/A') tooltipParts.push(`Severity: ${severity}`);
        if (category !== 'N/A') tooltipParts.push(`Category: ${category}`);

        const tooltip = tooltipParts.join('\n');

        row.innerHTML = `
            <td style="border-left-color: ${borderColor};">
                <div class="threat-name" title="${tooltip}">${threat}</div>
            </td>
            <td style="border-left-color: ${borderColor};">
                <div class="threat-time" title="${tooltip}">${time}</div>
            </td>
        `;

        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    container.appendChild(table);
}

// Initialize and update mini sparkline charts
function createMiniChart(canvasId, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx.getContext('2d'), {
        type: 'line',
        data: {
            labels: Array(MAX_MINI_POINTS).fill(''),
            datasets: [{
                data: [],
                borderColor: color,
                backgroundColor: color + '20',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            },
            scales: {
                x: { display: false },
                y: { display: false }
            },
            animation: { duration: 0 }
        }
    });
}

function updateMiniChart(chart, data, color) {
    if (!chart) return;

    chart.data.datasets[0].data = data;
    chart.update('none');
}

// Update status indicator
function updateStatus(isOnline, message = '', deviceName = '') {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');

    if (isOnline) {
        statusDot.classList.remove('offline');
        statusDot.classList.add('online');
        // If device name is provided, use it. Otherwise preserve existing text if it already has a device name
        if (deviceName) {
            statusText.textContent = `Connected: ${deviceName}`;
        } else if (!statusText.textContent.includes(':')) {
            // Only change to generic "Connected" if there's no device name already
            statusText.textContent = 'Connected';
        }
        // else: preserve existing "Connected: DeviceName" text
    } else {
        statusDot.classList.remove('online');
        statusDot.classList.add('offline');
        // Special message for no devices configured
        if (message === 'no_device') {
            statusText.textContent = 'No device connected';
        } else if (deviceName) {
            statusText.textContent = `Disconnected: ${deviceName}`;
        } else if (!statusText.textContent.includes(':')) {
            statusText.textContent = message || 'Disconnected';
        }
        // else: preserve existing "Disconnected: DeviceName" text
    }
}

// Show error message
function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.textContent = `Error: ${message}`;
    errorDiv.style.display = 'block';

    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

// Fetch data from API
async function fetchThroughputData() {
    try {
        const response = await fetch('/api/throughput');

        // Handle authentication errors
        if (response.status === 401) {
            console.log('Session expired, redirecting to login...');
            window.location.href = '/login';
            return;
        }

        // Handle rate limiting
        if (response.status === 429) {
            console.warn('Rate limit exceeded');
            updateStatus(false);
            showError('Rate limit exceeded. Please wait before trying again.');
            return;
        }

        // Check if response is JSON
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            throw new Error('Expected JSON response but got ' + contentType);
        }

        const data = await response.json();

        if (data.status === 'success') {
            updateStats(data);
            updateChart(data);
            updateStatus(true);

        } else {
            updateStatus(false);
            showError(data.message || 'Failed to fetch data');
        }
    } catch (error) {
        console.error('Fetch error:', error);
        updateStatus(false);
        showError('Connection error: ' + error.message);
    }
}

// Add smooth number animation
function animateValue(element, start, end, duration) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            current = end;
            clearInterval(timer);
        }
        element.textContent = current.toFixed(2);
    }, 16);
}

/**
 * Preload recent historical data to populate chart on page load
 * Queries last 30 minutes of data from database to avoid empty chart
 * Also preloads mini chart data for PPS and Sessions
 */
async function preloadChartData() {
    try {
        console.log('Preloading recent historical data for charts...');

        const deviceId = selectedDeviceId || currentSettings?.selected_device_id;
        if (!deviceId) {
            console.warn('No device selected for preload, skipping...');
            return;
        }

        // Query last 30 minutes of data (should give us MAX_DATA_POINTS worth)
        const response = await fetch(`/api/throughput/history?device_id=${deviceId}&range=30m`);
        const data = await response.json();

        if (data.status === 'success' && data.samples && data.samples.length > 0) {
            console.log(`Preloaded ${data.samples.length} historical samples`);

            // Clear existing data
            chartData.labels = [];
            chartData.inbound = [];
            chartData.outbound = [];
            chartData.total = [];

            // Clear mini chart data
            miniChartData.pps = [];
            miniChartData.sessions = [];
            miniChartData.tcp = [];
            miniChartData.udp = [];

            // Take last MAX_DATA_POINTS for main chart, last MAX_MINI_POINTS for mini charts
            const mainChartSamples = data.samples.slice(-MAX_DATA_POINTS);
            const miniChartSamples = data.samples.slice(-MAX_MINI_POINTS);

            // Populate main chart data arrays
            mainChartSamples.forEach(sample => {
                const timestamp = new Date(sample.timestamp).toLocaleTimeString();
                chartData.labels.push(timestamp);
                chartData.inbound.push(sample.inbound_mbps || 0);
                chartData.outbound.push(sample.outbound_mbps || 0);
                chartData.total.push(sample.total_mbps || 0);
            });

            // Populate mini chart data arrays
            miniChartSamples.forEach(sample => {
                // PPS data
                miniChartData.pps.push(sample.total_pps || 0);

                // Sessions data
                miniChartData.sessions.push(sample.sessions_active || 0);
                miniChartData.tcp.push(sample.sessions_tcp || 0);
                miniChartData.udp.push(sample.sessions_udp || 0);
            });

            // Update main chart with preloaded data
            chart.update();

            // Update mini charts with preloaded data
            if (ppsChart) {
                updateMiniChart(ppsChart, miniChartData.pps, '#ffffff');
            }
            if (sessionChart) {
                updateMiniChart(sessionChart, miniChartData.sessions, '#ff6600');
            }
            if (tcpChart) {
                updateMiniChart(tcpChart, miniChartData.tcp, '#3b82f6');
            }
            if (udpChart) {
                updateMiniChart(udpChart, miniChartData.udp, '#8b5cf6');
            }

            console.log(`Charts initialized with ${chartData.labels.length} main chart points and ${miniChartData.pps.length} mini chart points`);
        } else {
            console.log('No historical data available for preload');
        }
    } catch (error) {
        console.error('Error preloading chart data:', error);
        // Continue with empty chart if preload fails
    }
}

// Initialize the application
let isInitialized = false;
async function init() {
    if (isInitialized) {
        console.log('App already initialized, skipping...');
        return;
    }

    console.log('Initializing Palo Alto Firewall Monitor...');
    isInitialized = true;

    // Load settings first
    await initSettings();

    // Load devices and populate device selector
    if (typeof loadDevices === 'function') {
        await loadDevices();
        console.log('Devices loaded on initialization');
    }

    // Initialize mini charts (destroy existing ones first to avoid "Canvas already in use" error)
    if (sessionChart) sessionChart.destroy();
    if (tcpChart) tcpChart.destroy();
    if (udpChart) udpChart.destroy();
    if (ppsChart) ppsChart.destroy();

    sessionChart = createMiniChart('sessionChart', '#ffffff');
    tcpChart = createMiniChart('tcpChart', '#3b82f6');
    udpChart = createMiniChart('udpChart', '#8b5cf6');
    ppsChart = createMiniChart('ppsChart', '#ffffff');

    // Set up interface update button
    const updateInterfaceBtn = document.getElementById('updateInterfaceBtn');
    if (updateInterfaceBtn) {
        updateInterfaceBtn.addEventListener('click', updateMonitoredInterface);
    }

    // Set up logout button
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }

    // Set up time range buttons
    const timeRangeButtons = document.querySelectorAll('.time-range-btn');
    timeRangeButtons.forEach(btn => {
        btn.addEventListener('click', () => handleTimeRangeChange(btn.dataset.range));
    });

    // Set up export and stats buttons
    const exportBtn = document.getElementById('exportHistoryBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportHistoricalData);
    }

    const toggleStatsBtn = document.getElementById('toggleStatsBtn');
    if (toggleStatsBtn) {
        toggleStatsBtn.addEventListener('click', toggleStatistics);
    }

    const closeStatsBtn = document.getElementById('closeStatsBtn');
    if (closeStatsBtn) {
        closeStatsBtn.addEventListener('click', () => {
            document.getElementById('statsPanel').style.display = 'none';
        });
    }

    // Preload recent historical data to populate chart
    await preloadChartData();

    // Initial fetch
    fetchThroughputData();

    // Set up polling with the loaded UPDATE_INTERVAL
    updateIntervalId = setInterval(fetchThroughputData, UPDATE_INTERVAL);
}

// Start the app when DOM is ready
document.addEventListener('DOMContentLoaded', init);

// ============================================================================
// Historical Throughput Functionality
// ============================================================================

let currentTimeRange = 'realtime';

/**
 * Handle time range button click
 */
async function handleTimeRangeChange(range) {
    console.log('Time range changed to:', range);
    currentTimeRange = range;

    // Update button styles
    document.querySelectorAll('.time-range-btn').forEach(btn => {
        if (btn.dataset.range === range) {
            btn.style.background = 'linear-gradient(135deg, #FA582D 0%, #FF7A55 100%)';
        } else {
            btn.style.background = '#4a5568';
        }
    });

    if (range === 'realtime') {
        // Resume real-time updates
        if (!updateIntervalId) {
            updateIntervalId = setInterval(fetchThroughputData, UPDATE_INTERVAL);
        }
        fetchThroughputData();

        // Hide export and stats buttons in real-time mode
        document.getElementById('exportHistoryBtn').style.display = 'none';
        document.getElementById('toggleStatsBtn').style.display = 'none';
        document.getElementById('statsPanel').style.display = 'none';
    } else {
        // Stop real-time updates
        if (updateIntervalId) {
            clearInterval(updateIntervalId);
            updateIntervalId = null;
        }
        // Load historical data
        await loadHistoricalThroughput(range);
    }
}

/**
 * Load historical throughput data
 */
async function loadHistoricalThroughput(range) {
    try {
        console.log('Loading historical data for range:', range);

        const deviceId = selectedDeviceId || currentSettings?.selected_device_id;
        if (!deviceId) {
            console.warn('No device selected');
            return;
        }

        const response = await fetch(`/api/throughput/history?device_id=${deviceId}&range=${range}`);
        const data = await response.json();

        if (data.status === 'success' && data.samples) {
            console.log(`Loaded ${data.samples.length} historical samples (${data.resolution} resolution)`);

            // Clear existing chart data
            throughputChart.data.labels = [];
            throughputChart.data.datasets[0].data = [];
            throughputChart.data.datasets[1].data = [];
            throughputChart.data.datasets[2].data = [];

            // Add historical data to chart
            data.samples.forEach(sample => {
                const timestamp = new Date(sample.timestamp).toLocaleTimeString();
                throughputChart.data.labels.push(timestamp);
                throughputChart.data.datasets[0].data.push(sample.inbound_mbps || 0);
                throughputChart.data.datasets[1].data.push(sample.outbound_mbps || 0);
                throughputChart.data.datasets[2].data.push(sample.total_mbps || 0);
            });

            throughputChart.update();

            // Show export and stats buttons when viewing historical data
            document.getElementById('exportHistoryBtn').style.display = 'block';
            document.getElementById('toggleStatsBtn').style.display = 'block';

            // Auto-load statistics
            loadHistoricalStats(range);
        } else {
            console.error('Failed to load historical data:', data.message);
        }
    } catch (error) {
        console.error('Error loading historical data:', error);
    }
}

/**
 * Load historical statistics
 */
async function loadHistoricalStats(range) {
    try {
        const deviceId = selectedDeviceId || currentSettings?.selected_device_id;
        if (!deviceId) return;

        const response = await fetch(`/api/throughput/history/stats?device_id=${deviceId}&range=${range}`);
        const data = await response.json();

        if (data.status === 'success' && data.stats) {
            // Update stats display
            document.getElementById('statsInboundMin').textContent = data.stats.inbound_mbps.min;
            document.getElementById('statsInboundMax').textContent = data.stats.inbound_mbps.max;
            document.getElementById('statsInboundAvg').textContent = data.stats.inbound_mbps.avg;

            document.getElementById('statsOutboundMin').textContent = data.stats.outbound_mbps.min;
            document.getElementById('statsOutboundMax').textContent = data.stats.outbound_mbps.max;
            document.getElementById('statsOutboundAvg').textContent = data.stats.outbound_mbps.avg;

            document.getElementById('statsTotalMin').textContent = data.stats.total_mbps.min;
            document.getElementById('statsTotalMax').textContent = data.stats.total_mbps.max;
            document.getElementById('statsTotalAvg').textContent = data.stats.total_mbps.avg;

            document.getElementById('statsSampleCount').textContent = data.sample_count.toLocaleString();
        }
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

/**
 * Toggle statistics panel
 */
function toggleStatistics() {
    const panel = document.getElementById('statsPanel');
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
    } else {
        panel.style.display = 'none';
    }
}

/**
 * Export historical data to CSV
 */
function exportHistoricalData() {
    const deviceId = selectedDeviceId || currentSettings?.selected_device_id;
    if (!deviceId) {
        console.warn('No device selected');
        return;
    }

    // Open export URL in new window to trigger download
    const exportUrl = `/api/throughput/history/export?device_id=${deviceId}&range=${currentTimeRange}`;
    window.open(exportUrl, '_blank');
}

// ============================================================================
// Logout Functionality
// ============================================================================

/**
 * Handle logout - clears session and redirects to login page
 */
async function handleLogout() {
    try {
        // Get CSRF token
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

        // Call logout API
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        });

        // Redirect to login page regardless of response
        // This ensures user is logged out even if API call fails
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
        // Still redirect to login page on error
        window.location.href = '/login';
    }
}

// updateMonitoredInterface function moved to devices.js where selectedDeviceId and currentDevices are defined

// Sidebar resize functionality
function initSidebarResize() {
    const sidebar = document.querySelector('.sidebar');
    const resizeHandle = document.querySelector('.resize-handle');
    let isResizing = false;

    resizeHandle.addEventListener('mousedown', () => {
        isResizing = true;
        document.body.style.cursor = 'ew-resize';
        document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;

        const newWidth = e.clientX;
        const minWidth = parseInt(getComputedStyle(sidebar).minWidth);
        const maxWidth = parseInt(getComputedStyle(sidebar).maxWidth);

        if (newWidth >= minWidth && newWidth <= maxWidth) {
            sidebar.style.width = newWidth + 'px';
        }
    });

    document.addEventListener('mouseup', () => {
        isResizing = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    });
}

// Page navigation
// Track currently visible page for device change refreshes
let currentVisiblePage = 'homepage';

function initPageNavigation() {
    const menuItems = document.querySelectorAll('.menu-item');
    const pages = {
        'homepage': document.getElementById('homepage-content'),
        'connected-devices': document.getElementById('connected-devices-content'),
        'applications': document.getElementById('applications-content'),
        'device-info': document.getElementById('device-info-content'),
        'logs': document.getElementById('logs-content'),
        'devices': document.getElementById('devices-content'),
        'settings': document.getElementById('settings-content')
    };

    menuItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetPage = item.getAttribute('data-page');
            currentVisiblePage = targetPage; // Track current page

            // Update active menu item
            menuItems.forEach(mi => mi.classList.remove('active'));
            item.classList.add('active');

            // Show target page, hide others
            Object.keys(pages).forEach(pageKey => {
                if (pageKey === targetPage) {
                    pages[pageKey].style.display = 'block';
                    if (pageKey === 'device-info') {
                        // Load interfaces by default (first tab)
                        loadInterfaces();
                    } else if (pageKey === 'connected-devices') {
                        loadConnectedDevices();
                    } else if (pageKey === 'applications') {
                        loadApplications();
                        setupApplicationsEventListeners();
                    } else if (pageKey === 'logs') {
                        // Load system logs by default (first tab)
                        loadSystemLogs();
                    } else if (pageKey === 'devices') {
                        loadDevices();
                    } else if (pageKey === 'settings') {
                        loadSettings();
                    }
                } else {
                    pages[pageKey].style.display = 'none';
                }
            });
        });
    });

    // Modal event listeners for devices page
    const addDeviceBtn = document.getElementById('addDeviceBtn');
    if (addDeviceBtn) {
        addDeviceBtn.addEventListener('click', () => showDeviceModal());
    }

    const closeModalBtn = document.getElementById('closeModalBtn');
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', hideDeviceModal);
    }

    const cancelModalBtn = document.getElementById('cancelModalBtn');
    if (cancelModalBtn) {
        cancelModalBtn.addEventListener('click', hideDeviceModal);
    }

    const deviceForm = document.getElementById('deviceForm');
    if (deviceForm) {
        deviceForm.addEventListener('submit', saveDevice);
    }

    const testConnectionBtn = document.getElementById('testConnectionBtn');
    if (testConnectionBtn) {
        testConnectionBtn.addEventListener('click', testConnection);
    }

    // Logs page tab switching
    const logsTabs = document.querySelectorAll('.logs-tab');
    if (logsTabs.length > 0) {
        logsTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.getAttribute('data-tab');

                // Update active tab styling
                logsTabs.forEach(t => {
                    t.classList.remove('active');
                    t.style.color = 'rgba(255, 255, 255, 0.6)';
                    t.style.borderBottom = '3px solid transparent';
                });
                tab.classList.add('active');
                tab.style.color = '#FA582D';
                tab.style.borderBottom = '3px solid #FA582D';

                // Show target tab content, hide others
                const systemLogsTab = document.getElementById('system-logs-tab');
                const trafficLogsTab = document.getElementById('traffic-logs-tab');

                if (targetTab === 'system-logs') {
                    systemLogsTab.style.display = 'block';
                    trafficLogsTab.style.display = 'none';
                    loadSystemLogs();
                } else if (targetTab === 'traffic-logs') {
                    systemLogsTab.style.display = 'none';
                    trafficLogsTab.style.display = 'block';
                    updateTrafficPage();
                }
            });
        });
    }

    // Device Info page tab switching
    const deviceInfoTabs = document.querySelectorAll('.device-info-tab');
    if (deviceInfoTabs.length > 0) {
        deviceInfoTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.getAttribute('data-tab');

                // Update active tab styling
                deviceInfoTabs.forEach(t => {
                    t.classList.remove('active');
                    t.style.color = 'rgba(255, 255, 255, 0.6)';
                    t.style.borderBottom = '3px solid transparent';
                });
                tab.classList.add('active');
                tab.style.color = '#FA582D';
                tab.style.borderBottom = '3px solid #FA582D';

                // Show target tab content, hide others
                const softwareUpdatesTab = document.getElementById('software-updates-tab');
                const interfacesTab = document.getElementById('interfaces-tab');
                const dhcpTab = document.getElementById('dhcp-tab');
                const techSupportTab = document.getElementById('tech-support-tab');
                const rebootTab = document.getElementById('reboot-tab');

                if (targetTab === 'software-updates') {
                    softwareUpdatesTab.style.display = 'block';
                    interfacesTab.style.display = 'none';
                    dhcpTab.style.display = 'none';
                    techSupportTab.style.display = 'none';
                    rebootTab.style.display = 'none';
                    loadSoftwareUpdates();
                } else if (targetTab === 'interfaces') {
                    softwareUpdatesTab.style.display = 'none';
                    interfacesTab.style.display = 'block';
                    dhcpTab.style.display = 'none';
                    techSupportTab.style.display = 'none';
                    rebootTab.style.display = 'none';
                    loadInterfaces();
                } else if (targetTab === 'dhcp') {
                    softwareUpdatesTab.style.display = 'none';
                    interfacesTab.style.display = 'none';
                    dhcpTab.style.display = 'block';
                    techSupportTab.style.display = 'none';
                    rebootTab.style.display = 'none';
                    loadDhcpLeases();
                } else if (targetTab === 'tech-support') {
                    softwareUpdatesTab.style.display = 'none';
                    interfacesTab.style.display = 'none';
                    dhcpTab.style.display = 'none';
                    techSupportTab.style.display = 'block';
                    rebootTab.style.display = 'none';
                } else if (targetTab === 'reboot') {
                    softwareUpdatesTab.style.display = 'none';
                    interfacesTab.style.display = 'none';
                    dhcpTab.style.display = 'none';
                    techSupportTab.style.display = 'none';
                    rebootTab.style.display = 'block';
                }
            });
        });
    }

    // Software Updates sub-tab switching (PAN-OS / Components)
    const softwareSubTabs = document.querySelectorAll('.software-sub-tab');
    if (softwareSubTabs.length > 0) {
        softwareSubTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.getAttribute('data-tab');

                // Update active sub-tab styling
                softwareSubTabs.forEach(t => {
                    t.classList.remove('active');
                    t.style.color = 'rgba(255, 255, 255, 0.6)';
                    t.style.borderBottom = '3px solid transparent';
                });
                tab.classList.add('active');
                tab.style.color = '#FA582D';
                tab.style.borderBottom = '3px solid #FA582D';

                // Show target sub-tab content, hide others
                const panosSubTab = document.getElementById('panos-sub-tab');
                const componentsSubTab = document.getElementById('components-sub-tab');

                if (targetTab === 'panos') {
                    panosSubTab.style.display = 'block';
                    componentsSubTab.style.display = 'none';
                } else if (targetTab === 'components') {
                    panosSubTab.style.display = 'none';
                    componentsSubTab.style.display = 'block';
                }
            });
        });
    }
}

/**
 * CRITICAL: Centralized Device Change Handler
 *
 * This function is responsible for clearing and refreshing ALL data when
 * the connected device changes. Any new features that display data MUST
 * be registered here to ensure proper refresh on device change.
 *
 * Called by: onDeviceChange() in devices.js
 *
 * Responsibilities:
 * 1. Clear all chart data and reset charts
 * 2. Zero/reset all dashboard values and show loading states
 * 3. Clear all historical data arrays
 * 4. Reset all mini charts
 * 5. Clear threat logs and application displays
 * 6. Trigger refresh of all page-specific data
 * 7. Restart update interval with fresh data
 *
 * IMPORTANT: When adding new data displays to the dashboard or any page,
 * you MUST update this function to clear/reset those values.
 */
function refreshAllDataForDevice() {
    console.log('=== refreshAllDataForDevice called ===');

    // ========================================================================
    // 0. RESET TIME RANGE TO REAL-TIME
    // ========================================================================
    if (currentTimeRange !== 'realtime') {
        console.log('Resetting time range to real-time on device change');
        handleTimeRangeChange('realtime');
    }

    // ========================================================================
    // 1. CLEAR MAIN CHART DATA
    // ========================================================================
    chartData.labels = [];
    chartData.inbound = [];
    chartData.outbound = [];
    chartData.total = [];

    chart.data.labels = [];
    chart.data.datasets[0].data = [];
    chart.data.datasets[1].data = [];
    chart.data.datasets[2].data = [];
    chart.update('none');
    console.log('Main chart cleared');

    // ========================================================================
    // 2. CLEAR HISTORICAL DATA ARRAYS
    // ========================================================================
    historicalData.inbound = [];
    historicalData.outbound = [];
    historicalData.total = [];
    historicalData.sessions = [];
    historicalData.tcp = [];
    historicalData.udp = [];
    historicalData.icmp = [];
    historicalData.criticalThreats = [];
    historicalData.mediumThreats = [];
    historicalData.blockedUrls = [];
    historicalData.urlFiltering = [];
    historicalData.interfaceErrors = [];
    console.log('Historical data arrays cleared');

    // ========================================================================
    // 3. RESET DASHBOARD VALUES TO LOADING STATE
    // ========================================================================
    // Throughput stats
    const inboundValue = document.getElementById('inboundValue');
    if (inboundValue) {
        inboundValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const outboundValue = document.getElementById('outboundValue');
    if (outboundValue) {
        outboundValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const totalValue = document.getElementById('totalValue');
    if (totalValue) {
        totalValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    // Reset 5-minute averages
    const inboundAvg = document.getElementById('inboundAvg');
    if (inboundAvg) {
        inboundAvg.textContent = '-';
    }

    const outboundAvg = document.getElementById('outboundAvg');
    if (outboundAvg) {
        outboundAvg.textContent = '-';
    }

    const totalAvg = document.getElementById('totalAvg');
    if (totalAvg) {
        totalAvg.textContent = '-';
    }

    // Session stats
    const sessionValue = document.getElementById('sessionValue');
    if (sessionValue) {
        sessionValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const tcpValue = document.getElementById('tcpValue');
    if (tcpValue) {
        tcpValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const udpValue = document.getElementById('udpValue');
    if (udpValue) {
        udpValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const icmpValue = document.getElementById('icmpValue');
    if (icmpValue) {
        icmpValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    // Threat stats
    const criticalValue = document.getElementById('criticalValue');
    if (criticalValue) {
        criticalValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const mediumValue = document.getElementById('mediumValue');
    if (mediumValue) {
        mediumValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const blockedUrlValue = document.getElementById('blockedUrlValue');
    if (blockedUrlValue) {
        blockedUrlValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const topAppsValue = document.getElementById('topAppsValue');
    if (topAppsValue) {
        topAppsValue.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    // Interface errors
    const interfaceErrorsElement = document.getElementById('interfaceErrorsValue');
    if (interfaceErrorsElement) {
        interfaceErrorsElement.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    // Network Traffic PPS (packets per second) counters
    const totalPps = document.getElementById('totalPps');
    if (totalPps) {
        totalPps.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const inboundPps = document.getElementById('inboundPps');
    if (inboundPps) {
        inboundPps.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    const outboundPps = document.getElementById('outboundPps');
    if (outboundPps) {
        outboundPps.innerHTML = '<span style="font-size: 0.7em;">Loading...</span>';
    }

    console.log('Dashboard values reset to loading');

    // ========================================================================
    // 4. RESET SIDEBAR STATS
    // ========================================================================
    const sidebarPPS = document.getElementById('sidebarPPS');
    const sidebarUptime = document.getElementById('sidebarUptime');
    const sidebarWanIp = document.getElementById('sidebarWanIp');
    const sidebarWanSpeed = document.getElementById('sidebarWanSpeed');
    const sidebarApiStats = document.getElementById('sidebarApiStats');
    const sidebarLastUpdate = document.getElementById('sidebarLastUpdate');
    const sidebarPanosVersion = document.getElementById('sidebarPanosVersion');
    const sidebarLicenseExpired = document.getElementById('sidebarLicenseExpired');
    const sidebarLicenseLicensed = document.getElementById('sidebarLicenseLicensed');

    if (sidebarPPS) sidebarPPS.textContent = '0 PPS';
    if (sidebarUptime) sidebarUptime.textContent = '-';
    if (sidebarWanIp) sidebarWanIp.textContent = '-';
    if (sidebarWanSpeed) sidebarWanSpeed.textContent = '-';
    if (sidebarApiStats) sidebarApiStats.textContent = '-';
    if (sidebarLastUpdate) sidebarLastUpdate.textContent = '-';
    if (sidebarPanosVersion) sidebarPanosVersion.textContent = '-';
    if (sidebarLicenseExpired) sidebarLicenseExpired.textContent = '0';
    if (sidebarLicenseLicensed) sidebarLicenseLicensed.textContent = '0';

    // Sidebar last seen stats
    const sidebarCritical = document.getElementById('sidebarCriticalLastSeen');
    const sidebarMedium = document.getElementById('sidebarMediumLastSeen');
    const sidebarBlocked = document.getElementById('sidebarBlockedUrlLastSeen');
    if (sidebarCritical) sidebarCritical.textContent = '-';
    if (sidebarMedium) sidebarMedium.textContent = '-';
    if (sidebarBlocked) sidebarBlocked.textContent = '-';

    console.log('Sidebar stats reset');

    // ========================================================================
    // 5. RESET MINI CHARTS
    // ========================================================================
    miniChartData.sessions = [];
    miniChartData.tcp = [];
    miniChartData.udp = [];
    miniChartData.pps = [];

    if (sessionChart) {
        sessionChart.data.datasets[0].data = [];
        sessionChart.update('none');
    }
    if (tcpChart) {
        tcpChart.data.datasets[0].data = [];
        tcpChart.update('none');
    }
    if (udpChart) {
        udpChart.data.datasets[0].data = [];
        udpChart.update('none');
    }
    if (ppsChart) {
        ppsChart.data.datasets[0].data = [];
        ppsChart.update('none');
    }

    console.log('Mini charts reset');

    // ========================================================================
    // 6. CLEAR THREAT LOGS AND APPLICATION DISPLAYS
    // ========================================================================
    const criticalLogs = document.getElementById('criticalLogs');
    if (criticalLogs) {
        criticalLogs.innerHTML = '<div style="color: #ffffff; text-align: center; padding: 10px;">Loading...</div>';
    }

    const mediumLogs = document.getElementById('mediumLogs');
    if (mediumLogs) {
        mediumLogs.innerHTML = '<div style="color: #ffffff; text-align: center; padding: 10px;">Loading...</div>';
    }

    const blockedUrlLogs = document.getElementById('blockedUrlLogs');
    if (blockedUrlLogs) {
        blockedUrlLogs.innerHTML = '<div style="color: #ffffff; text-align: center; padding: 10px;">Loading...</div>';
    }

    const topAppsContainer = document.getElementById('topAppsContainer');
    if (topAppsContainer) {
        topAppsContainer.innerHTML = '<div style="color: #ffffff; text-align: center; padding: 10px;">Loading...</div>';
    }

    console.log('Threat logs and app displays cleared');

    // ========================================================================
    // 7. REFRESH ALL PAGE DATA
    // ========================================================================
    console.log('Triggering refresh of all page data...');

    // Restart update interval for dashboard data
    if (updateIntervalId) {
        clearInterval(updateIntervalId);
    }

    // Preload historical data for charts before starting real-time updates
    preloadChartData();

    fetchThroughputData();
    updateIntervalId = setInterval(fetchThroughputData, UPDATE_INTERVAL);
    console.log(`Update interval restarted: ${UPDATE_INTERVAL}ms`);

    // OPTIMIZATION: Only refresh the currently visible page (not all pages)
    // This reduces device switch from 8+ API calls to 1-2 calls
    console.log('Current visible page:', currentVisiblePage);
    console.log('Loading only visible page data...');

    // Clear UI state for Device Info tabs (lightweight - no API calls)
    const panosVersionInfo = document.getElementById('panosVersionInfo');
    if (panosVersionInfo) {
        panosVersionInfo.innerHTML = '';
    }
    const checkButton = document.getElementById('checkPanosVersionBtn');
    if (checkButton) {
        checkButton.disabled = false;
        checkButton.textContent = 'Check for Updates';
    }

    // Clear reboot UI state when switching devices
    const rebootButton = document.getElementById('rebootFirewallBtn');
    if (rebootButton) {
        rebootButton.disabled = false;
        rebootButton.textContent = 'Reboot Firewall';
        rebootButton.style.background = '';
    }
    const rebootSuccess = document.getElementById('rebootSuccess');
    if (rebootSuccess) {
        rebootSuccess.style.display = 'none';
        rebootSuccess.innerHTML = '';
    }
    const rebootError = document.getElementById('rebootErrorMessage');
    if (rebootError) {
        rebootError.style.display = 'none';
        rebootError.textContent = '';
    }

    // Load only the currently visible page
    if (currentVisiblePage === 'home') {
        // Dashboard - throughput already refreshed by interval above
        console.log('Dashboard active - using interval for updates');
    } else if (currentVisiblePage === 'connected-devices' && typeof loadConnectedDevices === 'function') {
        console.log('Loading Connected Devices page');
        loadConnectedDevices();
    } else if (currentVisiblePage === 'applications' && typeof loadApplications === 'function') {
        console.log('Loading Applications page');
        loadApplications();
    } else if (currentVisiblePage === 'device-info') {
        // Check which Device Info tab is visible
        const softwareTab = document.getElementById('software-updates-tab');
        const interfacesTab = document.getElementById('interfaces-tab');
        const dhcpTab = document.getElementById('dhcp-tab');

        if (softwareTab && softwareTab.style.display !== 'none' && typeof loadSoftwareUpdates === 'function') {
            console.log('Loading Software Updates tab');
            loadSoftwareUpdates();
        } else if (interfacesTab && interfacesTab.style.display !== 'none' && typeof loadInterfaces === 'function') {
            console.log('Loading Interfaces tab');
            loadInterfaces();
        } else if (dhcpTab && dhcpTab.style.display !== 'none' && typeof loadDhcpLeases === 'function') {
            console.log('Loading DHCP tab');
            loadDhcpLeases();
        }
        // Tech Support and Reboot tabs don't auto-load data
    } else if (currentVisiblePage === 'logs' && typeof loadSystemLogs === 'function') {
        console.log('Loading System Logs page');
        loadSystemLogs();
    } else if (currentVisiblePage === 'traffic' && typeof updateTrafficPage === 'function') {
        console.log('Loading Traffic page');
        updateTrafficPage();
    }

    console.log('=== refreshAllDataForDevice complete ===');
}

// Note: Modal functions (showCriticalThreatsModal, showMediumThreatsModal, showBlockedUrlsModal, showTopAppsModal)
// have been moved to pages.js for better code organization

