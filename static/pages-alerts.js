/**
 * PANfm Alerts Management UI
 * Frontend for alert configuration, history, and notifications
 */

// ===== Alert Configuration Management =====

// Store configs globally for edit function
let alertConfigs = [];

async function loadAlertConfigs(deviceId = null) {
    console.log('Loading alert configurations...');
    await loadDeviceNamesCache();  // Load device names first

    let url = '/api/alerts/configs';
    if (deviceId) {
        url += `?device_id=${encodeURIComponent(deviceId)}`;
    }

    fetch(url)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderAlertConfigs(data.data);
            } else {
                showError('Failed to load alert configurations');
            }
        })
        .catch(error => {
            console.error('Error loading alert configs:', error);
            showError('Error loading alert configurations');
        });
}

function renderAlertConfigs(configs) {
    console.log('[DEBUG] renderAlertConfigs called with', configs.length, 'configs:', configs);

    // Store configs globally for edit function
    alertConfigs = configs;

    const container = document.getElementById('alertConfigsTable');
    if (!container) {
        console.error('[ERROR] alertConfigsTable container not found!');
        return;
    }

    if (configs.length === 0) {
        console.log('[DEBUG] No configs to render, showing empty message');
        alertConfigs = [];
        container.innerHTML = '<p style="color: #999; text-align: center; padding: 40px; font-family: var(--font-secondary);">No alert configurations found. Create your first alert using the buttons above.</p>';
        return;
    }

    console.log('[DEBUG] Building styled table HTML for', configs.length, 'configs');

    let html = `
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;">
                <thead>
                    <tr style="background: #f5f5f5; border-bottom: 2px solid #FA582D;">
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Device</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Metric</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Threshold</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Severity</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Channels</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Status</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;

    configs.forEach((config, index) => {
        const severityColors = {
            'critical': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        };
        const severityColor = severityColors[config.severity] || '#6c757d';
        const rowStyle = index % 2 === 0 ? 'background: #ffffff;' : 'background: #f8f9fa;';

        html += `
            <tr style="${rowStyle} border-bottom: 1px solid #dee2e6;" onmouseover="this.style.backgroundColor='#f0f0f0'" onmouseout="this.style.backgroundColor='${index % 2 === 0 ? '#ffffff' : '#f8f9fa'}'">
                <td style="padding: 12px; color: #333;"><strong>${escapeHtml(getDeviceNameById(config.device_id))}</strong></td>
                <td style="padding: 12px; color: #666;">${formatMetricName(config.metric_type)}</td>
                <td style="padding: 12px; color: #666;"><code style="background: #f1f3f5; padding: 2px 6px; border-radius: 4px;">${config.threshold_operator} ${config.threshold_value}</code></td>
                <td style="padding: 12px; text-align: center;">
                    <span style="display: inline-block; padding: 4px 12px; border-radius: 12px; background: ${severityColor}; color: white; font-size: 0.75em; font-weight: 600; text-transform: uppercase; font-family: var(--font-primary);">${config.severity}</span>
                </td>
                <td style="padding: 12px; color: #666;">${(config.notification_channels || []).join(', ') || 'None'}</td>
                <td style="padding: 12px; text-align: center;">
                    ${config.enabled ?
                        '<span style="color: #28a745; font-weight: 600;">✓ Enabled</span>' :
                        '<span style="color: #6c757d;">✗ Disabled</span>'}
                </td>
                <td style="padding: 12px; text-align: center;">
                    <button onclick="editAlertConfig(${config.id})" style="padding: 6px 12px; margin: 0 4px; background: #ff6600; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">Edit</button>
                    <button onclick="deleteAlertConfig(${config.id})" style="padding: 6px 12px; margin: 0 4px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">Delete</button>
                </td>
            </tr>
        `;
    });

    html += `
                    </tbody>
                </table>
            <div style="color: #666; text-align: right; margin-top: 10px; font-size: 0.85em; font-family: var(--font-secondary);">
                Total: ${configs.length} alert${configs.length !== 1 ? 's' : ''}
            </div>
        </div>
    `;
    console.log('[DEBUG] Setting innerHTML with styled HTML (length:', html.length, 'chars)');
    container.innerHTML = html;
    console.log('[DEBUG] Table rendered successfully! Orange header should be visible.');
}

function showCreateAlertModal() {
    document.getElementById('alertConfigModal').style.display = 'flex';
    document.getElementById('alertConfigModalTitle').textContent = 'Create Alert';
    document.getElementById('alertConfigForm').reset();
    document.getElementById('alertConfigId').value = '';
    loadDevicesIntoDropdown('alertConfigDeviceId');

    // Don't set up device change handler here - let users manually add options if needed
}

function showCreateApplicationAlertModal() {
    document.getElementById('alertConfigModal').style.display = 'flex';
    document.getElementById('alertConfigModalTitle').textContent = 'Create Alert';
    document.getElementById('alertConfigForm').reset();
    document.getElementById('alertConfigId').value = '';
    loadDevicesIntoDropdown('alertConfigDeviceId');

    // Set up device change handler to load applications dynamically
    const deviceDropdown = document.getElementById('alertConfigDeviceId');

    // Remove any existing change listeners to avoid duplicates
    const newDeviceDropdown = deviceDropdown.cloneNode(true);
    deviceDropdown.parentNode.replaceChild(newDeviceDropdown, deviceDropdown);

    // Add the change listener to load applications
    newDeviceDropdown.addEventListener('change', loadApplicationsForDevice);

    // Also hide standard metrics from the dropdown
    setTimeout(() => {
        const metricDropdown = document.getElementById('alertConfigMetricType');
        Array.from(metricDropdown.options).forEach(option => {
            // Hide standard metrics, only show application metrics
            if (!option.value.startsWith('app_') && option.value !== '') {
                option.style.display = 'none';
            }
        });
    }, 100);
}

function editAlertConfig(id) {
    console.log('[editAlertConfig] Editing alert config ID:', id);

    // Find the config in the loaded configs array
    const config = alertConfigs.find(c => c.id === id);
    if (!config) {
        console.error('[editAlertConfig] Alert configuration not found for ID:', id);
        showError('Alert configuration not found');
        return;
    }

    console.log('[editAlertConfig] Found config:', config);

    // Show modal
    document.getElementById('alertConfigModal').style.display = 'flex';

    // Change modal title to "Edit Alert"
    document.getElementById('alertConfigModalTitle').textContent = 'Edit Alert';

    // Populate form fields with existing values
    document.getElementById('alertConfigId').value = id;
    document.getElementById('alertConfigDeviceId').value = config.device_id;
    document.getElementById('alertConfigMetricType').value = config.metric_type;
    document.getElementById('alertConfigThreshold').value = config.threshold_value;
    document.getElementById('alertConfigOperator').value = config.threshold_operator;
    document.getElementById('alertConfigSeverity').value = config.severity;
    document.getElementById('alertConfigEnabled').checked = config.enabled;

    // Handle notification channels (multi-select)
    const channelsSelect = document.getElementById('alertConfigChannels');
    Array.from(channelsSelect.options).forEach(option => {
        option.selected = (config.notification_channels || []).includes(option.value);
    });

    // Load devices into dropdown
    loadDevicesIntoDropdown('alertConfigDeviceId');

    console.log('[editAlertConfig] Modal populated with config data');
}

async function loadApplicationsForDevice() {
    const deviceId = document.getElementById('alertConfigDeviceId').value;
    const metricDropdown = document.getElementById('alertConfigMetricType');

    if (!deviceId) {
        // Remove application options if no device selected
        removeApplicationOptions();
        return;
    }

    try {
        const response = await fetch(`/api/alerts/applications?device_id=${encodeURIComponent(deviceId)}`);
        const data = await response.json();

        if (data.status === 'success' && data.applications && data.applications.length > 0) {
            // Remove existing application options
            removeApplicationOptions();

            // Add new application options
            const applications = data.applications;
            applications.forEach(appName => {
                const option = document.createElement('option');
                option.value = `app_${appName}`;
                option.textContent = `Application: ${appName.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase())}`;
                metricDropdown.appendChild(option);
            });

            console.log(`Loaded ${applications.length} applications for device ${deviceId}`);
        }
    } catch (error) {
        console.error('Error loading applications:', error);
    }
}

function removeApplicationOptions() {
    const metricDropdown = document.getElementById('alertConfigMetricType');
    const options = Array.from(metricDropdown.options);

    options.forEach(option => {
        if (option.value.startsWith('app_')) {
            metricDropdown.removeChild(option);
        }
    });
}

function saveAlertConfig() {
    console.log('[saveAlertConfig] Function called');

    const id = document.getElementById('alertConfigId').value;
    const isEdit = id !== '';

    const data = {
        device_id: document.getElementById('alertConfigDeviceId').value,
        metric_type: document.getElementById('alertConfigMetricType').value,
        threshold_value: parseFloat(document.getElementById('alertConfigThreshold').value),
        threshold_operator: document.getElementById('alertConfigOperator').value,
        severity: document.getElementById('alertConfigSeverity').value,
        notification_channels: Array.from(document.getElementById('alertConfigChannels').selectedOptions).map(opt => opt.value),
        enabled: document.getElementById('alertConfigEnabled').checked
    };

    console.log('[saveAlertConfig] Form data:', data);

    // Validate required fields
    if (!data.device_id) {
        console.error('[saveAlertConfig] Validation failed: No device selected');
        showError('Please select a device');
        return;
    }

    if (!data.metric_type) {
        console.error('[saveAlertConfig] Validation failed: No metric selected');
        showError('Please select a metric type');
        return;
    }

    if (isNaN(data.threshold_value)) {
        console.error('[saveAlertConfig] Validation failed: Invalid threshold value');
        showError('Please enter a valid threshold value');
        return;
    }

    const url = isEdit ? `/api/alerts/configs/${id}` : '/api/alerts/configs';
    const method = isEdit ? 'PUT' : 'POST';

    console.log(`[saveAlertConfig] Sending ${method} request to ${url}`);

    fetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        console.log(`[saveAlertConfig] Response status: ${response.status}`);
        return response.json();
    })
    .then(result => {
        console.log('[saveAlertConfig] Response data:', result);
        if (result.status === 'success') {
            closeAlertConfigModal();
            loadAlertConfigs();
            showSuccess(isEdit ? 'Alert updated successfully' : 'Alert created successfully');
        } else {
            showError(result.message || 'Failed to save alert');
        }
    })
    .catch(error => {
        console.error('[saveAlertConfig] Error caught:', error);
        showError('Error saving alert configuration: ' + error.message);
    });
}

function deleteAlertConfig(id) {
    if (!confirm('Are you sure you want to delete this alert configuration?')) {
        return;
    }

    fetch(`/api/alerts/configs/${id}`, {
        method: 'DELETE',
        headers: {
            'X-CSRFToken': getCsrfToken()
        }
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            loadAlertConfigs();
            showSuccess('Alert deleted successfully');
        } else {
            showError(result.message || 'Failed to delete alert');
        }
    })
    .catch(error => {
        console.error('Error deleting alert:', error);
        showError('Error deleting alert');
    });
}

function closeAlertConfigModal() {
    document.getElementById('alertConfigModal').style.display = 'none';
}

// ===== Alert History Management =====

async function loadAlertHistory(unresolvedOnly = false) {
    console.log('Loading alert history...');
    await loadDeviceNamesCache();  // Load device names first

    let url = '/api/alerts/history?limit=100';
    if (unresolvedOnly) {
        url += '&unresolved_only=true';
    }

    fetch(url)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderAlertHistory(data.data);
            } else {
                showError('Failed to load alert history');
            }
        })
        .catch(error => {
            console.error('Error loading alert history:', error);
            showError('Error loading alert history');
        });
}

function renderAlertHistory(history) {
    const container = document.getElementById('alertHistoryTable');
    if (!container) return;

    if (history.length === 0) {
        container.innerHTML = '<p>No alerts in history.</p>';
        return;
    }

    let html = `
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;">
                <thead>
                    <tr style="background: #f5f5f5; border-bottom: 2px solid #FA582D;">
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Time</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Device</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Message</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Severity</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Status</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;

    history.forEach((alert, index) => {
        const severityColors = {
            'critical': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        };
        const severityColor = severityColors[alert.severity] || '#6c757d';
        const rowStyle = index % 2 === 0 ? 'background: #ffffff;' : 'background: #f8f9fa;';

        const statusText = alert.acknowledged_at ? '✓ Acknowledged' : '🔴 Active';

        html += `
            <tr style="${rowStyle} border-bottom: 1px solid #dee2e6;" onmouseover="this.style.backgroundColor='#f0f0f0'" onmouseout="this.style.backgroundColor='${index % 2 === 0 ? '#ffffff' : '#f8f9fa'}'">
                <td style="padding: 12px; color: #333;">${formatTimestamp(alert.triggered_at)}</td>
                <td style="padding: 12px; color: #666;">${escapeHtml(getDeviceNameById(alert.device_id))}</td>
                <td style="padding: 12px; color: #666;">${escapeHtml(alert.message)}</td>
                <td style="padding: 12px; text-align: center;">
                    <span style="display: inline-block; padding: 4px 12px; border-radius: 12px; background: ${severityColor}; color: white; font-size: 0.75em; font-weight: 600; text-transform: uppercase; font-family: var(--font-primary);">${alert.severity}</span>
                </td>
                <td style="padding: 12px; text-align: center; color: #666;">${statusText}</td>
                <td style="padding: 12px; text-align: center;">
                    ${!alert.acknowledged_at ? `<button onclick="acknowledgeAlert(${alert.id})" style="padding: 6px 12px; margin: 0 4px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">Acknowledge</button>` : ''}
                    ${!alert.resolved_at ? `<button onclick="resolveAlert(${alert.id})" style="padding: 6px 12px; margin: 0 4px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">Resolve</button>` : ''}
                </td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

function acknowledgeAlert(id) {
    fetch(`/api/alerts/history/${id}/acknowledge`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({
            acknowledged_by: 'admin'  // TODO: Get from session
        })
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            loadAlertHistory();
            loadAlertStats(); // Update statistics
            // Refresh modals if they're open
            refreshOpenModals();
            // No alert box - just silently acknowledge
        } else {
            showError(result.message || 'Failed to acknowledge alert');
        }
    })
    .catch(error => {
        console.error('Error acknowledging alert:', error);
        showError('Error acknowledging alert');
    });
}

/**
 * Resolve an alert
 * @param {number} id - Alert history ID
 */
function resolveAlert(id) {
    const reason = prompt('Enter resolution reason (optional):') || 'Manually resolved';

    fetch(`/api/alerts/history/${id}/resolve`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({
            resolved_reason: reason,
            resolved_by: 'admin'  // TODO: Get from session
        })
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            loadAlertHistory();
            loadAlertStats(); // Update statistics
            // Refresh modals if they're open
            refreshOpenModals();
            // No alert box - just silently resolve
        } else {
            showError(result.message || 'Failed to resolve alert');
        }
    })
    .catch(error => {
        console.error('Error resolving alert:', error);
        showError('Error resolving alert');
    });
}

// Helper function to refresh open modals
function refreshOpenModals() {
    const infoModal = document.getElementById('infoAlertsModal');
    const warningModal = document.getElementById('warningAlertsModal');
    const criticalModal = document.getElementById('criticalAlertsModal');

    if (infoModal && infoModal.style.display === 'flex') {
        // Refresh INFO alerts modal
        fetch('/api/alerts/history?unresolved=true&severity=info')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    renderAlertsInTable(data.data, 'infoAlertsTable', 'No info alerts at this time.');
                }
            })
            .catch(error => console.error('Error refreshing info alerts modal:', error));
    }

    if (warningModal && warningModal.style.display === 'flex') {
        // Refresh WARNING alerts modal
        fetch('/api/alerts/history?unresolved=true&severity=warning')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    renderAlertsInTable(data.data, 'warningAlertsTable', 'No warning alerts at this time.');
                }
            })
            .catch(error => console.error('Error refreshing warning alerts modal:', error));
    }

    if (criticalModal && criticalModal.style.display === 'flex') {
        // Refresh CRITICAL alerts modal
        fetch('/api/alerts/history?unresolved=true&severity=critical')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    renderAlertsInTable(data.data, 'criticalAlertsTable', 'No critical alerts at this time.');
                }
            })
            .catch(error => console.error('Error refreshing critical alerts modal:', error));
    }
}

// ===== Alert Statistics =====

function loadAlertStats() {
    fetch('/api/alerts/stats')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderAlertStats(data.data);
                loadLatestAlertsBySeverity();  // Load latest alerts for cards
            }
        })
        .catch(error => {
            console.error('Error loading alert stats:', error);
        });
}

function renderAlertStats(stats) {
    // Update individual stat tiles (new 3-card layout: INFO, WARNING, CRITICAL)
    const infoEl = document.getElementById('alertStatsInfo');
    const warningEl = document.getElementById('alertStatsWarning');
    const criticalEl = document.getElementById('alertStatsCritical');

    if (infoEl) infoEl.textContent = stats.info_alerts || 0;
    if (warningEl) warningEl.textContent = stats.warning_alerts || 0;
    if (criticalEl) criticalEl.textContent = stats.critical_alerts || 0;
}

// Load latest alerts for each severity card (unacknowledged only)
async function loadLatestAlertsBySeverity() {
    try {
        // Fetch latest unacknowledged INFO alert
        const infoResp = await fetch('/api/alerts/history?unresolved=true&severity=info&limit=100');
        const infoData = await infoResp.json();
        // Filter for unacknowledged (acknowledged_at is null)
        const unackInfo = infoData.status === 'success' ? infoData.data.filter(a => !a.acknowledged_at) : [];
        const latestInfo = unackInfo.length > 0 ? unackInfo[0] : null;

        // Fetch latest unacknowledged WARNING alert
        const warningResp = await fetch('/api/alerts/history?unresolved=true&severity=warning&limit=100');
        const warningData = await warningResp.json();
        const unackWarning = warningData.status === 'success' ? warningData.data.filter(a => !a.acknowledged_at) : [];
        const latestWarning = unackWarning.length > 0 ? unackWarning[0] : null;

        // Fetch latest unacknowledged CRITICAL alert
        const criticalResp = await fetch('/api/alerts/history?unresolved=true&severity=critical&limit=100');
        const criticalData = await criticalResp.json();
        const unackCritical = criticalData.status === 'success' ? criticalData.data.filter(a => !a.acknowledged_at) : [];
        const latestCritical = unackCritical.length > 0 ? unackCritical[0] : null;

        // Update card displays
        updateLatestAlertOnCard('alertLatestInfo', latestInfo);
        updateLatestAlertOnCard('alertLatestWarning', latestWarning);
        updateLatestAlertOnCard('alertLatestCritical', latestCritical);

    } catch (error) {
        console.error('Error loading latest alerts:', error);
    }
}

function updateLatestAlertOnCard(elementId, alert) {
    const el = document.getElementById(elementId);
    if (!el) return;

    if (alert) {
        const message = alert.message.length > 60 ? alert.message.substring(0, 60) + '...' : alert.message;
        el.innerHTML = `<div style="font-size: 0.7em; margin-top: 8px; opacity: 0.85; line-height: 1.3;">${escapeHtml(message)}</div>`;
    } else {
        el.innerHTML = '<div style="font-size: 0.7em; margin-top: 8px; opacity: 0.6;">No active alerts</div>';
    }
}

// ===== Notification Testing =====

function testEmailNotification() {
    console.log('Testing email notification...');

    fetch('/api/alerts/notifications/test/email', {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCsrfToken()
        }
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            showSuccess('Test email sent successfully!');
        } else {
            showError(result.message || 'Failed to send test email');
        }
    })
    .catch(error => {
        console.error('Error testing email:', error);
        showError('Error testing email notification');
    });
}

function testWebhookNotification() {
    console.log('Testing webhook notification...');

    fetch('/api/alerts/notifications/test/webhook', {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCsrfToken()
        }
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            showSuccess('Test webhook sent successfully!');
        } else {
            showError(result.message || 'Failed to send test webhook');
        }
    })
    .catch(error => {
        console.error('Error testing webhook:', error);
        showError('Error testing webhook notification');
    });
}

function testSlackNotification() {
    console.log('Testing Slack notification...');

    fetch('/api/alerts/notifications/test/slack', {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCsrfToken()
        }
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            showSuccess('Test Slack message sent successfully!');
        } else {
            showError(result.message || 'Failed to send test Slack message');
        }
    })
    .catch(error => {
        console.error('Error testing Slack:', error);
        showError('Error testing Slack notification');
    });
}

// ===== Utility Functions =====

function formatMetricName(metricType) {
    // Handle application metrics (format: "app_<application_name>")
    if (metricType.startsWith('app_')) {
        const appName = metricType.substring(4); // Remove "app_" prefix
        return `Application: ${appName.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`;
    }

    // Handle category metrics (format: "category_<category_name>") - legacy
    if (metricType.startsWith('category_')) {
        const categoryName = metricType.substring(9); // Remove "category_" prefix
        return `Category: ${categoryName.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}`;
    }

    const names = {
        'throughput_in': 'Inbound Throughput',
        'throughput_out': 'Outbound Throughput',
        'throughput_total': 'Total Throughput',
        'cpu': 'CPU Usage',
        'memory': 'Memory Usage',
        'sessions': 'Active Sessions',
        'threats_critical': 'Critical Threats',
        'interface_errors': 'Interface Errors'
    };
    return names[metricType] || metricType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

function showSuccess(message) {
    // TODO: Implement toast notification
    alert(message);
}

function showError(message) {
    // TODO: Implement toast notification
    alert('Error: ' + message);
}

// ===== Device Name Cache =====

// Device name cache for alert displays
let deviceNamesCache = null;

async function loadDeviceNamesCache() {
    if (deviceNamesCache) return deviceNamesCache;

    try {
        const response = await fetch('/api/devices');
        const data = await response.json();

        if (data.status === 'success' && data.devices) {
            deviceNamesCache = {};
            data.devices.forEach(device => {
                deviceNamesCache[device.id] = device.name;
            });
            console.log(`Loaded ${Object.keys(deviceNamesCache).length} device names into cache`);
            return deviceNamesCache;
        }
    } catch (error) {
        console.error('Error loading device names:', error);
    }
    return {};
}

function getDeviceNameById(deviceId) {
    if (!deviceNamesCache) return deviceId.substring(0, 8) + '...';
    return deviceNamesCache[deviceId] || (deviceId.substring(0, 8) + '...');
}

// ===== Alert Template Management =====

function loadAlertTemplates() {
    console.log('Loading alert templates...');

    fetch('/api/alerts/templates')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderAlertTemplates(data.data);
            } else {
                showError('Failed to load alert templates');
            }
        })
        .catch(error => {
            console.error('Error loading templates:', error);
            showError('Error loading alert templates');
        });
}

function renderAlertTemplates(templates) {
    const container = document.getElementById('alertTemplatesContainer');
    if (!container) return;

    if (templates.length === 0) {
        container.innerHTML = '<p>No templates available.</p>';
        return;
    }

    let html = '<div class="templates-grid">';

    templates.forEach(template => {
        html += `
            <div class="template-card">
                <h3>${escapeHtml(template.name)}</h3>
                <p class="template-description">${escapeHtml(template.description)}</p>
                <div class="template-info">
                    <span class="badge">${escapeHtml(template.category)}</span>
                    <span class="badge">${template.alert_count} alerts</span>
                </div>
                <button onclick="viewTemplateDetails('${template.id}')" class="btn-small">View Details</button>
                <button onclick="showApplyTemplateModal('${template.id}')" class="btn-small btn-primary">Apply Template</button>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function viewTemplateDetails(templateId) {
    console.log(`Viewing template: ${templateId}`);

    fetch(`/api/alerts/templates/${templateId}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showTemplateDetailsModal(data.data);
            } else {
                showError('Failed to load template details');
            }
        })
        .catch(error => {
            console.error('Error loading template details:', error);
            showError('Error loading template details');
        });
}

function showTemplateDetailsModal(template) {
    const modal = document.getElementById('templateDetailsModal');
    if (!modal) return;

    let alertsHtml = '<ul class="template-alerts-list">';
    template.alerts.forEach(alert => {
        alertsHtml += `
            <li>
                <strong>${formatMetricName(alert.metric_type)}</strong>:
                ${alert.threshold_operator} ${alert.threshold_value}
                <span class="severity-badge severity-${alert.severity}">${alert.severity}</span>
                <br><em>${escapeHtml(alert.description)}</em>
            </li>
        `;
    });
    alertsHtml += '</ul>';

    document.getElementById('templateDetailsContent').innerHTML = `
        <h2>${escapeHtml(template.name)}</h2>
        <p><strong>Category:</strong> ${escapeHtml(template.category)}</p>
        <p><strong>Description:</strong> ${escapeHtml(template.description)}</p>
        <h3>Alert Rules (${template.alerts.length})</h3>
        ${alertsHtml}
    `;

    modal.style.display = 'flex';
}

function closeTemplateDetailsModal() {
    document.getElementById('templateDetailsModal').style.display = 'none';
}

function showApplyTemplateModal(templateId) {
    document.getElementById('applyTemplateModal').style.display = 'flex';
    document.getElementById('applyTemplateId').value = templateId;
    loadDevicesIntoDropdown('applyTemplateDeviceId');
}

function applyTemplate() {
    const templateId = document.getElementById('applyTemplateId').value;
    const deviceId = document.getElementById('applyTemplateDeviceId').value;
    const channels = Array.from(document.getElementById('applyTemplateChannels').selectedOptions).map(opt => opt.value);

    if (!deviceId) {
        showError('Please select a device');
        return;
    }

    console.log(`Applying template ${templateId} to device ${deviceId}`);

    fetch(`/api/alerts/templates/${templateId}/apply`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({
            device_id: deviceId,
            notification_channels: channels
        })
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            closeApplyTemplateModal();
            loadAlertConfigs();
            showSuccess(`Template applied successfully! Created ${result.created.length} alerts.`);
        } else {
            showError(result.message || 'Failed to apply template');
        }
    })
    .catch(error => {
        console.error('Error applying template:', error);
        showError('Error applying template');
    });
}

function closeApplyTemplateModal() {
    document.getElementById('applyTemplateModal').style.display = 'none';
}

// ===== Quick Start Scenarios =====

function loadQuickStartScenarios() {
    console.log('Loading quick start scenarios...');

    fetch('/api/alerts/quick-start')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderQuickStartScenarios(data.data);
            } else {
                showError('Failed to load quick start scenarios');
            }
        })
        .catch(error => {
            console.error('Error loading quick start:', error);
            showError('Error loading quick start scenarios');
        });
}

function renderQuickStartScenarios(scenarios) {
    const container = document.getElementById('quickStartContainer');
    if (!container) return;

    if (scenarios.length === 0) {
        container.innerHTML = '<p>No quick start scenarios available.</p>';
        return;
    }

    let html = '<div class="quick-start-grid">';

    scenarios.forEach(scenario => {
        html += `
            <div class="scenario-card">
                <h3>${escapeHtml(scenario.name)}</h3>
                <p class="scenario-description">${escapeHtml(scenario.description)}</p>
                <div class="scenario-info">
                    <p><strong>Templates:</strong> ${scenario.templates.length}</p>
                    <p><strong>Channels:</strong> ${scenario.channels.join(', ')}</p>
                </div>
                <button onclick="showApplyQuickStartModal('${scenario.id}')" class="btn-primary">Apply Scenario</button>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function showApplyQuickStartModal(scenarioId) {
    document.getElementById('applyQuickStartModal').style.display = 'flex';
    document.getElementById('applyQuickStartId').value = scenarioId;
    loadDevicesIntoDropdown('applyQuickStartDeviceId');
}

function applyQuickStart() {
    const scenarioId = document.getElementById('applyQuickStartId').value;
    const deviceId = document.getElementById('applyQuickStartDeviceId').value;

    if (!deviceId) {
        showError('Please select a device');
        return;
    }

    console.log(`Applying quick start ${scenarioId} to device ${deviceId}`);

    fetch(`/api/alerts/quick-start/${scenarioId}/apply`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({
            device_id: deviceId
        })
    })
    .then(response => response.json())
    .then(result => {
        if (result.status === 'success') {
            closeApplyQuickStartModal();
            loadAlertConfigs();
            const totalCreated = result.templates.reduce((sum, t) => sum + t.created.length, 0);
            showSuccess(`Quick start applied successfully! Created ${totalCreated} alerts across ${result.templates.length} templates.`);
        } else {
            showError(result.message || 'Failed to apply quick start');
        }
    })
    .catch(error => {
        console.error('Error applying quick start:', error);
        showError('Error applying quick start');
    });
}

function closeApplyQuickStartModal() {
    document.getElementById('applyQuickStartModal').style.display = 'none';
}

// ===== Device Management =====

function loadDevicesIntoDropdown(selectId) {
    console.log(`[loadDevicesIntoDropdown] Called with selectId: ${selectId}`);

    const select = document.getElementById(selectId);
    if (!select) {
        console.error(`[loadDevicesIntoDropdown] ERROR: Dropdown element with ID '${selectId}' not found in DOM`);
        return;
    }

    console.log(`[loadDevicesIntoDropdown] Dropdown element found, fetching devices from /api/devices...`);

    fetch('/api/devices')
        .then(response => {
            console.log(`[loadDevicesIntoDropdown] API response status: ${response.status}`);
            return response.json();
        })
        .then(data => {
            console.log(`[loadDevicesIntoDropdown] API response data:`, data);

            if (data.status === 'success') {
                select.innerHTML = '<option value="">Select Device</option>';

                if (!data.devices || data.devices.length === 0) {
                    console.warn(`[loadDevicesIntoDropdown] No devices found in response`);
                    select.innerHTML += '<option value="" disabled>No devices configured</option>';
                    return;
                }

                data.devices.forEach(device => {
                    const option = document.createElement('option');
                    option.value = device.id;
                    option.textContent = `${device.name} (${device.ip})`;
                    select.appendChild(option);
                });

                console.log(`[loadDevicesIntoDropdown] SUCCESS: Loaded ${data.devices.length} devices into dropdown '${selectId}'`);
            } else {
                console.error(`[loadDevicesIntoDropdown] API returned error status:`, data.message);
                showError('Failed to load devices: ' + (data.message || 'Unknown error'));
            }
        })
        .catch(error => {
            console.error(`[loadDevicesIntoDropdown] EXCEPTION caught:`, error);
            showError('Error loading devices. Check console for details.');
        });
}

// ===== Page Initialization =====

// Auto-refresh interval for alerts page (30 seconds)
let alertsRefreshInterval = null;

function initAlertsPage() {
    console.log('Initializing alerts page...');

    // Initial load
    loadAlertStats();
    loadAlertConfigs();
    loadAlertHistory(false);

    // Load notification channel settings (from settings.js)
    if (typeof loadNotificationChannels === 'function') {
        loadNotificationChannels();
    }

    // Clear any existing interval
    if (alertsRefreshInterval) {
        clearInterval(alertsRefreshInterval);
    }

    // Set up auto-refresh every 30 seconds
    alertsRefreshInterval = setInterval(() => {
        console.log('Auto-refreshing alerts data...');
        loadAlertStats();
        loadAlertConfigs();
        loadAlertHistory(false);  // Refresh history to show new alerts
    }, 30000);  // 30 seconds

    console.log('Alerts page auto-refresh enabled (30s interval)');
}

// Clean up interval when leaving alerts page
function cleanupAlertsPage() {
    if (alertsRefreshInterval) {
        clearInterval(alertsRefreshInterval);
        alertsRefreshInterval = null;
        console.log('Alerts page auto-refresh disabled');
    }
}

function initTemplatesPage() {
    console.log('Initializing templates page...');
    loadAlertTemplates();
    loadQuickStartScenarios();
}

// ===== New Modal Functions for Improved UI =====

function showTemplatesModal() {
    const modal = document.getElementById('templatesBrowserModal');
    if (modal) {
        modal.style.display = 'flex';
        loadTemplatesIntoBrowser();
    }
}

function closeTemplatesBrowserModal() {
    const modal = document.getElementById('templatesBrowserModal');
    if (modal) modal.style.display = 'none';
}

function loadTemplatesIntoBrowser() {
    const container = document.getElementById('templatesBrowserContainer');
    if (!container) return;

    fetch('/api/alerts/templates')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderTemplatesInBrowser(data.data);
            } else {
                container.innerHTML = '<p style="color: #dc3545;">Failed to load templates</p>';
            }
        })
        .catch(error => {
            console.error('Error loading templates:', error);
            container.innerHTML = '<p style="color: #dc3545;">Error loading templates</p>';
        });
}

function renderTemplatesInBrowser(templates) {
    const container = document.getElementById('templatesBrowserContainer');
    if (!container) return;

    let html = '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px;">';

    templates.forEach(template => {
        html += `
            <div style="background: #f8f9fa; border: 2px solid #e0e0e0; border-radius: 10px; padding: 20px; transition: all 0.3s; cursor: pointer;"
                 onmouseover="this.style.borderColor='#FA582D'; this.style.boxShadow='0 4px 12px rgba(250, 88, 45, 0.2)'"
                 onmouseout="this.style.borderColor='#e0e0e0'; this.style.boxShadow='none'">
                <h3 style="color: #333; margin: 0 0 10px 0; font-size: 1.1em; font-family: var(--font-primary);">${escapeHtml(template.name)}</h3>
                <p style="color: #666; font-size: 0.9em; margin: 0 0 15px 0; min-height: 40px; font-family: var(--font-secondary);">${escapeHtml(template.description)}</p>
                <div style="display: flex; gap: 8px; margin-bottom: 15px;">
                    <span style="padding: 4px 12px; background: #FA582D; color: white; border-radius: 4px; font-size: 0.85em;">${escapeHtml(template.category)}</span>
                    <span style="padding: 4px 12px; background: #17a2b8; color: white; border-radius: 4px; font-size: 0.85em;">${template.alert_count} rules</span>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button onclick="viewTemplateDetails('${template.id}')" style="flex: 1; padding: 8px; background: #f0f0f0; color: #333; border: 1px solid #ddd; border-radius: 6px; cursor: pointer; font-size: 0.9em; font-family: var(--font-primary);">View Details</button>
                    <button onclick="closeTemplatesBrowserModal(); showApplyTemplateModal('${template.id}')" style="flex: 1; padding: 8px; background: linear-gradient(135deg, #FA582D 0%, #FF7A55 100%); color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.9em; font-family: var(--font-primary);">Apply</button>
                </div>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function showQuickStartModal() {
    const modal = document.getElementById('quickStartBrowserModal');
    if (modal) {
        modal.style.display = 'flex';
        loadQuickStartIntoBrowser();
    }
}

function closeQuickStartBrowserModal() {
    const modal = document.getElementById('quickStartBrowserModal');
    if (modal) modal.style.display = 'none';
}

function loadQuickStartIntoBrowser() {
    const container = document.getElementById('quickStartBrowserContainer');
    if (!container) return;

    fetch('/api/alerts/quick-start')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderQuickStartInBrowser(data.data);
            } else {
                container.innerHTML = '<p style="color: #dc3545;">Failed to load quick start scenarios</p>';
            }
        })
        .catch(error => {
            console.error('Error loading quick start:', error);
            container.innerHTML = '<p style="color: #dc3545;">Error loading quick start scenarios</p>';
        });
}

function renderQuickStartInBrowser(scenarios) {
    const container = document.getElementById('quickStartBrowserContainer');
    if (!container) return;

    let html = '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px;">';

    scenarios.forEach(scenario => {
        html += `
            <div style="background: linear-gradient(135deg, #FA582D 0%, #FF7A55 100%); color: white; border-radius: 12px; padding: 25px; transition: all 0.3s; cursor: pointer; box-shadow: 0 4px 12px rgba(250, 88, 45, 0.2);"
                 onmouseover="this.style.transform='translateY(-4px)'; this.style.boxShadow='0 8px 20px rgba(250, 88, 45, 0.3)'"
                 onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 12px rgba(250, 88, 45, 0.2)'">
                <h3 style="margin: 0 0 12px 0; font-size: 1.2em; font-family: var(--font-primary);">🚀 ${escapeHtml(scenario.name)}</h3>
                <p style="margin: 0 0 20px 0; opacity: 0.95; font-size: 0.95em; min-height: 40px; font-family: var(--font-secondary);">${escapeHtml(scenario.description)}</p>
                <div style="background: rgba(255, 255, 255, 0.2); padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <div style="margin-bottom: 8px;"><strong>Templates:</strong> ${scenario.templates.length}</div>
                    <div><strong>Channels:</strong> ${scenario.channels.join(', ')}</div>
                </div>
                <button onclick="closeQuickStartBrowserModal(); showApplyQuickStartModal('${scenario.id}')"
                        style="width: 100%; padding: 12px; background: white; color: #FA582D; border: none; border-radius: 8px; cursor: pointer; font-weight: 700; font-size: 1em; font-family: var(--font-primary);">
                    Deploy Scenario
                </button>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function closeAlertHistoryModal() {
    const modal = document.getElementById('alertHistoryModal');
    if (modal) modal.style.display = 'none';
}

function filterAlertHistory() {
    const unresolvedOnly = document.getElementById('historyUnresolvedOnly')?.checked || false;
    loadAlertHistoryIntoModal(unresolvedOnly);
}

function loadAlertHistoryIntoModal(unresolvedOnly = false) {
    const modal = document.getElementById('alertHistoryModal');
    const container = document.getElementById('alertHistoryTableModal');

    if (!modal || !container) return;

    modal.style.display = 'flex';

    let url = '/api/alerts/history?limit=100';
    if (unresolvedOnly) {
        url += '&unresolved_only=true';
    }

    fetch(url)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderAlertHistoryInModal(data.data);
            } else {
                container.innerHTML = '<p style="color: #dc3545;">Failed to load alert history</p>';
            }
        })
        .catch(error => {
            console.error('Error loading alert history:', error);
            container.innerHTML = '<p style="color: #dc3545;">Error loading alert history</p>';
        });
}

function renderAlertHistoryInModal(alerts) {
    const container = document.getElementById('alertHistoryTableModal');
    if (!container) return;

    if (alerts.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #666; padding: 40px;">No alerts found.</p>';
        return;
    }

    let html = `
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;">
                <thead>
                    <tr style="background: #f5f5f5; border-bottom: 2px solid #FA582D;">
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Time</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Device</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Metric</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Value</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Severity</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Status</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;

    alerts.forEach((alert, index) => {
        const severityColors = {
            'critical': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        };
        const severityColor = severityColors[alert.severity] || '#6c757d';
        const rowStyle = index % 2 === 0 ? 'background: #ffffff;' : 'background: #f8f9fa;';
        const time = new Date(alert.triggered_at).toLocaleString();
        const isResolved = alert.resolved_at != null;

        html += `
            <tr style="${rowStyle} border-bottom: 1px solid #dee2e6;" onmouseover="this.style.backgroundColor='#f0f0f0'" onmouseout="this.style.backgroundColor='${index % 2 === 0 ? '#ffffff' : '#f8f9fa'}'">
                <td style="padding: 12px; color: #333;">${time}</td>
                <td style="padding: 12px; color: #666;">${escapeHtml(getDeviceNameById(alert.device_id))}</td>
                <td style="padding: 12px; color: #666;">${formatMetricName(alert.metric_type)}</td>
                <td style="padding: 12px; color: #666;">${alert.actual_value.toFixed(2)}</td>
                <td style="padding: 12px; text-align: center;">
                    <span style="display: inline-block; padding: 4px 12px; border-radius: 12px; background: ${severityColor}; color: white; font-size: 0.75em; font-weight: 600; text-transform: uppercase; font-family: var(--font-primary);">${alert.severity}</span>
                </td>
                <td style="padding: 12px; text-align: center; color: #666;">${isResolved ? '✓ Resolved' : '⚠ Active'}</td>
                <td style="padding: 12px; text-align: center;">
                    ${!alert.acknowledged_at ? `<button onclick="acknowledgeAlert(${alert.id})" style="padding: 6px 12px; margin: 0 4px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">Acknowledge</button>` : ''}
                    ${!isResolved ? `<button onclick="resolveAlert(${alert.id})" style="padding: 6px 12px; margin: 0 4px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">Resolve</button>` : ''}
                </td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// ===== Active Alerts and Critical Alerts Modals =====

function showActiveAlertsModal() {
    console.log('Showing active alerts modal...');
    document.getElementById('activeAlertsModal').style.display = 'flex';

    // Fetch active alerts (unresolved)
    fetch('/api/alerts/history?unresolved=true')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderAlertsInTable(data.data, 'activeAlertsTable', 'No active alerts at this time.');
            } else {
                document.getElementById('activeAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading active alerts</p>';
            }
        })
        .catch(error => {
            console.error('Error loading active alerts:', error);
            document.getElementById('activeAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading active alerts</p>';
        });
}

function closeActiveAlertsModal() {
    document.getElementById('activeAlertsModal').style.display = 'none';
}

function showCriticalAlertsModal() {
    console.log('Showing critical alerts modal...');
    document.getElementById('criticalAlertsModal').style.display = 'flex';

    // Fetch all unacknowledged + last 5 acknowledged critical alerts
    Promise.all([
        fetch('/api/alerts/history?unresolved=true&severity=critical&limit=100').then(r => r.json()),
        fetch('/api/alerts/history?acknowledged=true&severity=critical&limit=5').then(r => r.json())
    ])
        .then(([unresolvedData, ackData]) => {
            if (unresolvedData.status === 'success' && ackData.status === 'success') {
                // Filter unresolved to only get unacknowledged (acknowledged_at is null)
                const unackAlerts = unresolvedData.data.filter(a => !a.acknowledged_at);
                // Combine: unacknowledged first, then acknowledged (max 5)
                const combinedAlerts = [...unackAlerts, ...ackData.data];
                renderAlertsInTable(combinedAlerts, 'criticalAlertsTable', 'No critical alerts.');
            } else {
                document.getElementById('criticalAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading critical alerts</p>';
            }
        })
        .catch(error => {
            console.error('Error loading critical alerts:', error);
            document.getElementById('criticalAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading critical alerts</p>';
        });
}

function closeCriticalAlertsModal() {
    document.getElementById('criticalAlertsModal').style.display = 'none';
}

// INFO Alerts Modal
function showInfoAlertsModal() {
    console.log('Showing info alerts modal...');
    document.getElementById('infoAlertsModal').style.display = 'flex';

    // Fetch all unacknowledged + last 5 acknowledged info alerts
    Promise.all([
        fetch('/api/alerts/history?unresolved=true&severity=info&limit=100').then(r => r.json()),
        fetch('/api/alerts/history?acknowledged=true&severity=info&limit=5').then(r => r.json())
    ])
        .then(([unresolvedData, ackData]) => {
            if (unresolvedData.status === 'success' && ackData.status === 'success') {
                // Filter unresolved to only get unacknowledged (acknowledged_at is null)
                const unackAlerts = unresolvedData.data.filter(a => !a.acknowledged_at);
                // Combine: unacknowledged first, then acknowledged (max 5)
                const combinedAlerts = [...unackAlerts, ...ackData.data];
                renderAlertsInTable(combinedAlerts, 'infoAlertsTable', 'No info alerts.');
            } else {
                document.getElementById('infoAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading info alerts</p>';
            }
        })
        .catch(error => {
            console.error('Error loading info alerts:', error);
            document.getElementById('infoAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading info alerts</p>';
        });
}

function closeInfoAlertsModal() {
    document.getElementById('infoAlertsModal').style.display = 'none';
}

// WARNING Alerts Modal
function showWarningAlertsModal() {
    console.log('Showing warning alerts modal...');
    document.getElementById('warningAlertsModal').style.display = 'flex';

    // Fetch all unacknowledged + last 5 acknowledged warning alerts
    Promise.all([
        fetch('/api/alerts/history?unresolved=true&severity=warning&limit=100').then(r => r.json()),
        fetch('/api/alerts/history?acknowledged=true&severity=warning&limit=5').then(r => r.json())
    ])
        .then(([unresolvedData, ackData]) => {
            if (unresolvedData.status === 'success' && ackData.status === 'success') {
                // Filter unresolved to only get unacknowledged (acknowledged_at is null)
                const unackAlerts = unresolvedData.data.filter(a => !a.acknowledged_at);
                // Combine: unacknowledged first, then acknowledged (max 5)
                const combinedAlerts = [...unackAlerts, ...ackData.data];
                renderAlertsInTable(combinedAlerts, 'warningAlertsTable', 'No warning alerts.');
            } else {
                document.getElementById('warningAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading warning alerts</p>';
            }
        })
        .catch(error => {
            console.error('Error loading warning alerts:', error);
            document.getElementById('warningAlertsTable').innerHTML = '<p style="color: #dc3545;">Error loading warning alerts</p>';
        });
}

function closeWarningAlertsModal() {
    document.getElementById('warningAlertsModal').style.display = 'none';
}

// Alert History Full Modal (Last 50 Alerts)
function showAlertHistoryFullModal() {
    console.log('Showing full alert history modal...');
    document.getElementById('alertHistoryFullModal').style.display = 'flex';

    // Fetch last 50 alerts (both active AND resolved, all severities, sorted newest first)
    fetch('/api/alerts/history?limit=50')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderAlertHistoryFull(data.data);
            } else {
                document.getElementById('alertHistoryFullTable').innerHTML = '<p style="color: #dc3545;">Error loading alert history</p>';
            }
        })
        .catch(error => {
            console.error('Error loading alert history:', error);
            document.getElementById('alertHistoryFullTable').innerHTML = '<p style="color: #dc3545;">Error loading alert history</p>';
        });
}

function closeAlertHistoryFullModal() {
    document.getElementById('alertHistoryFullModal').style.display = 'none';
}

// Acknowledge All functions for each severity
function acknowledgeAllInfoAlerts() {
    fetch('/api/alerts/history?unresolved=true&severity=info')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.length > 0) {
                const alertIds = data.data.map(alert => alert.id);
                // Acknowledge each alert
                Promise.all(alertIds.map(id =>
                    fetch(`/api/alerts/history/${id}/acknowledge`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCsrfToken()
                        },
                        body: JSON.stringify({ acknowledged_by: 'admin' })
                    })
                )).then(() => {
                    loadAlertStats();
                    refreshOpenModals();
                });
            }
        })
        .catch(error => console.error('Error acknowledging info alerts:', error));
}

function acknowledgeAllWarningAlerts() {
    fetch('/api/alerts/history?unresolved=true&severity=warning')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.length > 0) {
                const alertIds = data.data.map(alert => alert.id);
                // Acknowledge each alert
                Promise.all(alertIds.map(id =>
                    fetch(`/api/alerts/history/${id}/acknowledge`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCsrfToken()
                        },
                        body: JSON.stringify({ acknowledged_by: 'admin' })
                    })
                )).then(() => {
                    loadAlertStats();
                    refreshOpenModals();
                });
            }
        })
        .catch(error => console.error('Error acknowledging warning alerts:', error));
}

function acknowledgeAllCriticalAlerts() {
    fetch('/api/alerts/history?unresolved=true&severity=critical')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.length > 0) {
                const alertIds = data.data.map(alert => alert.id);
                // Acknowledge each alert
                Promise.all(alertIds.map(id =>
                    fetch(`/api/alerts/history/${id}/acknowledge`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCsrfToken()
                        },
                        body: JSON.stringify({ acknowledged_by: 'admin' })
                    })
                )).then(() => {
                    loadAlertStats();
                    refreshOpenModals();
                });
            }
        })
        .catch(error => console.error('Error acknowledging critical alerts:', error));
}

function renderAlertHistoryFull(alerts) {
    const container = document.getElementById('alertHistoryFullTable');
    if (!container) return;

    if (alerts.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #666; padding: 40px; font-family: var(--font-secondary);">No alert history found.</p>';
        return;
    }

    const severityColors = {
        'critical': '#dc3545',
        'warning': '#ffc107',
        'info': '#17a2b8'
    };

    let html = `
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;">
                <thead>
                    <tr style="background: #f5f5f5; border-bottom: 2px solid #dee2e6;">
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Time</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Device</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Message</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Severity</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Status</th>
                    </tr>
                </thead>
                <tbody>
    `;

    alerts.forEach((alert, index) => {
        const severityColor = severityColors[alert.severity] || '#6c757d';
        const rowStyle = index % 2 === 0 ? 'background: #ffffff;' : 'background: #f8f9fa;';
        const time = new Date(alert.triggered_at).toLocaleString();
        const statusText = alert.acknowledged_at ? '✓ Acknowledged' : '🔴 Active';
        const deviceName = getDeviceNameById(alert.device_id);

        html += `
            <tr style="${rowStyle} border-bottom: 1px solid #dee2e6;" onmouseover="this.style.backgroundColor='#f0f0f0'" onmouseout="this.style.backgroundColor='${index % 2 === 0 ? '#ffffff' : '#f8f9fa'}'">
                <td style="padding: 12px; color: #333; font-size: 0.9em;">${time}</td>
                <td style="padding: 12px; color: #666; font-size: 0.9em;">${escapeHtml(deviceName)}</td>
                <td style="padding: 12px; color: #666; font-size: 0.9em;">${escapeHtml(alert.message)}</td>
                <td style="padding: 12px; text-align: center;">
                    <span style="display: inline-block; padding: 4px 12px; border-radius: 12px; background: ${severityColor}; color: white; font-size: 0.75em; font-weight: 600; text-transform: uppercase; font-family: var(--font-primary);">${alert.severity}</span>
                </td>
                <td style="padding: 12px; text-align: center; color: #666; font-size: 0.85em;">${statusText}</td>
            </tr>
        `;
    });

    html += `</tbody></table>
             <div style="color: #666; text-align: right; margin-top: 10px; font-size: 0.85em; font-family: var(--font-secondary);">
                 Showing ${alerts.length} most recent alert${alerts.length !== 1 ? 's' : ''}
             </div>
         </div>`;
    container.innerHTML = html;
}

// Resolve all active alerts
function resolveAllActiveAlerts() {
    if (!confirm('Are you sure you want to resolve all active alerts?')) {
        return;
    }

    // Fetch all unresolved alerts
    fetch('/api/alerts/history?unresolved=true')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.length > 0) {
                const resolvePromises = data.data.map(alert => {
                    return fetch(`/api/alerts/history/${alert.id}/resolve`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCsrfToken()
                        },
                        body: JSON.stringify({
                            resolved_reason: 'Bulk resolved from Active Alerts modal'
                        })
                    });
                });

                Promise.all(resolvePromises)
                    .then(() => {
                        showSuccess(`Resolved ${data.data.length} alert(s)`);
                        loadAlertHistory();
                        loadAlertStats();
                        // Refresh the active alerts modal
                        fetch('/api/alerts/history?unresolved=true')
                            .then(response => response.json())
                            .then(data => {
                                if (data.status === 'success') {
                                    renderAlertsInTable(data.data, 'activeAlertsTable', 'No active alerts at this time.');
                                }
                            });
                    })
                    .catch(error => {
                        console.error('Error resolving all alerts:', error);
                        showError('Error resolving some alerts');
                    });
            } else {
                showSuccess('No active alerts to resolve');
            }
        })
        .catch(error => {
            console.error('Error fetching active alerts:', error);
            showError('Error fetching active alerts');
        });
}

// Resolve all critical alerts
function resolveAllCriticalAlerts() {
    if (!confirm('Are you sure you want to resolve all critical alerts?')) {
        return;
    }

    // Fetch all unresolved critical alerts
    fetch('/api/alerts/history?unresolved=true&severity=critical')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.data.length > 0) {
                const resolvePromises = data.data.map(alert => {
                    return fetch(`/api/alerts/history/${alert.id}/resolve`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCsrfToken()
                        },
                        body: JSON.stringify({
                            resolved_reason: 'Bulk resolved from Critical Alerts modal'
                        })
                    });
                });

                Promise.all(resolvePromises)
                    .then(() => {
                        showSuccess(`Resolved ${data.data.length} critical alert(s)`);
                        loadAlertHistory();
                        loadAlertStats();
                        // Refresh the critical alerts modal
                        fetch('/api/alerts/history?unresolved=true&severity=critical')
                            .then(response => response.json())
                            .then(data => {
                                if (data.status === 'success') {
                                    renderAlertsInTable(data.data, 'criticalAlertsTable', 'No critical alerts at this time.');
                                }
                            });
                    })
                    .catch(error => {
                        console.error('Error resolving all critical alerts:', error);
                        showError('Error resolving some alerts');
                    });
            } else {
                showSuccess('No critical alerts to resolve');
            }
        })
        .catch(error => {
            console.error('Error fetching critical alerts:', error);
            showError('Error fetching critical alerts');
        });
}

/**
 * Format alert message to display on multiple lines
 * Example: "[COOLDOWN] Inbound Throughput on PA1410: 710.39 Mbps > 350.00 Mbps"
 * Becomes:
 * Line 1: [COOLDOWN] Inbound
 * Line 2: Throughput on PA1410:
 * Line 3: 710.39 Mbps > 350.00 Mbps
 */
function formatAlertMessage(message) {
    // Pattern: [TAG] Word Throughput on DEVICE: VALUE > VALUE
    const match = message.match(/^(\[.*?\]\s+\w+)\s+(Throughput on [^:]+:)\s+(.+)$/);

    if (match) {
        const line1 = escapeHtml(match[1]);  // [COOLDOWN] Inbound
        const line2 = escapeHtml(match[2]);  // Throughput on PA1410:
        const line3 = escapeHtml(match[3]);  // 710.39 Mbps > 350.00 Mbps

        return `${line1}<br>${line2}<br>${line3}`;
    }

    // If pattern doesn't match, return escaped original message
    return escapeHtml(message);
}

function renderAlertsInTable(alerts, containerId, emptyMessage) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (alerts.length === 0) {
        container.innerHTML = `<p style="text-align: center; color: #666; padding: 40px; font-family: var(--font-secondary);">${emptyMessage}</p>`;
        return;
    }

    let html = `
        <div style="overflow-x: auto;">
            <table style="width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;">
                <thead>
                    <tr style="background: #f5f5f5; border-bottom: 2px solid #FA582D;">
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Time</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Device</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600; color: #333; font-family: var(--font-primary);">Message</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Severity</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Status</th>
                        <th style="padding: 12px; text-align: center; font-weight: 600; color: #333; font-family: var(--font-primary);">Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;

    alerts.forEach((alert, index) => {
        const severityColors = {
            'critical': '#dc3545',
            'warning': '#ffc107',
            'info': '#17a2b8'
        };
        const severityColor = severityColors[alert.severity] || '#6c757d';
        const rowStyle = index % 2 === 0 ? 'background: #ffffff;' : 'background: #f8f9fa;';
        const time = new Date(alert.triggered_at).toLocaleString();
        const statusText = alert.acknowledged_at ? '✓ Acknowledged' : '🔴 Active';

        html += `
            <tr style="${rowStyle} border-bottom: 1px solid #dee2e6;" onmouseover="this.style.backgroundColor='#f0f0f0'" onmouseout="this.style.backgroundColor='${index % 2 === 0 ? '#ffffff' : '#f8f9fa'}'">
                <td style="padding: 12px; color: #333;">${time}</td>
                <td style="padding: 12px; color: #666;">${escapeHtml(getDeviceNameById(alert.device_id))}</td>
                <td style="padding: 12px; color: #666; line-height: 1.5;">${formatAlertMessage(alert.message)}</td>
                <td style="padding: 12px; text-align: center;">
                    <span style="display: inline-block; padding: 4px 12px; border-radius: 12px; background: ${severityColor}; color: white; font-size: 0.75em; font-weight: 600; text-transform: uppercase; font-family: var(--font-primary);">${alert.severity}</span>
                </td>
                <td style="padding: 12px; text-align: center; color: #666;">${statusText}</td>
                <td style="padding: 12px; text-align: center;">
                    ${!alert.acknowledged_at ? `<button onclick="acknowledgeAlert(${alert.id})" style="padding: 6px 12px; margin: 0 4px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: var(--font-primary);">Acknowledge</button>` : ''}
                </td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// Export functions for global access
window.loadAlertConfigs = loadAlertConfigs;
window.loadAlertHistory = loadAlertHistory;
window.showCreateAlertModal = showCreateAlertModal;
window.showCreateApplicationAlertModal = showCreateApplicationAlertModal;
window.editAlertConfig = editAlertConfig;
window.saveAlertConfig = saveAlertConfig;
window.deleteAlertConfig = deleteAlertConfig;
window.closeAlertConfigModal = closeAlertConfigModal;
window.acknowledgeAlert = acknowledgeAlert;
window.resolveAlert = resolveAlert;
window.testEmailNotification = testEmailNotification;
window.testWebhookNotification = testWebhookNotification;
window.testSlackNotification = testSlackNotification;
window.initAlertsPage = initAlertsPage;
window.loadAlertTemplates = loadAlertTemplates;
window.viewTemplateDetails = viewTemplateDetails;
window.closeTemplateDetailsModal = closeTemplateDetailsModal;
window.showApplyTemplateModal = showApplyTemplateModal;
window.applyTemplate = applyTemplate;
window.closeApplyTemplateModal = closeApplyTemplateModal;
window.loadQuickStartScenarios = loadQuickStartScenarios;
window.showApplyQuickStartModal = showApplyQuickStartModal;
window.applyQuickStart = applyQuickStart;
window.closeApplyQuickStartModal = closeApplyQuickStartModal;
window.initTemplatesPage = initTemplatesPage;
window.showTemplatesModal = showTemplatesModal;
window.closeTemplatesBrowserModal = closeTemplatesBrowserModal;
window.showQuickStartModal = showQuickStartModal;
window.closeQuickStartBrowserModal = closeQuickStartBrowserModal;
window.closeAlertHistoryModal = closeAlertHistoryModal;
window.filterAlertHistory = filterAlertHistory;
window.showInfoAlertsModal = showInfoAlertsModal;
window.closeInfoAlertsModal = closeInfoAlertsModal;
window.showWarningAlertsModal = showWarningAlertsModal;
window.closeWarningAlertsModal = closeWarningAlertsModal;
window.showCriticalAlertsModal = showCriticalAlertsModal;
window.closeCriticalAlertsModal = closeCriticalAlertsModal;
window.showAlertHistoryFullModal = showAlertHistoryFullModal;
window.closeAlertHistoryFullModal = closeAlertHistoryFullModal;
window.acknowledgeAllInfoAlerts = acknowledgeAllInfoAlerts;
window.acknowledgeAllWarningAlerts = acknowledgeAllWarningAlerts;
window.acknowledgeAllCriticalAlerts = acknowledgeAllCriticalAlerts;
window.resolveAllActiveAlerts = resolveAllActiveAlerts;
window.resolveAllCriticalAlerts = resolveAllCriticalAlerts;
