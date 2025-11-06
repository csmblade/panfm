"""
PANfm Version Management
Semantic Versioning: MAJOR.MINOR.PATCH

MAJOR: Breaking changes, major architecture changes
MINOR: New features, significant updates (backward compatible)
PATCH: Bug fixes, small improvements, documentation updates
"""

# Current version
VERSION_MAJOR = 1
VERSION_MINOR = 7
VERSION_PATCH = 5

# Build metadata (optional)
VERSION_BUILD = "20251106"  # YYYYMMDD format

# Pre-release identifier (optional, e.g., 'alpha', 'beta', 'rc1')
VERSION_PRERELEASE = None

# Codename for this version (optional)
VERSION_CODENAME = "Chart Preloading"


def get_version():
    """
    Get the full version string
    Returns: str - Full version string (e.g., "1.0.3" or "1.0.3-beta")
    """
    version = f"{VERSION_MAJOR}.{VERSION_MINOR}.{VERSION_PATCH}"

    if VERSION_PRERELEASE:
        version += f"-{VERSION_PRERELEASE}"

    return version


def get_version_info():
    """
    Get detailed version information
    Returns: dict - Dictionary with version details
    """
    return {
        'version': get_version(),
        'major': VERSION_MAJOR,
        'minor': VERSION_MINOR,
        'patch': VERSION_PATCH,
        'build': VERSION_BUILD,
        'prerelease': VERSION_PRERELEASE,
        'codename': VERSION_CODENAME,
        'display': get_display_version()
    }


def get_display_version():
    """
    Get version string suitable for UI display
    Returns: str - Formatted version for display (e.g., "v1.0.3 - Tech Support")
    """
    version = f"v{get_version()}"

    if VERSION_CODENAME:
        version += f" - {VERSION_CODENAME}"

    return version


def get_short_version():
    """
    Get short version string (MAJOR.MINOR only)
    Returns: str - Short version (e.g., "1.0")
    """
    return f"{VERSION_MAJOR}.{VERSION_MINOR}"


# Version history and changelog
VERSION_HISTORY = [
    {
        'version': '1.7.5',
        'codename': 'Chart Preloading',
        'date': '2025-11-06',
        'type': 'patch',
        'changes': [
            'CRITICAL FIX: Chart now preloads with recent historical data on page load',
            'BUG: Opening new browser showed empty chart starting from zero',
            'BUG: chartData arrays initialized empty, only filled as new data arrived',
            'BUG: User had to wait for MAX_DATA_POINTS cycles before seeing useful chart',
            'FIX: Added preloadChartData() function to load last 30 data points from database',
            'FIX: Queries /api/throughput/history?range=30m on page load',
            'FIX: Populates chartData.labels, inbound, outbound, total arrays before polling starts',
            'IMPACT: New browser sessions immediately show recent throughput history',
            'IMPACT: Chart appears populated instead of empty on first load',
            'IMPACT: Better user experience - no waiting for data to accumulate',
            'Implementation: preloadChartData() called before fetchThroughputData() in init()',
            'Takes last MAX_DATA_POINTS (30) samples from historical query',
            'Graceful fallback: If no data available, continues with empty chart',
            'Modified files: static/app.js (added preloadChartData function, 47 lines)',
            'Modified files: version.py (bumped to v1.7.5)',
            'This completes the database-first architecture with full chart preloading'
        ]
    },
    {
        'version': '1.7.4',
        'codename': 'Auto-Select Device Fix',
        'date': '2025-11-06',
        'type': 'patch',
        'changes': [
            'CRITICAL FIX: /api/throughput returns no data when selected_device_id is empty',
            'BUG: When settings.selected_device_id is empty, endpoint queries database with device_id=""',
            'BUG: Query WHERE device_id = "" matches no rows, returns None, displays zeros',
            'FIX: Auto-select first enabled device if selected_device_id is empty',
            'FIX: Loads devices and picks first enabled device automatically',
            'IMPACT: Dashboard now shows data even if no device explicitly selected',
            'IMPACT: Works on fresh install or when settings are reset',
            'IMPACT: Fixes "no data being returned at all" issue',
            'Modified files: routes.py (/api/throughput endpoint with auto-select)',
            'Modified files: version.py (bumped to v1.7.4)',
            'Works with v1.7.3 collector fix to provide complete solution'
        ]
    },
    {
        'version': '1.7.3',
        'codename': 'Collector Initialization Fix',
        'date': '2025-11-06',
        'type': 'patch',
        'changes': [
            'CRITICAL FIX: Collector was not loading devices at all - NO DATA WAS BEING COLLECTED',
            'BUG: device_manager.load_devices() returns a LIST, not a dict',
            'BUG: Collector called devices_data.get("devices", []) on a list, always returned empty []',
            'BUG: This caused "No devices configured, skipping collection" on every cycle',
            'FIX: Changed to directly use devices = device_manager.load_devices()',
            'FIX: Removed incorrect .get("devices", []) call',
            'IMPACT: Collector now actually runs and stores data in database',
            'IMPACT: Scheduler starts properly when container/app starts',
            'IMPACT: Data collection works independently of selected device',
            'Modified files: throughput_collector.py (fixed device loading)',
            'Modified files: version.py (bumped to v1.7.3)',
            'This fixes the issue where NO data was being gathered at all'
        ]
    },
    {
        'version': '1.7.2',
        'codename': 'Multi-Device Collection Fix',
        'date': '2025-11-06',
        'type': 'patch',
        'changes': [
            'CRITICAL FIX: get_throughput_data() now accepts device_id parameter',
            'BUG: Collector was calling get_throughput_data(device_id) but function ignored the parameter',
            'BUG: Function always used selected_device_id from settings, only collecting data for currently selected device',
            'FIX: Added device_id parameter to get_throughput_data() with fallback to settings',
            'FIX: Collector now properly collects data from ALL enabled devices, not just selected one',
            'IMPACT: Multi-device environments now correctly populate database with all device data',
            'IMPACT: Multiple browsers/machines now see updated data from any device',
            'Modified files: firewall_api.py (added device_id parameter to get_throughput_data)',
            'Modified files: version.py (bumped to v1.7.2)',
            'This fixes the issue where different browsers showed no data for non-selected devices'
        ]
    },
    {
        'version': '1.7.1',
        'codename': 'Database-First Architecture',
        'date': '2025-11-06',
        'type': 'patch',
        'changes': [
            'ARCHITECTURE CHANGE: /api/throughput endpoint now reads from SQLite database instead of querying firewall',
            'PERFORMANCE: Eliminates redundant real-time firewall API calls for throughput data',
            'EFFICIENCY: Background APScheduler collector uses configurable refresh_interval from settings',
            'USER CONTROL: APScheduler interval respects refresh_interval setting (default 15s)',
            'MULTI-BROWSER: All browsers/tabs now see consistent data from database cache',
            'NEW: get_latest_sample() method in throughput_storage.py',
            'DYNAMIC: Query window uses 2x refresh_interval as max age to allow for timing variance',
            'Graceful fallback: Returns zeros if no recent data (collector starting up)',
            'BENEFIT: Reduced firewall API load, improved scalability',
            'BENEFIT: User can control collection frequency via Settings page',
            'BENEFIT: Foundation for Phase 2 migration of all dashboard data to database-first',
            'Modified files: app.py (APScheduler uses refresh_interval)',
            'Modified files: routes.py (refactored /api/throughput endpoint, dynamic max_age)',
            'Modified files: throughput_storage.py (added get_latest_sample method)',
            'KEPT: previous_stats global variable (still used by collector for rate calculation)',
            'No frontend changes required - endpoint returns same JSON format'
        ]
    },
    {
        'version': '1.7.0',
        'codename': 'Historical Analytics',
        'date': '2025-11-06',
        'type': 'minor',
        'changes': [
            'NEW FEATURE: Historical network throughput graphing with 90-day retention',
            'SQLite-based time-series storage (~10.4 MB per device for 90 days)',
            'Background data collection via APScheduler (15-second intervals)',
            'New backend modules: throughput_storage.py (390 lines), throughput_collector.py (170 lines)',
            'NEW: CSV export functionality - download historical data with all metrics',
            'NEW: Statistics endpoint - min/max/avg calculations for time ranges',
            'NEW: Interactive statistics panel with detailed metrics',
            'New API endpoints: GET /api/throughput/history, /history/export, /history/stats',
            'Time range support: 1h, 6h, 24h, 7d, 30d, 90d',
            'Auto-resolution: raw (<6h), hourly (week), daily (>7d)',
            'Export includes: timestamp, throughput (Mbps/PPS), sessions, CPU, memory',
            'Statistics show: min/max/avg for inbound/outbound/total throughput',
            'UI: Time range selector with 7 preset buttons',
            'UI: Export CSV button (green) and Stats button (purple) appear in historical mode',
            'UI: Collapsible statistics panel with color-coded metrics',
            'UI: Auto-reset to real-time when device changes',
            'Integrated with backup/restore system (throughput_db field in backups)',
            'New settings: throughput_retention_days (90), throughput_collection_enabled (true)',
            'Automatic cleanup of old data based on retention policy',
            'New dependency: Flask-APScheduler==1.13.1',
            'Modified files: app.py, config.py, routes.py, backup_restore.py, requirements.txt',
            'Modified files: templates/index.html, static/app.js',
            'Database file: throughput_history.db (auto-created, included in backups)',
            'Rate limits: history (600/hour), export (100/hour), stats (600/hour)'
        ]
    },
    {
        'version': '1.6.3',
        'codename': 'DHCP Monitoring',
        'date': '2025-11-03',
        'type': 'patch',
        'changes': [
            'NEW FEATURE: DHCP tab added to Device Info page',
            'Display active DHCP leases with IP, MAC, hostname, state, expiration, interface',
            'Concise summary showing total active leases',
            'State color coding: BOUND (green), EXPIRED (red), OFFERED (yellow)',
            'Empty state handling for firewalls without DHCP configured',
            'New backend module: firewall_api_dhcp.py (336 lines)',
            'New API endpoint: GET /api/dhcp-leases (rate limit: 600/hour)',
            'Functions: get_dhcp_servers(), get_dhcp_leases_detailed(), parse_dhcp_entry()',
            'API command: <show><dhcp><server><lease></lease></server></dhcp></show>',
            'Tab positioned after Interfaces tab for logical workflow',
            'Frontend: loadDhcpLeases() and renderDhcpTable() in pages.js',
            'Device change integration: refreshAllDataForDevice() updated',
            'Full XML parsing with graceful error handling',
            'Modified files: firewall_api_dhcp.py (new), routes.py, firewall_api.py',
            'Modified files: templates/index.html, static/pages.js, static/app.js, version.py'
        ]
    },
    {
        'version': '1.6.2',
        'codename': 'Bug Fix Release',
        'date': '2025-11-03',
        'type': 'patch',
        'changes': [
            'CRITICAL FIX: Double encryption bug completely resolved',
            'Enhanced is_encrypted() to use Fernet signature detection (gAAAAA prefix)',
            'Previous length-based check (>80 chars) was insufficient',
            'Now verifies base64-decoded data starts with Fernet version byte',
            'Fixed save_devices() to check encryption status before encrypting API keys',
            'Prevents double encryption when devices loaded/modified/saved',
            'CRITICAL FIX: Auto-select first device after backup restore',
            'Fixed "No connected devices found" error after restore',
            'Applications and Connected Devices pages now work immediately after restore',
            'Auto-selects first device if selected_device_id is empty after device restore',
            'CLEANUP: Removed deprecated "version" field from docker-compose.yml',
            'Eliminates Docker Compose v2.x warning message',
            'DOCUMENTATION: Added backup/restore integration requirement to CLAUDE.md',
            'All future features with persistent data must integrate with backup system',
            'Added testing requirements and code patterns to follow',
            'ENCRYPTION CONSISTENCY: Future-proofed device manager operations',
            'Explicit decrypt_api_keys=True in add_device(), update_device(), delete_device()',
            'Modified files: device_manager.py, encryption.py, backup_restore.py',
            'Modified files: docker-compose.yml, .claude/CLAUDE.md',
            '6 commits: cbf5f42, 78a7faf, 5de1b38, 8890fe6, d4d376b, 33d0cb9'
        ]
    },
    {
        'version': '1.6.1',
        'codename': 'Secure Backup Recovery',
        'date': '2025-11-03',
        'type': 'patch',
        'changes': [
            'CRITICAL FIX: Encryption key now included in backups for disaster recovery',
            'SECURITY: Backup filename changed to "panfm_backup_SECURE_[timestamp].json"',
            'SECURITY: Added prominent warning in UI after backup creation',
            'Fixed CRITICAL data loss scenario: backups can now be restored after reinstall',
            'Problem: Backups encrypted with key A could not be decrypted with key B (after reinstall)',
            'Solution: Backup now includes base64-encoded encryption key',
            'Restore process now writes encryption.key BEFORE restoring encrypted data',
            'Backwards compatible: Old backups without encryption_key will show warning',
            'Added security warnings in backup creation UI (recommended storage practices)',
            'UI displays prominent warning about backup sensitivity after download',
            'Updated backup structure: Added "encryption_key" field (base64-encoded)',
            'Enhanced backup docstrings with security warnings',
            'File permissions: encryption.key automatically set to 600 (owner read/write only)',
            'Restore order: encryption_key → settings → devices → metadata',
            'Added debug logging for key restore operations',
            'Modified files: backup_restore.py, pages-backup-restore.js, version.py',
            'This fix ensures disaster recovery works correctly across reinstalls/migrations'
        ]
    },
    {
        'version': '1.6.0',
        'codename': 'Backup & Restore',
        'date': '2025-11-03',
        'type': 'minor',
        'changes': [
            'NEW MAJOR FEATURE: Comprehensive Backup & Restore system',
            'NEW: Site-wide backup (Settings + Devices + Metadata) with JSON export',
            'NEW: Selective restore - choose which components to restore',
            'NEW: Backup info display (version, timestamp, device count, metadata count)',
            'NEW: Metadata migration from global to per-device format',
            'NEW: Migration status check and one-click migration',
            'NEW: "Backup & Restore" tab in Settings page',
            'ARCHITECTURE: Metadata now supports per-device format {device_id: {mac: metadata}}',
            'Backward compatible with legacy global format {mac: metadata}',
            'Auto-detection of metadata format with UUID regex pattern',
            'New backend module: backup_restore.py (286 lines) - backup/restore operations',
            'Enhanced device_metadata.py (366 → 596 lines) - dual format support',
            '7 new API endpoints: backup create/export/restore/info, migration check/migrate',
            'Metadata migration assigns to selected_device_id from settings',
            'Frontend module: pages-backup-restore.js (392 lines) - full UI functionality',
            'File upload with backup validation and info display',
            'Download backups with timestamped filenames',
            'Selective restore checkboxes (Settings/Devices/Metadata)',
            'Migration UI with status check and execute buttons',
            'Comprehensive warning notices about restore operations',
            'Rate limiting: 20/hr backup creation, 10/hr restore, 100/hr info checks',
            'All endpoints protected with CSRF tokens and @login_required',
            'Debug logging throughout all new functions',
            'Backup files contain encrypted data (safe to download)',
            'File size compliance: backup_restore.py (286), pages-backup-restore.js (392)',
            'routes.py: 1531 → 1744 lines (+213 for new endpoints)'
        ]
    },
    {
        'version': '1.5.4',
        'codename': 'Security & Compliance',
        'date': '2025-11-03',
        'type': 'patch',
        'changes': [
            'CRITICAL SECURITY FIX: Removed CSRF bypass decorators from 6 state-changing endpoints',
            'Fixed CSRF vulnerability on device metadata import endpoint (line 590)',
            'Fixed CSRF vulnerability on device create endpoint (line 834)',
            'Fixed CSRF vulnerability on device update endpoint (line 927)',
            'Fixed CSRF vulnerability on device delete endpoint (line 959)',
            'Fixed CSRF vulnerability on test connection endpoint (line 1040)',
            'Fixed CSRF vulnerability on reverse DNS endpoint (line 1309)',
            'API COMPLIANCE: Fixed device_manager.py to use api_request_get() wrapper',
            'Ensures proper API call tracking and statistics across all operations',
            'CODE REVIEW: Comprehensive 4-agent review completed (Security, API, Quality, Frontend)',
            'Security Grade: B+ (87/100) - CSRF issues resolved, perfect encryption/auth',
            'API Compliance: 98/100 - Sequential calls, proper error handling, XML parsing',
            'Code Quality: B+ (89.5/100) - 95% debug logging coverage, excellent CSRF frontend',
            'Frontend Compliance: 88/100 - Strong device management and typography standards',
            'All CSRF tokens now properly validated on mutating operations',
            'Frontend already sending tokens correctly - backend was unnecessarily bypassing',
            'Database loading fixes: UTF-8 encoding, caching, Docker persistence (v1.5.3)',
            'Improved empty database detection and error handling'
        ]
    },
    {
        'version': '1.5.3',
        'codename': 'Device Metadata',
        'date': '2025-11-03',
        'type': 'patch',
        'changes': [
            'NEW: Location field added to device metadata',
            'NEW: Location column in Connected Devices table (blue badge)',
            'NEW: Location displayed in expandable row details alongside comments',
            'Enhanced device metadata modal with location input field',
            'Location stored and encrypted in device_metadata.json',
            'Chevron indicator now appears for devices with location OR comment',
            'Updated table colspan from 9 to 10 columns for proper layout',
            'Location badge uses distinct blue color (#4A90E2) vs tags (orange)',
            'Consistent styling across table and expandable details',
            'pages-connected-devices.js: 791 lines (under 1,000 limit)'
        ]
    },
    {
        'version': '1.5.2',
        'codename': 'Debug Logging',
        'date': '2025-10-31',
        'type': 'patch',
        'changes': [
            'MAJOR: Comprehensive debug logging improvements across entire codebase',
            'Fixed CRITICAL: All exception handlers now use exception() for full tracebacks (16 functions)',
            'Fixed premature timeout during long PAN-OS upgrades (12-15 min operations)',
            'Added smart timeout extension - extends if receiving progress updates',
            'Fixed intermittent API timeout errors with retry logic and exponential backoff',
            'Added entry logging to 19 utility functions for better tracking',
            'Added progress logging to device management and encryption operations',
            'Debug logging compliance: 95%+ (up from 75%)',
            'Files improved: firewall_api.py, firewall_api_upgrades.py, firewall_api_content.py',
            'Files improved: firewall_api_devices.py, encryption.py, auth.py, device_manager.py, config.py',
            'Increased API timeout from 30s to 60s for large operations',
            'Added consecutive failure tracking (requires 3 failures before abort)',
            'All logging follows CLAUDE.md standards for easier troubleshooting'
        ]
    },
    {
        'version': '1.5.1',
        'codename': 'Hotfix Selector',
        'date': '2025-10-29',
        'type': 'patch',
        'changes': [
            'CRITICAL BUG FIX: Upgrade confirmation modal now shows correct version',
            'Fixed: Selecting hotfix version (e.g., 12.1.3-h1) was showing base version (12.1.3) in confirmation',
            'Added explicit dropdown value re-read before starting upgrade workflow',
            'Prevents potential race condition in version state management',
            'Added debug logging for version selection tracking',
            'Repository cleanup: Removed 32 unnecessary files (~1.8MB)',
            'Simplified README.md from 314 to 89 lines - Docker deployment focused',
            'Added project badges (Version, Python, Flask, Docker, License)',
            'Enhanced .gitignore with cleanup patterns',
            'Rate limiting improvements for auto-refresh support (600/hour monitoring endpoints)'
        ]
    },
    {
        'version': '1.5.0',
        'codename': 'Content Management',
        'date': '2025-10-29',
        'type': 'minor',
        'changes': [
            'NEW: Content update system for App & Threat, Antivirus, WildFire',
            'Combined download & install workflow with job polling',
            'Check for Updates button in Components tab (Device Info)',
            'Same modal design as PAN-OS upgrades for consistency',
            'No reboot required for content updates',
            'New backend module: firewall_api_content.py (211 lines)',
            'New frontend module: pages-content-updates.js (374 lines)',
            '3 new API endpoints: /api/content-updates/check, download, install',
            'Reuses existing job polling infrastructure (/api/panos-upgrade/job-status)',
            'Per .clinerules: New modules maintain file size limits',
            'All functions include debug logging',
            'CSRF tokens on all POST requests',
            'Rate limiting: check 20/hr, download/install 50/hr'
        ]
    },
    {
        'version': '1.4.0',
        'codename': 'Performance Optimized',
        'date': '2025-10-28',
        'type': 'minor',
        'changes': [
            'CRITICAL: Fixed firewall forced update server connections every 10-15 seconds',
            'New lightweight /api/firewall-health endpoint for reboot monitoring',
            'Removed automatic update checks from software-updates endpoint',
            'Update server checks now ONLY occur when user clicks "Check for Updates"',
            'MAJOR: Optimized device switching - reduced from 8+ API calls to 1-2 calls',
            'refreshAllDataForDevice() now loads only currently visible page',
            'Removed duplicate page loading that was causing extra API calls',
            'Reduced Applications default log fetch from 5000 to 1000 (80% less data)',
            'Added check_firewall_health() function for lightweight health checks',
            'Updated reboot monitoring in both standalone and upgrade tabs',
            'Significant reduction in firewall load and network traffic',
            'Performance improvements: 75-85% reduction in device switch API calls'
        ]
    },
    {
        'version': '1.3.3',
        'codename': 'Resilient Upgrades',
        'date': '2025-10-28',
        'type': 'patch',
        'changes': [
            'Fixed reboot monitoring in standalone Reboot tab (was freezing)',
            'Added real-time device polling during reboot (15-second intervals)',
            'Added live status indicators (🔴 offline, 🟡 checking, 🟢 online)',
            'Added elapsed time counter during reboot monitoring',
            'Automatic page refresh when device comes back online after reboot',
            'Fixed device switch caching - reboot UI state now clears when switching devices',
            'Improved error logging in check_available_panos_versions() for diagnostics',
            'Better error messages for connectivity issues'
        ]
    },
    {
        'version': '1.3.2',
        'codename': 'Resilient Upgrades',
        'date': '2025-10-28',
        'type': 'patch',
        'changes': [
            'Fixed base image detection for hotfix versions (e.g., 12.1.3-h1)',
            'Base image is now determined as the first (lowest) version in target major.minor series',
            'Handles non-x.y.0 base images correctly (e.g., 12.1.2 as base for 12.1.3)',
            'Hotfix versions now correctly identify their base version',
            'Added comprehensive console logging for base image detection',
            'Case-insensitive check for downloaded status',
            'File size: 999 lines (within 1,000-line JavaScript limit)'
        ]
    },
    {
        'version': '1.3.1',
        'codename': 'Resilient Upgrades',
        'date': '2025-10-28',
        'type': 'patch',
        'changes': [
            'Added automatic base image detection and download for PAN-OS upgrades',
            'New function: getRequiredBaseImage() detects when maintenance releases need base images',
            'Base image logic: x.y.0 required before installing x.y.z (where z > 0)',
            'Automatic workflow: Downloads base image first if needed, then target version',
            'UI indicators: Green checkmark if base downloaded, yellow warning if needed',
            'Dynamic button text: "Download Base + Version, Install & Reboot" when base needed',
            'Confirmation dialog shows actual steps including base image download',
            'Adjusted progress percentages: Base (0-20%), Target (20-40%), Install (40-90%), Reboot (90-100%)',
            'Updated pollJobStatus() to accept custom progress ranges',
            'Prevents installation failures due to missing base images',
            'Code optimizations to stay under 1,000-line JavaScript limit (999 lines)',
            'Increased software-updates endpoint rate limit to 120 per minute'
        ]
    },
    {
        'version': '1.3.0',
        'codename': 'Resilient Upgrades',
        'date': '2025-10-28',
        'type': 'minor',
        'changes': [
            'Added automatic reboot monitoring with real-time device status polling',
            'New feature: Pulsing progress bar animation during reboot monitoring',
            'New feature: Live elapsed time counter during reboot (updates every second)',
            'New feature: Status indicators (🔴 offline, 🟡 checking, 🟢 online)',
            'New feature: Automatic device data refresh when reboot completes',
            'Added browser navigation resilience - resume monitoring after closing browser',
            'Added localStorage persistence for upgrade and reboot monitoring state',
            'New feature: Version dropdown to select any available PAN-OS version',
            'New feature: Skip download step if version already downloaded',
            'Improved download success detection - checks details field for "success"',
            'Fixed rate limiting: Changed polling interval from 5s to 15s',
            'Set job-status endpoint rate limit to 300/hour (15s intervals)',
            'Set software-updates endpoint rate limit to 120/minute for reboot monitoring',
            'Added SSL warning suppression for self-signed certificates',
            'Fixed error message persistence when switching devices',
            'Added device status indicators on Managed Devices page (🟢🔴⚫)',
            'Added sortable columns on Managed Devices page (all 6 columns)',
            'Added standalone Reboot tab in Device Info section',
            'Improved error handling and state cleanup throughout workflow',
            'pages-panos-upgrade.js: 650 → 875 lines (browser resilience + reboot monitoring)',
            'Maintained compliance with .clinerules (under 1,000-line JavaScript limit)'
        ]
    },
    {
        'version': '1.2.0',
        'codename': 'Automated Upgrades',
        'date': '2025-10-28',
        'type': 'minor',
        'changes': [
            'Added PAN-OS automated upgrade system with 5-step workflow',
            'New feature: Check for available PAN-OS versions',
            'New feature: Download PAN-OS versions with job tracking',
            'New feature: Install PAN-OS versions with job tracking',
            'New feature: Real-time job status polling (5-second intervals)',
            'New feature: Firewall reboot after upgrade',
            'Added upgrade progress modal with visual feedback',
            'New backend module: firewall_api_upgrades.py (~400 lines)',
            'New frontend module: pages-panos-upgrade.js (~360 lines)',
            'Added 5 new API endpoints for upgrade operations',
            'Added api_request_post() utility function for POST requests',
            'Maintained modular architecture per .clinerules guidelines'
        ]
    },
    {
        'version': '1.1.1',
        'codename': 'Traffic Insights',
        'date': '2025-10-28',
        'type': 'patch',
        'changes': [
            'Fixed interface IP address display - properly merge hw and ifnet XML data',
            'Fixed VLAN display - replace "0" with "-" for untagged interfaces',
            'Standardized table styling across all pages (Connected Devices, Applications, Interfaces)',
            'Unified font sizing (0.9em) and padding (12px) for consistent readability',
            'Applied brand typography (Roboto headers, Open Sans content) consistently',
            'Improved text fitting in table columns with proper spacing'
        ]
    },
    {
        'version': '1.1.0',
        'codename': 'Traffic Insights',
        'date': '2025-10-28',
        'type': 'minor',
        'changes': [
            'Added Tony Mode - disable session timeout with keepalive',
            'Added real-time interface traffic graphs (updates every 15 seconds)',
            'Added per-interface traffic rate display (Kbps/Mbps/Gbps)',
            'Replaced transceiver column with live traffic visualization',
            'Added support for subinterface traffic monitoring',
            'Implemented DHCP IP address detection for interfaces',
            'Added speed formatting for WAN and interface speeds (Mbps/Gbps)',
            'New API endpoint: /api/interface-traffic',
            'New API endpoint: /api/session-keepalive'
        ]
    },
    {
        'version': '1.0.3',
        'codename': 'Tech Support',
        'date': '2025-10-27',
        'type': 'patch',
        'changes': [
            'Added tech support file generation with progress tracking',
            'Removed policies page and related code',
            'Fixed CSRF token handling for POST requests',
            'Restored utility functions (formatTimestamp, formatDaysAgo)',
            'Updated documentation (.claude/PROJECT_MANIFEST.md, .claude/.clinerules)'
        ]
    },
    {
        'version': '1.0.2',
        'codename': 'Security Hardening',
        'date': '2025-10-27',
        'type': 'minor',
        'changes': [
            'Added authentication system with bcrypt password hashing',
            'Implemented CSRF protection with Flask-WTF',
            'Added rate limiting with Flask-Limiter',
            'Improved encryption security with file permissions',
            'Removed hardcoded credentials',
            'Added environment-based configuration'
        ]
    },
    {
        'version': '1.0.1',
        'codename': 'Module Split',
        'date': '2025-10-27',
        'type': 'patch',
        'changes': [
            'Split firewall_api.py into specialized modules',
            'Created firewall_api_logs.py for log functions',
            'Created firewall_api_policies.py for policy functions',
            'Created firewall_api_devices.py for device functions',
            'Maintained backward compatibility'
        ]
    },
    {
        'version': '1.0.0',
        'codename': 'Modular Refactoring',
        'date': '2025-10-26',
        'type': 'major',
        'changes': [
            'Initial modular architecture',
            'Split monolithic app.py into focused modules',
            'Created .claude/PROJECT_MANIFEST.md documentation',
            'Established development guidelines'
        ]
    }
]


if __name__ == '__main__':
    # Print version information when run directly
    print(f"PANfm Version: {get_display_version()}")
    print(f"Full version: {get_version()}")
    print(f"Build: {VERSION_BUILD}")
    print(f"\nVersion Info:")
    import json
    print(json.dumps(get_version_info(), indent=2))
