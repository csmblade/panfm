"""
PANfm Version Management
Semantic Versioning: MAJOR.MINOR.PATCH

MAJOR: Breaking changes, major architecture changes
MINOR: New features, significant updates (backward compatible)
PATCH: Bug fixes, small improvements, documentation updates
"""

# Current version
VERSION_MAJOR = 1
VERSION_MINOR = 5
VERSION_PATCH = 3

# Build metadata (optional)
VERSION_BUILD = "20251103"  # YYYYMMDD format

# Pre-release identifier (optional, e.g., 'alpha', 'beta', 'rc1')
VERSION_PRERELEASE = None

# Codename for this version (optional)
VERSION_CODENAME = "Device Metadata"


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
