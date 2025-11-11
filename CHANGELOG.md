# Changelog

All notable changes to PANfm (Palo Alto Networks Firewall Monitor) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.10.0] - 2025-11-11 - "Production Architecture"

### Major Changes
- **Dual-Process Architecture**: Separated web server and scheduler into independent processes
  - `app.py` (web process) - Serves HTTP requests, read-only database access
  - `clock.py` (background scheduler) - APScheduler for data collection and alerts
  - Eliminates scheduler blocking web requests
  - Independent scaling and debugging
- **Database-First Design**: All throughput data now stored in SQLite with 1-minute retention
  - `throughput_history.db` - Historical metrics with configurable retention
  - `throughput_storage.py` - SQLAlchemy ORM models (1,496 lines)
  - `throughput_collector.py` - Automated data collection (668 lines)
- **Docker Compose Multi-Service**: Two containers sharing volume mounts
  - `panfm` service (web)
  - `panfm-clock` service (scheduler)

### Added
- SQLite Write-Ahead Logging (WAL) mode for better concurrency
- Database retention policies (configurable per-table)
- Throughput chart time range selector (1h, 6h, 12h, 24h, 7d, 30d)
- Services page showing APScheduler and database status
- Alembic migrations for database schema versioning
- Test scheduler script for development

### Changed
- Removed APScheduler from app.py (moved to clock.py)
- Throughput data served from database instead of in-memory
- Applications page now database-first for consistency
- Docker deployment requires both containers running

### Fixed
- Eliminated scheduler-induced web request blocking
- Resolved database locking issues during collection
- Memory leaks from long-running in-process scheduler

**For detailed information, see**: [RELEASE_NOTES_v1.10.0.md](RELEASE_NOTES_v1.10.0.md)

---

## [1.9.0] - "Intelligent Alerting"

### Major Changes
- **Complete Alert System** with 9 pre-built alert templates
- **Multi-Channel Notifications**: SMTP email and webhook support
- **4 Quick-Start Scenarios** for rapid deployment

### Added
- **Alert Manager** (`alert_manager.py`, 953 lines)
  - 9 alert types: CPU, memory, sessions, threats, interface errors, interface down, disk usage, license expiring, firewall unreachable
  - Flexible scheduling with business hours support
  - Alert state management (triggered, acknowledged, resolved)
- **Notification System** (`notification_manager.py`, 602 lines)
  - SMTP client with TLS support
  - Webhook HTTP POST notifications
  - Template rendering with device context
  - Test notification functionality
- **Alert Templates** (`alert_templates.py`, 570 lines)
  - 9 comprehensive templates with recommended thresholds
  - Quick-start scenarios: Basic Monitoring, Critical Only, Full Coverage, Business Hours
- **Alerts UI** (`pages-alerts.js`, 1,189 lines)
  - Alert configuration interface
  - Alert history with filtering
  - Acknowledgment and resolution
  - Real-time status updates
- **24 Alert API Endpoints** (`routes_alerts.py`, 776 lines)
- SQLite `alerts.db` database for alert history

### Changed
- Added alert monitoring to background scheduler

**For detailed information, see**: [RELEASE_NOTES_v1.9.0.md](RELEASE_NOTES_v1.9.0.md)

---

## [1.8.3] - "UI/UX Enhancement"

### Added
- Time range dropdown for throughput charts (1h, 6h, 12h, 24h, 7d, 30d)
- Database-first architecture for Applications page

### Changed
- Applications page now queries database instead of real-time API calls
- Improved consistency between throughput and applications data

---

## [1.8.2] - "Phase 6 Refactoring"

### Changed
- Split `pages-connected-devices.js` (1,024 lines) into 3 focused modules:
  - `pages-connected-devices-core.js` (624 lines) - Core data, state, table rendering
  - `pages-connected-devices-metadata.js` (482 lines) - Metadata modal, autocomplete, API
  - `pages-connected-devices-export.js` (138 lines) - CSV/XML export

---

## [1.8.1] - "Phase 2 & 3 Modular Architecture Refactoring"

### Changed
- Split `firewall_api.py` (967 lines) into 12 focused modules
- Split `routes.py` (966 lines) into 6 focused route modules
- Total reduction: 1,933 lines → 228 + 57 lines in main files

**Created Firewall API Modules**:
- `firewall_api_metrics.py` (422 lines)
- `firewall_api_throughput.py` (426 lines)
- `firewall_api_logs.py` (452 lines)
- `firewall_api_applications.py` (359 lines)
- `firewall_api_health.py` (303 lines)
- `firewall_api_mac.py` (128 lines)
- `firewall_api_network.py` (526 lines)
- `firewall_api_devices.py` (461 lines)
- `firewall_api_upgrades.py` (427 lines)
- `firewall_api_content.py` (229 lines)
- `firewall_api_dhcp.py` (288 lines)

**Created Route Modules**:
- `routes_auth.py` (138 lines)
- `routes_monitoring.py` (635 lines)
- `routes_devices.py` (1,187 lines)
- `routes_operations.py` (301 lines)
- `routes_upgrades.py` (197 lines)

---

## [1.6.3] - "DHCP Monitoring"

### Added
- DHCP lease monitoring and display
- DHCP hostname mappings integrated with connected devices
- `firewall_api_dhcp.py` module

**For detailed information, see**: [RELEASE_NOTES_v1.6.3.md](RELEASE_NOTES_v1.6.3.md)

---

## [1.6.1] - "Backup & Restore System"

### Added
- Full backup/restore system (`backup_restore.py`)
- Backup includes encryption key for disaster recovery
- Export/import functionality for all critical data
- 8+ data sources backed up

---

## [1.5.4] - "Device Metadata System"

### Added
- Custom device names, tags, locations, and comments
- Device metadata management (`device_metadata.py`, 366 lines)
- 8 metadata API endpoints
- Export/import for metadata backup
- Autocomplete for tags and locations

**For detailed information, see**: [RELEASE_NOTES_v1.5.4.md](RELEASE_NOTES_v1.5.4.md)

---

## [1.5.0] - "Content Management"

### Added
- Content update management system
- Check, download, and install content updates
- Job-based progress tracking

---

## [1.3.0] - "Resilient Upgrades"

### Added
- Automatic reboot monitoring with status polling
- Browser navigation resilience (localStorage state)
- Version dropdown for PAN-OS selection
- Device status indicators on Managed Devices page

### Changed
- Job polling interval from 5s to 15s (reduced API load)
- Rate limiting improvements for upgrade workflows

---

## [1.2.0] - "Automated Upgrades"

### Added
- PAN-OS automated upgrade system (5-step workflow)
- `firewall_api_upgrades.py` module
- `pages-panos-upgrade.js` frontend module
- Real-time job status polling

---

## [1.0.3] - "Tech Support"

### Added
- Tech support file generation
- Asynchronous job-based generation
- Download link for completed files

### Removed
- Policies page (removed `firewall_api_policies.py`)

---

## [1.0.2] - "Security Hardening"

### Added
- Authentication system (`auth.py`)
- CSRF protection (Flask-WTF)
- Rate limiting (Flask-Limiter)
- Encryption security improvements
- Environment-based configuration

---

## [1.0.1] - "Module Split"

### Changed
- Split `firewall_api.py` (1,567 lines) into 4 modules
- 63% reduction in main file size

---

## [1.0.0] - "Modular Refactoring"

### Changed
- Refactored monolithic `app.py` (1,895 lines) into 6 modules
- Created PROJECT_MANIFEST.md
- Maintained all functionality

---

## [0.9.0] - "Monolith"

### Initial
- Single `app.py` file (1,895 lines)
- Basic firewall monitoring functionality

---

## Version Numbering

PANfm follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes, major architecture changes
- **MINOR**: New features, significant updates (backward compatible)
- **PATCH**: Bug fixes, small improvements, documentation updates

## Documentation

For detailed release notes, see individual `RELEASE_NOTES_v*.md` files in the repository root.

For architecture details, see `.claude/reference/module-details.md`.
