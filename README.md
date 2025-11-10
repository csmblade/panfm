# PANfm - Palo Alto Networks Firewall Monitor

![Version](https://img.shields.io/badge/Version-1.8.1-brightgreen?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web_Framework-black?style=for-the-badge&logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Visitors](https://api.visitorbadge.io/api/visitors?path=csmblade%2Fpanfm&countColor=%23FA582D&style=for-the-badge&labelStyle=upper)

A real-time monitoring dashboard for Palo Alto Networks firewalls with automated PAN-OS upgrades, content management, and multi-device support. This is a POC experiment to see how agentic AI can help bring ideas to life.

<p align="center">
  <img src="screenshot.png" alt="PANfm Dashboard Screenshot" width="800">
</p>

## Quick Start

### Prerequisites
- Docker and Docker Compose

### Choose Your Branch

PANfm uses a two-branch workflow:
- **`main` branch** - Stable production releases (recommended for deployment)
- **`test` branch** - Active development (for contributors and testing)

For production use, clone `main`.

### Deploy with Docker

```bash
# Clone the repository (main branch - stable)
git clone https://github.com/csmblade/panfm.git
cd panfm

# IMPORTANT: First-time setup - Create required files BEFORE starting Docker
# This prevents Docker from creating directories instead of files
chmod +x setup.sh
./setup.sh

# Start the application
docker compose up -d

# View logs
docker compose logs -f
```

**CRITICAL:** Always run `./setup.sh` BEFORE `docker compose up`. If you skip this step, Docker will create directories instead of files for the volume mounts, causing the application to fail.

**Note:** The `setup.sh` script creates:
- `settings.json` - Default application settings
- `devices.json` - Empty device list
- `encryption.key` - Encryption key for sensitive data
- `auth.json` - User authentication data (default: admin/admin)
- `device_metadata.json` - Device metadata storage (encrypted)
- `mac_vendor_db.json` - MAC vendor database (upload via Settings)
- `service_port_db.json` - Service port database (upload via Settings)
- `data/` - Data directory

The dashboard will be available at **http://localhost:3000**

### First Login

**Default Credentials:**
- Username: `admin`
- Password: `admin`

**IMPORTANT:** You will be required to change the default password on first login.

## Updating the Application

When you update the code (git pull), restart the Docker container:

```bash
# Quick restart (preserves data)
docker compose restart

# Full rebuild (if dependencies changed)
docker compose down
docker compose up -d --build
```

### Troubleshooting Login Issues After Update

If you get 401 errors after updating from an older version, your auth.json may need to be migrated to the new structure:

```bash
chmod +x fix-auth.sh
./fix-auth.sh
```

This will reset your credentials to the default `admin/admin`.

### Windows Users

Use the provided batch scripts for convenience:

```cmd
quick-restart.bat      # Quick restart (keeps data)
restart-docker.bat     # Full restart (clears volumes)
```

## Local Development & Testing

### Test Before Committing (Docker Desktop)

**For Windows developers using Docker Desktop**, you can test changes locally before pushing to GitHub:

```cmd
# 1. Make your code changes in your editor

# 2. Test locally with Docker Desktop
local-test.bat

# 3. Test in browser at http://localhost:3000
#    - Verify all features work
#    - Check browser console for errors (F12)
#    - Verify Services tab shows APScheduler/Database status

# 4. If everything works, commit and push
docker compose down
git add .
git commit -m "Your commit message"
git push origin test
```

**What `local-test.bat` does**:
- ✅ Checks Docker Desktop is running
- ✅ Rebuilds image with your latest code
- ✅ Starts fresh container on port 3000
- ✅ Opens browser automatically
- ✅ Shows testing checklist

**Detailed Setup Guide**: See [DOCKER_SETUP.md](DOCKER_SETUP.md) for complete Docker Desktop setup instructions, troubleshooting, and advanced commands.

### Quick Development Scripts

| Script | Purpose | Data |
|--------|---------|------|
| `local-test.bat` | **Full test before commit** | Fresh |
| `quick-restart.bat` | Quick code changes | Kept |
| `restart-docker.bat` | Clean state needed | Cleared |

## Data Persistence

The following data persists across container restarts:
- `encryption.key` - Encryption key (DO NOT LOSE THIS)
- `settings.json` - Application settings (encrypted)
- `devices.json` - Firewall device configurations (encrypted)
- `auth.json` - User authentication data (encrypted)
- `device_metadata.json` - Device custom names, tags, locations (encrypted)
- `mac_vendor_db.json` - MAC vendor database (6.7MB, optional)
- `service_port_db.json` - Service port database (851KB, optional)

**IMPORTANT:** Backup `encryption.key` securely. Losing it means losing access to all encrypted data.

### Optional Databases

Download and upload via **Settings > Databases**:
- **MAC Vendor Database**: [maclookup.app](https://maclookup.app/downloads/json-database) - Shows manufacturer names for MAC addresses
- **Service Port Database**: Upload your own JSON mapping of port numbers to service names

## Features

- Multi-device firewall monitoring
- Database-first architecture with 1-minute updates
- Historical throughput and system metrics with advanced charting
- Automated PAN-OS upgrades
- Content update management
- Traffic and threat log analysis
- Connected devices tracking
- DHCP lease monitoring
- Security policy management
- All sensitive data encrypted at rest

## Support

For issues or questions, check the application logs:

```bash
docker compose logs -f
```

Enable debug logging in the Settings page for detailed troubleshooting.

## Branches

- **`main`** - Stable production releases, tagged versions
- **`test`** - Active development, latest features

## License

MIT License - See LICENSE file for details

---

Built for network security professionals
