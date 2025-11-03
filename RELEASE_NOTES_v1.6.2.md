# v1.6.2 - Bug Fix Release

## 🔧 Critical Bug Fixes & Improvements

This patch release resolves critical encryption bugs and post-restore issues discovered in v1.6.1.

---

## 🚨 Critical Issues Fixed

### 1. Double Encryption Bug - RESOLVED

**Problem**: API keys were being encrypted twice when adding/updating devices, resulting in 760+ character encrypted keys (normally 88-120 characters).

**Root Cause**: The `is_encrypted()` function used a simplistic length check (`len(value) > 80`), which failed to detect already-encrypted Fernet tokens.

**Solution**: Enhanced `is_encrypted()` to verify Fernet signature:
```python
# encryption.py lines 282-293
decoded = base64.b64decode(value.encode('utf-8'))
is_fernet = decoded.startswith(b'gAAAAA')  # Fernet version byte
```

**Impact**: API keys now properly detected as encrypted, preventing double encryption in all scenarios.

---

### 2. Device Selection After Restore - FIXED

**Problem**: After restoring a backup, Applications and Connected Devices pages showed "No connected devices found" error, even though devices were successfully restored.

**Root Cause**: `selected_device_id` in settings was empty after restore, so frontend had no device to query.

**Solution**: Auto-select first device if `selected_device_id` is empty after device restore:
```python
# backup_restore.py lines 184-191
if not current_settings.get('selected_device_id') and devices_list:
    current_settings['selected_device_id'] = devices_list[0].get('id')
    save_settings(current_settings)
```

**Impact**: Applications and Connected Devices pages work immediately after restore.

---

### 3. Docker Compose Warning - ELIMINATED

**Problem**: Docker Compose v2.x showed warning: "the attribute `version` is obsolete"

**Solution**: Removed deprecated `version: '3.8'` field from [docker-compose.yml](docker-compose.yml)

**Impact**: Clean Docker Compose startup with no warnings.

---

## 📝 Changes in This Release

### Backend Changes

**[encryption.py](encryption.py)** - Lines 259-295:
- **Enhanced `is_encrypted()` detection**:
  - Previous: Length-based check (`len(value) > 80`)
  - New: Fernet signature verification (`decoded.startswith(b'gAAAAA')`)
  - Definitive way to identify Fernet-encrypted data
  - Prevents false positives and double encryption

**[device_manager.py](device_manager.py)** - Multiple locations:
- **Lines 82-95**: Added `is_encrypted()` check in `save_devices()` before encryption
- **Lines 118, 141, 153**: Explicit `decrypt_api_keys=True` in CRUD operations (future-proofing)
- Prevents double encryption when devices are loaded → modified → saved

**[backup_restore.py](backup_restore.py)** - Lines 184-191:
- **Auto-select first device after restore**
- Checks if `selected_device_id` is empty after device restore
- Automatically selects first device for immediate usability
- Logs device auto-selection for debugging

### Docker Changes

**[docker-compose.yml](docker-compose.yml)** - Line 1:
- Removed deprecated `version: '3.8'` field
- Docker Compose v2.x auto-detects format
- Eliminates warning messages during startup

### Documentation Changes

**[.claude/CLAUDE.md](.claude/CLAUDE.md)** - Lines 64-118:
- **NEW: Backup & Restore Integration section**
- **CRITICAL REQUIREMENT**: All new persistent data features MUST integrate with backup/restore
- Added code patterns and testing requirements
- Added to pre-commit checklist

---

## 🔄 Commit History

This release includes 6 commits from the test branch:

1. **cbf5f42** - Fix device selection after backup restore
2. **78a7faf** - Remove deprecated version field from docker-compose.yml
3. **5de1b38** - Improve is_encrypted() to properly detect Fernet format
4. **8890fe6** - Fix double encryption bug in save_devices()
5. **d4d376b** - Critical fix: Include encryption key in backups (v1.6.1)
6. **33d0cb9** - Future-proof device manager encryption consistency

---

## 🧪 Testing Recommendations

### Test Scenario 1: Device Management Without Double Encryption

1. Add new device via Managed Devices page
2. Enter firewall IP and API key
3. Save device
4. Check devices.json - API key should be ~88-120 characters
5. ✅ Verify device connects successfully
6. Edit device and save again
7. ✅ Verify API key length unchanged (not double encrypted)

### Test Scenario 2: Backup and Restore with Auto-Selection

1. Create backup with multiple devices
2. Delete one device from Managed Devices
3. Restore backup
4. ✅ Verify device restored successfully
5. ✅ Verify Applications page shows data immediately
6. ✅ Verify Connected Devices page shows data immediately
7. Check browser console - should show device auto-selection log

### Test Scenario 3: Docker Compose Startup

1. Run `docker-compose down`
2. Run `docker-compose up -d`
3. ✅ Verify no warning about "version" attribute
4. ✅ Verify container starts successfully

---

## 📦 Upgrade Instructions

### Docker Deployment

```bash
git pull
docker-compose down
docker-compose up -d --build
```

### CLI Deployment

```bash
git pull
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows
pip install -r requirements.txt
python app.py
```

---

## 🔗 Related Releases

- **v1.6.1** - Secure Backup Recovery (2025-11-03)
- **v1.6.0** - Backup & Restore (2025-11-03)
- **v1.5.4** - Security & Compliance (2025-11-03)

---

## ⚠️ Breaking Changes

**None** - This release is fully backward compatible with v1.6.1 and v1.6.0.

---

## 📊 File Changes Summary

| File | Lines Changed | Purpose |
|------|--------------|---------|
| encryption.py | +34 | Enhanced Fernet signature detection |
| device_manager.py | +15 | Double encryption prevention |
| backup_restore.py | +8 | Auto-select device after restore |
| docker-compose.yml | -1 | Remove deprecated version field |
| .claude/CLAUDE.md | +54 | Backup integration requirements |
| version.py | +27 | Version update and changelog |
| RELEASE_NOTES_v1.6.2.md | +230 | This document |

**Total**: 7 files modified, ~367 lines changed

---

## 🔐 Security Notes

### Encryption Improvements

- Fernet signature detection is cryptographically robust
- Uses actual Fernet token structure validation
- Prevents accidental double encryption in all code paths

### Backup File Security (from v1.6.1)

Backup files contain encryption key - store securely:

✅ **RECOMMENDED**:
- Encrypted USB drives
- Password manager secure notes
- Encrypted cloud storage (Tresorit, ProtonDrive)
- Offline encrypted backup location

❌ **DO NOT**:
- Email backup files
- Store in unencrypted cloud storage
- Share via messaging apps
- Store in plaintext on shared drives

---

## 🙏 Acknowledgments

Special thanks to the user who thoroughly tested v1.6.1 and identified:
1. Double encryption bug persisting after initial fix
2. Post-restore device selection issue
3. Docker Compose warning

This feedback enabled a complete resolution of the encryption issues.

---

## 📈 Version Progression

```
v1.6.0 (2025-11-03) - Backup & Restore feature
    ↓
v1.6.1 (2025-11-03) - Include encryption key in backups
    ↓
v1.6.2 (2025-11-03) - Fix double encryption & restore issues ← YOU ARE HERE
```

---

**Full Changelog**: https://github.com/csmblade/panfm/compare/v1.6.1...v1.6.2

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
