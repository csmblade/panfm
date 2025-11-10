"""
Flask route handlers for PAN-OS upgrades and content updates
Handles version checking, downloading, installing, and rebooting
"""
from flask import jsonify, request
from auth import login_required
from firewall_api import (
    get_firewall_config,
    check_available_panos_versions,
    download_panos_version,
    install_panos_version,
    check_job_status,
    reboot_firewall,
    check_content_updates,
    download_content_update,
    install_content_update
)
from logger import debug, error
import traceback


def register_upgrades_routes(app, csrf, limiter):
    """Register PAN-OS upgrade and content update routes"""
    debug("Registering PAN-OS upgrade and content update routes")

    # ============================================================================
    # PAN-OS Upgrade API Routes
    # ============================================================================

    @app.route('/api/panos-versions', methods=['GET'])
    @limiter.limit("100 per hour")  # Allow reasonable number of version checks
    @login_required
    def get_panos_versions():
        """Get available PAN-OS versions"""
        debug("=== PAN-OS Versions API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_available_panos_versions(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error checking PAN-OS versions: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/download', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow retries and multiple download operations
    @login_required
    def download_panos():
        """Download a specific PAN-OS version"""
        debug("=== PAN-OS Download API endpoint called ===")
        try:
            data = request.get_json()
            version = data.get('version')

            if not version:
                return jsonify({'status': 'error', 'message': 'Version parameter required'}), 400

            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = download_panos_version(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error downloading PAN-OS: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/install', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow retries and testing
    @login_required
    def install_panos():
        """Install a downloaded PAN-OS version"""
        debug("=== PAN-OS Install API endpoint called ===")
        try:
            data = request.get_json()
            version = data.get('version')

            if not version:
                return jsonify({'status': 'error', 'message': 'Version parameter required'}), 400

            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = install_panos_version(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error installing PAN-OS: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/job-status/<job_id>', methods=['GET'])
    @limiter.limit("2000 per hour")  # Very high limit for continuous job polling (4/min sustained = 240/hr, set 8x buffer)
    @login_required
    def get_panos_job_status(job_id):
        """Check the status of a PAN-OS upgrade job"""
        debug(f"=== PAN-OS Job Status API endpoint called for job {job_id} ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                error("No firewall configured for job status check")
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            debug(f"Checking job status for job_id={job_id} on {firewall_ip}")
            result = check_job_status(firewall_ip, api_key, job_id)
            debug(f"Job status result: {result}")
            return jsonify(result)

        except Exception as e:
            error(f"Error checking job status for job {job_id}: {str(e)}")
            error(f"Traceback: {traceback.format_exc()}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/panos-upgrade/reboot', methods=['POST'])
    @limiter.limit("100 per hour")  # Allow multiple reboots for testing
    @login_required
    def reboot_panos():
        """Reboot the firewall after upgrade"""
        debug("=== PAN-OS Reboot API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = reboot_firewall(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error rebooting firewall: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ============================================================================
    # Content Update API Routes (App & Threat, Antivirus, WildFire)
    # ============================================================================

    @app.route('/api/content-updates/check', methods=['GET'])
    @limiter.limit("100 per hour")
    @login_required
    def check_content_updates_api():
        """Check for available content updates (App & Threat, AV, WildFire)"""
        debug("=== Content Updates Check API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = check_content_updates(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content updates check: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/content-updates/download', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def download_content_api():
        """Download latest content update"""
        debug("=== Content Update Download API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            result = download_content_update(firewall_ip, api_key)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content download: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @app.route('/api/content-updates/install', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def install_content_api():
        """Install downloaded content update"""
        debug("=== Content Update Install API endpoint called ===")
        try:
            firewall_ip, api_key, _ = get_firewall_config()
            if not firewall_ip or not api_key:
                return jsonify({'status': 'error', 'message': 'No device configured'}), 400

            data = request.get_json() or {}
            version = data.get('version', 'latest')

            result = install_content_update(firewall_ip, api_key, version)
            return jsonify(result)

        except Exception as e:
            error(f"Error in content install: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

    debug("PAN-OS upgrade and content update routes registered successfully")
