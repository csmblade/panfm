"""
Alert Management Routes for PANfm
API endpoints for alert configuration, history, notification management, and templates
"""
from flask import request, jsonify
from logger import debug, warning, exception
from auth import login_required
from alert_manager import alert_manager
from notification_manager import notification_manager
from alert_templates import (
    list_templates, get_template, apply_template,
    get_templates_by_category, get_template_categories,
    get_recommended_templates, customize_template,
    get_quick_start_recommendation, apply_quick_start,
    QUICK_START_RECOMMENDATIONS
)


def register_alert_routes(app, csrf, limiter):
    """
    Register all alert-related routes with the Flask app.

    Args:
        app: Flask application instance
        csrf: CSRF protection instance
        limiter: Rate limiter instance
    """
    debug("Registering alert management routes")

    # ===== Alert Configuration Endpoints =====

    @app.route('/api/alerts/configs', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_alert_configs():
        """Get all alert configurations, optionally filtered by device."""
        debug("GET /api/alerts/configs called")

        try:
            device_id = request.args.get('device_id')
            enabled_only = request.args.get('enabled_only', 'false').lower() == 'true'

            configs = alert_manager.get_alert_configs(
                device_id=device_id,
                enabled_only=enabled_only
            )

            return jsonify({
                'status': 'success',
                'data': configs,
                'count': len(configs)
            })

        except Exception as e:
            exception("Error getting alert configs: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get alert configurations: {str(e)}'
            }), 500

    @app.route('/api/alerts/configs', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def create_alert_config():
        """Create a new alert configuration."""
        debug("POST /api/alerts/configs called")

        try:
            data = request.get_json()

            # Validate required fields
            required_fields = ['device_id', 'metric_type', 'threshold_value',
                             'threshold_operator', 'severity', 'notification_channels']
            for field in required_fields:
                if field not in data:
                    return jsonify({
                        'status': 'error',
                        'message': f'Missing required field: {field}'
                    }), 400

            # Validate metric type
            valid_metrics = [
                'throughput_in', 'throughput_out', 'throughput_total',
                'cpu', 'memory', 'sessions', 'threats_critical', 'interface_errors'
            ]
            # Allow application metrics (format: "app_<application_name>")
            is_app_metric = data['metric_type'].startswith('app_')

            if not is_app_metric and data['metric_type'] not in valid_metrics:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid metric type. Must be one of: {", ".join(valid_metrics)} or app_<name>'
                }), 400

            # Validate operator
            valid_operators = ['>', '<', '>=', '<=', '==']
            if data['threshold_operator'] not in valid_operators:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid operator. Must be one of: {", ".join(valid_operators)}'
                }), 400

            # Validate severity
            valid_severities = ['critical', 'warning', 'info']
            if data['severity'] not in valid_severities:
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid severity. Must be one of: {", ".join(valid_severities)}'
                }), 400

            # Create alert config
            alert_id = alert_manager.create_alert_config(
                device_id=data['device_id'],
                metric_type=data['metric_type'],
                threshold_value=float(data['threshold_value']),
                threshold_operator=data['threshold_operator'],
                severity=data['severity'],
                notification_channels=data['notification_channels'],
                enabled=data.get('enabled', True)
            )

            if alert_id:
                return jsonify({
                    'status': 'success',
                    'message': 'Alert configuration created successfully',
                    'alert_id': alert_id
                }), 201
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to create alert configuration'
                }), 500

        except ValueError as e:
            exception("Invalid value in alert config: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Invalid value: {str(e)}'
            }), 400
        except Exception as e:
            exception("Error creating alert config: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to create alert configuration: {str(e)}'
            }), 500

    @app.route('/api/alerts/configs/<int:alert_id>', methods=['PUT'])
    @limiter.limit("100 per hour")
    @login_required
    def update_alert_config(alert_id):
        """Update an existing alert configuration."""
        debug(f"PUT /api/alerts/configs/{alert_id} called")

        try:
            data = request.get_json()

            # Build update dict from provided fields
            updates = {}
            if 'threshold_value' in data:
                updates['threshold_value'] = float(data['threshold_value'])
            if 'threshold_operator' in data:
                updates['threshold_operator'] = data['threshold_operator']
            if 'severity' in data:
                updates['severity'] = data['severity']
            if 'enabled' in data:
                updates['enabled'] = bool(data['enabled'])
            if 'notification_channels' in data:
                updates['notification_channels'] = data['notification_channels']

            if not updates:
                return jsonify({
                    'status': 'error',
                    'message': 'No fields to update'
                }), 400

            success = alert_manager.update_alert_config(alert_id, **updates)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Alert configuration updated successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Alert configuration not found or update failed'
                }), 404

        except ValueError as e:
            exception("Invalid value in alert update: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Invalid value: {str(e)}'
            }), 400
        except Exception as e:
            exception("Error updating alert config: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to update alert configuration: {str(e)}'
            }), 500

    @app.route('/api/alerts/configs/<int:alert_id>', methods=['DELETE'])
    @limiter.limit("100 per hour")
    @login_required
    def delete_alert_config(alert_id):
        """Delete an alert configuration."""
        debug(f"DELETE /api/alerts/configs/{alert_id} called")

        try:
            success = alert_manager.delete_alert_config(alert_id)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Alert configuration deleted successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Alert configuration not found'
                }), 404

        except Exception as e:
            exception("Error deleting alert config: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to delete alert configuration: {str(e)}'
            }), 500

    # ===== Alert History Endpoints =====

    @app.route('/api/alerts/history', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_alert_history():
        """Get alert history, optionally filtered."""
        debug("GET /api/alerts/history called")

        try:
            device_id = request.args.get('device_id')
            limit = int(request.args.get('limit', 100))
            unresolved_only = request.args.get('unresolved_only', 'false').lower() == 'true'
            unresolved = request.args.get('unresolved', 'false').lower() == 'true'
            acknowledged = request.args.get('acknowledged', 'false').lower() == 'true'
            severity = request.args.get('severity')  # 'critical', 'warning', or 'info'

            history = alert_manager.get_alert_history(
                device_id=device_id,
                limit=limit,
                unresolved_only=unresolved_only or unresolved,
                severity=severity
            )

            # Filter by acknowledged status if requested
            if acknowledged:
                history = [h for h in history if h.get('acknowledged_at') is not None][:limit]

            return jsonify({
                'status': 'success',
                'data': history,
                'count': len(history)
            })

        except ValueError as e:
            exception("Invalid parameter in alert history: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Invalid parameter: {str(e)}'
            }), 400
        except Exception as e:
            exception("Error getting alert history: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get alert history: {str(e)}'
            }), 500

    @app.route('/api/alerts/history/<int:history_id>/acknowledge', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def acknowledge_alert(history_id):
        """Acknowledge an alert."""
        debug(f"POST /api/alerts/history/{history_id}/acknowledge called")

        try:
            data = request.get_json()
            acknowledged_by = data.get('acknowledged_by', 'admin')

            success = alert_manager.acknowledge_alert(history_id, acknowledged_by)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Alert acknowledged successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Alert not found'
                }), 404

        except Exception as e:
            exception("Error acknowledging alert: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to acknowledge alert: {str(e)}'
            }), 500

    @app.route('/api/alerts/history/<int:history_id>/resolve', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def resolve_alert(history_id):
        """Resolve an alert."""
        debug(f"POST /api/alerts/history/{history_id}/resolve called")

        try:
            data = request.get_json()
            resolved_reason = data.get('resolved_reason', 'Manually resolved')

            success = alert_manager.resolve_alert(history_id, resolved_reason)

            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'Alert resolved successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Alert not found'
                }), 404

        except Exception as e:
            exception("Error resolving alert: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to resolve alert: {str(e)}'
            }), 500

    # ===== Maintenance Window Endpoints =====

    @app.route('/api/alerts/maintenance-windows', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_maintenance_windows():
        """Get all maintenance windows."""
        debug("GET /api/alerts/maintenance-windows called")

        try:
            # TODO: Implement maintenance window retrieval
            # This will be added in a future enhancement
            return jsonify({
                'status': 'success',
                'data': [],
                'message': 'Maintenance windows feature coming soon'
            })

        except Exception as e:
            exception("Error getting maintenance windows: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get maintenance windows: {str(e)}'
            }), 500

    @app.route('/api/alerts/maintenance-windows', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def create_maintenance_window():
        """Create a maintenance window."""
        debug("POST /api/alerts/maintenance-windows called")

        try:
            # TODO: Implement maintenance window creation
            # This will be added in a future enhancement
            return jsonify({
                'status': 'error',
                'message': 'Maintenance windows feature coming soon'
            }), 501

        except Exception as e:
            exception("Error creating maintenance window: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to create maintenance window: {str(e)}'
            }), 500

    # ===== Notification Channel Endpoints =====

    @app.route('/api/alerts/notification-channels', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_notification_channels():
        """Get all notification channels."""
        debug("GET /api/alerts/notification-channels called")

        try:
            # TODO: Implement notification channel retrieval
            # This will be added in Phase 5 (notification system)
            return jsonify({
                'status': 'success',
                'data': [],
                'message': 'Notification channels feature coming soon'
            })

        except Exception as e:
            exception("Error getting notification channels: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get notification channels: {str(e)}'
            }), 500

    @app.route('/api/alerts/notification-channels', methods=['POST'])
    @limiter.limit("100 per hour")
    @login_required
    def create_notification_channel():
        """Create a notification channel."""
        debug("POST /api/alerts/notification-channels called")

        try:
            # TODO: Implement notification channel creation
            # This will be added in Phase 5 (notification system)
            return jsonify({
                'status': 'error',
                'message': 'Notification channels feature coming soon'
            }), 501

        except Exception as e:
            exception("Error creating notification channel: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to create notification channel: {str(e)}'
            }), 500

    # ===== Notification Testing Endpoints =====

    @app.route('/api/alerts/notifications/test/email', methods=['POST'])
    @limiter.limit("10 per hour")
    @login_required
    def test_email_notification():
        """Test email notification configuration."""
        debug("POST /api/alerts/notifications/test/email called")

        try:
            result = notification_manager.test_email()
            return jsonify(result)

        except Exception as e:
            exception(f"Error testing email: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Failed to test email: {str(e)}'
            }), 500

    @app.route('/api/alerts/notifications/test/webhook', methods=['POST'])
    @limiter.limit("10 per hour")
    @login_required
    def test_webhook_notification():
        """Test webhook notification configuration."""
        debug("POST /api/alerts/notifications/test/webhook called")

        try:
            result = notification_manager.test_webhook()
            return jsonify(result)

        except Exception as e:
            exception(f"Error testing webhook: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Failed to test webhook: {str(e)}'
            }), 500

    @app.route('/api/alerts/notifications/test/slack', methods=['POST'])
    @limiter.limit("10 per hour")
    @login_required
    def test_slack_notification():
        """Test Slack notification configuration."""
        debug("POST /api/alerts/notifications/test/slack called")

        try:
            result = notification_manager.test_slack()
            return jsonify(result)

        except Exception as e:
            exception(f"Error testing Slack: {e}")
            return jsonify({
                'status': 'error',
                'message': f'Failed to test Slack: {str(e)}'
            }), 500

    # ===== Alert Statistics Endpoint =====

    @app.route('/api/alerts/stats', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_alert_stats():
        """Get alert statistics."""
        debug("GET /api/alerts/stats called")

        try:
            device_id = request.args.get('device_id')

            # Get all configs and history
            configs = alert_manager.get_alert_configs(device_id=device_id)
            history = alert_manager.get_alert_history(device_id=device_id, limit=1000)

            # Calculate statistics
            stats = {
                'total_configs': len(configs),
                'enabled_configs': len([c for c in configs if c['enabled']]),
                'total_alerts': len(history),
                'unresolved_alerts': len([h for h in history if not h['resolved_at']]),
                # Count only unacknowledged alerts (acknowledged_at is None)
                'critical_alerts': len([h for h in history if h['severity'] == 'critical' and not h['acknowledged_at']]),
                'warning_alerts': len([h for h in history if h['severity'] == 'warning' and not h['acknowledged_at']]),
                'info_alerts': len([h for h in history if h['severity'] == 'info' and not h['acknowledged_at']]),
                'acknowledged_alerts': len([h for h in history if h['acknowledged_at'] and not h['resolved_at']]),
                'by_severity': {
                    'critical': len([h for h in history if h['severity'] == 'critical']),
                    'warning': len([h for h in history if h['severity'] == 'warning']),
                    'info': len([h for h in history if h['severity'] == 'info'])
                }
            }

            return jsonify({
                'status': 'success',
                'data': stats
            })

        except Exception as e:
            exception("Error getting alert stats: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get alert statistics: {str(e)}'
            }), 500

    # ===== Alert Template Endpoints =====

    @app.route('/api/alerts/templates', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_alert_templates():
        """Get all available alert templates."""
        debug("GET /api/alerts/templates called")

        try:
            category = request.args.get('category')

            if category:
                templates = get_templates_by_category(category)
            else:
                templates = list_templates()

            return jsonify({
                'status': 'success',
                'data': templates,
                'count': len(templates)
            })

        except Exception as e:
            exception("Error getting alert templates: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get alert templates: {str(e)}'
            }), 500

    @app.route('/api/alerts/templates/<template_id>', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_alert_template(template_id):
        """Get a specific alert template by ID."""
        debug(f"GET /api/alerts/templates/{template_id} called")

        try:
            template = get_template(template_id)

            if template:
                return jsonify({
                    'status': 'success',
                    'data': template
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': f'Template not found: {template_id}'
                }), 404

        except Exception as e:
            exception("Error getting alert template: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get alert template: {str(e)}'
            }), 500

    @app.route('/api/alerts/templates/<template_id>/apply', methods=['POST'])
    @limiter.limit("50 per hour")
    @login_required
    def apply_alert_template(template_id):
        """Apply an alert template to a device."""
        debug(f"POST /api/alerts/templates/{template_id}/apply called")

        try:
            data = request.get_json()

            # Validate required fields
            if 'device_id' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'Missing required field: device_id'
                }), 400

            device_id = data['device_id']
            notification_channels = data.get('notification_channels', [])

            # Apply template
            result = apply_template(device_id, template_id, notification_channels)

            if result['status'] == 'success':
                return jsonify(result), 201
            else:
                return jsonify(result), 400

        except Exception as e:
            exception(f"Error applying template {template_id}: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to apply template: {str(e)}'
            }), 500

    @app.route('/api/alerts/templates/categories', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_alert_template_categories():
        """Get all template categories."""
        debug("GET /api/alerts/templates/categories called")

        try:
            categories = get_template_categories()

            return jsonify({
                'status': 'success',
                'data': categories,
                'count': len(categories)
            })

        except Exception as e:
            exception("Error getting template categories: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get template categories: {str(e)}'
            }), 500

    @app.route('/api/alerts/templates/recommended', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_recommended_alert_templates():
        """Get recommended templates for a device type."""
        debug("GET /api/alerts/templates/recommended called")

        try:
            device_type = request.args.get('device_type', 'firewall')
            templates = get_recommended_templates(device_type)

            return jsonify({
                'status': 'success',
                'data': templates,
                'count': len(templates)
            })

        except Exception as e:
            exception("Error getting recommended templates: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get recommended templates: {str(e)}'
            }), 500

    @app.route('/api/alerts/quick-start', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_quick_start_scenarios():
        """Get all quick start scenarios."""
        debug("GET /api/alerts/quick-start called")

        try:
            # Return all scenarios with their details
            scenarios = []
            for scenario_id, scenario in QUICK_START_RECOMMENDATIONS.items():
                scenarios.append({
                    'id': scenario_id,
                    'name': scenario['name'],
                    'description': scenario['description'],
                    'templates': scenario['templates'],
                    'channels': scenario['channels']
                })

            return jsonify({
                'status': 'success',
                'data': scenarios,
                'count': len(scenarios)
            })

        except Exception as e:
            exception("Error getting quick start scenarios: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get quick start scenarios: {str(e)}'
            }), 500

    @app.route('/api/alerts/quick-start/<scenario_id>/apply', methods=['POST'])
    @limiter.limit("20 per hour")
    @login_required
    def apply_quick_start_scenario(scenario_id):
        """Apply a quick start scenario to a device."""
        debug(f"POST /api/alerts/quick-start/{scenario_id}/apply called")

        try:
            data = request.get_json()

            # Validate required fields
            if 'device_id' not in data:
                return jsonify({
                    'status': 'error',
                    'message': 'Missing required field: device_id'
                }), 400

            device_id = data['device_id']

            # Apply quick start scenario
            result = apply_quick_start(device_id, scenario_id)

            if result['status'] == 'success':
                return jsonify(result), 201
            else:
                return jsonify(result), 400

        except Exception as e:
            exception(f"Error applying quick start {scenario_id}: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to apply quick start: {str(e)}'
            }), 500

    # ===== Application Metrics Endpoint =====

    @app.route('/api/alerts/applications', methods=['GET'])
    @limiter.limit("600 per hour")
    @login_required
    def get_alert_applications():
        """Get available applications for application-based alerts."""
        debug("GET /api/alerts/applications called")

        try:
            device_id = request.args.get('device_id')

            if not device_id:
                return jsonify({
                    'status': 'error',
                    'message': 'device_id parameter is required'
                }), 400

            # Import here to avoid circular imports
            from firewall_api_applications import get_application_statistics
            from firewall_api import get_firewall_config

            # Get firewall config for the device
            firewall_config = get_firewall_config(device_id)

            # Get application statistics
            app_stats = get_application_statistics(firewall_config)
            applications = app_stats.get('applications', [])

            # Extract application names
            app_list = sorted([app.get('name') for app in applications if app.get('name')])

            return jsonify({
                'status': 'success',
                'applications': app_list,
                'count': len(app_list)
            })

        except Exception as e:
            exception("Error getting applications: %s", str(e))
            return jsonify({
                'status': 'error',
                'message': f'Failed to get applications: {str(e)}'
            }), 500

    debug("Alert management routes registered successfully")
