"""
Alert Templates for PANfm
Pre-configured alert templates for common monitoring scenarios

Usage:
    from alert_templates import ALERT_TEMPLATES, apply_template

    # Apply a template to a device
    apply_template(device_id, 'critical_system_health', ['email', 'slack'])
"""
from typing import Dict, List, Optional
from logger import debug, info, exception
from alert_manager import alert_manager


# ===== Alert Template Definitions =====

ALERT_TEMPLATES = {
    'critical_system_health': {
        'name': 'Critical System Health',
        'description': 'Essential alerts for critical system conditions (CPU, Memory, Sessions)',
        'category': 'System Health',
        'severity': 'critical',
        'alerts': [
            {
                'metric_type': 'cpu',
                'threshold_value': 90.0,
                'threshold_operator': '>',
                'severity': 'critical',
                'description': 'CPU usage above 90% - immediate attention required'
            },
            {
                'metric_type': 'memory',
                'threshold_value': 90.0,
                'threshold_operator': '>',
                'severity': 'critical',
                'description': 'Memory usage above 90% - potential OOM risk'
            },
            {
                'metric_type': 'sessions',
                'threshold_value': 100000,
                'threshold_operator': '>',
                'severity': 'critical',
                'description': 'Active sessions exceed 100k - capacity warning'
            }
        ]
    },

    'warning_system_health': {
        'name': 'Warning System Health',
        'description': 'Early warning alerts for system resource concerns',
        'category': 'System Health',
        'severity': 'warning',
        'alerts': [
            {
                'metric_type': 'cpu',
                'threshold_value': 75.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'CPU usage above 75% - monitor closely'
            },
            {
                'metric_type': 'memory',
                'threshold_value': 75.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Memory usage above 75% - consider optimization'
            },
            {
                'metric_type': 'sessions',
                'threshold_value': 80000,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Active sessions above 80k - approaching limits'
            }
        ]
    },

    'network_performance': {
        'name': 'Network Performance',
        'description': 'Monitor network throughput and bandwidth utilization',
        'category': 'Network',
        'severity': 'warning',
        'alerts': [
            {
                'metric_type': 'throughput_in',
                'threshold_value': 800.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Inbound throughput above 800 Mbps - high utilization'
            },
            {
                'metric_type': 'throughput_out',
                'threshold_value': 800.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Outbound throughput above 800 Mbps - high utilization'
            },
            {
                'metric_type': 'throughput_total',
                'threshold_value': 900.0,
                'threshold_operator': '>',
                'severity': 'critical',
                'description': 'Total throughput above 900 Mbps - near capacity'
            }
        ]
    },

    'security_monitoring': {
        'name': 'Security Monitoring',
        'description': 'Critical security alerts for threat detection',
        'category': 'Security',
        'severity': 'critical',
        'alerts': [
            {
                'metric_type': 'threats_critical',
                'threshold_value': 1,
                'threshold_operator': '>=',
                'severity': 'critical',
                'description': 'Critical threat detected - immediate investigation required'
            },
            {
                'metric_type': 'threats_critical',
                'threshold_value': 5,
                'threshold_operator': '>=',
                'severity': 'critical',
                'description': 'Multiple critical threats (5+) - possible attack'
            }
        ]
    },

    'network_health': {
        'name': 'Network Interface Health',
        'description': 'Monitor network interface errors and issues',
        'category': 'Network',
        'severity': 'warning',
        'alerts': [
            {
                'metric_type': 'interface_errors',
                'threshold_value': 10,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Interface errors detected - check cable/port health'
            },
            {
                'metric_type': 'interface_errors',
                'threshold_value': 100,
                'threshold_operator': '>',
                'severity': 'critical',
                'description': 'High interface errors (100+) - hardware issue likely'
            }
        ]
    },

    'capacity_planning': {
        'name': 'Capacity Planning',
        'description': 'Monitor resource usage for capacity planning',
        'category': 'Capacity',
        'severity': 'info',
        'alerts': [
            {
                'metric_type': 'cpu',
                'threshold_value': 60.0,
                'threshold_operator': '>',
                'severity': 'info',
                'description': 'CPU above 60% - track trends for capacity planning'
            },
            {
                'metric_type': 'memory',
                'threshold_value': 60.0,
                'threshold_operator': '>',
                'severity': 'info',
                'description': 'Memory above 60% - track trends for capacity planning'
            },
            {
                'metric_type': 'sessions',
                'threshold_value': 60000,
                'threshold_operator': '>',
                'severity': 'info',
                'description': 'Sessions above 60k - track growth for scaling'
            }
        ]
    },

    'low_throughput': {
        'name': 'Low Throughput Detection',
        'description': 'Alert when throughput drops below expected levels',
        'category': 'Network',
        'severity': 'warning',
        'alerts': [
            {
                'metric_type': 'throughput_total',
                'threshold_value': 1.0,
                'threshold_operator': '<',
                'severity': 'warning',
                'description': 'Total throughput below 1 Mbps - possible connectivity issue'
            },
            {
                'metric_type': 'throughput_total',
                'threshold_value': 0.1,
                'threshold_operator': '<',
                'severity': 'critical',
                'description': 'Total throughput below 0.1 Mbps - likely outage'
            }
        ]
    },

    'session_limits': {
        'name': 'Session Limits',
        'description': 'Monitor session count approaching firewall limits',
        'category': 'Capacity',
        'severity': 'critical',
        'alerts': [
            {
                'metric_type': 'sessions',
                'threshold_value': 50000,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Sessions above 50k - monitor for growth'
            },
            {
                'metric_type': 'sessions',
                'threshold_value': 75000,
                'threshold_operator': '>',
                'severity': 'critical',
                'description': 'Sessions above 75k - approaching platform limits'
            }
        ]
    },

    'comprehensive_monitoring': {
        'name': 'Comprehensive Monitoring',
        'description': 'Full monitoring suite with balanced thresholds',
        'category': 'Complete',
        'severity': 'warning',
        'alerts': [
            {
                'metric_type': 'cpu',
                'threshold_value': 80.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'CPU usage above 80%'
            },
            {
                'metric_type': 'memory',
                'threshold_value': 80.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Memory usage above 80%'
            },
            {
                'metric_type': 'throughput_total',
                'threshold_value': 850.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Total throughput above 850 Mbps'
            },
            {
                'metric_type': 'sessions',
                'threshold_value': 70000,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Active sessions above 70k'
            },
            {
                'metric_type': 'threats_critical',
                'threshold_value': 1,
                'threshold_operator': '>=',
                'severity': 'critical',
                'description': 'Critical threat detected'
            },
            {
                'metric_type': 'interface_errors',
                'threshold_value': 50,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Interface errors detected'
            }
        ]
    },

    'high_bandwidth_usage': {
        'name': 'High Bandwidth Usage',
        'description': 'Monitor for devices downloading/uploading 1GB+ in 5 minutes - identifies specific IP addresses and hostnames',
        'category': 'Traffic Monitoring',
        'severity': 'warning',
        'alerts': [
            {
                'metric_type': 'per_ip_bandwidth_5min',
                'threshold_value': 1024.0,
                'threshold_operator': '>',
                'severity': 'warning',
                'description': 'Device exceeded 1GB transfer in 5 minutes (alert shows IP address and hostname)'
            }
        ]
    }
}


# ===== Template Management Functions =====

def list_templates() -> List[Dict]:
    """
    Get list of all available alert templates.

    Returns:
        List of template summaries with name, description, category, alert count
    """
    templates = []

    for template_id, template in ALERT_TEMPLATES.items():
        templates.append({
            'id': template_id,
            'name': template['name'],
            'description': template['description'],
            'category': template['category'],
            'alert_count': len(template['alerts'])
        })

    return templates


def get_template(template_id: str) -> Optional[Dict]:
    """
    Get a specific alert template by ID.

    Args:
        template_id: Template identifier

    Returns:
        Template dict or None if not found
    """
    return ALERT_TEMPLATES.get(template_id)


def apply_template(device_id: str, template_id: str,
                   notification_channels: List[str] = None) -> Dict:
    """
    Apply an alert template to a device.

    Args:
        device_id: Device ID to apply template to
        template_id: Template identifier
        notification_channels: List of notification channels (email, webhook, slack)

    Returns:
        Dict with success status and created alert IDs
    """
    debug(f"Applying template '{template_id}' to device {device_id}")

    template = ALERT_TEMPLATES.get(template_id)
    if not template:
        return {
            'status': 'error',
            'message': f'Template not found: {template_id}'
        }

    if notification_channels is None:
        notification_channels = []

    created_alerts = []
    failed_alerts = []

    for alert_config in template['alerts']:
        try:
            alert_id = alert_manager.create_alert_config(
                device_id=device_id,
                metric_type=alert_config['metric_type'],
                threshold_value=alert_config['threshold_value'],
                threshold_operator=alert_config['threshold_operator'],
                severity=alert_config['severity'],
                notification_channels=notification_channels,
                enabled=True
            )

            if alert_id:
                created_alerts.append({
                    'id': alert_id,
                    'metric': alert_config['metric_type'],
                    'description': alert_config['description']
                })
                debug(f"Created alert {alert_id} for {alert_config['metric_type']}")
            else:
                failed_alerts.append({
                    'metric': alert_config['metric_type'],
                    'error': 'Failed to create alert'
                })

        except Exception as e:
            exception(f"Error creating alert for {alert_config['metric_type']}: {e}")
            failed_alerts.append({
                'metric': alert_config['metric_type'],
                'error': str(e)
            })

    info(f"Template '{template_id}' applied: {len(created_alerts)} created, {len(failed_alerts)} failed")

    return {
        'status': 'success' if created_alerts else 'error',
        'template': template['name'],
        'created': created_alerts,
        'failed': failed_alerts,
        'message': f'Created {len(created_alerts)} alerts for device {device_id}'
    }


def get_recommended_templates(device_type: str = 'firewall') -> List[str]:
    """
    Get recommended templates for a device type.

    Args:
        device_type: Type of device ('firewall', 'all')

    Returns:
        List of recommended template IDs
    """
    if device_type == 'firewall':
        return [
            'critical_system_health',
            'security_monitoring',
            'network_performance',
            'network_health'
        ]
    elif device_type == 'all':
        return [
            'comprehensive_monitoring'
        ]
    else:
        return list(ALERT_TEMPLATES.keys())


def customize_template(template_id: str, adjustments: Dict) -> Optional[Dict]:
    """
    Customize a template with adjusted thresholds.

    Args:
        template_id: Template to customize
        adjustments: Dict of metric_type -> new threshold_value

    Returns:
        Customized template dict or None if template not found

    Example:
        customize_template('critical_system_health', {'cpu': 85.0, 'memory': 85.0})
    """
    template = ALERT_TEMPLATES.get(template_id)
    if not template:
        return None

    # Deep copy template
    import copy
    customized = copy.deepcopy(template)
    customized['name'] = f"{template['name']} (Customized)"

    # Apply adjustments
    for alert in customized['alerts']:
        metric = alert['metric_type']
        if metric in adjustments:
            alert['threshold_value'] = adjustments[metric]
            debug(f"Adjusted {metric} threshold to {adjustments[metric]}")

    return customized


# ===== Template Categories =====

def get_templates_by_category(category: str) -> List[Dict]:
    """
    Get all templates in a category.

    Args:
        category: Category name (System Health, Network, Security, Capacity, Complete)

    Returns:
        List of templates in the category
    """
    templates = []

    for template_id, template in ALERT_TEMPLATES.items():
        if template['category'] == category:
            templates.append({
                'id': template_id,
                'name': template['name'],
                'description': template['description'],
                'alert_count': len(template['alerts'])
            })

    return templates


def get_template_categories() -> List[str]:
    """
    Get list of all template categories.

    Returns:
        List of unique category names
    """
    categories = set()

    for template in ALERT_TEMPLATES.values():
        categories.add(template['category'])

    return sorted(list(categories))


# ===== Quick Start Templates =====

QUICK_START_RECOMMENDATIONS = {
    'production': {
        'name': 'Production Environment',
        'templates': ['critical_system_health', 'security_monitoring'],
        'channels': ['email', 'slack'],
        'description': 'Essential monitoring for production firewalls'
    },
    'development': {
        'name': 'Development Environment',
        'templates': ['warning_system_health', 'capacity_planning'],
        'channels': ['email'],
        'description': 'Relaxed monitoring for dev/test environments'
    },
    'high_security': {
        'name': 'High Security',
        'templates': ['security_monitoring', 'critical_system_health', 'network_health'],
        'channels': ['email', 'slack', 'webhook'],
        'description': 'Maximum security monitoring with all channels'
    },
    'traffic_monitoring': {
        'name': 'Traffic Monitoring',
        'templates': ['high_bandwidth_usage'],
        'channels': ['slack'],
        'description': 'Monitor IP addresses downloading 1GB+ in 5 minutes with hostname lookup'
    }
}


def get_quick_start_recommendation(scenario: str) -> Optional[Dict]:
    """
    Get quick start recommendation for a scenario.

    Args:
        scenario: Scenario name (production, development, high_security, capacity_focused)

    Returns:
        Recommendation dict or None if not found
    """
    return QUICK_START_RECOMMENDATIONS.get(scenario)


def apply_quick_start(device_id: str, scenario: str) -> Dict:
    """
    Apply a quick start scenario to a device.

    Args:
        device_id: Device ID to apply to
        scenario: Scenario name

    Returns:
        Dict with results from all applied templates
    """
    debug(f"Applying quick start scenario '{scenario}' to device {device_id}")

    recommendation = QUICK_START_RECOMMENDATIONS.get(scenario)
    if not recommendation:
        return {
            'status': 'error',
            'message': f'Scenario not found: {scenario}'
        }

    results = {
        'status': 'success',
        'scenario': recommendation['name'],
        'templates': []
    }

    for template_id in recommendation['templates']:
        result = apply_template(
            device_id=device_id,
            template_id=template_id,
            notification_channels=recommendation['channels']
        )
        results['templates'].append(result)

    total_created = sum(len(r['created']) for r in results['templates'])
    info(f"Quick start '{scenario}' applied: {total_created} total alerts created")

    return results
