resource "cloudflare_notification_policy" "example_notification_policy" {
  account_id = "023e105f4ecef8ad9ca31a8372d0c353"
  alert_type = "universal_ssl_event_type"
  enabled = true
  mechanisms = {
    email = [{
      id = "test@example.com"
    }]
    pagerduty = [{
      id = "e8133a15-00a4-4d69-aec1-32f70c51f6e5"
    }]
    webhooks = [{
      id = "14cc1190-5d2b-4b98-a696-c424cb2ad05f"
    }]
  }
  name = "SSL Notification Event Policy"
  alert_interval = "30m"
  description = "Something describing the policy."
  filters = {
    actions = ["string"]
    affected_asns = ["string"]
    affected_components = ["string"]
    affected_locations = ["string"]
    airport_code = ["string"]
    alert_trigger_preferences = ["string"]
    alert_trigger_preferences_value = ["string"]
    enabled = ["string"]
    environment = ["string"]
    event = ["string"]
    event_source = ["string"]
    event_type = ["string"]
    group_by = ["string"]
    health_check_id = ["string"]
    incident_impact = ["INCIDENT_IMPACT_NONE"]
    input_id = ["string"]
    insight_class = ["string"]
    limit = ["string"]
    logo_tag = ["string"]
    megabits_per_second = ["string"]
    new_health = ["string"]
    new_status = ["string"]
    packets_per_second = ["string"]
    pool_id = ["string"]
    pop_names = ["string"]
    product = ["string"]
    project_id = ["string"]
    protocol = ["string"]
    query_tag = ["string"]
    requests_per_second = ["string"]
    selectors = ["string"]
    services = ["string"]
    slo = ["99.9"]
    status = ["string"]
    target_hostname = ["string"]
    target_ip = ["string"]
    target_zone_name = ["string"]
    traffic_exclusions = ["security_events"]
    tunnel_id = ["string"]
    tunnel_name = ["string"]
    where = ["string"]
    zones = ["string"]
  }
}
