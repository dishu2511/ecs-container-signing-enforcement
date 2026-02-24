import json

def determine_severity(event_detail):
    """Determine severity based on cluster/service name and reason code."""
    cluster_arn = event_detail.get("clusterArn", "")
    service_name = event_detail.get("serviceName", "")
    reason_code = event_detail.get("reason_code", "")
    
    # HIGH severity for production environments
    if any(x in cluster_arn.lower() or (service_name and x in service_name.lower()) 
           for x in ["prod", "production"]):
        return "HIGH"
    
    # HIGH severity for critical failures
    if reason_code in ["KMS_VERIFY_FAILURE", "REGISTRY_AUTH_FAILURE"]:
        return "HIGH"
    
    return "MEDIUM"

def handler(event, context):
    """Triage Lambda: enriches DecisionEvent with severity and routing info."""
    print("Triage event:", json.dumps(event))
    
    # Extract DecisionEvent detail
    detail = event.get("detail", {})
    
    # Determine severity
    severity = determine_severity(detail)
    
    # Extract key fields for routing
    cluster_short = detail.get("clusterArn", "").split("/")[-1] if "/" in detail.get("clusterArn", "") else detail.get("clusterArn", "")
    
    # Build enriched event
    enriched = {
        **detail,
        "severity": severity,
        "clusterShortName": cluster_short,
        "shouldAlert": True,  # Future: add logic to suppress alerts
        "alertChannels": ["slack"]  # Future: add PagerDuty for HIGH severity
    }
    
    print(f"Triage result: severity={severity}, reason={detail.get('reason_code')}")
    
    return enriched
