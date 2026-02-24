import json
import os
import boto3
from urllib.request import Request, urlopen
from urllib.error import URLError
from botocore.exceptions import ClientError

secrets = boto3.client("secretsmanager")
ssm = boto3.client("ssm")

SLACK_WEBHOOK_SECRET_NAME = os.environ.get("SLACK_WEBHOOK_SECRET_NAME", "/container-signing/slack-webhook")

def get_slack_webhook_url() -> str:
    """Retrieve Slack webhook URL from Secrets Manager or SSM."""
    try:
        resp = secrets.get_secret_value(SecretId=SLACK_WEBHOOK_SECRET_NAME)
        secret_str = resp.get("SecretString", "")
        try:
            secret_json = json.loads(secret_str)
            if "webhook_url" in secret_json:
                return secret_json["webhook_url"]
        except:
            pass
        if secret_str.startswith("https://"):
            return secret_str
    except ClientError as e:
        print(f"Secrets Manager lookup failed: {e}")
    
    try:
        resp = ssm.get_parameter(Name=SLACK_WEBHOOK_SECRET_NAME, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except ClientError as e:
        print(f"SSM lookup failed: {e}")
    
    raise RuntimeError("Could not retrieve Slack webhook URL")

def post_to_slack(message_payload: dict):
    """POST to Slack webhook with retry."""
    webhook_url = get_slack_webhook_url()
    data = json.dumps(message_payload).encode("utf-8")
    req = Request(webhook_url, data=data, headers={"Content-Type": "application/json"})
    
    try:
        with urlopen(req, timeout=3) as resp:
            if 200 <= resp.status < 300:
                print("Slack notification sent successfully")
                return
    except URLError:
        pass
    
    # Retry once
    with urlopen(req, timeout=3) as resp:
        if 200 <= resp.status < 300:
            print("Slack notification sent (retry)")
        else:
            print(f"Slack returned non-2xx: {resp.status}")

def handler(event, context):
    """Alert Lambda: sends Slack notification."""
    print("Alert event:", json.dumps(event))
    
    # Event comes from Step Functions (enriched by triage)
    severity = event.get("severity", "MEDIUM")
    reason_code = event.get("reason_code", "UNKNOWN")
    cluster_short = event.get("clusterShortName", "unknown")
    service_name = event.get("serviceName") or "N/A"
    image = event.get("image", "unknown")
    image_digest = event.get("imageDigest", "N/A")
    account_id = event.get("accountId", "unknown")
    region = event.get("region", "unknown")
    task_arn = event.get("taskArn", "unknown")
    
    slack_payload = {
        "text": "🚫 ECS task blocked (unsigned/unapproved image)",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚫 ECS Task Blocked"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Reason:*\n{reason_code}"},
                    {"type": "mrkdwn", "text": f"*Cluster:*\n{cluster_short}"},
                    {"type": "mrkdwn", "text": f"*Service:*\n{service_name}"},
                    {"type": "mrkdwn", "text": f"*Image:*\n`{image[:100]}`"},
                    {"type": "mrkdwn", "text": f"*Digest:*\n`{image_digest[:20]}...`"},
                    {"type": "mrkdwn", "text": f"*Account:*\n{account_id}"},
                    {"type": "mrkdwn", "text": f"*Region:*\n{region}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Task ARN:*\n`{task_arn}`"}
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "Denied in PENDING. Task stopped. Signature verification failed or external image not allowlisted."}
                ]
            }
        ]
    }
    
    try:
        post_to_slack(slack_payload)
        return {"ok": True, "alerted": True}
    except Exception as e:
        print(f"Failed to send Slack notification: {e}")
        return {"ok": False, "error": str(e)}
