import json
import os
import re
import subprocess
import boto3
import base64
from datetime import datetime, timezone
from botocore.exceptions import ClientError

ecs = boto3.client("ecs")
ecr = boto3.client("ecr")
events = boto3.client("events")

KMS_KEY_ARN = os.environ["KMS_KEY_ARN"]
COSIGN_PATH = os.environ.get("COSIGN_PATH", "/opt/cosign/cosign")
FAIL_ACTION = os.environ.get("FAIL_ACTION", "STOP_TASK")
CLUSTER_ARN_FILTER = os.environ.get("CLUSTER_ARN_FILTER")
REPO_ALLOWLIST = os.environ.get("REPO_ALLOWLIST")
ALLOWLIST_IMAGES = {x.strip() for x in os.getenv("ALLOWLIST_IMAGES", "").split(",") if x.strip()}
ALLOWLIST_DIGESTS = {x.strip() for x in os.getenv("ALLOWLIST_DIGESTS", "").split(",") if x.strip()}
ALLOWLIST_PREFIXES = {x.strip() for x in os.getenv("ALLOWLIST_PREFIXES", "").split(",") if x.strip()}

DECISION_EVENT_SOURCE = os.environ.get("DECISION_EVENT_SOURCE", "container.signing")
DECISION_EVENT_DETAIL_TYPE = os.environ.get("DECISION_EVENT_DETAIL_TYPE", "ContainerSigningDecision")
DECISION_EVENT_BUS = os.environ.get("DECISION_EVENT_BUS", "default")
MAX_EVIDENCE_BYTES = int(os.environ.get("MAX_EVIDENCE_BYTES", "2048"))

def extract_digest(image: str):
    if "@sha256:" in image:
        return image.split("@", 1)[1]
    return None

def truncate_text(s: str, max_bytes: int) -> str:
    if not s:
        return ""
    encoded = s.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return s
    return encoded[:max_bytes].decode("utf-8", errors="ignore") + "...[truncated]"

def get_cosign_version() -> str:
    try:
        result = subprocess.run([COSIGN_PATH, "version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()[:200]
    except:
        pass
    return "unknown"

def publish_decision_event(detail: dict):
    try:
        events.put_events(
            Entries=[{
                "Source": DECISION_EVENT_SOURCE,
                "DetailType": DECISION_EVENT_DETAIL_TYPE,
                "EventBusName": DECISION_EVENT_BUS,
                "Detail": json.dumps(detail)
            }]
        )
        print(f"Published DecisionEvent: {detail.get('decision')} / {detail.get('reason_code')}")
    except Exception as e:
        print(f"Failed to publish DecisionEvent (non-fatal): {e}")

def image_region(image_ref_with_digest: str) -> str:
    match = re.match(r"^\d+\.dkr\.ecr\.(?P<region>[\w-]+)\.amazonaws\.com\/", image_ref_with_digest)
    if not match:
        raise ValueError(f"Could not parse region from image: {image_ref_with_digest}")
    return match.group("region")

def ecr_basic_auth(region: str):
    ecr_client = boto3.client("ecr", region_name=region)
    resp = ecr_client.get_authorization_token()
    token = resp["authorizationData"][0]["authorizationToken"]
    decoded = base64.b64decode(token).decode("utf-8")
    username, password = decoded.split(":", 1)
    return username, password

def parse_ecr_image(image: str):
    m = re.match(r"^(?P<acct>\d+)\.dkr\.ecr\.(?P<region>[\w-]+)\.amazonaws\.com\/(?P<repo>[^@:]+)(?P<ref>[:@].+)$", image)
    if not m:
        return None
    return m.group("acct"), m.group("region"), m.group("repo"), m.group("ref")

def resolve_to_digest(acct: str, region: str, repo: str, ref: str) -> str:
    if ref.startswith("@sha256:"):
        return ref.replace("@", "")
    if ref.startswith(":"):
        tag = ref[1:]
        regional_ecr = boto3.client("ecr", region_name=region)
        resp = regional_ecr.describe_images(repositoryName=repo, imageIds=[{"imageTag": tag}])
        details = resp.get("imageDetails", [])
        if not details or "imageDigest" not in details[0]:
            raise RuntimeError(f"Could not resolve tag to digest: {repo}:{tag}")
        return details[0]["imageDigest"]
    raise RuntimeError(f"Unknown image ref format: {ref}")

def stop_task(cluster_arn: str, task_arn: str, reason: str):
    ecs.stop_task(cluster=cluster_arn, task=task_arn, reason=reason)

def emit_deny_event(cluster_arn, task_arn, task_def_arn, task_group, container_name, image, 
                    image_digest, image_with_digest, reason_code, last_status, 
                    cosign_exit, cosign_stderr, cosign_stdout):
    arn_parts = task_arn.split(":")
    region = arn_parts[3] if len(arn_parts) > 3 else "unknown"
    account_id = arn_parts[4] if len(arn_parts) > 4 else "unknown"
    
    service_name = None
    if task_group and task_group.startswith("service:"):
        service_name = task_group.split(":", 1)[1]
    
    detail = {
        "decision": "DENY",
        "reason_code": reason_code,
        "accountId": account_id,
        "region": region,
        "clusterArn": cluster_arn,
        "taskArn": task_arn,
        "taskDefinitionArn": task_def_arn,
        "serviceName": service_name,
        "containerName": container_name,
        "image": image,
        "imageDigest": image_digest,
        "imageRefWithDigest": image_with_digest,
        "kmsKeyUri": f"awskms:///{KMS_KEY_ARN}",
        "cosignVersion": get_cosign_version(),
        "cosignExitCode": cosign_exit,
        "cosignStderr": truncate_text(cosign_stderr, MAX_EVIDENCE_BYTES),
        "cosignStdout": truncate_text(cosign_stdout, MAX_EVIDENCE_BYTES),
        "lastStatus": last_status,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    publish_decision_event(detail)

def handler(event, context):
    print("EVENT:", json.dumps(event))

    detail = event.get("detail", {})
    cluster_arn = detail.get("clusterArn")
    task_arn = detail.get("taskArn")
    last_status = detail.get("lastStatus")

    if not cluster_arn or not task_arn:
        print("Missing clusterArn/taskArn; ignoring.")
        return {"ok": True, "ignored": True}

    if CLUSTER_ARN_FILTER and cluster_arn != CLUSTER_ARN_FILTER:
        print(f"Ignoring cluster {cluster_arn} (filter set).")
        return {"ok": True, "ignored": True}

    try:
        task_resp = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
        tasks = task_resp.get("tasks", [])
        if not tasks:
            print("Task not found; ignoring.")
            return {"ok": True, "ignored": True}
        task = tasks[0]
        task_def_arn = task.get("taskDefinitionArn")
        if not task_def_arn:
            print("No taskDefinitionArn; ignoring.")
            return {"ok": True, "ignored": True}
    except ClientError as e:
        print("describe_tasks error:", str(e))
        return {"ok": False, "error": "describe_tasks_failed"}

    try:
        td = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
        container_defs = td.get("containerDefinitions", [])
    except ClientError as e:
        print("describe_task_definition error:", str(e))
        return {"ok": False, "error": "describe_task_definition_failed"}

    allowlist = None
    if REPO_ALLOWLIST:
        allowlist = {x.strip() for x in REPO_ALLOWLIST.split(",") if x.strip()}

    failures = []
    for c in container_defs:
        image = c.get("image")
        name = c.get("name", "unknown")
        if not image:
            continue

        digest_in_ref = extract_digest(image)

        if digest_in_ref and digest_in_ref in ALLOWLIST_DIGESTS:
            print(f"ALLOWLIST: allowing approved digest {digest_in_ref} for {image}")
            continue

        if image in ALLOWLIST_IMAGES:
            print(f"ALLOWLIST: allowing approved image {image}")
            continue

        if any(image.startswith(p) for p in ALLOWLIST_PREFIXES):
            print(f"ALLOWLIST: allowing by prefix for {image}")
            continue

        parsed = parse_ecr_image(image)
        if not parsed:
            emit_deny_event(cluster_arn, task_arn, task_def_arn, task.get("group", ""),
                          name, image, "N/A", image, "NON_ECR_NOT_ALLOWLISTED", 
                          last_status, -1, f"Image not ECR: {image}", "")
            failures.append(f"Container {name}: not ECR and not in allowlist: {image}")
            continue

        acct, region, repo, ref = parsed
        if allowlist and repo not in allowlist:
            print(f"Skipping repo {repo} (not in allowlist).")
            continue

        try:
            digest = resolve_to_digest(acct, region, repo, ref)
            image_with_digest = f"{acct}.dkr.ecr.{region}.amazonaws.com/{repo}@{digest}"
            print(f"Verifying container {name} -> {image_with_digest}")
            
            region_img = image_region(image_with_digest)
            username, password = ecr_basic_auth(region_img)
            kms_key_uri = f"awskms:///{KMS_KEY_ARN}"
            cmd = [COSIGN_PATH, "verify", "--verbose", "--key", kms_key_uri,
                   "--registry-username", username, "--registry-password", password,
                   image_with_digest]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            print("COSIGN_EXIT:", result.returncode)
            print("COSIGN_STDERR:", result.stderr)
            print("COSIGN_STDOUT:", result.stdout)
            
            if result.returncode != 0:
                stderr_lower = result.stderr.lower()
                if "no signatures found" in stderr_lower or "no matching signatures" in stderr_lower:
                    reason_code = "SIGNATURE_MISSING"
                elif "verification failed" in stderr_lower:
                    reason_code = "SIGNATURE_VERIFY_FAILED"
                elif "kms" in stderr_lower:
                    reason_code = "KMS_VERIFY_FAILURE"
                elif "auth" in stderr_lower or "unauthorized" in stderr_lower:
                    reason_code = "REGISTRY_AUTH_FAILURE"
                elif "network" in stderr_lower or "timeout" in stderr_lower:
                    reason_code = "NETWORK_EGRESS_FAILURE"
                else:
                    reason_code = "SIGNATURE_VERIFY_FAILED"
                
                emit_deny_event(cluster_arn, task_arn, task_def_arn, task.get("group", ""),
                              name, image, digest, image_with_digest, reason_code,
                              last_status, result.returncode, result.stderr, result.stdout)
                failures.append(f"Container {name}: cosign verify failed")
            else:
                print(f"OK: signature valid for {name}")
        except Exception as e:
            reason_code = "UNKNOWN"
            error_str = str(e).lower()
            if "auth" in error_str:
                reason_code = "REGISTRY_AUTH_FAILURE"
            elif "network" in error_str or "timeout" in error_str:
                reason_code = "NETWORK_EGRESS_FAILURE"
            
            emit_deny_event(cluster_arn, task_arn, task_def_arn, task.get("group", ""),
                          name, image, digest if 'digest' in locals() else "N/A",
                          image_with_digest if 'image_with_digest' in locals() else image,
                          reason_code, last_status, -1, str(e), "")
            failures.append(f"Container {name}: {str(e)}")

    if failures:
        reason = f"Signature verification failed: {', '.join(failures)[:240]}"
        print("FAIL:", reason)

        if FAIL_ACTION == "STOP_TASK":
            try:
                stop_task(cluster_arn, task_arn, reason)
                print(f"Stopped task {task_arn}")
            except ClientError as e:
                print("stop_task error:", str(e))
                return {"ok": False, "error": "stop_task_failed", "reason": reason}

        return {"ok": False, "verified": False, "reason": reason, "lastStatus": last_status}

    return {"ok": True, "verified": True, "lastStatus": last_status}
