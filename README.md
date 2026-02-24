# ECS Container Signing Enforcement

Automated container signature verification for AWS ECS using Cosign and AWS KMS. This infrastructure enforces image signing policies with Lambda-based verification, Step Functions orchestration, and Slack alerting.

## 🏗️ Architecture

```
ECS Task (PENDING)
    ↓
EventBridge Rule
    ↓
Enforcement Lambda
    ├─→ Verifies signature with Cosign + KMS
    ├─→ Stops task if unsigned/invalid
    └─→ Emits DecisionEvent to EventBridge
            ↓
    EventBridge Rule (DENY events)
            ↓
    Step Functions Workflow
            ↓
    Triage Lambda (enriches with severity)
            ↓
    Alert Lambda (sends Slack notification)
```

## 🎯 Features

- ✅ **Automated Verification**: Intercepts ECS tasks in PENDING state
- ✅ **Cosign Integration**: Uses Cosign with AWS KMS for signature verification
- ✅ **Policy Enforcement**: Stops unsigned/invalid containers automatically
- ✅ **Event-Driven**: Publishes structured decision events to EventBridge
- ✅ **Smart Alerting**: Triage-based severity classification with Slack notifications
- ✅ **Allowlisting**: Support for approved images, digests, and registry prefixes
- ✅ **Infrastructure as Code**: Complete Pulumi deployment

## 📋 Components

### Lambda Functions
1. **Enforcement Lambda** - Verifies container signatures and stops non-compliant tasks
2. **Triage Lambda** - Analyzes failures and determines severity
3. **Alert Lambda** - Sends formatted Slack notifications

### AWS Resources
- ECS Cluster with Fargate tasks
- Lambda Layer with Cosign binary
- EventBridge rules for task state changes and decision events
- Step Functions workflow for alert orchestration
- IAM roles with least-privilege permissions
- CloudWatch Log Groups for monitoring

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Pulumi CLI installed
- AWS credentials configured
- AWS KMS key for Cosign signatures
- Slack webhook URL (for alerts)

### 1. Clone and Setup

```bash
git clone https://github.com/yourusername/ecs-container-signing-enforcement.git
cd ecs-container-signing-enforcement
pip install -r requirements.txt
```

### 2. Configure Stack

Copy the example config and fill in your values:

```bash
cp Pulumi.example.yaml Pulumi.<your-stack-name>.yaml
```

Edit `Pulumi.<your-stack-name>.yaml`:

```yaml
config:
  aws:region: us-east-1
  ecs-container-signing-infra:aws_account_id: "123456789012"
  ecs-container-signing-infra:kms_key_id: "your-kms-key-id"
  ecs-container-signing-infra:vpc_id: "vpc-xxxxx"
  ecs-container-signing-infra:subnet_id: "subnet-xxxxx"
  ecs-container-signing-infra:ecr_repository: "your-repo-name"
```

See [CONFIG.md](CONFIG.md) for detailed configuration instructions.

### 3. Store Slack Webhook

```bash
aws ssm put-parameter \
    --name /container-signing/slack-webhook \
    --value "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" \
    --type SecureString \
    --region <your-region>
```

### 4. Deploy

```bash
pulumi stack select <your-stack-name>
pulumi up
```

The deployment will:
- Download the latest Cosign binary
- Create Lambda layer with Cosign
- Package all Lambda functions
- Deploy complete infrastructure

## 🧪 Testing

### Test with Unsigned Image

```bash
# Run busybox task (unsigned)
aws ecs run-task \
    --cluster <cluster-name> \
    --task-definition busybox-task \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[<subnet-id>],assignPublicIp=ENABLED}" \
    --region <your-region>
```

Expected behavior:
1. Task starts in PENDING state
2. Enforcement Lambda verifies signature
3. Task is stopped (unsigned image)
4. DecisionEvent published to EventBridge
5. Step Functions workflow triggered
6. Slack notification sent

### Monitor Logs

```bash
# Enforcement Lambda
aws logs tail /aws/lambda/container-signing-test-verify --follow --region <your-region>

# Triage Lambda
aws logs tail /aws/lambda/container-signing-triage --follow --region <your-region>

# Alert Lambda
aws logs tail /aws/lambda/container-signing-alert --follow --region <your-region>
```

### Check Step Functions Execution

```bash
aws stepfunctions list-executions \
    --state-machine-arn <state-machine-arn> \
    --region <your-region>
```

## ⚙️ Configuration

### Environment Variables (Enforcement Lambda)

| Variable | Description | Default |
|----------|-------------|---------|
| `KMS_KEY_ARN` | AWS KMS key ARN for signature verification | Required |
| `COSIGN_PATH` | Path to Cosign binary in Lambda layer | `/opt/bin/cosign` |
| `FAIL_ACTION` | Action on verification failure | `STOP_TASK` |
| `DECISION_EVENT_SOURCE` | EventBridge event source | `container.signing` |
| `DECISION_EVENT_DETAIL_TYPE` | EventBridge detail type | `ContainerSigningDecision` |

### Allowlisting

Configure via environment variables:

- `ALLOWLIST_IMAGES` - Comma-separated full image refs
- `ALLOWLIST_DIGESTS` - Comma-separated SHA256 digests
- `ALLOWLIST_PREFIXES` - Comma-separated registry prefixes (e.g., `docker.io/library/`)
- `REPO_ALLOWLIST` - Comma-separated ECR repository names

### Reason Codes

| Code | Description |
|------|-------------|
| `SIGNATURE_MISSING` | No Cosign signature found |
| `SIGNATURE_VERIFY_FAILED` | Signature verification failed |
| `KMS_VERIFY_FAILURE` | KMS key access error |
| `REGISTRY_AUTH_FAILURE` | ECR authentication failed |
| `NON_ECR_NOT_ALLOWLISTED` | Non-ECR image not in allowlist |
| `NETWORK_EGRESS_FAILURE` | Network connectivity issue |

## 📊 Outputs

After deployment, Pulumi exports:

```bash
pulumi stack output cluster_name
pulumi stack output cluster_arn
pulumi stack output enforcement_lambda_arn
pulumi stack output triage_lambda_arn
pulumi stack output alert_lambda_arn
pulumi stack output state_machine_arn
pulumi stack output layer_arn
```

## 🔒 Security

### IAM Permissions

**Enforcement Lambda:**
- `ecs:DescribeTasks`, `ecs:DescribeTaskDefinition`, `ecs:StopTask`
- `ecr:DescribeImages`, `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`
- `kms:GetPublicKey`, `kms:Verify`, `kms:DescribeKey` (scoped to KMS key)
- `events:PutEvents` (for DecisionEvents)
- `ssm:GetParameter` (for Slack webhook)

**Triage Lambda:**
- CloudWatch Logs write permissions

**Alert Lambda:**
- `ssm:GetParameter` (for Slack webhook)
- CloudWatch Logs write permissions

**Step Functions:**
- `lambda:InvokeFunction` (for Triage and Alert Lambdas)

### Best Practices

- Store Slack webhook in SSM Parameter Store (SecureString)
- Use KMS key with restricted access policies
- Enable CloudWatch Logs encryption
- Review IAM policies regularly
- Monitor EventBridge metrics

## 📚 Additional Resources

- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [Pulumi AWS Provider](https://www.pulumi.com/registry/packages/aws/)
- [Example Payloads](example-payloads.json) - Sample event structures

## 🧹 Cleanup

Remove all resources:

```bash
pulumi destroy
```

This will delete:
- ECS cluster and task definitions
- All Lambda functions and layers
- EventBridge rules
- Step Functions state machine
- IAM roles and policies
- CloudWatch Log Groups
- S3 bucket (if created)

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details

## 🐛 Troubleshooting

### Task not being stopped

- Check EventBridge rule is enabled
- Verify Lambda has `ecs:StopTask` permission
- Check CloudWatch Logs for errors

### Signature verification failing

- Ensure KMS key policy allows Lambda role
- Verify Cosign signature exists on image
- Check ECR authentication is working

### Slack notifications not received

- Verify SSM parameter exists and is accessible
- Check Alert Lambda CloudWatch Logs
- Test webhook URL manually

### Step Functions not triggering

- Verify EventBridge rule for DecisionEvents is enabled
- Check EventBridge role has `states:StartExecution` permission
- Review Step Functions execution history

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Check CloudWatch Logs for detailed error messages
- Review [CONFIG.md](CONFIG.md) for configuration help
