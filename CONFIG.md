# Configuration Setup

## Initial Setup

1. **Copy the example config:**
   ```bash
   cp Pulumi.example.yaml Pulumi.<your-stack-name>.yaml
   ```

2. **Fill in your values:**
   Edit `Pulumi.<your-stack-name>.yaml` with your AWS account details:

   ```yaml
   config:
     aws:region: ap-southeast-2  # Your AWS region
     ecs-container-signing-infra:aws_account_id: "123456789012"  # Your AWS account ID
     ecs-container-signing-infra:kms_key_id: "your-kms-key-id"  # Your KMS key ID (not full ARN)
     ecs-container-signing-infra:vpc_id: "vpc-xxxxx"  # Your VPC ID
     ecs-container-signing-infra:subnet_id: "subnet-xxxxx"  # Your subnet ID
     ecs-container-signing-infra:ecr_repository: "container-signing-test"  # Your ECR repo name
   ```

3. **Set your Pulumi stack:**
   ```bash
   pulumi stack select <your-stack-name>
   ```

## Configuration Values

| Key | Description | Example |
|-----|-------------|---------|
| `aws:region` | AWS region to deploy to | `ap-southeast-2` |
| `aws_account_id` | Your AWS account ID | `123456789012` |
| `kms_key_id` | KMS key ID for cosign (not full ARN) | `030a988b-a04a-42e0-9563-95aa0a131092` |
| `vpc_id` | VPC ID for ECS tasks | `vpc-0a5b50d00f6e5318e` |
| `subnet_id` | Subnet ID for ECS tasks | `subnet-039e1fa032a38212e` |
| `ecr_repository` | ECR repository name | `container-signing-test` |

## Security Note

- `Pulumi.<stack-name>.yaml` files are gitignored and should NOT be committed
- Only `Pulumi.example.yaml` should be committed as a template
- Store actual config values securely (e.g., in your CI/CD secrets)
