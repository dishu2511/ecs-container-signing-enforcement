"""A Python Pulumi program"""

import json
import pulumi
import pulumi_aws as aws
from cosign_layer import CosignLayer

# Load configuration
config = pulumi.Config()
aws_config = pulumi.Config("aws")

aws_account_id = config.require("aws_account_id")
kms_key_id = config.require("kms_key_id")
vpc_id = config.require("vpc_id")
subnet_id = config.require("subnet_id")
ecr_repository = config.get("ecr_repository") or "container-signing-test"
aws_region = aws_config.require("region")

# Get current AWS account ID and region dynamically
current = aws.get_caller_identity()
region = aws.get_region()

# ECS Cluster
cluster = aws.ecs.Cluster("container-signing-cluster")

# IAM Role for ECS Task Execution
task_exec_role = aws.iam.Role("task-exec-role",
    assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ecs-tasks.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }""")

aws.iam.RolePolicyAttachment("task-exec-policy",
    role=task_exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")

# Task Definition
task_definition = aws.ecs.TaskDefinition("container-signing-task",
    family="container-signing-task",
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    cpu="256",
    memory="512",
    execution_role_arn=task_exec_role.arn,
    container_definitions=pulumi.Output.json_dumps([{
        "name": "container-signing-app",
        "image": f"{aws_account_id}.dkr.ecr.{aws_region}.amazonaws.com/{ecr_repository}:latest",
        "essential": True,
        "command": ["sh", "-c", "while true; do echo running; sleep 30; done"],
        "portMappings": [{
            "containerPort": 80,
            "protocol": "tcp"
        }],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": "/ecs/container-signing-task",
                "awslogs-region": aws_region,
                "awslogs-stream-prefix": "ecs"
            }
        }
    }]))

# CloudWatch Log Group
log_group = aws.cloudwatch.LogGroup("ecs-log-group",
    name="/ecs/container-signing-task",
    retention_in_days=7)

# Security Group for ECS Task
security_group = aws.ec2.SecurityGroup("ecs-task-sg",
    vpc_id=vpc_id,
    egress=[{
        "protocol": "-1",
        "from_port": 0,
        "to_port": 0,
        "cidr_blocks": ["0.0.0.0/0"]
    }])

# Service with Signed Container Task
service = aws.ecs.Service("container-signing-service",
    cluster=cluster.arn,
    task_definition=task_definition.arn,
    desired_count=1,
    launch_type="FARGATE",
    network_configuration={
        "assign_public_ip": True,
        "subnets": [subnet_id],
        "security_groups": [security_group.id]
    })

# Busybox Task Definition
busybox_log_group = aws.cloudwatch.LogGroup("busybox-log-group",
    name="/ecs/busybox-task",
    retention_in_days=7)

busybox_task_definition = aws.ecs.TaskDefinition("busybox-task",
    family="busybox-task",
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    cpu="256",
    memory="512",
    execution_role_arn=task_exec_role.arn,
    container_definitions=pulumi.Output.json_dumps([{
        "name": "busybox-app",
        "image": "busybox:latest",
        "essential": True,
        "command": ["sh", "-c", "while true; do echo hello; sleep 30; done"],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": "/ecs/busybox-task",
                "awslogs-region": aws_region,
                "awslogs-stream-prefix": "ecs"
            }
        }
    }]))

# Service with Un-Signed Container Task
busybox_service = aws.ecs.Service("busybox-service",
    cluster=cluster.arn,
    task_definition=busybox_task_definition.arn,
    desired_count=1,
    launch_type="FARGATE",
    network_configuration={
        "assign_public_ip": True,
        "subnets": ["subnet-039e1fa032a38212e"],
        "security_groups": [security_group.id]
    })

# Prepare cosign layer
cosign_prep = CosignLayer("cosign-prep")

# S3 bucket for large Lambda layer
layer_bucket = aws.s3.Bucket("cosign-layer-bucket",
    force_destroy=True)

layer_object = aws.s3.BucketObject("cosign-layer-zip",
    bucket=layer_bucket.id,
    key="cosign-layer.zip",
    source=cosign_prep.zip_path.apply(lambda p: pulumi.FileAsset(p)))

# Lambda IAM Role
lambda_role = aws.iam.Role("lambda-verify-role",
    assume_role_policy="""{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }""")

# Get current AWS account ID and region
current = aws.get_caller_identity()
region = aws.get_region()

# Build KMS key ARN
kms_key_arn = f"arn:aws:kms:{aws_region}:{aws_account_id}:key/{kms_key_id}"

lambda_policy = aws.iam.RolePolicy("lambda-verify-policy",
    role=lambda_role.id,
    policy=pulumi.Output.all(current.account_id, region.name).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecs:DescribeTasks",
                    "ecs:DescribeTaskDefinition",
                    "ecs:StopTask"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:DescribeImages",
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kms:GetPublicKey",
                    "kms:Verify",
                    "kms:DescribeKey",
                    "kms:Decrypt"
                ],
                "Resource": kms_key_arn
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": f"arn:aws:logs:{args[1]}:{args[0]}:log-group:/aws/lambda/container-signing-test-verify:*"
            },
            {
                "Effect": "Allow",
                "Action": "events:PutEvents",
                "Resource": f"arn:aws:events:{args[1]}:{args[0]}:event-bus/default"
            },
            {
                "Effect": "Allow",
                "Action": "ssm:GetParameter",
                "Resource": f"arn:aws:ssm:{args[1]}:{args[0]}:parameter/container-signing/slack-webhook"
            }
        ]
    })))

# Lambda Layer
layer = aws.lambda_.LayerVersion("cosign-layer",
    layer_name="cosign-layer",
    s3_bucket=layer_bucket.id,
    s3_key=layer_object.key,
    compatible_runtimes=["python3.11"])

# Enforcement Lambda Function
enforcement_lambda = aws.lambda_.Function("container-signing-verify",
    name="container-signing-test-verify",
    runtime="python3.11",
    handler="enforcement_lambda.handler",
    role=lambda_role.arn,
    code=pulumi.FileArchive("./enforcement_lambda.zip"),
    layers=[layer.arn],
    architectures=["x86_64"],
    timeout=300,
    environment={
        "variables": {
            "KMS_KEY_ARN": kms_key_arn,
            "COSIGN_PATH": "/opt/bin/cosign",
            "FAIL_ACTION": "STOP_TASK",
            "DOCKER_CONFIG": "/opt/.docker",
            "PATH": "/opt/bin:/usr/local/bin:/usr/bin:/bin",
            "DECISION_EVENT_SOURCE": "container.signing",
            "DECISION_EVENT_DETAIL_TYPE": "ContainerSigningDecision",
            "DECISION_EVENT_BUS": "default",
            "MAX_EVIDENCE_BYTES": "2048"
        }
    })

# Triage Lambda Role
triage_lambda_role = aws.iam.Role("triage-lambda-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }))

aws.iam.RolePolicyAttachment("triage-lambda-basic",
    role=triage_lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")

# Triage Lambda Log Group
triage_log_group = aws.cloudwatch.LogGroup("triage-log-group",
    name="/aws/lambda/container-signing-triage",
    retention_in_days=7)

# Triage Lambda Function
triage_lambda = aws.lambda_.Function("triage-lambda",
    name="container-signing-triage",
    runtime="python3.11",
    handler="triage_lambda.handler",
    role=triage_lambda_role.arn,
    code=pulumi.FileArchive("./triage_lambda.zip"),
    timeout=60)

# Alert Lambda Role
alert_lambda_role = aws.iam.Role("alert-lambda-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }))

aws.iam.RolePolicyAttachment("alert-lambda-basic",
    role=alert_lambda_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")

alert_lambda_policy = aws.iam.RolePolicy("alert-lambda-policy",
    role=alert_lambda_role.id,
    policy=pulumi.Output.all(current.account_id, region.name).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ssm:GetParameter",
                "Resource": f"arn:aws:ssm:{args[1]}:{args[0]}:parameter/container-signing/slack-webhook"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": f"arn:aws:logs:{args[1]}:{args[0]}:log-group:/aws/lambda/container-signing-alert:*"
            }
        ]
    })))

# Alert Lambda Log Group
alert_log_group = aws.cloudwatch.LogGroup("alert-log-group",
    name="/aws/lambda/container-signing-alert",
    retention_in_days=7)

# Alert Lambda Function
alert_lambda = aws.lambda_.Function("alert-lambda",
    name="container-signing-alert",
    runtime="python3.11",
    handler="alert_lambda.handler",
    role=alert_lambda_role.arn,
    code=pulumi.FileArchive("./alert_lambda.zip"),
    timeout=30,
    environment={
        "variables": {
            "SLACK_WEBHOOK_SECRET_NAME": "/container-signing/slack-webhook"
        }
    })

# Step Functions Role
sfn_role = aws.iam.Role("sfn-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }))

sfn_policy = aws.iam.RolePolicy("sfn-policy",
    role=sfn_role.id,
    policy=pulumi.Output.all(triage_lambda.arn, alert_lambda.arn).apply(lambda arns: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": [arns[0], arns[1]]
            }
        ]
    })))

# Step Functions State Machine
state_machine = aws.sfn.StateMachine("triage-alert-workflow",
    name="container-signing-triage-alert",
    role_arn=sfn_role.arn,
    definition=pulumi.Output.all(triage_lambda.arn, alert_lambda.arn).apply(
        lambda arns: open("stepfunction_definition.json").read()
            .replace("${TriageLambdaArn}", arns[0])
            .replace("${AlertLambdaArn}", arns[1])
    ))

# EventBridge Rule for ECS Task State Change (triggers enforcement)
event_rule = aws.cloudwatch.EventRule("ecs-task-start-rule",
    name="container-signing-test-ecs-task-start",
    event_pattern=cluster.arn.apply(lambda arn: pulumi.Output.json_dumps({
        "source": ["aws.ecs"],
        "detail-type": ["ECS Task State Change"],
        "detail": {
            "clusterArn": [arn],
            "lastStatus": ["PENDING"]
        }
    })))

aws.cloudwatch.EventTarget("lambda-target",
    rule=event_rule.name,
    arn=enforcement_lambda.arn)

aws.lambda_.Permission("eventbridge-invoke",
    action="lambda:InvokeFunction",
    function=enforcement_lambda.name,
    principal="events.amazonaws.com",
    source_arn=event_rule.arn)

# EventBridge Role for invoking Step Functions
eventbridge_sfn_role = aws.iam.Role("eventbridge-sfn-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }))

eventbridge_sfn_policy = aws.iam.RolePolicy("eventbridge-sfn-policy",
    role=eventbridge_sfn_role.id,
    policy=state_machine.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "states:StartExecution",
            "Resource": arn
        }]
    })))

# EventBridge Rule for DecisionEvent (triggers Step Functions)
decision_event_rule = aws.cloudwatch.EventRule("decision-event-rule",
    name="container-signing-decision-event",
    event_pattern=pulumi.Output.json_dumps({
        "source": ["container.signing"],
        "detail-type": ["ContainerSigningDecision"],
        "detail": {
            "decision": ["DENY"]
        }
    }))

aws.cloudwatch.EventTarget("sfn-target",
    rule=decision_event_rule.name,
    arn=state_machine.arn,
    role_arn=eventbridge_sfn_role.arn)

pulumi.export("cluster_name", cluster.name)
pulumi.export("cluster_arn", cluster.arn)
pulumi.export("enforcement_lambda_arn", enforcement_lambda.arn)
pulumi.export("triage_lambda_arn", triage_lambda.arn)
pulumi.export("alert_lambda_arn", alert_lambda.arn)
pulumi.export("state_machine_arn", state_machine.arn)
pulumi.export("layer_arn", layer.arn)
pulumi.export("event_rule_arn", event_rule.arn)
pulumi.export("decision_event_rule_arn", decision_event_rule.arn)

