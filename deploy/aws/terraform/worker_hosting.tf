locals {
  worker_service_name           = "${var.name_prefix}-${var.environment}-worker"
  worker_name_hash              = substr(sha1(local.worker_service_name), 0, 8)
  worker_iam_name_prefix        = "${trimsuffix(substr(local.worker_service_name, 0, 43), "-")}-${local.worker_name_hash}"
  worker_policy_name_base       = "${trimsuffix(substr(local.worker_service_name, 0, 47), "-")}-${local.worker_name_hash}"
  worker_fargate_memory_options = lookup(local.api_fargate_memory_by_cpu, tostring(var.worker_task_cpu), [])
  worker_default_environment_variables = {
    IDENTRAIL_SERVICE_NAME                          = "identrail-worker"
    IDENTRAIL_WORKER_SCAN_ENABLED                   = "false"
    IDENTRAIL_WORKER_RUN_NOW                        = "false"
    IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED          = "true"
    IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL         = "2s"
    IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE       = "5"
    IDENTRAIL_WORKER_SCAN_POLICY_SCHEDULER_ENABLED  = "true"
    IDENTRAIL_WORKER_SCAN_POLICY_SCHEDULER_INTERVAL = "1m"
    IDENTRAIL_WORKER_REPO_SCAN_ENABLED              = "false"
    IDENTRAIL_RUN_MIGRATIONS                        = "false"
    IDENTRAIL_RUN_MIGRATIONS_ONLY                   = "false"
  }
  worker_runtime_environment_variables = merge(
    local.api_runtime_environment_variables,
    local.worker_default_environment_variables,
    var.worker_environment_variables
  )
  worker_runtime_secrets              = merge(var.api_secrets, var.worker_secrets)
  worker_secret_config_names          = toset(keys(local.worker_runtime_secrets))
  worker_combined_secret_kms_key_arns = distinct(concat(var.api_secret_kms_key_arns, var.worker_secret_kms_key_arns))
  worker_secret_resource_arns = toset([
    for value_from in values(local.worker_runtime_secrets) : join(":", slice(split(":", value_from), 0, 7))
  ])
  worker_environment = [
    for name, value in local.worker_runtime_environment_variables : {
      name  = name
      value = value
    }
  ]
  worker_secrets = [
    for name, value_from in local.worker_runtime_secrets : {
      name      = name
      valueFrom = value_from
    }
  ]
}

resource "terraform_data" "worker_inputs" {
  count = var.create_worker_hosting_resources ? 1 : 0

  input = local.worker_service_name

  lifecycle {
    precondition {
      condition     = var.create_api_hosting_resources
      error_message = "worker hosting requires create_api_hosting_resources=true so the worker can share the API ECS cluster and network."
    }

    precondition {
      condition     = length(trimspace(var.worker_container_image)) > 0
      error_message = "worker_container_image is required when create_worker_hosting_resources=true."
    }

    precondition {
      condition     = can(regex("^ghcr\\.io/identrail/identrail-worker(:|@sha256:).+$", var.worker_container_image))
      error_message = "worker_container_image must reference ghcr.io/identrail/identrail-worker."
    }

    precondition {
      condition     = contains(local.worker_fargate_memory_options, var.worker_task_memory)
      error_message = "worker_task_cpu and worker_task_memory must be a valid AWS Fargate CPU/memory pair."
    }

    precondition {
      condition     = contains(local.worker_secret_config_names, "IDENTRAIL_DATABASE_URL")
      error_message = "worker hosting requires IDENTRAIL_DATABASE_URL in inherited api_secrets or worker_secrets."
    }

    precondition {
      condition     = lower(local.worker_runtime_environment_variables["IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED"]) == "true"
      error_message = "worker hosting requires IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED=true so queued API scans can be processed."
    }

    precondition {
      condition     = lower(local.worker_runtime_environment_variables["IDENTRAIL_RUN_MIGRATIONS"]) == "false"
      error_message = "worker hosting requires IDENTRAIL_RUN_MIGRATIONS=false so long-running worker tasks do not run schema migrations during startup."
    }

    precondition {
      condition     = lower(local.worker_runtime_environment_variables["IDENTRAIL_RUN_MIGRATIONS_ONLY"]) == "false"
      error_message = "worker hosting requires IDENTRAIL_RUN_MIGRATIONS_ONLY=false so long-running worker tasks start the worker loop."
    }
  }
}

data "aws_iam_policy_document" "worker_task_execution_secrets" {
  count = var.create_worker_hosting_resources && length(local.worker_runtime_secrets) > 0 ? 1 : 0

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.worker_secret_resource_arns
  }

  dynamic "statement" {
    for_each = length(local.worker_combined_secret_kms_key_arns) > 0 ? [1] : []

    content {
      actions   = ["kms:Decrypt"]
      resources = local.worker_combined_secret_kms_key_arns
    }
  }
}

resource "aws_iam_role" "worker_task_execution" {
  count = var.create_worker_hosting_resources ? 1 : 0

  name               = "${local.worker_iam_name_prefix}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role[0].json
}

resource "aws_iam_role_policy_attachment" "worker_task_execution" {
  count = var.create_worker_hosting_resources ? 1 : 0

  role       = aws_iam_role.worker_task_execution[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "worker_task_execution_secrets" {
  count = var.create_worker_hosting_resources && length(local.worker_runtime_secrets) > 0 ? 1 : 0

  name   = "${local.worker_policy_name_base}-secrets"
  role   = aws_iam_role.worker_task_execution[0].id
  policy = data.aws_iam_policy_document.worker_task_execution_secrets[0].json
}

resource "aws_iam_role" "worker_task" {
  count = var.create_worker_hosting_resources ? 1 : 0

  name               = "${local.worker_iam_name_prefix}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role[0].json
}

resource "aws_iam_role_policy" "worker_task_exec_command" {
  count = var.create_worker_hosting_resources && var.api_enable_execute_command ? 1 : 0

  name   = "${local.worker_policy_name_base}-exec"
  role   = aws_iam_role.worker_task[0].id
  policy = data.aws_iam_policy_document.api_task_exec_command[0].json
}

resource "aws_iam_role_policy" "worker_task_aws_collector" {
  count = var.create_worker_hosting_resources ? 1 : 0

  name   = "${local.worker_policy_name_base}-aws-collector"
  role   = aws_iam_role.worker_task[0].id
  policy = data.aws_iam_policy_document.api_task_aws_collector[0].json
}

resource "aws_security_group" "worker_service" {
  count = var.create_worker_hosting_resources ? 1 : 0

  name        = "${local.worker_service_name}-service"
  description = "Private egress for the Identrail worker ECS service"
  vpc_id      = var.api_vpc_id
}

resource "aws_vpc_security_group_egress_rule" "worker_service_egress" {
  count = var.create_worker_hosting_resources ? 1 : 0

  security_group_id = aws_security_group.worker_service[0].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_ecs_task_definition" "worker" {
  count = var.create_worker_hosting_resources ? 1 : 0

  family                   = local.worker_service_name
  cpu                      = var.worker_task_cpu
  execution_role_arn       = aws_iam_role.worker_task_execution[0].arn
  memory                   = var.worker_task_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  task_role_arn            = aws_iam_role.worker_task[0].arn

  container_definitions = jsonencode([
    {
      name        = "worker"
      image       = var.worker_container_image
      essential   = true
      environment = local.worker_environment
      secrets     = local.worker_secrets
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["worker"].name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "worker"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "worker" {
  count = var.create_worker_hosting_resources ? 1 : 0

  name            = local.worker_service_name
  cluster         = aws_ecs_cluster.api[0].id
  task_definition = aws_ecs_task_definition.worker[0].arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  enable_ecs_managed_tags            = true
  enable_execute_command             = var.api_enable_execute_command
  propagate_tags                     = "SERVICE"
  wait_for_steady_state              = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    assign_public_ip = var.api_task_assign_public_ip
    security_groups  = [aws_security_group.worker_service[0].id]
    subnets          = local.api_task_subnet_ids
  }

  depends_on = [
    terraform_data.worker_inputs,
    aws_iam_role_policy_attachment.worker_task_execution,
    aws_iam_role_policy.worker_task_execution_secrets,
    aws_iam_role_policy.worker_task_aws_collector,
  ]
}
