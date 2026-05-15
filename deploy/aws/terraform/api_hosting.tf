locals {
  api_service_name     = "${var.name_prefix}-${var.environment}-api"
  api_name_hash        = substr(sha1(local.api_service_name), 0, 8)
  api_name_prefix      = "${trimsuffix(substr(local.api_service_name, 0, 23), "-")}-${local.api_name_hash}"
  api_iam_name_prefix  = "${trimsuffix(substr(local.api_service_name, 0, 43), "-")}-${local.api_name_hash}"
  api_policy_name_base = "${trimsuffix(substr(local.api_service_name, 0, 47), "-")}-${local.api_name_hash}"
  api_fargate_memory_by_cpu = {
    "256"   = [512, 1024, 2048]
    "512"   = [1024, 2048, 3072, 4096]
    "1024"  = [2048, 3072, 4096, 5120, 6144, 7168, 8192]
    "2048"  = range(4096, 16385, 1024)
    "4096"  = range(8192, 30721, 1024)
    "8192"  = range(16384, 61441, 4096)
    "16384" = range(32768, 122881, 8192)
  }
  api_fargate_memory_options = lookup(local.api_fargate_memory_by_cpu, tostring(var.api_task_cpu), [])
  api_cors_allowed_origins   = join(",", var.api_cors_allowed_origins)
  api_trusted_proxies        = join(",", var.api_trusted_proxy_cidr_blocks)
  api_task_subnet_ids        = length(var.api_task_subnet_ids) > 0 ? var.api_task_subnet_ids : var.api_private_subnet_ids
  api_default_environment_variables = {
    IDENTRAIL_AWS_REGION           = var.aws_region
    IDENTRAIL_AWS_SOURCE           = "sdk"
    IDENTRAIL_CORS_ALLOWED_ORIGINS = local.api_cors_allowed_origins
    IDENTRAIL_HTTP_ADDR            = ":${var.api_container_port}"
    IDENTRAIL_REQUIRE_LIVE_SOURCES = "true"
    IDENTRAIL_RUN_MIGRATIONS       = "false"
    IDENTRAIL_RUN_MIGRATIONS_ONLY  = "false"
    IDENTRAIL_TRUSTED_PROXIES      = local.api_trusted_proxies
  }
  api_runtime_environment_variables = merge(local.api_default_environment_variables, var.api_environment_variables)
  api_config_names                  = toset(concat(keys(local.api_runtime_environment_variables), keys(var.api_secrets)))
  api_secret_config_names           = toset(keys(var.api_secrets))
  api_secret_resource_arns = toset([
    for value_from in values(var.api_secrets) : join(":", slice(split(":", value_from), 0, 7))
  ])
  api_runtime_cors_allowed_origins = compact([
    for origin in split(",", lookup(local.api_runtime_environment_variables, "IDENTRAIL_CORS_ALLOWED_ORIGINS", "")) : trimspace(origin)
  ])
  api_runtime_trusted_proxies = compact([
    for cidr_block in split(",", lookup(local.api_runtime_environment_variables, "IDENTRAIL_TRUSTED_PROXIES", "")) : trimspace(cidr_block)
  ])
  api_workos_login_enabled = lower(lookup(local.api_runtime_environment_variables, "IDENTRAIL_FEATURE_WORKOS_LOGIN", "")) == "true"
  api_main_route_table_ids = [
    for route_table_id, route_table in data.aws_route_table.api_vpc : route_table_id
    if anytrue([for association in route_table.associations : association.main])
  ]
  api_public_subnet_explicit_route_table_ids = {
    for subnet_id in var.api_public_subnet_ids : subnet_id => [
      for route_table_id, route_table in data.aws_route_table.api_vpc : route_table_id
      if anytrue([for association in route_table.associations : association.subnet_id == subnet_id])
    ]
  }
  api_public_subnet_effective_route_table_ids = {
    for subnet_id in var.api_public_subnet_ids : subnet_id => (
      length(local.api_public_subnet_explicit_route_table_ids[subnet_id]) > 0 ?
      local.api_public_subnet_explicit_route_table_ids[subnet_id] :
      local.api_main_route_table_ids
    )
  }
  api_task_subnet_explicit_route_table_ids = {
    for subnet_id in local.api_task_subnet_ids : subnet_id => [
      for route_table_id, route_table in data.aws_route_table.api_vpc : route_table_id
      if anytrue([for association in route_table.associations : association.subnet_id == subnet_id])
    ]
  }
  api_task_subnet_effective_route_table_ids = {
    for subnet_id in local.api_task_subnet_ids : subnet_id => (
      length(local.api_task_subnet_explicit_route_table_ids[subnet_id]) > 0 ?
      local.api_task_subnet_explicit_route_table_ids[subnet_id] :
      local.api_main_route_table_ids
    )
  }
  api_new_auth_enabled = lower(lookup(local.api_runtime_environment_variables, "IDENTRAIL_FEATURE_NEW_AUTH", "")) == "true"
  api_has_supported_auth = (
    contains(local.api_secret_config_names, "IDENTRAIL_API_KEY_SCOPES") ||
    (contains(local.api_secret_config_names, "IDENTRAIL_API_KEYS") && contains(local.api_secret_config_names, "IDENTRAIL_WRITE_API_KEYS")) ||
    (contains(local.api_config_names, "IDENTRAIL_OIDC_ISSUER_URL") && contains(local.api_config_names, "IDENTRAIL_OIDC_AUDIENCE")) ||
    (local.api_new_auth_enabled && contains(local.api_config_names, "IDENTRAIL_PUBLIC_BASE_URL") && contains(local.api_secret_config_names, "IDENTRAIL_SESSION_KEY"))
  )
  api_environment = [
    for name, value in local.api_runtime_environment_variables : {
      name  = name
      value = value
    }
  ]
  api_secrets = [
    for name, value_from in var.api_secrets : {
      name      = name
      valueFrom = value_from
    }
  ]
}

data "aws_partition" "current" {}

data "aws_subnet" "api_public" {
  count = var.create_api_hosting_resources ? length(var.api_public_subnet_ids) : 0

  id = var.api_public_subnet_ids[count.index]
}

data "aws_subnet" "api_task" {
  count = var.create_api_hosting_resources ? length(local.api_task_subnet_ids) : 0

  id = local.api_task_subnet_ids[count.index]
}

data "aws_route_tables" "api_vpc" {
  count = var.create_api_hosting_resources ? 1 : 0

  vpc_id = var.api_vpc_id
}

data "aws_route_table" "api_vpc" {
  for_each = var.create_api_hosting_resources ? toset(data.aws_route_tables.api_vpc[0].ids) : toset([])

  route_table_id = each.value
}

resource "terraform_data" "api_inputs" {
  count = var.create_api_hosting_resources ? 1 : 0

  input = local.api_service_name

  lifecycle {
    precondition {
      condition     = can(regex("^vpc-[0-9a-f]+$", var.api_vpc_id))
      error_message = "api_vpc_id must be a valid VPC ID when create_api_hosting_resources=true."
    }

    precondition {
      condition = length(distinct(var.api_public_subnet_ids)) >= 2 && alltrue([
        for subnet_id in var.api_public_subnet_ids : can(regex("^subnet-[0-9a-f]+$", subnet_id))
      ])
      error_message = "api_public_subnet_ids must include at least two distinct valid subnet IDs when create_api_hosting_resources=true."
    }

    precondition {
      condition     = length(distinct(data.aws_subnet.api_public[*].availability_zone_id)) >= 2
      error_message = "api_public_subnet_ids must include public subnets in at least two distinct Availability Zones when create_api_hosting_resources=true."
    }

    precondition {
      condition = alltrue([
        for subnet in data.aws_subnet.api_public : subnet.vpc_id == var.api_vpc_id
      ])
      error_message = "api_public_subnet_ids must all belong to api_vpc_id when create_api_hosting_resources=true."
    }

    precondition {
      condition = alltrue([
        for route_table_ids in values(local.api_public_subnet_effective_route_table_ids) : anytrue([
          for route_table_id in route_table_ids : anytrue([
            for route in data.aws_route_table.api_vpc[route_table_id].routes : route.cidr_block == "0.0.0.0/0" && can(regex("^igw-", route.gateway_id))
          ])
        ])
      ])
      error_message = "api_public_subnet_ids must resolve to explicit or inherited main route tables with a 0.0.0.0/0 Internet Gateway route when create_api_hosting_resources=true."
    }

    precondition {
      condition = length(distinct(local.api_task_subnet_ids)) >= 2 && alltrue([
        for subnet_id in local.api_task_subnet_ids : can(regex("^subnet-[0-9a-f]+$", subnet_id))
      ])
      error_message = "API hosting requires at least two distinct valid ECS task subnet IDs. Set api_task_subnet_ids, or leave it empty and set api_private_subnet_ids."
    }

    precondition {
      condition = alltrue([
        for subnet in data.aws_subnet.api_task : subnet.vpc_id == var.api_vpc_id
      ])
      error_message = "ECS task subnets must all belong to api_vpc_id when create_api_hosting_resources=true."
    }

    precondition {
      condition     = length(distinct(data.aws_subnet.api_task[*].availability_zone_id)) >= 2
      error_message = "ECS task subnets must span at least two distinct Availability Zones when create_api_hosting_resources=true."
    }

    precondition {
      condition = can(regex(
        "^arn:${data.aws_partition.current.partition}:acm:${var.aws_region}:[0-9]{12}:certificate/.+$",
        var.api_certificate_arn
      ))
      error_message = "api_certificate_arn must be an ACM certificate ARN in the active AWS partition and aws_region when create_api_hosting_resources=true."
    }

    precondition {
      condition     = var.api_task_assign_public_ip || var.api_private_subnet_egress_ready
      error_message = "API hosting requires egress for ECS tasks: set api_private_subnet_egress_ready=true for private task subnets, or set api_task_assign_public_ip=true with public task subnets for the low-cost first cutover path."
    }

    precondition {
      condition = !var.api_task_assign_public_ip || alltrue([
        for route_table_ids in values(local.api_task_subnet_effective_route_table_ids) : anytrue([
          for route_table_id in route_table_ids : anytrue([
            for route in data.aws_route_table.api_vpc[route_table_id].routes : route.cidr_block == "0.0.0.0/0" && can(regex("^igw-", route.gateway_id))
          ])
        ])
      ])
      error_message = "api_task_assign_public_ip=true requires ECS task subnets to have an Internet Gateway default route."
    }

    precondition {
      condition     = length(trimspace(var.api_container_image)) > 0
      error_message = "api_container_image is required when create_api_hosting_resources=true."
    }

    precondition {
      condition     = contains(local.api_secret_config_names, "IDENTRAIL_DATABASE_URL")
      error_message = "api_secrets must include IDENTRAIL_DATABASE_URL when create_api_hosting_resources=true."
    }

    precondition {
      condition     = local.api_has_supported_auth
      error_message = "API hosting requires at least one supported auth mode: IDENTRAIL_API_KEY_SCOPES in api_secrets, legacy IDENTRAIL_API_KEYS plus IDENTRAIL_WRITE_API_KEYS in api_secrets, OIDC issuer plus audience, or new auth with IDENTRAIL_FEATURE_NEW_AUTH=true, IDENTRAIL_PUBLIC_BASE_URL, and IDENTRAIL_SESSION_KEY in api_secrets."
    }

    precondition {
      condition = !local.api_workos_login_enabled || (
        local.api_new_auth_enabled &&
        contains(local.api_config_names, "IDENTRAIL_WORKOS_CLIENT_ID") &&
        contains(local.api_config_names, "IDENTRAIL_WORKOS_ENVIRONMENT_ID") &&
        contains(local.api_secret_config_names, "IDENTRAIL_WORKOS_API_KEY") &&
        contains(local.api_secret_config_names, "IDENTRAIL_WORKOS_WEBHOOK_SECRET")
      )
      error_message = "WorkOS login requires IDENTRAIL_FEATURE_NEW_AUTH=true, IDENTRAIL_WORKOS_CLIENT_ID, and IDENTRAIL_WORKOS_ENVIRONMENT_ID in api_environment_variables, plus IDENTRAIL_WORKOS_API_KEY and IDENTRAIL_WORKOS_WEBHOOK_SECRET in api_secrets."
    }

    precondition {
      condition = length(local.api_runtime_cors_allowed_origins) > 0 && alltrue([
        for origin in local.api_runtime_cors_allowed_origins : can(regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$", origin))
      ])
      error_message = "API hosting requires IDENTRAIL_CORS_ALLOWED_ORIGINS to contain at least one bare HTTPS web origin without paths, queries, fragments, or trailing slashes."
    }

    precondition {
      condition = length(local.api_runtime_trusted_proxies) > 0 && alltrue([
        for cidr_block in local.api_runtime_trusted_proxies : can(cidrhost(cidr_block, 0)) && can(cidrnetmask(cidr_block))
      ])
      error_message = "API hosting requires IDENTRAIL_TRUSTED_PROXIES to contain at least one trusted ALB/VPC proxy CIDR."
    }

    precondition {
      condition     = contains(local.api_fargate_memory_options, var.api_task_memory)
      error_message = "api_task_cpu and api_task_memory must be a valid AWS Fargate CPU/memory pair."
    }

    precondition {
      condition     = lower(local.api_runtime_environment_variables["IDENTRAIL_AWS_SOURCE"]) == "sdk"
      error_message = "API hosting requires IDENTRAIL_AWS_SOURCE=sdk so hosted ECS tasks use live AWS collection instead of fixtures."
    }

    precondition {
      condition     = lower(local.api_runtime_environment_variables["IDENTRAIL_REQUIRE_LIVE_SOURCES"]) == "true"
      error_message = "API hosting requires IDENTRAIL_REQUIRE_LIVE_SOURCES=true so hosted ECS tasks cannot serve fixture-backed scans."
    }

    precondition {
      condition     = lower(local.api_runtime_environment_variables["IDENTRAIL_RUN_MIGRATIONS"]) == "false"
      error_message = "API hosting requires IDENTRAIL_RUN_MIGRATIONS=false so long-running ECS tasks do not run schema migrations during startup."
    }

    precondition {
      condition     = lower(local.api_runtime_environment_variables["IDENTRAIL_RUN_MIGRATIONS_ONLY"]) == "false"
      error_message = "API hosting requires IDENTRAIL_RUN_MIGRATIONS_ONLY=false so long-running ECS tasks start the API server."
    }

    precondition {
      condition     = !var.api_autoscaling_enabled || var.api_autoscaling_max_capacity >= var.api_autoscaling_min_capacity
      error_message = "api_autoscaling_max_capacity must be greater than or equal to api_autoscaling_min_capacity when autoscaling is enabled."
    }
  }
}

data "aws_iam_policy_document" "ecs_tasks_assume_role" {
  count = var.create_api_hosting_resources ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "api_task_execution_secrets" {
  count = var.create_api_hosting_resources && length(var.api_secrets) > 0 ? 1 : 0

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.api_secret_resource_arns
  }

  dynamic "statement" {
    for_each = length(var.api_secret_kms_key_arns) > 0 ? [1] : []

    content {
      actions   = ["kms:Decrypt"]
      resources = var.api_secret_kms_key_arns
    }
  }
}

data "aws_iam_policy_document" "api_task_exec_command" {
  count = var.create_api_hosting_resources && var.api_enable_execute_command ? 1 : 0

  statement {
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "api_task_aws_collector" {
  count = var.create_api_hosting_resources ? 1 : 0

  statement {
    actions = [
      "iam:ListRoles",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
    ]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.api_connector_role_arns) > 0 ? [1] : []

    content {
      actions   = ["sts:AssumeRole"]
      resources = var.api_connector_role_arns
    }
  }
}

resource "aws_ecs_cluster" "api" {
  count = var.create_api_hosting_resources ? 1 : 0

  name = local.api_service_name

  setting {
    name  = "containerInsights"
    value = var.api_container_insights_enabled ? "enabled" : "disabled"
  }
}

resource "aws_iam_role" "api_task_execution" {
  count = var.create_api_hosting_resources ? 1 : 0

  name               = "${local.api_iam_name_prefix}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role[0].json
}

resource "aws_iam_role_policy_attachment" "api_task_execution" {
  count = var.create_api_hosting_resources ? 1 : 0

  role       = aws_iam_role.api_task_execution[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "api_task_execution_secrets" {
  count = var.create_api_hosting_resources && length(var.api_secrets) > 0 ? 1 : 0

  name   = "${local.api_policy_name_base}-secrets"
  role   = aws_iam_role.api_task_execution[0].id
  policy = data.aws_iam_policy_document.api_task_execution_secrets[0].json
}

resource "aws_iam_role" "api_task" {
  count = var.create_api_hosting_resources ? 1 : 0

  name               = "${local.api_iam_name_prefix}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume_role[0].json
}

resource "aws_iam_role_policy" "api_task_exec_command" {
  count = var.create_api_hosting_resources && var.api_enable_execute_command ? 1 : 0

  name   = "${local.api_policy_name_base}-exec"
  role   = aws_iam_role.api_task[0].id
  policy = data.aws_iam_policy_document.api_task_exec_command[0].json
}

resource "aws_iam_role_policy" "api_task_aws_collector" {
  count = var.create_api_hosting_resources ? 1 : 0

  name   = "${local.api_policy_name_base}-aws-collector"
  role   = aws_iam_role.api_task[0].id
  policy = data.aws_iam_policy_document.api_task_aws_collector[0].json
}

resource "aws_security_group" "api_load_balancer" {
  count = var.create_api_hosting_resources ? 1 : 0

  name        = "${local.api_service_name}-alb"
  description = "Public HTTPS ingress for the Identrail API load balancer"
  vpc_id      = var.api_vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "api_load_balancer_https" {
  count = var.create_api_hosting_resources ? length(var.api_allowed_cidr_blocks) : 0

  security_group_id = aws_security_group.api_load_balancer[0].id
  cidr_ipv4         = var.api_allowed_cidr_blocks[count.index]
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "api_load_balancer_http" {
  count = var.create_api_hosting_resources && var.api_enable_http_redirect ? length(var.api_allowed_cidr_blocks) : 0

  security_group_id = aws_security_group.api_load_balancer[0].id
  cidr_ipv4         = var.api_allowed_cidr_blocks[count.index]
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "api_load_balancer_to_service" {
  count = var.create_api_hosting_resources ? 1 : 0

  security_group_id            = aws_security_group.api_load_balancer[0].id
  referenced_security_group_id = aws_security_group.api_service[0].id
  from_port                    = var.api_container_port
  ip_protocol                  = "tcp"
  to_port                      = var.api_container_port
}

resource "aws_security_group" "api_service" {
  count = var.create_api_hosting_resources ? 1 : 0

  name        = "${local.api_service_name}-service"
  description = "Private ECS service access for the Identrail API"
  vpc_id      = var.api_vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "api_service_from_load_balancer" {
  count = var.create_api_hosting_resources ? 1 : 0

  security_group_id            = aws_security_group.api_service[0].id
  referenced_security_group_id = aws_security_group.api_load_balancer[0].id
  from_port                    = var.api_container_port
  ip_protocol                  = "tcp"
  to_port                      = var.api_container_port
}

resource "aws_vpc_security_group_egress_rule" "api_service_egress" {
  count = var.create_api_hosting_resources ? 1 : 0

  security_group_id = aws_security_group.api_service[0].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_lb" "api" {
  count = var.create_api_hosting_resources ? 1 : 0

  name                       = local.api_name_prefix
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.api_load_balancer[0].id]
  subnets                    = var.api_public_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = var.api_load_balancer_deletion_protection
}

resource "aws_lb_target_group" "api" {
  count = var.create_api_hosting_resources ? 1 : 0

  name        = local.api_name_prefix
  port        = var.api_container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.api_vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = var.api_health_check_path
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "api_https" {
  count = var.create_api_hosting_resources ? 1 : 0

  load_balancer_arn = aws_lb.api[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.api_tls_policy
  certificate_arn   = var.api_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api[0].arn
  }
}

resource "aws_lb_listener" "api_http_redirect" {
  count = var.create_api_hosting_resources && var.api_enable_http_redirect ? 1 : 0

  load_balancer_arn = aws_lb.api[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_ecs_task_definition" "api" {
  count = var.create_api_hosting_resources ? 1 : 0

  family                   = local.api_service_name
  cpu                      = var.api_task_cpu
  execution_role_arn       = aws_iam_role.api_task_execution[0].arn
  memory                   = var.api_task_memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  task_role_arn            = aws_iam_role.api_task[0].arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = var.api_container_image
      essential = true
      portMappings = [
        {
          containerPort = var.api_container_port
          hostPort      = var.api_container_port
          protocol      = "tcp"
        }
      ]
      environment = local.api_environment
      secrets     = local.api_secrets
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.service["api"].name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "api"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "api" {
  count = var.create_api_hosting_resources ? 1 : 0

  name            = local.api_service_name
  cluster         = aws_ecs_cluster.api[0].id
  task_definition = aws_ecs_task_definition.api[0].arn
  desired_count   = var.api_desired_count
  launch_type     = "FARGATE"

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  enable_ecs_managed_tags            = true
  enable_execute_command             = var.api_enable_execute_command
  health_check_grace_period_seconds  = var.api_health_check_grace_period_seconds
  propagate_tags                     = "SERVICE"
  wait_for_steady_state              = false

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api[0].arn
    container_name   = "api"
    container_port   = var.api_container_port
  }

  network_configuration {
    assign_public_ip = var.api_task_assign_public_ip
    security_groups  = [aws_security_group.api_service[0].id]
    # Private tasks require operator-confirmed NAT/VPC endpoints. The optional
    # public-IP path keeps ingress restricted to the ALB security group while
    # avoiding NAT Gateway cost for the first cutover.
    subnets = local.api_task_subnet_ids
  }

  depends_on = [
    terraform_data.api_inputs,
    aws_iam_role_policy_attachment.api_task_execution,
    aws_iam_role_policy.api_task_execution_secrets,
    aws_iam_role_policy.api_task_aws_collector,
    aws_lb_listener.api_https,
  ]
}

resource "aws_appautoscaling_target" "api" {
  count = var.create_api_hosting_resources && var.api_autoscaling_enabled ? 1 : 0

  max_capacity       = var.api_autoscaling_max_capacity
  min_capacity       = var.api_autoscaling_min_capacity
  resource_id        = "service/${aws_ecs_cluster.api[0].name}/${aws_ecs_service.api[0].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  count = var.create_api_hosting_resources && var.api_autoscaling_enabled ? 1 : 0

  name               = "${local.api_service_name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api[0].resource_id
  scalable_dimension = aws_appautoscaling_target.api[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.api[0].service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = var.api_autoscaling_target_cpu_percent

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
