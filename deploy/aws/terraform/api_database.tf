locals {
  api_database_subnet_ids = length(var.api_database_subnet_ids) > 0 ? var.api_database_subnet_ids : (
    length(var.api_private_subnet_ids) > 0 ? var.api_private_subnet_ids : local.api_task_subnet_ids
  )
  api_database_identifier = "${local.api_name_prefix}-db"
  api_database_secret_name = (
    "${var.name_prefix}/${var.environment}/api/database-url"
  )
  api_database_final_snapshot_identifier = (
    length(trimspace(var.api_database_final_snapshot_identifier)) > 0 ?
    trimspace(var.api_database_final_snapshot_identifier) :
    "${local.api_database_identifier}-final"
  )
  api_database_max_allocated_storage = var.api_database_max_allocated_storage == 0 ? null : var.api_database_max_allocated_storage
}

data "aws_subnet" "api_database" {
  count = var.create_api_database ? length(local.api_database_subnet_ids) : 0

  id = local.api_database_subnet_ids[count.index]
}

resource "terraform_data" "api_database_inputs" {
  count = var.create_api_database ? 1 : 0

  input = local.api_database_identifier

  lifecycle {
    precondition {
      condition     = var.create_api_hosting_resources
      error_message = "create_api_database=true requires create_api_hosting_resources=true so the database can be wired to the API service security group and runtime secret."
    }

    precondition {
      condition = length(distinct(local.api_database_subnet_ids)) >= 2 && alltrue([
        for subnet_id in local.api_database_subnet_ids : can(regex("^subnet-[0-9a-f]+$", subnet_id))
      ])
      error_message = "create_api_database=true requires at least two distinct valid database subnet IDs. Set api_database_subnet_ids, api_private_subnet_ids, or api_task_subnet_ids."
    }

    precondition {
      condition = alltrue([
        for subnet in data.aws_subnet.api_database : subnet.vpc_id == var.api_vpc_id
      ])
      error_message = "api_database_subnet_ids must all belong to api_vpc_id when create_api_database=true."
    }

    precondition {
      condition     = length(distinct(data.aws_subnet.api_database[*].availability_zone_id)) >= 2
      error_message = "api_database_subnet_ids must span at least two distinct Availability Zones when create_api_database=true."
    }

    precondition {
      condition     = var.api_database_max_allocated_storage == 0 || var.api_database_max_allocated_storage >= var.api_database_allocated_storage
      error_message = "api_database_max_allocated_storage must be 0 or greater than or equal to api_database_allocated_storage."
    }

    precondition {
      condition     = !contains(keys(var.api_secrets), "IDENTRAIL_DATABASE_URL")
      error_message = "Do not set api_secrets.IDENTRAIL_DATABASE_URL when create_api_database=true; Terraform creates and wires the managed database URL secret."
    }
  }
}

resource "random_password" "api_database" {
  count = local.api_database_enabled ? 1 : 0

  length  = 32
  special = false
}

resource "aws_security_group" "api_database" {
  count = local.api_database_enabled ? 1 : 0

  name        = "${local.api_name_prefix}-db"
  description = "Private PostgreSQL access for the Identrail API database"
  vpc_id      = var.api_vpc_id

  tags = {
    Name = "${local.api_service_name}-database"
  }
}

resource "aws_vpc_security_group_ingress_rule" "api_database_from_api_service" {
  count = local.api_database_enabled ? 1 : 0

  security_group_id            = aws_security_group.api_database[0].id
  referenced_security_group_id = aws_security_group.api_service[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Allow PostgreSQL from Identrail API tasks"
}

resource "aws_vpc_security_group_ingress_rule" "api_database_from_worker_service" {
  count = local.api_database_enabled && var.create_worker_hosting_resources ? 1 : 0

  security_group_id            = aws_security_group.api_database[0].id
  referenced_security_group_id = aws_security_group.worker_service[0].id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "Allow PostgreSQL from Identrail worker tasks"
}

resource "aws_db_subnet_group" "api_database" {
  count = local.api_database_enabled ? 1 : 0

  name       = local.api_database_identifier
  subnet_ids = local.api_database_subnet_ids

  tags = {
    Name = "${local.api_service_name}-database"
  }
}

resource "aws_db_instance" "api_database" {
  count = local.api_database_enabled ? 1 : 0

  identifier                      = local.api_database_identifier
  allocated_storage               = var.api_database_allocated_storage
  max_allocated_storage           = local.api_database_max_allocated_storage
  storage_type                    = "gp3"
  storage_encrypted               = true
  engine                          = "postgres"
  engine_version                  = var.api_database_engine_version
  auto_minor_version_upgrade      = true
  instance_class                  = var.api_database_instance_class
  db_name                         = var.api_database_name
  username                        = var.api_database_username
  password                        = random_password.api_database[0].result
  port                            = 5432
  db_subnet_group_name            = aws_db_subnet_group.api_database[0].name
  vpc_security_group_ids          = [aws_security_group.api_database[0].id]
  publicly_accessible             = false
  multi_az                        = false
  backup_retention_period         = var.api_database_backup_retention_days
  copy_tags_to_snapshot           = true
  deletion_protection             = var.api_database_deletion_protection
  skip_final_snapshot             = var.api_database_skip_final_snapshot
  final_snapshot_identifier       = var.api_database_skip_final_snapshot ? null : local.api_database_final_snapshot_identifier
  apply_immediately               = var.api_database_apply_immediately
  performance_insights_enabled    = false
  enabled_cloudwatch_logs_exports = []

  tags = {
    Name = "${local.api_service_name}-database"
  }

  depends_on = [
    terraform_data.api_database_inputs,
  ]
}

resource "aws_secretsmanager_secret" "api_database_url" {
  count = local.api_database_enabled ? 1 : 0

  name                    = local.api_database_secret_name
  description             = "Identrail ${var.environment} managed RDS PostgreSQL URL"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "api_database_url" {
  count = local.api_database_enabled ? 1 : 0

  secret_id = aws_secretsmanager_secret.api_database_url[0].id
  secret_string = format(
    "postgresql://%s:%s@%s:%s/%s?sslmode=require",
    var.api_database_username,
    random_password.api_database[0].result,
    aws_db_instance.api_database[0].address,
    aws_db_instance.api_database[0].port,
    var.api_database_name,
  )
}
