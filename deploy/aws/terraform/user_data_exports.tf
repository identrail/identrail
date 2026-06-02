resource "aws_s3_bucket" "user_data_exports" {
  count = local.user_data_export_bucket_enabled ? 1 : 0

  bucket = local.user_data_export_bucket_name

  tags = merge(var.tags, {
    Name      = local.user_data_export_bucket_name
    Component = "user-data-exports"
  })
}

resource "aws_s3_bucket_public_access_block" "user_data_exports" {
  count = local.user_data_export_bucket_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.user_data_exports[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "user_data_exports" {
  count = local.user_data_export_bucket_enabled ? 1 : 0

  bucket = aws_s3_bucket.user_data_exports[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "user_data_exports" {
  count = local.user_data_export_bucket_enabled ? 1 : 0

  bucket = aws_s3_bucket.user_data_exports[0].id

  rule {
    id     = "expire-user-data-exports"
    status = "Enabled"

    filter {
      prefix = local.user_data_export_s3_prefix
    }

    expiration {
      days = var.user_data_export_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "user_data_exports" {
  count = local.user_data_export_bucket_enabled ? 1 : 0

  statement {
    actions = [
      "s3:DeleteObject",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.user_data_exports[0].arn}/${local.user_data_export_s3_prefix}*"]
  }
}

resource "aws_iam_role_policy" "api_task_user_data_exports" {
  count = local.user_data_export_bucket_enabled ? 1 : 0

  name   = "${local.api_policy_name_base}-user-exports"
  role   = aws_iam_role.api_task[0].id
  policy = data.aws_iam_policy_document.user_data_exports[0].json
}

resource "aws_iam_role_policy" "worker_task_user_data_exports" {
  count = local.user_data_export_bucket_enabled && var.create_worker_hosting_resources ? 1 : 0

  name   = "${local.worker_policy_name_base}-user-exports"
  role   = aws_iam_role.worker_task[0].id
  policy = data.aws_iam_policy_document.user_data_exports[0].json
}
