locals {
  aws_connector_registration_name = "${var.name_prefix}-${var.environment}-aws-registration"
}

resource "terraform_data" "aws_connector_registration_inputs" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  input = local.aws_connector_registration_name

  lifecycle {
    precondition {
      condition     = var.create_worker_hosting_resources
      error_message = "AWS connector registration requires create_worker_hosting_resources=true."
    }
  }
}

resource "aws_sns_topic" "aws_connector_registration" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  # CloudFormation publishes from customer accounts. SNS SSE-KMS would require
  # every customer publisher to have permissions on an Identrail KMS key.
  name = local.aws_connector_registration_name
}

data "aws_iam_policy_document" "aws_connector_registration_topic" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  # CloudFormation custom resources publish under whichever credentials the
  # stack was launched with: the deployer's IAM identity when no service
  # role is configured, or the CloudFormation execution role otherwise.
  # Neither path uses the `cloudformation.amazonaws.com` service principal
  # directly, and only the deployer path populates `aws:CalledVia`, so a
  # service-role deployment would be rejected by any tighter condition.
  # Ingress is therefore restricted only to secure transport; the
  # payload-level token check plus per-connector attempt binding is what
  # authenticates the registration, and the queue's visibility timeout and
  # small worker batch size keep unauthenticated noise from starving
  # legitimate handshakes.
  statement {
    sid       = "AllowCloudFormationCustomResourceDelivery"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.aws_connector_registration[0].arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SecureTransport"
      values   = ["true"]
    }
  }
}

resource "aws_sns_topic_policy" "aws_connector_registration" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  arn    = aws_sns_topic.aws_connector_registration[0].arn
  policy = data.aws_iam_policy_document.aws_connector_registration_topic[0].json
}

resource "aws_sqs_queue" "aws_connector_registration_dlq" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  name                      = "${local.aws_connector_registration_name}-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "aws_connector_registration" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  name                      = local.aws_connector_registration_name
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10
  # The worker processes each message with STS + read-only permission
  # checks, which can take tens of seconds under network jitter. Hold
  # messages long enough that a slow batch cannot race the redelivery
  # window; the worker also fetches fewer messages per receive so that
  # serial processing stays within this window.
  visibility_timeout_seconds = 600
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.aws_connector_registration_dlq[0].arn
    maxReceiveCount     = 5
  })
}

data "aws_iam_policy_document" "aws_connector_registration_queue" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  statement {
    sid       = "AllowRegistrationTopicDelivery"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.aws_connector_registration[0].arn]

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_sns_topic.aws_connector_registration[0].arn]
    }
  }
}

resource "aws_sqs_queue_policy" "aws_connector_registration" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  queue_url = aws_sqs_queue.aws_connector_registration[0].url
  policy    = data.aws_iam_policy_document.aws_connector_registration_queue[0].json
}

resource "aws_sns_topic_subscription" "aws_connector_registration" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  topic_arn = aws_sns_topic.aws_connector_registration[0].arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.aws_connector_registration[0].arn

  depends_on = [aws_sqs_queue_policy.aws_connector_registration]
}

data "aws_iam_policy_document" "worker_aws_connector_registration" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  statement {
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ReceiveMessage",
    ]
    resources = [aws_sqs_queue.aws_connector_registration[0].arn]
  }
}

resource "aws_iam_role_policy" "worker_aws_connector_registration" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  name   = "${local.worker_policy_name_base}-aws-registration"
  role   = aws_iam_role.worker_task[0].id
  policy = data.aws_iam_policy_document.worker_aws_connector_registration[0].json
}

resource "aws_cloudwatch_metric_alarm" "aws_connector_registration_dlq" {
  count = var.create_aws_connector_registration_provider ? 1 : 0

  alarm_name          = "${local.aws_connector_registration_name}-dlq-not-empty"
  alarm_description   = "AWS connector registrations exhausted automatic retries."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.aws_connector_registration_dlq[0].name
  }

  alarm_actions = var.aws_connector_registration_alarm_topic_arns
  ok_actions    = var.aws_connector_registration_alarm_topic_arns
}
