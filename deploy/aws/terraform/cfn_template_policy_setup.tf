data "aws_iam_policy_document" "cfn_template_policy_setup_assume_role" {
  count = var.create_cfn_template_policy_setup_role ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [trimspace(var.cfn_template_policy_setup_oidc_provider_arn)]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = [local.cfn_template_policy_setup_oidc_audience]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:identrail/identrail:ref:refs/heads/dev"]
    }
  }
}

data "aws_iam_policy_document" "cfn_template_policy_setup" {
  count = var.create_cfn_template_policy_setup_role ? 1 : 0

  statement {
    sid = "ManageExactTemplateBucketPolicy"

    actions = [
      "s3:GetBucketPolicy",
      "s3:PutBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
    ]
    resources = [local.cfn_template_policy_setup_bucket_arn]
  }

  statement {
    sid       = "ListOnlyTemplateDigestPrefix"
    actions   = ["s3:ListBucket"]
    resources = [local.cfn_template_policy_setup_bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["connectors/aws/sha256/*"]
    }
  }

  statement {
    sid = "ReadAccountPublicAccessBlock"

    actions = [
      "s3:GetAccountPublicAccessBlock",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }
}

locals {
  cfn_template_policy_setup_oidc_audience = data.aws_partition.current.partition == "aws-cn" ? "sts.amazonaws.com.cn" : "sts.amazonaws.com"
  cfn_template_policy_setup_bucket_arn    = "arn:${data.aws_partition.current.partition}:s3:::${trimspace(var.cfn_template_policy_setup_bucket_name)}"
}

resource "aws_iam_role" "cfn_template_policy_setup" {
  count = var.create_cfn_template_policy_setup_role ? 1 : 0

  name               = var.cfn_template_policy_setup_role_name
  assume_role_policy = data.aws_iam_policy_document.cfn_template_policy_setup_assume_role[0].json

  tags = merge(local.common_tags, {
    Component = "cfn-template-policy-setup"
  })

  lifecycle {
    precondition {
      condition = can(regex(
        "^arn:${data.aws_partition.current.partition}:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$",
        trimspace(var.cfn_template_policy_setup_oidc_provider_arn)
      ))
      error_message = "cfn_template_policy_setup_oidc_provider_arn must be the account GitHub Actions OIDC provider ARN in the active AWS partition when the setup role is enabled."
    }
  }
}

resource "aws_iam_role_policy" "cfn_template_policy_setup" {
  count = var.create_cfn_template_policy_setup_role ? 1 : 0

  name   = "${var.cfn_template_policy_setup_role_name}-permissions"
  role   = aws_iam_role.cfn_template_policy_setup[0].id
  policy = data.aws_iam_policy_document.cfn_template_policy_setup[0].json
}
