# AWS SQS and SNS Reachability Collector

Issue #1493 adds metadata-only reachability for Amazon SQS queues and Amazon
SNS topics under the AWS platform parent issue #1472.

## Endpoint

```http
GET /v1/workspaces/{workspace_id}/projects/{project_id}/aws/sqs-sns-reachability
```

Optional query parameters:

- `connector_id`: scope evidence to a configured AWS connector.
- `fixture_state`: deterministic validation state (`success`, `empty`,
  `degraded`, `partial_failure`, `permission_denied`).
- `resource_type`: filter to `sqs_queue`, `sns_topic`, `sqs`, or `sns`.
- `identity`: filter over policy principals, principal types, actions, and
  inferred capabilities.

## What It Collects

- SQS queue ARNs, names, URLs, tags, FIFO state, KMS/SQS-managed encryption
  metadata, visibility timeout, retention period, resource policy grants, and
  DLQ ARNs.
- SNS topic ARNs, names, tags, FIFO state, KMS encryption metadata, resource
  policy grants, subscription counts, subscription protocols, AWS ARN
  endpoints, redaction flags for non-ARN endpoints, filter-policy presence,
  raw-message-delivery metadata, and subscription DLQs.
- Exposure classifications: `public`, `cross_account`, `restricted`,
  `private_with_grants`, `private`, or `unknown`.
- Graph-safe `can_access` relationships only for concrete IAM role/user ARNs
  in Allow statements. Wildcards, services, federated principals, canonical
  users, and non-IAM ARNs remain resource metadata.

## What It Does Not Collect

- SQS message bodies or message attributes.
- SNS notification payloads.
- Raw email, SMS, mobile push, HTTPS, or other non-ARN subscription endpoint
  values.
- Identity-policy expansion for publish/consume/subscribe permissions.
- Any write, publish, receive, delete, purge, subscribe, or mutation action.

## Required AWS Permissions

- `sqs:ListQueues`
- `sqs:GetQueueAttributes`
- `sqs:ListQueueTags`
- `sns:ListTopics`
- `sns:GetTopicAttributes`
- `sns:ListSubscriptionsByTopic`
- `sns:GetSubscriptionAttributes`
- `sns:ListTagsForResource`

The connector policy must not include `sqs:SendMessage`,
`sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:PurgeQueue`, `sns:Publish`,
`sns:Subscribe`, or `sns:SetTopicAttributes`.

## Diagnostics

| Code | Meaning | Operator action |
| --- | --- | --- |
| `sqs_sns_reachability_page_failed` | A list page failed. | Retry the failed metadata page and keep retained records visible. |
| `sqs_queue_attributes_failed` | Queue attributes could not be read. | Confirm `sqs:GetQueueAttributes` and retry. |
| `sqs_queue_policy_parse_failed` | Queue policy was invalid JSON or unsupported shape. | Audit the queue policy; unparseable grants are skipped. |
| `sns_topic_attributes_failed` | Topic attributes could not be read. | Confirm `sns:GetTopicAttributes` and retry. |
| `sns_topic_policy_parse_failed` | Topic policy was invalid JSON or unsupported shape. | Audit the topic policy; unparseable grants are skipped. |
| `sns_topic_subscriptions_failed` | Topic subscription listing failed. | Confirm `sns:ListSubscriptionsByTopic` and retry. |
| `sns_subscription_attributes_failed` | Subscription metadata could not be read. | Confirm `sns:GetSubscriptionAttributes`; endpoint values remain redacted. |
| `permission_denied` | Required read-only metadata permissions are missing. | Update the connector policy and re-run validation. |

## Validation

Use fixture mode for deterministic local checks:

```bash
IDENTRAIL_AWS_SOURCE=fixture go test ./internal/api -run SQSSNSReachability
go test ./internal/providers/aws -run SQSSNSReachability
```
