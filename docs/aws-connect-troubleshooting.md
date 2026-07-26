# AWS Connect Troubleshooting

AWS Connect diagnostics describe setup coverage gaps, not runtime machine-identity findings. They are safe to show in the app because they use stable codes, scoped evidence references, and plain repair actions without serializing secrets.

## Diagnostic Codes

| Code | Meaning | Operator action | Tradeoff |
| --- | --- | --- | --- |
| `assume_role_failed` | Identrail could not assume the configured IAM role. | Update the role trust policy for the current Identrail account and External ID, then revalidate. | Restores read-only collection without adding write remediation permissions. |
| `external_id_mismatch` | AWS trust policy and Identrail setup are using different External ID values. | Copy the current trust-policy guidance, update AWS, then revalidate. | The connector remains unavailable until both sides match. |
| `role_arn_malformed` | The submitted role ARN is not a valid IAM role ARN. | Paste the full IAM role ARN from AWS, then revalidate. | No AWS calls are attempted until the ARN shape is valid. |
| `missing_read_only_permission_tier` | The role or capability gate is missing the expected read-only permissions. | Refresh the expected policy, update the role, then revalidate. | Narrower permissions limit blast radius, but Identrail will not claim coverage for unreadable services. |
| `connector_config_missing` | The Identrail deployment is missing CloudFormation setup configuration. | Configure the AWS template URL and checksum, then retry setup. | Operators can still use manual setup while one-click launch is unavailable. |
| `cloudformation_stack_not_deployed` | AWS has not reported an active stack or StackSet instance yet. | Open the launch URL, complete AWS deployment, then refresh status. | Coverage is withheld until AWS reports active instances. |
| `stackset_trusted_access_missing` | CloudFormation StackSets trusted access is not enabled in AWS Organizations. | Enable trusted access from the management account, then refresh status. | Required for service-managed StackSets. |
| `delegated_admin_recommended` | StackSet administration is using or expecting the management account path. | Register a delegated administrator when possible. | Management-account operation can work, but delegated administration narrows blast radius. |
| `selected_target_missing_stackset_instance` | A selected OU, account, or region does not have an active StackSet instance. | Review targets, launch or retry StackSet deployment, then refresh status. | Healthy targets remain visible, but coverage is partial. |
| `member_account_permission_denied` | AWS denied StackSet deployment in a member account. | Fix member-account StackSet permissions and retry the instance. | The account is excluded from claimed coverage until repaired. |
| `region_unsupported_or_not_opted_in` | The selected region is unsupported or not opted in for the member account. | Enable the region or remove it from the selected target set. | Removing it avoids failures, but coverage excludes workloads there. |
| `suspended_accounts_excluded` | One or more selected organization accounts are suspended and excluded from effective coverage. | Remove suspended accounts from the selected targets or reactivate them in AWS Organizations, then refresh status. | Excluding suspended accounts keeps active targets usable, but Identrail will not claim coverage for those accounts. |
| `partial_stackset_coverage` | Some StackSet instances failed while others remain usable. | Retry failed instances, then refresh status. | Identrail keeps successful targets visible but does not claim full coverage. |

## Repair Actions

- `refresh_status`: re-read connector and StackSet status without changing AWS.
- `validate_role`: retry the read-only role validation.
- `open_stackset` / `launch_stack`: open the AWS console launch URL returned by the backend.
- `refresh_policy`: fetch the expected read-only policy preview.
- `copy_trust_policy`: copy the current trust-policy guidance for manual role setup.
- `open_docs`: open this runbook or the AWS connector guide.

All actions require the operator to make the AWS-side change explicitly. This flow does not execute AWS write remediation.
