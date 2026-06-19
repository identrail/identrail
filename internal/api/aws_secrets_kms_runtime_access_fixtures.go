package api

import (
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/runtime/secretsaccess"
)

// awsSecretsKMSRuntimeAccessFixtureInputs returns deterministic observed
// accesses and static grants for each fixture state. The default success
// state intentionally exercises all three correlation outcomes —
// confirmed, observed_without_grant, and granted_unused — plus a
// cross-account unused grant, so the operator-facing surface and the
// tests cover the full taxonomy without a live AWS account. All inputs
// are metadata-only.
func awsSecretsKMSRuntimeAccessFixtureInputs(accountID string, region string, fixtureState string, checkedAt time.Time) ([]secretsaccess.ObservedAccess, []secretsaccess.StaticGrant, []AWSSecretsKMSRuntimeAccessDiagnostic, []AWSSecretsKMSRuntimeAccessCoverageGap, []string, []string, string, bool) {
	base := checkedAt.Add(-30 * time.Minute)
	paymentsRole := fmt.Sprintf("arn:aws:iam::%s:role/payments-app", accountID)
	invoiceRole := fmt.Sprintf("arn:aws:iam::%s:role/invoice-agent", accountID)
	analyticsRole := fmt.Sprintf("arn:aws:iam::%s:role/analytics-export", accountID)
	partnerRole := "arn:aws:iam::999999999999:role/partner-reader"

	paymentsKey := fmt.Sprintf("arn:aws:kms:%s:%s:key/cmk-payments", region, accountID)
	analyticsKey := fmt.Sprintf("arn:aws:kms:%s:%s:key/cmk-analytics", region, accountID)
	stripeSecret := fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:prod/payments/stripe", region, accountID)
	openAISecret := fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:prod/ai/openai-key", region, accountID)
	partnerSecret := fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:prod/partner/webhook", region, accountID)

	observed := []secretsaccess.ObservedAccess{
		{
			EventID:        "evt-corr-kms-confirmed",
			IdentityNodeID: awsIdentityNodeIDForAPI(paymentsRole),
			PrincipalARN:   paymentsRole,
			AccountID:      accountID,
			Region:         region,
			ResourceKind:   secretsaccess.ResourceKindKMSKey,
			ResourceARN:    paymentsKey,
			ResourceName:   "cmk-payments",
			Action:         "kms:Decrypt",
			SessionID:      "ASIA-payments-sess",
			LineageStatus:  "resolved",
			ObservedAt:     base.Add(4 * time.Minute),
			EvidenceRef:    fmt.Sprintf("runtime-evidence://%s/%s/evt-corr-kms-confirmed", accountID, region),
		},
		{
			EventID:        "evt-corr-secret-confirmed",
			IdentityNodeID: awsIdentityNodeIDForAPI(paymentsRole),
			PrincipalARN:   paymentsRole,
			AccountID:      accountID,
			Region:         region,
			ResourceKind:   secretsaccess.ResourceKindSecret,
			ResourceARN:    stripeSecret,
			ResourceName:   "prod/payments/stripe",
			Action:         "secretsmanager:GetSecretValue",
			SessionID:      "ASIA-payments-sess",
			LineageStatus:  "resolved",
			ObservedAt:     base.Add(6 * time.Minute),
			EvidenceRef:    fmt.Sprintf("runtime-evidence://%s/%s/evt-corr-secret-confirmed", accountID, region),
		},
		{
			EventID:        "evt-corr-secret-no-grant",
			IdentityNodeID: awsIdentityNodeIDForAPI(invoiceRole),
			PrincipalARN:   invoiceRole,
			AccountID:      accountID,
			Region:         region,
			ResourceKind:   secretsaccess.ResourceKindSecret,
			ResourceARN:    openAISecret,
			ResourceName:   "prod/ai/openai-key",
			Action:         "secretsmanager:GetSecretValue",
			SessionID:      "ASIA-invoice-sess",
			LineageStatus:  "source_identity_missing",
			ObservedAt:     base.Add(9 * time.Minute),
			EvidenceRef:    fmt.Sprintf("runtime-evidence://%s/%s/evt-corr-secret-no-grant", accountID, region),
		},
	}

	static := []secretsaccess.StaticGrant{
		{
			IdentityNodeID: awsIdentityNodeIDForAPI(paymentsRole),
			PrincipalARN:   paymentsRole,
			AccountID:      accountID,
			Region:         region,
			ResourceKind:   secretsaccess.ResourceKindKMSKey,
			ResourceARN:    paymentsKey,
			ResourceName:   "cmk-payments",
			Source:         secretsaccess.SourceKeyPolicy,
			Effect:         "Allow",
			Confidence:     0.9,
			EvidenceRef:    paymentsKey,
		},
		{
			IdentityNodeID: awsIdentityNodeIDForAPI(paymentsRole),
			PrincipalARN:   paymentsRole,
			AccountID:      accountID,
			Region:         region,
			ResourceKind:   secretsaccess.ResourceKindSecret,
			ResourceARN:    stripeSecret,
			ResourceName:   "prod/payments/stripe",
			Source:         secretsaccess.SourceResourcePolicy,
			Effect:         "Allow",
			Confidence:     0.88,
			EvidenceRef:    stripeSecret,
		},
		{
			IdentityNodeID: awsIdentityNodeIDForAPI(analyticsRole),
			PrincipalARN:   analyticsRole,
			AccountID:      accountID,
			Region:         region,
			ResourceKind:   secretsaccess.ResourceKindKMSKey,
			ResourceARN:    analyticsKey,
			ResourceName:   "cmk-analytics",
			Source:         secretsaccess.SourceKMSGrant,
			Effect:         "Allow",
			Confidence:     0.86,
			EvidenceRef:    analyticsKey,
		},
		{
			IdentityNodeID: awsIdentityNodeIDForAPI(partnerRole),
			PrincipalARN:   partnerRole,
			AccountID:      accountID,
			Region:         region,
			ResourceKind:   secretsaccess.ResourceKindSecret,
			ResourceARN:    partnerSecret,
			ResourceName:   "prod/partner/webhook",
			Source:         secretsaccess.SourceResourcePolicy,
			Effect:         "Allow",
			CrossAccount:   true,
			Confidence:     0.82,
			EvidenceRef:    partnerSecret,
		},
	}

	switch fixtureState {
	case "empty":
		return nil, nil, nil, []AWSSecretsKMSRuntimeAccessCoverageGap{{
			Capability:  "secrets_kms_runtime_access",
			Status:      "empty",
			Reason:      "No Secrets Manager / KMS runtime accesses or static reachability grants were available in the fixture window.",
			Remediation: "Confirm CloudTrail data-event logging is enabled for Secrets Manager and KMS, then retry.",
		}}, nil, nil, awsPlatformDependencyStatusReady, true
	case "degraded":
		return observed, static, []AWSSecretsKMSRuntimeAccessDiagnostic{{
			Collector:   secretsaccess.CollectorName,
			SourceID:    "evt-corr-secret-no-grant",
			Code:        "runtime_event_delivery_delayed",
			Message:     "One Secrets Manager read arrived after the expected collection window; correlation confidence is reduced.",
			Remediation: "Keep delayed evidence visible and avoid automated remediation until delivery catches up.",
			Retryable:   true,
		}}, nil, []string{"runtime correlation includes delayed or low-confidence evidence"}, []string{"Review delayed CloudTrail delivery before using correlations for remediation."}, awsPlatformDependencyStatusDegraded, true
	case "partial_failure":
		// The static reachability side failed to load; the observed
		// runtime accesses remain visible but cannot be confirmed
		// against a static grant.
		return observed, nil, []AWSSecretsKMSRuntimeAccessDiagnostic{{
				Collector:   secretsaccess.CollectorName,
				SourceID:    "static_reachability",
				Code:        "static_reachability_unavailable",
				Message:     "KMS and Secrets Manager static reachability could not be loaded; observed accesses cannot be confirmed.",
				Remediation: "Retry the static reachability collectors and re-run the correlation without discarding observed evidence.",
				Retryable:   true,
			}}, []AWSSecretsKMSRuntimeAccessCoverageGap{{
				Capability:  "static_reachability_join",
				Status:      "partial_failure",
				Reason:      "Static reachability edges were unavailable, so observed accesses could not be confirmed against grants.",
				Remediation: "Retry KMS/Secrets Manager reachability collection and re-run the correlation.",
			}}, []string{"static reachability join is incomplete; observed accesses are unconfirmed"}, []string{"Retry the static reachability collectors and re-run the correlation."}, awsPlatformDependencyStatusDegraded, true
	case "permission_denied":
		return nil, nil, []AWSSecretsKMSRuntimeAccessDiagnostic{{
				Collector:   secretsaccess.CollectorName,
				SourceID:    "cloudtrail",
				Code:        "permission_denied",
				Message:     "Runtime event sources are not authorized for this connector; no Secrets Manager / KMS runtime access can be correlated.",
				Remediation: "Grant metadata-only CloudTrail access. Do not grant secret-value or decrypt reads.",
				Retryable:   true,
			}}, []AWSSecretsKMSRuntimeAccessCoverageGap{{
				Capability:  "secrets_kms_runtime_access",
				Status:      "permission_denied",
				Reason:      "Runtime event source cannot be queried with the current connector permissions.",
				Remediation: "Add read-only CloudTrail access and retry.",
			}}, []string{"runtime event sources are not authorized for this connector"}, []string{"Grant metadata-only CloudTrail access; do not grant secret-value or decrypt reads."}, awsPlatformDependencyStatusBlocked, true
	default:
		return observed, static, nil, awsSecretsKMSRuntimeAccessBaseCoverageGaps(), nil, nil, awsPlatformDependencyStatusReady, true
	}
}

// awsSecretsKMSRuntimeAccessBaseCoverageGaps documents what this
// correlation intentionally does not model, so operators do not read an
// observed_without_grant or granted_unused result as more (or less)
// than it is.
func awsSecretsKMSRuntimeAccessBaseCoverageGaps() []AWSSecretsKMSRuntimeAccessCoverageGap {
	return []AWSSecretsKMSRuntimeAccessCoverageGap{
		{
			Capability:  "iam_identity_policy_reachability",
			Status:      "unsupported",
			Reason:      "Static reachability is sourced from KMS key policies / grants and Secrets Manager resource policies only. Access authorized by IAM identity policies is not enumerated, so an observed read can show as observed_without_grant.",
			Remediation: "Treat observed_without_grant as 'needs IAM-policy confirmation', not automatically as drift.",
		},
		{
			Capability:  "data_event_completeness",
			Status:      "degraded",
			Reason:      "Secrets Manager GetSecretValue and KMS Decrypt are CloudTrail data events. Unless a data-event trail or CloudTrail Lake is configured, observed coverage is incomplete and granted_unused may reflect missing telemetry.",
			Remediation: "Enable CloudTrail data events for Secrets Manager and KMS to make granted_unused conclusions reliable.",
		},
	}
}
