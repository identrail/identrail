package api

import (
	"fmt"
	"time"

	"github.com/identrail/identrail/internal/runtime/s3access"
)

// awsS3RuntimeAccessFixtureInputs returns deterministic observed accesses
// and static grants for each fixture state. The default success state
// exercises all three correlation outcomes — confirmed,
// observed_without_grant, and granted_unused — plus a write that exceeds
// a read-only grant and a sensitive, publicly exposed bucket, so the
// surface and tests cover the taxonomy without a live AWS account. Object
// keys are never present: only bucket ARNs and bounded safe prefixes.
func awsS3RuntimeAccessFixtureInputs(accountID string, region string, fixtureState string, checkedAt time.Time) ([]s3access.ObservedAccess, []s3access.StaticGrant, []AWSS3RuntimeAccessDiagnostic, []AWSS3RuntimeAccessCoverageGap, []string, []string, string, bool) {
	base := checkedAt.Add(-30 * time.Minute)
	reportsRole := fmt.Sprintf("arn:aws:iam::%s:role/reporting-app", accountID)
	pipelineRole := fmt.Sprintf("arn:aws:iam::%s:role/ingest-pipeline", accountID)
	analyticsRole := fmt.Sprintf("arn:aws:iam::%s:role/analytics-export", accountID)
	partnerRole := "arn:aws:iam::999999999999:role/partner-reader"

	reportsBucket := fmt.Sprintf("arn:aws:s3:::%s-financial-reports", accountID)
	ingestBucket := fmt.Sprintf("arn:aws:s3:::%s-ingest-landing", accountID)
	ungovernedBucket := fmt.Sprintf("arn:aws:s3:::%s-adhoc-exports", accountID)
	analyticsBucket := fmt.Sprintf("arn:aws:s3:::%s-analytics-archive", accountID)
	piiBucket := fmt.Sprintf("arn:aws:s3:::%s-pii-customer", accountID)

	observed := []s3access.ObservedAccess{
		{
			EventID:        "evt-s3-read-confirmed",
			IdentityNodeID: awsIdentityNodeIDForAPI(reportsRole),
			PrincipalARN:   reportsRole,
			AccountID:      accountID,
			Region:         region,
			BucketARN:      reportsBucket,
			BucketName:     fmt.Sprintf("%s-financial-reports", accountID),
			AccessMode:     s3access.ModeRead,
			SafePrefixes:   []string{"daily"},
			Action:         "s3:GetObject",
			SessionID:      "ASIA-reports-sess",
			LineageStatus:  "resolved",
			ObservedAt:     base.Add(4 * time.Minute),
			EvidenceRef:    fmt.Sprintf("runtime-evidence://%s/%s/evt-s3-read-confirmed", accountID, region),
		},
		{
			// Write observed on a bucket the role can only read → confirmed
			// (bucket reachable) but flagged observed_mode_exceeds_grant.
			EventID:        "evt-s3-write-exceeds",
			IdentityNodeID: awsIdentityNodeIDForAPI(pipelineRole),
			PrincipalARN:   pipelineRole,
			AccountID:      accountID,
			Region:         region,
			BucketARN:      ingestBucket,
			BucketName:     fmt.Sprintf("%s-ingest-landing", accountID),
			AccessMode:     s3access.ModeWrite,
			SafePrefixes:   []string{"incoming"},
			Action:         "s3:PutObject",
			SessionID:      "ASIA-pipeline-sess",
			LineageStatus:  "resolved",
			ObservedAt:     base.Add(7 * time.Minute),
			EvidenceRef:    fmt.Sprintf("runtime-evidence://%s/%s/evt-s3-write-exceeds", accountID, region),
		},
		{
			// Observed access with no static grant (authorized via IAM
			// identity policy, which the static collector does not model).
			EventID:        "evt-s3-no-grant",
			IdentityNodeID: awsIdentityNodeIDForAPI(reportsRole),
			PrincipalARN:   reportsRole,
			AccountID:      accountID,
			Region:         region,
			BucketARN:      ungovernedBucket,
			BucketName:     fmt.Sprintf("%s-adhoc-exports", accountID),
			AccessMode:     s3access.ModeList,
			SafePrefixes:   []string{"<redacted>"},
			Action:         "s3:ListBucket",
			SessionID:      "ASIA-reports-sess",
			LineageStatus:  "source_identity_missing",
			ObservedAt:     base.Add(9 * time.Minute),
			EvidenceRef:    fmt.Sprintf("runtime-evidence://%s/%s/evt-s3-no-grant", accountID, region),
		},
	}

	static := []s3access.StaticGrant{
		{
			IdentityNodeID: awsIdentityNodeIDForAPI(reportsRole),
			PrincipalARN:   reportsRole,
			AccountID:      accountID,
			Region:         region,
			BucketARN:      reportsBucket,
			BucketName:     fmt.Sprintf("%s-financial-reports", accountID),
			AllowedModes:   []string{s3access.ModeRead, s3access.ModeList},
			Source:         s3access.SourceBucketPolicy,
			Effect:         "Allow",
			Sensitivity:    "elevated",
			Exposure:       "restricted",
			Confidence:     0.9,
			EvidenceRef:    reportsBucket,
		},
		{
			IdentityNodeID: awsIdentityNodeIDForAPI(pipelineRole),
			PrincipalARN:   pipelineRole,
			AccountID:      accountID,
			Region:         region,
			BucketARN:      ingestBucket,
			BucketName:     fmt.Sprintf("%s-ingest-landing", accountID),
			AllowedModes:   []string{s3access.ModeRead},
			Source:         s3access.SourceBucketPolicy,
			Effect:         "Allow",
			Sensitivity:    "standard",
			Exposure:       "private",
			Confidence:     0.88,
			EvidenceRef:    ingestBucket,
		},
		{
			IdentityNodeID: awsIdentityNodeIDForAPI(analyticsRole),
			PrincipalARN:   analyticsRole,
			AccountID:      accountID,
			Region:         region,
			BucketARN:      analyticsBucket,
			BucketName:     fmt.Sprintf("%s-analytics-archive", accountID),
			AllowedModes:   []string{s3access.ModeRead, s3access.ModeWrite, s3access.ModeList},
			Source:         s3access.SourceBucketPolicy,
			Effect:         "Allow",
			Sensitivity:    "standard",
			Exposure:       "private",
			Confidence:     0.86,
			EvidenceRef:    analyticsBucket,
		},
		{
			// Sensitive bucket exposed cross-account and never observed.
			IdentityNodeID: awsIdentityNodeIDForAPI(partnerRole),
			PrincipalARN:   partnerRole,
			AccountID:      accountID,
			Region:         region,
			BucketARN:      piiBucket,
			BucketName:     fmt.Sprintf("%s-pii-customer", accountID),
			AllowedModes:   []string{s3access.ModeRead},
			Source:         s3access.SourceBucketPolicy,
			Effect:         "Allow",
			CrossAccount:   true,
			Sensitivity:    "high",
			Exposure:       "cross_account",
			Confidence:     0.82,
			EvidenceRef:    piiBucket,
		},
	}

	switch fixtureState {
	case "empty":
		return nil, nil, nil, []AWSS3RuntimeAccessCoverageGap{{
			Capability:  "s3_runtime_access",
			Status:      "empty",
			Reason:      "No S3 runtime accesses or static reachability grants were available in the fixture window.",
			Remediation: "Confirm CloudTrail S3 data-event logging is enabled, then retry.",
		}}, nil, nil, awsPlatformDependencyStatusReady, true
	case "degraded":
		return observed, static, []AWSS3RuntimeAccessDiagnostic{{
			Collector:   s3access.CollectorName,
			SourceID:    "evt-s3-no-grant",
			Code:        "runtime_event_delivery_delayed",
			Message:     "One S3 access arrived after the expected collection window; correlation confidence is reduced.",
			Remediation: "Keep delayed evidence visible and avoid automated remediation until delivery catches up.",
			Retryable:   true,
		}}, nil, []string{"runtime correlation includes delayed or low-confidence evidence"}, []string{"Review delayed CloudTrail delivery before using correlations for remediation."}, awsPlatformDependencyStatusDegraded, true
	case "partial_failure":
		return observed, nil, []AWSS3RuntimeAccessDiagnostic{{
				Collector:   s3access.CollectorName,
				SourceID:    "static_reachability",
				Code:        "static_reachability_unavailable",
				Message:     "S3 bucket reachability could not be loaded; observed accesses cannot be confirmed.",
				Remediation: "Retry the S3 reachability collector and re-run the correlation without discarding observed evidence.",
				Retryable:   true,
			}}, []AWSS3RuntimeAccessCoverageGap{{
				Capability:  "static_reachability_join",
				Status:      "partial_failure",
				Reason:      "Static reachability edges were unavailable, so observed accesses could not be confirmed against grants.",
				Remediation: "Retry S3 reachability collection and re-run the correlation.",
			}}, []string{"static reachability join is incomplete; observed accesses are unconfirmed"}, []string{"Retry the S3 reachability collector and re-run the correlation."}, awsPlatformDependencyStatusDegraded, true
	case "permission_denied":
		return nil, nil, []AWSS3RuntimeAccessDiagnostic{{
				Collector:   s3access.CollectorName,
				SourceID:    "cloudtrail",
				Code:        "permission_denied",
				Message:     "Runtime event sources are not authorized for this connector; no S3 runtime access can be correlated.",
				Remediation: "Grant metadata-only CloudTrail access. Do not grant object-content reads.",
				Retryable:   true,
			}}, []AWSS3RuntimeAccessCoverageGap{{
				Capability:  "s3_runtime_access",
				Status:      "permission_denied",
				Reason:      "Runtime event source cannot be queried with the current connector permissions.",
				Remediation: "Add read-only CloudTrail access and retry.",
			}}, []string{"runtime event sources are not authorized for this connector"}, []string{"Grant metadata-only CloudTrail access; do not grant object-content reads."}, awsPlatformDependencyStatusBlocked, true
	default:
		return observed, static, nil, awsS3RuntimeAccessBaseCoverageGaps(), nil, nil, awsPlatformDependencyStatusReady, true
	}
}

// awsS3RuntimeAccessBaseCoverageGaps documents what this correlation
// intentionally does not model and the redaction boundary it enforces.
func awsS3RuntimeAccessBaseCoverageGaps() []AWSS3RuntimeAccessCoverageGap {
	return []AWSS3RuntimeAccessCoverageGap{
		{
			Capability:  "iam_identity_policy_reachability",
			Status:      "unsupported",
			Reason:      "Static reachability is sourced from S3 bucket policies only. Access authorized by IAM identity policies is not enumerated, so an observed access can show as observed_without_grant.",
			Remediation: "Treat observed_without_grant as 'needs IAM-policy confirmation', not automatically as drift.",
		},
		{
			Capability:  "object_key_visibility",
			Status:      "unsupported",
			Reason:      "Object keys and object contents are never collected. Access is correlated at bucket granularity; only a bounded, sanitized top-level prefix is surfaced, and identifying prefixes are redacted.",
			Remediation: "Use the bucket, access mode, and safe prefix for triage; inspect specific keys directly in AWS when investigating.",
		},
		{
			Capability:  "data_event_completeness",
			Status:      "degraded",
			Reason:      "S3 GetObject/PutObject/ListBucket are CloudTrail data events. Unless an S3 data-event trail or CloudTrail Lake is configured, observed coverage is incomplete and granted_unused may reflect missing telemetry.",
			Remediation: "Enable CloudTrail S3 data events to make granted_unused conclusions reliable.",
		},
	}
}
