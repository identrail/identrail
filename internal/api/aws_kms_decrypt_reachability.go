package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
)

const (
	awsKMSDecryptReachabilityCurrentIssue = 1489
	awsKMSDecryptReachabilityVersion      = "aws-kms-decrypt-reachability-inventory-v1"
)

// AWSKMSDecryptReachabilityInventoryRequest is the operator-facing request.
type AWSKMSDecryptReachabilityInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSKMSCoverageGap names a KMS capability this wave intentionally does not
// model, with the reason and remediation an operator should rely on.
type AWSKMSCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSKMSDecryptReachabilityInventoryResult is the deterministic envelope this
// endpoint returns.
type AWSKMSDecryptReachabilityInventoryResult struct {
	TenantID                   string                                `json:"tenant_id"`
	WorkspaceID                string                                `json:"workspace_id"`
	ProjectID                  string                                `json:"project_id"`
	ConnectorID                string                                `json:"connector_id,omitempty"`
	AccountID                  string                                `json:"account_id,omitempty"`
	Region                     string                                `json:"region,omitempty"`
	ParentIssueNumber          int                                   `json:"parent_issue_number"`
	ParentIssueRef             string                                `json:"parent_issue_ref"`
	CurrentIssueNumber         int                                   `json:"current_issue_number"`
	CurrentIssueRef            string                                `json:"current_issue_ref"`
	Version                    string                                `json:"version"`
	Status                     string                                `json:"status"`
	FixtureState               string                                `json:"fixture_state"`
	Confidence                 float64                               `json:"confidence"`
	KeyCount                   int                                   `json:"key_count"`
	CustomerManagedKeyCount    int                                   `json:"customer_managed_key_count"`
	AWSManagedKeyCount         int                                   `json:"aws_managed_key_count"`
	PublicKeyCount             int                                   `json:"public_key_count"`
	CrossAccountKeyCount       int                                   `json:"cross_account_key_count"`
	RestrictedKeyCount         int                                   `json:"restricted_key_count"`
	KeysWithRotationCount      int                                   `json:"keys_with_rotation_count"`
	KeysMissingRotationCount   int                                   `json:"keys_missing_rotation_count"`
	KeysPendingDeletionCount   int                                   `json:"keys_pending_deletion_count"`
	MultiRegionKeyCount        int                                   `json:"multi_region_key_count"`
	IdentityGrantCount         int                                   `json:"identity_grant_count"`
	PublicGrantCount           int                                   `json:"public_grant_count"`
	CrossAccountGrantCount     int                                   `json:"cross_account_grant_count"`
	DenyGrantCount             int                                   `json:"deny_grant_count"`
	LiveGrantCount             int                                   `json:"live_grant_count"`
	CrossAccountLiveGrantCount int                                   `json:"cross_account_live_grant_count"`
	RelationshipCount          int                                   `json:"relationship_count"`
	FailureReasons             []string                              `json:"failure_reasons"`
	RemediationHints           []string                              `json:"remediation_hints"`
	EvidenceLinks              []string                              `json:"evidence_links"`
	CoverageGaps               []AWSKMSCoverageGap                   `json:"coverage_gaps"`
	Records                    []AWSKMSDecryptReachabilityRecord     `json:"records"`
	Relationships              []AWSKMSDecryptReachabilityEdge       `json:"relationships"`
	Diagnostics                []AWSKMSDecryptReachabilityDiagnostic `json:"diagnostics"`
	GeneratedAt                time.Time                             `json:"generated_at"`
	UpdatedAt                  time.Time                             `json:"updated_at"`
}

// AWSKMSDecryptReachabilityRecord is one KMS key's metadata, exposure
// classification, and the identity grants inferred from its key policy +
// live grants.
type AWSKMSDecryptReachabilityRecord struct {
	AccountID               string                `json:"account_id"`
	Region                  string                `json:"region"`
	Service                 string                `json:"service"`
	KeyARN                  string                `json:"key_arn"`
	KeyID                   string                `json:"key_id"`
	KeyManager              string                `json:"key_manager,omitempty"`
	KeyState                string                `json:"key_state,omitempty"`
	KeyUsage                string                `json:"key_usage,omitempty"`
	KeySpec                 string                `json:"key_spec,omitempty"`
	Origin                  string                `json:"origin,omitempty"`
	Description             string                `json:"description,omitempty"`
	Enabled                 bool                  `json:"enabled"`
	CreatedAt               string                `json:"created_at,omitempty"`
	DeletionDate            string                `json:"deletion_date,omitempty"`
	MultiRegion             bool                  `json:"multi_region,omitempty"`
	MultiRegionPrimary      bool                  `json:"multi_region_primary,omitempty"`
	PrimaryKeyARN           string                `json:"primary_key_arn,omitempty"`
	ReplicaKeyARNs          []string              `json:"replica_key_arns,omitempty"`
	RotationEnabled         bool                  `json:"rotation_enabled"`
	RotationSupported       bool                  `json:"rotation_supported"`
	Aliases                 []string              `json:"aliases,omitempty"`
	HasKeyPolicy            bool                  `json:"has_key_policy"`
	KeyPolicyStatementCount int                   `json:"key_policy_statement_count"`
	IAMDelegationEnabled    bool                  `json:"iam_delegation_enabled"`
	IdentityGrants          []AWSKMSIdentityGrant `json:"identity_grants,omitempty"`
	Grants                  []AWSKMSGrant         `json:"grants,omitempty"`
	ExposureClassification  string                `json:"exposure_classification"`
	ExposureReasons         []string              `json:"exposure_reasons,omitempty"`
	Tags                    map[string]string     `json:"tags,omitempty"`
	Source                  string                `json:"source"`
	EvidenceRef             string                `json:"evidence_ref"`
	FromNodeID              string                `json:"from_node_id"`
	RelationshipType        string                `json:"relationship_type"`
	Confidence              float64               `json:"confidence"`
	CollectedAt             time.Time             `json:"collected_at"`
	Status                  string                `json:"status"`
}

// AWSKMSIdentityGrant mirrors the collector-side key-policy grant struct.
type AWSKMSIdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"`
	Effect            string   `json:"effect"`
	Actions           []string `json:"actions,omitempty"`
	NotAction         bool     `json:"not_action,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

// AWSKMSGrant mirrors a live KMS grant.
type AWSKMSGrant struct {
	GrantID                     string   `json:"grant_id,omitempty"`
	Name                        string   `json:"name,omitempty"`
	GranteePrincipal            string   `json:"grantee_principal,omitempty"`
	GranteePrincipalType        string   `json:"grantee_principal_type,omitempty"`
	RetiringPrincipal           string   `json:"retiring_principal,omitempty"`
	IssuingAccount              string   `json:"issuing_account,omitempty"`
	Operations                  []string `json:"operations,omitempty"`
	Capabilities                []string `json:"capabilities,omitempty"`
	EncryptionContextKeys       []string `json:"encryption_context_keys,omitempty"`
	EncryptionContextSubsetKeys []string `json:"encryption_context_subset_keys,omitempty"`
	HasConstraints              bool     `json:"has_constraints,omitempty"`
	IsCrossAccount              bool     `json:"is_cross_account,omitempty"`
	CreatedAt                   string   `json:"created_at,omitempty"`
}

// AWSKMSDecryptReachabilityEdge is one graph edge from a principal to a key.
// Edges are only emitted for resolved, allow-effect, non-wildcard grants
// pointing at IAM role/user ARNs.
type AWSKMSDecryptReachabilityEdge struct {
	Type          string   `json:"type"`
	FromNodeID    string   `json:"from_node_id"`
	ToNodeID      string   `json:"to_node_id"`
	EvidenceRef   string   `json:"evidence_ref"`
	Effect        string   `json:"effect"`
	Source        string   `json:"source"` // "key_policy" or "kms_grant"
	PrincipalType string   `json:"principal_type"`
	Capabilities  []string `json:"capabilities,omitempty"`
	HasCondition  bool     `json:"has_condition,omitempty"`
}

// AWSKMSDecryptReachabilityDiagnostic is a structured collector diagnostic.
type AWSKMSDecryptReachabilityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSKMSDecryptReachabilityInventory returns the KMS decrypt reachability
// inventory for the supplied scope.
func (s *Service) GetAWSKMSDecryptReachabilityInventory(ctx context.Context, workspaceID string, projectID string, request AWSKMSDecryptReachabilityInventoryRequest) (AWSKMSDecryptReachabilityInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSKMSDecryptReachabilityInventoryResult{}, err
	}
	var (
		connection    AWSConnectionStatus
		hasConnection bool
	)
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSKMSDecryptReachabilityInventoryResult{}, err
	}
	return buildAWSKMSDecryptReachabilityInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSKMSDecryptReachabilityInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSKMSDecryptReachabilityInventoryRequest, checkedAt time.Time) (AWSKMSDecryptReachabilityInventoryResult, error) {
	fixtureState := normalizeAWSKMSDecryptReachabilityFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSKMSDecryptReachabilityInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsKMSDecryptReachabilityFixtureRecords(accountID, region, fixtureState, checkedAt)
	for _, record := range records {
		if err := validateKMSDecryptReachabilityRecord(scope, project, connectorID, record); err != nil {
			return AWSKMSDecryptReachabilityInventoryResult{}, fmt.Errorf("validate kms decrypt reachability record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSKMSDecryptReachabilityInventory(fixtureState, diagnostics, records)
	relationships := awsKMSDecryptReachabilityEdges(records)
	return AWSKMSDecryptReachabilityInventoryResult{
		TenantID:                   scope.TenantID,
		WorkspaceID:                project.WorkspaceID,
		ProjectID:                  project.ProjectID,
		ConnectorID:                connectorID,
		AccountID:                  accountID,
		Region:                     region,
		ParentIssueNumber:          awsPlatformDependencyParentIssue,
		ParentIssueRef:             awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:         awsKMSDecryptReachabilityCurrentIssue,
		CurrentIssueRef:            awsIssueRef(awsKMSDecryptReachabilityCurrentIssue),
		Version:                    awsKMSDecryptReachabilityVersion,
		Status:                     status,
		FixtureState:               fixtureState,
		Confidence:                 confidence,
		KeyCount:                   len(records),
		CustomerManagedKeyCount:    countKeysByManager(records, "CUSTOMER"),
		AWSManagedKeyCount:         countKeysByManager(records, "AWS"),
		PublicKeyCount:             countKeysByExposure(records, "public"),
		CrossAccountKeyCount:       countKeysByExposure(records, "cross_account"),
		RestrictedKeyCount:         countKeysByExposure(records, "restricted"),
		KeysWithRotationCount:      countKeysWith(records, func(r AWSKMSDecryptReachabilityRecord) bool { return r.RotationEnabled }),
		KeysMissingRotationCount:   countKeysWith(records, func(r AWSKMSDecryptReachabilityRecord) bool { return r.RotationSupported && !r.RotationEnabled }),
		KeysPendingDeletionCount:   countKeysWith(records, func(r AWSKMSDecryptReachabilityRecord) bool { return strings.EqualFold(r.KeyState, "PendingDeletion") }),
		MultiRegionKeyCount:        countKeysWith(records, func(r AWSKMSDecryptReachabilityRecord) bool { return r.MultiRegion }),
		IdentityGrantCount:         countKMSPolicyGrants(records, func(g AWSKMSIdentityGrant) bool { return true }),
		PublicGrantCount:           countKMSPolicyGrants(records, func(g AWSKMSIdentityGrant) bool { return g.IsPublic }),
		CrossAccountGrantCount:     countKMSPolicyGrants(records, func(g AWSKMSIdentityGrant) bool { return g.IsCrossAccount }),
		DenyGrantCount:             countKMSPolicyGrants(records, func(g AWSKMSIdentityGrant) bool { return strings.EqualFold(g.Effect, "Deny") }),
		LiveGrantCount:             countKMSLiveGrants(records, func(g AWSKMSGrant) bool { return true }),
		CrossAccountLiveGrantCount: countKMSLiveGrants(records, func(g AWSKMSGrant) bool { return g.IsCrossAccount }),
		RelationshipCount:          len(relationships),
		FailureReasons:             failures,
		RemediationHints:           remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsKMSDecryptReachabilityCurrentIssue),
			"/docs/aws-kms-decrypt-reachability",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsKMSDecryptReachabilityDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSKMSDecryptReachabilityFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsKMSDecryptReachabilityFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSKMSDecryptReachabilityRecord, []providers.SourceError, []AWSKMSCoverageGap) {
	gaps := []AWSKMSCoverageGap{{
		Capability:  "encryption_context_values",
		Status:      "unsupported",
		Reason:      "Live KMS grant encryption-context *values* can carry tenant/customer-specific identifiers and are not surfaced; only the constraint *keys* are recorded.",
		Remediation: "Audit encryption-context values directly in the AWS Console when investigating a specific grant.",
	}, {
		Capability:  "grant_constraint_subset_match",
		Status:      "unsupported",
		Reason:      "Subset-match grant constraints describe an unordered set; the wave records the keys but does not yet evaluate whether a caller satisfies the subset.",
		Remediation: "Treat subset-constrained grants as scope-limited and audit the caller's encryption context before relying on reachability.",
	}, {
		Capability:  "via_service_condition_resolution",
		Status:      "unsupported",
		Reason:      "kms:ViaService and kms:CallerAccount conditions are recorded as condition keys but their service / account values are not resolved into specific identity nodes.",
		Remediation: "Treat ViaService-conditioned grants as service-scoped until the dedicated condition resolver lands.",
	}}
	partition := awsKMSPartitionForRegion(region)
	cmkARN := fmt.Sprintf("arn:%s:kms:%s:%s:key/aaaa1111-2222-3333-4444-555566667777", partition, region, accountID)
	publicKeyARN := fmt.Sprintf("arn:%s:kms:%s:%s:key/bbbb1111-2222-3333-4444-555566667777", partition, region, accountID)
	crossAccountARN := fmt.Sprintf("arn:%s:kms:%s:%s:key/cccc1111-2222-3333-4444-555566667777", partition, region, accountID)
	awsManagedARN := fmt.Sprintf("arn:%s:kms:%s:%s:key/dddd1111-2222-3333-4444-555566667777", partition, region, accountID)
	restrictedARN := fmt.Sprintf("arn:%s:kms:%s:%s:key/eeee1111-2222-3333-4444-555566667777", partition, region, accountID)

	records := []AWSKMSDecryptReachabilityRecord{
		// Private customer-managed key with IAM delegation + an app-role grant.
		awsKMSDecryptReachabilityFixtureRecord(accountID, region, "aaaa1111-2222-3333-4444-555566667777", cmkARN, "private_with_grants", "CUSTOMER", checkedAt, partition, func(r *AWSKMSDecryptReachabilityRecord) {
			r.HasKeyPolicy = true
			r.KeyPolicyStatementCount = 2
			r.IAMDelegationEnabled = true
			r.RotationSupported = true
			r.RotationEnabled = true
			r.Aliases = []string{"alias/payments"}
			r.IdentityGrants = []AWSKMSIdentityGrant{
				{
					PrincipalARN:  fmt.Sprintf("arn:%s:iam::%s:root", partition, accountID),
					PrincipalType: "aws",
					Effect:        "Allow",
					Actions:       []string{"kms:*"},
					Capabilities:  []string{"admin", "decrypt", "encrypt", "grant", "sign"},
					StatementSid:  "EnableIAMUserPermissions",
				},
				{
					PrincipalARN:  fmt.Sprintf("arn:%s:iam::%s:role/payments-app", partition, accountID),
					PrincipalType: "aws",
					Effect:        "Allow",
					Actions:       []string{"kms:Decrypt", "kms:GenerateDataKey"},
					Capabilities:  []string{"decrypt", "encrypt"},
					StatementSid:  "AppAccess",
				},
			}
			r.Grants = []AWSKMSGrant{{
				GrantID:               "grant-0001",
				Name:                  "lambda-decrypt",
				GranteePrincipal:      fmt.Sprintf("arn:%s:iam::%s:role/lambda-decrypt", partition, accountID),
				GranteePrincipalType:  "aws",
				Operations:            []string{"Decrypt"},
				Capabilities:          []string{"decrypt"},
				HasConstraints:        true,
				EncryptionContextKeys: []string{"tenant_id"},
			}}
			r.ExposureReasons = []string{"kms_key_policy_allow_to_specific_principal"}
		}),
		// Public customer-managed key (wildcard principal, no condition).
		awsKMSDecryptReachabilityFixtureRecord(accountID, region, "bbbb1111-2222-3333-4444-555566667777", publicKeyARN, "public", "CUSTOMER", checkedAt, partition, func(r *AWSKMSDecryptReachabilityRecord) {
			r.HasKeyPolicy = true
			r.KeyPolicyStatementCount = 1
			r.RotationSupported = true
			r.Aliases = []string{"alias/public-data"}
			r.IdentityGrants = []AWSKMSIdentityGrant{{
				PrincipalARN:      "*",
				PrincipalType:     "*",
				Effect:            "Allow",
				Actions:           []string{"kms:Decrypt"},
				Capabilities:      []string{"decrypt"},
				IsPublic:          true,
				WildcardPrincipal: true,
				StatementSid:      "PublicDecrypt",
			}}
			r.ExposureReasons = []string{"kms_key_policy_allow_to_wildcard_principal"}
		}),
		// Cross-account customer-managed key (partner has Decrypt).
		awsKMSDecryptReachabilityFixtureRecord(accountID, region, "cccc1111-2222-3333-4444-555566667777", crossAccountARN, "cross_account", "CUSTOMER", checkedAt, partition, func(r *AWSKMSDecryptReachabilityRecord) {
			r.HasKeyPolicy = true
			r.KeyPolicyStatementCount = 1
			r.RotationSupported = true
			r.RotationEnabled = true
			r.Aliases = []string{"alias/partner-feed"}
			r.IdentityGrants = []AWSKMSIdentityGrant{{
				PrincipalARN:   fmt.Sprintf("arn:%s:iam::999999999999:role/partner-ingest", partition),
				PrincipalType:  "aws",
				Effect:         "Allow",
				Actions:        []string{"kms:Decrypt", "kms:GenerateDataKey"},
				Capabilities:   []string{"decrypt", "encrypt"},
				IsCrossAccount: true,
				StatementSid:   "PartnerDecrypt",
			}}
			r.ExposureReasons = []string{"kms_key_policy_allow_to_cross_account_principal"}
		}),
		// AWS-managed key (not actionable — surfaces as managed_by_aws).
		awsKMSDecryptReachabilityFixtureRecord(accountID, region, "dddd1111-2222-3333-4444-555566667777", awsManagedARN, "managed_by_aws", "AWS", checkedAt, partition, func(r *AWSKMSDecryptReachabilityRecord) {
			r.Aliases = []string{"alias/aws/s3"}
			r.HasKeyPolicy = false
			r.ExposureReasons = []string{"kms_managed_by_aws"}
		}),
		// Explicitly restricted key (deny-all to wildcard).
		awsKMSDecryptReachabilityFixtureRecord(accountID, region, "eeee1111-2222-3333-4444-555566667777", restrictedARN, "restricted", "CUSTOMER", checkedAt, partition, func(r *AWSKMSDecryptReachabilityRecord) {
			r.HasKeyPolicy = true
			r.KeyPolicyStatementCount = 2
			r.IAMDelegationEnabled = true
			r.RotationSupported = true
			r.RotationEnabled = true
			r.IdentityGrants = []AWSKMSIdentityGrant{
				{
					PrincipalARN:  fmt.Sprintf("arn:%s:iam::%s:root", partition, accountID),
					PrincipalType: "aws",
					Effect:        "Allow",
					Actions:       []string{"kms:*"},
					Capabilities:  []string{"admin", "decrypt", "encrypt", "grant", "sign"},
					StatementSid:  "EnableIAMUserPermissions",
				},
				{
					PrincipalARN:      "*",
					PrincipalType:     "*",
					Effect:            "Deny",
					Actions:           []string{"kms:*"},
					Capabilities:      []string{"admin", "decrypt", "encrypt", "grant", "sign"},
					WildcardPrincipal: true,
					StatementSid:      "DenyBreakGlass",
				},
			}
			r.ExposureReasons = []string{"kms_key_policy_explicit_deny_to_all"}
		}),
	}
	switch fixtureState {
	case "empty":
		return nil, nil, gaps
	case "degraded":
		// Flag the rotation-capable but rotation-disabled CMK as degraded.
		for i := range records {
			if records[i].KeyID != "bbbb1111-2222-3333-4444-555566667777" {
				continue
			}
			records[i].Status = "degraded"
			records[i].Confidence = 0.7
			records[i].ExposureReasons = append(records[i].ExposureReasons, "kms_rotation_disabled_on_rotation_capable_key")
			break
		}
		return records, []providers.SourceError{{
			Collector: kmsCollectorRefForAPI,
			SourceID:  publicKeyARN,
			Code:      "kms_rotation_disabled",
			Message:   "Customer-managed key has automatic rotation disabled despite supporting it",
			Retryable: false,
		}}, gaps
	case "partial_failure":
		return records[:3], []providers.SourceError{{
			Collector: kmsCollectorRefForAPI,
			SourceID:  fmt.Sprintf("service=kms|account=%s|region=%s|source=listgrants", accountID, region),
			Code:      "kms_list_grants_failed",
			Message:   "ListGrants for one key was throttled; earlier records remain visible",
			Retryable: true,
		}}, gaps
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: kmsCollectorRefForAPI,
			SourceID:  fmt.Sprintf("service=kms|account=%s|region=%s|source=listkeys", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only KMS metadata permission is missing",
			Retryable: false,
		}}, gaps
	default:
		return records, nil, gaps
	}
}

const kmsCollectorRefForAPI = "aws_kms/kms_decrypt_reachability"

func awsKMSDecryptReachabilityFixtureRecord(accountID, region, id, arn, exposure, manager string, checkedAt time.Time, partition string, mutate func(*AWSKMSDecryptReachabilityRecord)) AWSKMSDecryptReachabilityRecord {
	confidence := 0.9
	switch exposure {
	case "public":
		confidence = 0.95
	case "cross_account":
		confidence = 0.92
	case "restricted":
		confidence = 0.9
	case "private_with_grants":
		confidence = 0.87
	case "managed_by_aws":
		confidence = 0.85
	case "private":
		confidence = 0.84
	}
	record := AWSKMSDecryptReachabilityRecord{
		AccountID:              accountID,
		Region:                 region,
		Service:                "kms",
		KeyARN:                 arn,
		KeyID:                  id,
		KeyManager:             manager,
		KeyState:               "Enabled",
		KeyUsage:               "ENCRYPT_DECRYPT",
		KeySpec:                "SYMMETRIC_DEFAULT",
		Origin:                 "AWS_KMS",
		Enabled:                true,
		ExposureClassification: exposure,
		Tags:                   map[string]string{"owner": "payments-platform"},
		Source:                 "kms_key_metadata",
		EvidenceRef:            arn,
		FromNodeID:             "aws:resource:kms-key:" + arn,
		RelationshipType:       "can_decrypt",
		Confidence:             confidence,
		CollectedAt:            checkedAt,
		Status:                 "ready",
	}
	if mutate != nil {
		mutate(&record)
	}
	_ = partition
	return record
}

func awsKMSDecryptReachabilityEdges(records []AWSKMSDecryptReachabilityRecord) []AWSKMSDecryptReachabilityEdge {
	result := []AWSKMSDecryptReachabilityEdge{}
	for _, record := range records {
		toNode := "aws:resource:kms-key:" + record.KeyARN
		for _, grant := range record.IdentityGrants {
			if !strings.EqualFold(grant.Effect, "Allow") {
				continue
			}
			if grant.WildcardPrincipal || grant.PrincipalARN == "*" || grant.PrincipalARN == "" {
				continue
			}
			if !isIAMPrincipalARNForKMSEdge(grant.PrincipalARN) {
				continue
			}
			if !kmsCapabilitiesIncludeDecrypt(grant.Capabilities) {
				continue
			}
			result = append(result, AWSKMSDecryptReachabilityEdge{
				Type:          "can_decrypt",
				FromNodeID:    awsIdentityNodeIDForAPI(grant.PrincipalARN),
				ToNodeID:      toNode,
				EvidenceRef:   record.EvidenceRef,
				Effect:        grant.Effect,
				Source:        "key_policy",
				PrincipalType: grant.PrincipalType,
				Capabilities:  append([]string(nil), grant.Capabilities...),
				HasCondition:  grant.HasCondition,
			})
		}
		for _, grant := range record.Grants {
			if grant.GranteePrincipal == "" {
				continue
			}
			if !isIAMPrincipalARNForKMSEdge(grant.GranteePrincipal) {
				continue
			}
			if !kmsCapabilitiesIncludeDecrypt(grant.Capabilities) {
				continue
			}
			result = append(result, AWSKMSDecryptReachabilityEdge{
				Type:          "can_decrypt",
				FromNodeID:    awsIdentityNodeIDForAPI(grant.GranteePrincipal),
				ToNodeID:      toNode,
				EvidenceRef:   record.EvidenceRef,
				Effect:        "Allow",
				Source:        "kms_grant",
				PrincipalType: grant.GranteePrincipalType,
				Capabilities:  append([]string(nil), grant.Capabilities...),
				HasCondition:  grant.HasConstraints,
			})
		}
	}
	return result
}

func kmsCapabilitiesIncludeDecrypt(capabilities []string) bool {
	for _, capability := range capabilities {
		if strings.EqualFold(strings.TrimSpace(capability), "decrypt") {
			return true
		}
	}
	return false
}

func summarizeAWSKMSDecryptReachabilityInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSKMSDecryptReachabilityRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35,
			[]string{"kms decrypt reachability collection is blocked by missing read-only KMS permission"},
			[]string{"Grant kms:ListKeys, kms:DescribeKey, kms:GetKeyPolicy, kms:GetKeyRotationStatus, kms:ListAliases, kms:ListGrants, and kms:ListResourceTags. Do not enable encrypt/decrypt/sign/verify APIs."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.7,
			[]string{"one or more customer-managed KMS keys have rotation disabled"},
			[]string{"Enable automatic rotation for symmetric customer-managed keys or document the exception."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78,
			[]string{"one KMS sub-call failed while previously-collected key evidence remains visible"},
			[]string{"Retry the failed KMS metadata call without discarding successful key evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82,
				[]string{"kms decrypt reachability collection returned diagnostics"},
				[]string{"Review diagnostics before treating KMS coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, nil
	}
}

func awsKMSDecryptReachabilityDiagnostics(diagnostics []providers.SourceError) []AWSKMSDecryptReachabilityDiagnostic {
	result := make([]AWSKMSDecryptReachabilityDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSKMSDecryptReachabilityDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsKMSDecryptReachabilityDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsKMSDecryptReachabilityDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant the read-only KMS actions listed in the docs; do not enable cryptographic APIs."
	case "kms_rotation_disabled":
		return "Enable automatic rotation on the affected customer-managed key or document the exception."
	case "kms_describe_key_failed", "kms_key_policy_failed", "kms_key_rotation_failed",
		"kms_list_grants_failed", "kms_list_aliases_failed", "kms_list_tags_failed":
		return "Retry only the failed KMS metadata call and keep previously-collected key evidence visible."
	case "kms_key_policy_parse_failed":
		return "Audit the key policy document for invalid JSON; the collector skips unparseable policies rather than guessing."
	case "malformed_kms_decrypt_reachability_record":
		return "Confirm ListKeys returned a key with an id or ARN; the collector skips ambiguous records."
	default:
		return "Review the KMS collector diagnostic and retry after the scoped KMS permission issue is corrected."
	}
}

func countKeysByExposure(records []AWSKMSDecryptReachabilityRecord, exposure string) int {
	count := 0
	for _, record := range records {
		if record.ExposureClassification == exposure {
			count++
		}
	}
	return count
}

func countKeysByManager(records []AWSKMSDecryptReachabilityRecord, manager string) int {
	count := 0
	for _, record := range records {
		if strings.EqualFold(record.KeyManager, manager) {
			count++
		}
	}
	return count
}

func countKeysWith(records []AWSKMSDecryptReachabilityRecord, pred func(AWSKMSDecryptReachabilityRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countKMSPolicyGrants(records []AWSKMSDecryptReachabilityRecord, pred func(AWSKMSIdentityGrant) bool) int {
	count := 0
	for _, record := range records {
		for _, grant := range record.IdentityGrants {
			if pred(grant) {
				count++
			}
		}
	}
	return count
}

func countKMSLiveGrants(records []AWSKMSDecryptReachabilityRecord, pred func(AWSKMSGrant) bool) int {
	count := 0
	for _, record := range records {
		for _, grant := range record.Grants {
			if pred(grant) {
				count++
			}
		}
	}
	return count
}

// validateKMSDecryptReachabilityRecord enforces the scope-and-evidence
// subset of the service collector contract that is meaningful for resource
// records (KMS keys carry no role of their own). Required fields are
// checked in a deterministic order so callers see the same error for the
// same input.
func validateKMSDecryptReachabilityRecord(scope db.Scope, project db.TenancyProject, connectorID string, record AWSKMSDecryptReachabilityRecord) error {
	required := []struct {
		name  string
		value string
	}{
		{"tenant_id", scope.TenantID},
		{"workspace_id", project.WorkspaceID},
		{"project_id", project.ProjectID},
		{"connector_id", connectorID},
		{"account_id", record.AccountID},
		{"region", record.Region},
		{"service", record.Service},
		{"key_arn", record.KeyARN},
		{"key_id", record.KeyID},
		{"source", record.Source},
		{"evidence_ref", record.EvidenceRef},
		{"exposure_classification", record.ExposureClassification},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if record.Confidence <= 0 || record.Confidence > 1 {
		return fmt.Errorf("confidence must be greater than 0 and at most 1")
	}
	if record.CollectedAt.IsZero() {
		return fmt.Errorf("collected_at is required")
	}
	return nil
}

// isIAMPrincipalARNForKMSEdge reports whether the supplied principal looks
// like a real IAM role or user ARN. We only emit graph edges for principals
// that have an identity node in the graph; service principals, federated
// principals, and non-IAM ARNs would produce dangling references.
func isIAMPrincipalARNForKMSEdge(principal string) bool {
	trimmed := strings.TrimSpace(principal)
	if trimmed == "" {
		return false
	}
	parts := strings.SplitN(trimmed, ":", 6)
	if len(parts) != 6 {
		return false
	}
	if parts[0] != "arn" {
		return false
	}
	switch parts[1] {
	case "aws", "aws-us-gov", "aws-cn":
	default:
		return false
	}
	if parts[2] != "iam" {
		return false
	}
	if parts[3] != "" {
		return false
	}
	if len(parts[4]) != 12 {
		return false
	}
	for _, r := range parts[4] {
		if r < '0' || r > '9' {
			return false
		}
	}
	resource := parts[5]
	if strings.HasPrefix(resource, "role/") && len(resource) > len("role/") {
		return true
	}
	if strings.HasPrefix(resource, "user/") && len(resource) > len("user/") {
		return true
	}
	return false
}

// awsKMSPartitionForRegion is a local partition helper so the api package
// does not import the providers/aws helpers directly.
func awsKMSPartitionForRegion(region string) string {
	normalized := strings.ToLower(strings.TrimSpace(region))
	switch {
	case strings.HasPrefix(normalized, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(normalized, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}
