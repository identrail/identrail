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
	awsS3BucketReachabilityCurrentIssue = 1488
	awsS3BucketReachabilityVersion      = "aws-s3-bucket-reachability-inventory-v1"
)

// AWSS3BucketReachabilityInventoryRequest is the operator-facing request.
type AWSS3BucketReachabilityInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSS3CoverageGap names an S3 capability this wave intentionally does not
// model, with the reason and remediation an operator should rely on.
type AWSS3CoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// AWSS3BucketReachabilityInventoryResult is the deterministic envelope this
// endpoint returns.
type AWSS3BucketReachabilityInventoryResult struct {
	TenantID                string                              `json:"tenant_id"`
	WorkspaceID             string                              `json:"workspace_id"`
	ProjectID               string                              `json:"project_id"`
	ConnectorID             string                              `json:"connector_id,omitempty"`
	AccountID               string                              `json:"account_id,omitempty"`
	Region                  string                              `json:"region,omitempty"`
	ParentIssueNumber       int                                 `json:"parent_issue_number"`
	ParentIssueRef          string                              `json:"parent_issue_ref"`
	CurrentIssueNumber      int                                 `json:"current_issue_number"`
	CurrentIssueRef         string                              `json:"current_issue_ref"`
	Version                 string                              `json:"version"`
	Status                  string                              `json:"status"`
	FixtureState            string                              `json:"fixture_state"`
	Confidence              float64                             `json:"confidence"`
	BucketCount             int                                 `json:"bucket_count"`
	PublicBucketCount       int                                 `json:"public_bucket_count"`
	CrossAccountBucketCount int                                 `json:"cross_account_bucket_count"`
	RestrictedBucketCount   int                                 `json:"restricted_bucket_count"`
	BucketsWithPolicyCount  int                                 `json:"buckets_with_policy_count"`
	BucketsWithoutPABCount  int                                 `json:"buckets_without_pab_count"`
	BucketsWithKMSCount     int                                 `json:"buckets_with_kms_count"`
	AccessPointCount        int                                 `json:"access_point_count"`
	IdentityGrantCount      int                                 `json:"identity_grant_count"`
	PublicGrantCount        int                                 `json:"public_grant_count"`
	CrossAccountGrantCount  int                                 `json:"cross_account_grant_count"`
	DenyGrantCount          int                                 `json:"deny_grant_count"`
	RelationshipCount       int                                 `json:"relationship_count"`
	FailureReasons          []string                            `json:"failure_reasons"`
	RemediationHints        []string                            `json:"remediation_hints"`
	EvidenceLinks           []string                            `json:"evidence_links"`
	CoverageGaps            []AWSS3CoverageGap                  `json:"coverage_gaps"`
	Records                 []AWSS3BucketReachabilityRecord     `json:"records"`
	Relationships           []AWSS3BucketReachabilityEdge       `json:"relationships"`
	Diagnostics             []AWSS3BucketReachabilityDiagnostic `json:"diagnostics"`
	GeneratedAt             time.Time                           `json:"generated_at"`
	UpdatedAt               time.Time                           `json:"updated_at"`
}

// AWSS3BucketReachabilityRecord is one bucket's metadata, exposure
// classification, and the identity grants inferred from its bucket policy.
type AWSS3BucketReachabilityRecord struct {
	AccountID                  string                      `json:"account_id"`
	Region                     string                      `json:"region"`
	Service                    string                      `json:"service"`
	BucketARN                  string                      `json:"bucket_arn"`
	BucketName                 string                      `json:"bucket_name"`
	BucketRegion               string                      `json:"bucket_region,omitempty"`
	CreatedAt                  string                      `json:"created_at,omitempty"`
	HasBucketPolicy            bool                        `json:"has_bucket_policy"`
	BucketPolicyStatementCount int                         `json:"bucket_policy_statement_count"`
	PublicAccessBlock          *AWSS3PublicAccessBlock     `json:"public_access_block,omitempty"`
	OwnershipControls          string                      `json:"ownership_controls,omitempty"`
	BlockPublicACLs            bool                        `json:"block_public_acls"`
	BlockPublicPolicy          bool                        `json:"block_public_policy"`
	IgnorePublicACLs           bool                        `json:"ignore_public_acls"`
	RestrictPublicBuckets      bool                        `json:"restrict_public_buckets"`
	DefaultEncryptionAlgorithm string                      `json:"default_encryption_algorithm,omitempty"`
	DefaultEncryptionKMSKeyARN string                      `json:"default_encryption_kms_key_arn,omitempty"`
	BucketKeyEnabled           bool                        `json:"bucket_key_enabled"`
	AccessPoints               []AWSS3AccessPointReference `json:"access_points,omitempty"`
	IdentityGrants             []AWSS3IdentityGrant        `json:"identity_grants,omitempty"`
	ExposureClassification     string                      `json:"exposure_classification"`
	ExposureReasons            []string                    `json:"exposure_reasons,omitempty"`
	Tags                       map[string]string           `json:"tags,omitempty"`
	Source                     string                      `json:"source"`
	EvidenceRef                string                      `json:"evidence_ref"`
	FromNodeID                 string                      `json:"from_node_id"`
	RelationshipType           string                      `json:"relationship_type"`
	Confidence                 float64                     `json:"confidence"`
	CollectedAt                time.Time                   `json:"collected_at"`
	Status                     string                      `json:"status"`
}

// AWSS3PublicAccessBlock mirrors the per-bucket public-access-block payload.
type AWSS3PublicAccessBlock struct {
	BlockPublicACLs       bool `json:"block_public_acls"`
	IgnorePublicACLs      bool `json:"ignore_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

// AWSS3AccessPointReference is the metadata-only fingerprint of a single S3
// access point.
type AWSS3AccessPointReference struct {
	Name          string `json:"name"`
	ARN           string `json:"arn,omitempty"`
	NetworkOrigin string `json:"network_origin,omitempty"`
	VPCID         string `json:"vpc_id,omitempty"`
}

// AWSS3IdentityGrant mirrors the collector-side grant struct.
type AWSS3IdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"`
	Effect            string   `json:"effect"`
	Actions           []string `json:"actions,omitempty"`
	NotAction         bool     `json:"not_action,omitempty"`
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

// AWSS3BucketReachabilityEdge is one graph edge from a principal to a bucket.
// Edges are only emitted for resolved, allow-effect, non-wildcard grants.
type AWSS3BucketReachabilityEdge struct {
	Type          string `json:"type"`
	FromNodeID    string `json:"from_node_id"`
	ToNodeID      string `json:"to_node_id"`
	EvidenceRef   string `json:"evidence_ref"`
	Effect        string `json:"effect"`
	PrincipalType string `json:"principal_type"`
	HasCondition  bool   `json:"has_condition,omitempty"`
}

// AWSS3BucketReachabilityDiagnostic is a structured collector diagnostic.
type AWSS3BucketReachabilityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSS3BucketReachabilityInventory returns the S3 reachability inventory
// for the supplied scope.
func (s *Service) GetAWSS3BucketReachabilityInventory(ctx context.Context, workspaceID string, projectID string, request AWSS3BucketReachabilityInventoryRequest) (AWSS3BucketReachabilityInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSS3BucketReachabilityInventoryResult{}, err
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
		return AWSS3BucketReachabilityInventoryResult{}, err
	}
	return buildAWSS3BucketReachabilityInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSS3BucketReachabilityInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSS3BucketReachabilityInventoryRequest, checkedAt time.Time) (AWSS3BucketReachabilityInventoryResult, error) {
	fixtureState := normalizeAWSS3BucketReachabilityFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSS3BucketReachabilityInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics, coverageGaps := awsS3BucketReachabilityFixtureRecords(accountID, region, fixtureState, checkedAt)
	for _, record := range records {
		// S3 buckets are resource records, not workload-with-role records, so
		// they bypass the workload-oriented ServiceCollectorRecord validation
		// and instead get this lightweight scope check.
		if err := validateS3BucketReachabilityRecord(scope, project, connectorID, record); err != nil {
			return AWSS3BucketReachabilityInventoryResult{}, fmt.Errorf("validate s3 bucket reachability record: %w", err)
		}
	}
	status, confidence, failures, remediations := summarizeAWSS3BucketReachabilityInventory(fixtureState, diagnostics, records)
	relationships := awsS3BucketReachabilityEdges(records)
	return AWSS3BucketReachabilityInventoryResult{
		TenantID:                scope.TenantID,
		WorkspaceID:             project.WorkspaceID,
		ProjectID:               project.ProjectID,
		ConnectorID:             connectorID,
		AccountID:               accountID,
		Region:                  region,
		ParentIssueNumber:       awsPlatformDependencyParentIssue,
		ParentIssueRef:          awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:      awsS3BucketReachabilityCurrentIssue,
		CurrentIssueRef:         awsIssueRef(awsS3BucketReachabilityCurrentIssue),
		Version:                 awsS3BucketReachabilityVersion,
		Status:                  status,
		FixtureState:            fixtureState,
		Confidence:              confidence,
		BucketCount:             len(records),
		PublicBucketCount:       countBucketsByExposure(records, "public"),
		CrossAccountBucketCount: countBucketsByExposure(records, "cross_account"),
		RestrictedBucketCount:   countBucketsByExposure(records, "restricted"),
		BucketsWithPolicyCount:  countBucketsWith(records, func(r AWSS3BucketReachabilityRecord) bool { return r.HasBucketPolicy }),
		BucketsWithoutPABCount:  countBucketsWith(records, func(r AWSS3BucketReachabilityRecord) bool { return r.PublicAccessBlock == nil }),
		BucketsWithKMSCount: countBucketsWith(records, func(r AWSS3BucketReachabilityRecord) bool {
			return strings.HasPrefix(r.DefaultEncryptionAlgorithm, "aws:kms") || strings.TrimSpace(r.DefaultEncryptionKMSKeyARN) != ""
		}),
		AccessPointCount:       countAccessPoints(records),
		IdentityGrantCount:     countGrants(records, func(g AWSS3IdentityGrant) bool { return true }),
		PublicGrantCount:       countGrants(records, func(g AWSS3IdentityGrant) bool { return g.IsPublic }),
		CrossAccountGrantCount: countGrants(records, func(g AWSS3IdentityGrant) bool { return g.IsCrossAccount }),
		DenyGrantCount:         countGrants(records, func(g AWSS3IdentityGrant) bool { return strings.EqualFold(g.Effect, "Deny") }),
		RelationshipCount:      len(relationships),
		FailureReasons:         failures,
		RemediationHints:       remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsS3BucketReachabilityCurrentIssue),
			"/docs/aws-s3-bucket-reachability",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps:  coverageGaps,
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsS3BucketReachabilityDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}, nil
}

func normalizeAWSS3BucketReachabilityFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
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

func awsS3BucketReachabilityFixtureRecords(accountID, region, fixtureState string, checkedAt time.Time) ([]AWSS3BucketReachabilityRecord, []providers.SourceError, []AWSS3CoverageGap) {
	gaps := []AWSS3CoverageGap{{
		Capability:  "object_acl_grants",
		Status:      "unsupported",
		Reason:      "Per-object ACL grants are not modelled in this wave; only bucket-level policy and ACL configuration are surfaced.",
		Remediation: "Disable object ACLs (Object Ownership = BucketOwnerEnforced) for blast-radius reasoning until per-object collection ships.",
	}, {
		Capability:  "access_point_policies",
		Status:      "unsupported",
		Reason:      "Access point policy parsing is tracked separately; this wave only surfaces access point names, ARNs, and VPC origins.",
		Remediation: "Treat access-point-scoped reachability as unresolved until the dedicated parser lands.",
	}, {
		Capability:  "vpc_endpoint_policies",
		Status:      "unsupported",
		Reason:      "Bucket reachability through VPC endpoint policies is not modelled in this wave.",
		Remediation: "Audit aws:SourceVpc / aws:SourceVpce conditions manually until the network-layer mapper ships.",
	}}
	partition := awsS3PartitionForRegion(region)
	publicBucketARN := fmt.Sprintf("arn:%s:s3:::payments-public", partition)
	crossAccountARN := fmt.Sprintf("arn:%s:s3:::payments-cross-account", partition)
	restrictedARN := fmt.Sprintf("arn:%s:s3:::payments-encrypted", partition)
	internalARN := fmt.Sprintf("arn:%s:s3:::payments-internal", partition)
	records := []AWSS3BucketReachabilityRecord{
		awsS3BucketReachabilityFixtureRecord(accountID, region, "payments-public", publicBucketARN, "public", checkedAt, partition, func(r *AWSS3BucketReachabilityRecord) {
			r.HasBucketPolicy = true
			r.BucketPolicyStatementCount = 1
			r.IdentityGrants = []AWSS3IdentityGrant{{
				PrincipalARN:      "*",
				PrincipalType:     "*",
				Effect:            "Allow",
				Actions:           []string{"s3:GetObject"},
				IsPublic:          true,
				WildcardPrincipal: true,
				StatementSid:      "PublicRead",
			}}
			r.ExposureReasons = []string{"bucket_policy_allow_to_wildcard_principal"}
		}),
		awsS3BucketReachabilityFixtureRecord(accountID, region, "payments-cross-account", crossAccountARN, "cross_account", checkedAt, partition, func(r *AWSS3BucketReachabilityRecord) {
			r.HasBucketPolicy = true
			r.BucketPolicyStatementCount = 1
			r.IdentityGrants = []AWSS3IdentityGrant{{
				PrincipalARN:   fmt.Sprintf("arn:%s:iam::999999999999:role/partner-ingest", partition),
				PrincipalType:  "aws",
				Effect:         "Allow",
				Actions:        []string{"s3:PutObject", "s3:GetObject"},
				IsCrossAccount: true,
				StatementSid:   "PartnerAccess",
			}}
			r.PublicAccessBlock = &AWSS3PublicAccessBlock{
				BlockPublicACLs:       true,
				BlockPublicPolicy:     true,
				IgnorePublicACLs:      true,
				RestrictPublicBuckets: true,
			}
			r.BlockPublicACLs = true
			r.BlockPublicPolicy = true
			r.IgnorePublicACLs = true
			r.RestrictPublicBuckets = true
			r.ExposureReasons = []string{"bucket_policy_allow_to_cross_account_principal", "public_access_block_fully_enabled"}
		}),
		awsS3BucketReachabilityFixtureRecord(accountID, region, "payments-encrypted", restrictedARN, "restricted", checkedAt, partition, func(r *AWSS3BucketReachabilityRecord) {
			r.HasBucketPolicy = true
			r.BucketPolicyStatementCount = 1
			r.IdentityGrants = []AWSS3IdentityGrant{{
				PrincipalARN:      "*",
				PrincipalType:     "*",
				Effect:            "Deny",
				Actions:           []string{"s3:*"},
				ConditionKeys:     []string{"aws:SecureTransport"},
				HasCondition:      true,
				WildcardPrincipal: true,
				StatementSid:      "DenyInsecureTransport",
			}}
			r.DefaultEncryptionAlgorithm = "aws:kms"
			r.DefaultEncryptionKMSKeyARN = fmt.Sprintf("arn:%s:kms:%s:%s:key/payments-encrypted", partition, region, accountID)
			r.BucketKeyEnabled = true
			r.PublicAccessBlock = &AWSS3PublicAccessBlock{
				BlockPublicACLs:       true,
				BlockPublicPolicy:     true,
				IgnorePublicACLs:      true,
				RestrictPublicBuckets: true,
			}
			r.BlockPublicACLs = true
			r.BlockPublicPolicy = true
			r.IgnorePublicACLs = true
			r.RestrictPublicBuckets = true
			r.ExposureReasons = []string{"bucket_policy_explicit_deny_to_all", "public_access_block_fully_enabled"}
		}),
		awsS3BucketReachabilityFixtureRecord(accountID, region, "payments-internal", internalARN, "private_with_grants", checkedAt, partition, func(r *AWSS3BucketReachabilityRecord) {
			r.HasBucketPolicy = true
			r.BucketPolicyStatementCount = 1
			r.IdentityGrants = []AWSS3IdentityGrant{{
				PrincipalARN:  fmt.Sprintf("arn:%s:iam::%s:role/payments-app", partition, accountID),
				PrincipalType: "aws",
				Effect:        "Allow",
				Actions:       []string{"s3:GetObject", "s3:PutObject"},
				StatementSid:  "AppAccess",
			}}
			r.PublicAccessBlock = &AWSS3PublicAccessBlock{
				BlockPublicACLs:       true,
				BlockPublicPolicy:     true,
				IgnorePublicACLs:      true,
				RestrictPublicBuckets: true,
			}
			r.BlockPublicACLs = true
			r.BlockPublicPolicy = true
			r.IgnorePublicACLs = true
			r.RestrictPublicBuckets = true
			r.AccessPoints = []AWSS3AccessPointReference{{
				Name:          "payments-internal-vpc",
				ARN:           fmt.Sprintf("arn:%s:s3:%s:%s:accesspoint/payments-internal-vpc", partition, region, accountID),
				NetworkOrigin: "VPC",
				VPCID:         "vpc-0abc1234",
			}}
		}),
	}
	switch fixtureState {
	case "empty":
		return nil, nil, gaps
	case "degraded":
		// Flag the public bucket as degraded due to missing PAB.
		for i := range records {
			if records[i].BucketName != "payments-public" {
				continue
			}
			records[i].Status = "degraded"
			records[i].Confidence = 0.7
			records[i].PublicAccessBlock = nil
			records[i].ExposureReasons = append(records[i].ExposureReasons, "public_access_block_absent")
			break
		}
		return records, []providers.SourceError{{
			Collector: "aws_s3/s3_bucket_reachability",
			SourceID:  publicBucketARN,
			Code:      "s3_public_access_block_absent",
			Message:   "One S3 bucket has no PublicAccessBlock configuration; bucket-policy public exposure is unmitigated",
			Retryable: false,
		}}, gaps
	case "partial_failure":
		return records[:3], []providers.SourceError{{
			Collector: "aws_s3/s3_bucket_reachability",
			SourceID:  fmt.Sprintf("service=s3|account=%s|region=%s|source=getbucketpolicy", accountID, region),
			Code:      "s3_bucket_policy_failed",
			Message:   "One bucket's GetBucketPolicy call was throttled; earlier records remain visible",
			Retryable: true,
		}}, gaps
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_s3/s3_bucket_reachability",
			SourceID:  fmt.Sprintf("service=s3|account=%s|region=%s|source=listbuckets", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only S3 metadata permission is missing",
			Retryable: false,
		}}, gaps
	default:
		return records, nil, gaps
	}
}

func awsS3BucketReachabilityFixtureRecord(accountID, region, name, arn, exposure string, checkedAt time.Time, partition string, mutate func(*AWSS3BucketReachabilityRecord)) AWSS3BucketReachabilityRecord {
	confidence := 0.9
	switch exposure {
	case "public":
		confidence = 0.95
	case "cross_account":
		confidence = 0.92
	case "restricted":
		confidence = 0.9
	case "private_with_grants":
		confidence = 0.88
	}
	record := AWSS3BucketReachabilityRecord{
		AccountID:              accountID,
		Region:                 region,
		Service:                "s3",
		BucketARN:              arn,
		BucketName:             name,
		BucketRegion:           region,
		ExposureClassification: exposure,
		Tags:                   map[string]string{"owner": "payments-platform"},
		Source:                 "s3_bucket_metadata",
		EvidenceRef:            arn,
		FromNodeID:             "aws:resource:s3-bucket:" + arn,
		RelationshipType:       "can_access",
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

func awsS3BucketReachabilityEdges(records []AWSS3BucketReachabilityRecord) []AWSS3BucketReachabilityEdge {
	result := []AWSS3BucketReachabilityEdge{}
	for _, record := range records {
		toNode := "aws:resource:s3-bucket:" + record.BucketARN
		for _, grant := range record.IdentityGrants {
			if !strings.EqualFold(grant.Effect, "Allow") {
				continue
			}
			if grant.WildcardPrincipal || grant.PrincipalARN == "*" || grant.PrincipalARN == "" {
				continue
			}
			// Only emit edges for IAM principal ARNs (roles or users). Service
			// principals (e.g. lambda.amazonaws.com), federated principals, and
			// any non-IAM ARNs do not have an identity node in the graph yet,
			// so an edge to them would be a dangling reference.
			if !isIAMPrincipalARNForS3Edge(grant.PrincipalARN) {
				continue
			}
			result = append(result, AWSS3BucketReachabilityEdge{
				Type:          "can_access",
				FromNodeID:    awsIdentityNodeIDForAPI(grant.PrincipalARN),
				ToNodeID:      toNode,
				EvidenceRef:   record.EvidenceRef,
				Effect:        grant.Effect,
				PrincipalType: grant.PrincipalType,
				HasCondition:  grant.HasCondition,
			})
		}
	}
	return result
}

func summarizeAWSS3BucketReachabilityInventory(fixtureState string, diagnostics []providers.SourceError, records []AWSS3BucketReachabilityRecord) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35,
			[]string{"s3 bucket reachability collection is blocked by missing read-only S3 permission"},
			[]string{"Grant s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketPolicy, s3:GetPublicAccessBlock, s3:GetBucketOwnershipControls, s3:GetEncryptionConfiguration, s3:GetBucketTagging, and s3:ListAccessPoints. Do not enable object-content APIs."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.7,
			[]string{"one or more S3 buckets have unmitigated public exposure"},
			[]string{"Enable PublicAccessBlock on every bucket and confirm bucket policy statements do not allow * principals."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.78,
			[]string{"one S3 sub-listing failed while previously-collected bucket evidence remains visible"},
			[]string{"Retry the failed S3 metadata call without discarding successful bucket evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.82,
				[]string{"s3 bucket reachability collection returned diagnostics"},
				[]string{"Review diagnostics before treating S3 coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.93, nil, nil
	}
}

func awsS3BucketReachabilityDiagnostics(diagnostics []providers.SourceError) []AWSS3BucketReachabilityDiagnostic {
	result := make([]AWSS3BucketReachabilityDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSS3BucketReachabilityDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsS3BucketReachabilityDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsS3BucketReachabilityDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant the read-only S3 actions listed in the docs; do not enable object-content APIs."
	case "s3_public_access_block_absent":
		return "Enable PublicAccessBlock on the bucket and re-scan."
	case "s3_bucket_policy_failed", "s3_public_access_block_failed", "s3_ownership_controls_failed", "s3_bucket_encryption_failed", "s3_bucket_tagging_failed", "s3_bucket_location_failed", "s3_access_points_failed":
		return "Retry only the failed S3 metadata call and keep previously-collected bucket evidence visible."
	case "s3_bucket_policy_parse_failed":
		return "Audit the bucket policy document for invalid JSON; the collector skips unparseable policies rather than guessing."
	case "malformed_s3_bucket_record":
		return "Confirm ListBuckets returned a bucket with a name; the collector skips ambiguous records."
	default:
		return "Review the S3 collector diagnostic and retry after the scoped S3 permission issue is corrected."
	}
}

func countBucketsByExposure(records []AWSS3BucketReachabilityRecord, exposure string) int {
	count := 0
	for _, record := range records {
		if record.ExposureClassification == exposure {
			count++
		}
	}
	return count
}

func countBucketsWith(records []AWSS3BucketReachabilityRecord, pred func(AWSS3BucketReachabilityRecord) bool) int {
	count := 0
	for _, record := range records {
		if pred(record) {
			count++
		}
	}
	return count
}

func countAccessPoints(records []AWSS3BucketReachabilityRecord) int {
	count := 0
	for _, record := range records {
		count += len(record.AccessPoints)
	}
	return count
}

func countGrants(records []AWSS3BucketReachabilityRecord, pred func(AWSS3IdentityGrant) bool) int {
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

// validateS3BucketReachabilityRecord enforces the scope-and-evidence subset of
// the service collector contract that is meaningful for resource records (S3
// buckets carry no role of their own; the workload-with-role validation is the
// wrong contract for this surface). The required fields are checked in a
// deterministic order so callers always see the same error for the same input.
func validateS3BucketReachabilityRecord(scope db.Scope, project db.TenancyProject, connectorID string, record AWSS3BucketReachabilityRecord) error {
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
		{"bucket_arn", record.BucketARN},
		{"bucket_name", record.BucketName},
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

// isIAMPrincipalARNForS3Edge reports whether the supplied principal looks
// like a real IAM role or user ARN. We only emit graph edges for principals
// that have an identity node in the graph; service principals, federated
// principals, canonical user IDs, and non-IAM ARNs would produce dangling
// references and are intentionally excluded here.
func isIAMPrincipalARNForS3Edge(principal string) bool {
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
	// IAM ARNs have an empty region segment.
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

// awsS3PartitionForRegion is a small partition helper local to this file so
// the api package does not import the providers/aws helpers directly.
func awsS3PartitionForRegion(region string) string {
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
