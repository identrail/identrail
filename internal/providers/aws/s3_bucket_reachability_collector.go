package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	rawKindS3BucketReachability       = "s3_bucket_reachability"
	s3BucketReachabilityCollectorName = "s3_bucket_reachability"
	s3ServiceName                     = "s3"
)

// S3BucketReachability is the normalized envelope describing one S3 bucket
// (and any inferred identity reachability into it). The collector deliberately
// captures metadata only — never object contents, never bucket inventory
// listings — so this struct holds bucket configuration, exposure signals,
// and inferred identity grants from the bucket's resource policy.
type S3BucketReachability struct {
	awscontract.ServiceCollectorRecord

	BucketARN      string `json:"bucket_arn,omitempty"`
	BucketName     string `json:"bucket_name,omitempty"`
	BucketRegion   string `json:"bucket_region,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	ResourceStatus string `json:"resource_status,omitempty"`

	// Bucket policy and public-access surface.
	HasBucketPolicy            bool                 `json:"has_bucket_policy,omitempty"`
	BucketPolicyStatementCount int                  `json:"bucket_policy_statement_count,omitempty"`
	PublicAccessBlock          *S3PublicAccessBlock `json:"public_access_block,omitempty"`
	OwnershipControls          string               `json:"ownership_controls,omitempty"`
	BlockPublicACLs            bool                 `json:"block_public_acls,omitempty"`
	BlockPublicPolicy          bool                 `json:"block_public_policy,omitempty"`
	IgnorePublicACLs           bool                 `json:"ignore_public_acls,omitempty"`
	RestrictPublicBuckets      bool                 `json:"restrict_public_buckets,omitempty"`

	// Encryption surface.
	DefaultEncryptionAlgorithm string `json:"default_encryption_algorithm,omitempty"`
	DefaultEncryptionKMSKeyARN string `json:"default_encryption_kms_key_arn,omitempty"`
	BucketKeyEnabled           bool   `json:"bucket_key_enabled,omitempty"`

	// Access points (S3 access point names + ARNs, metadata only).
	AccessPoints []S3AccessPointReference `json:"access_points,omitempty"`

	// Identity reachability inferred from the bucket policy. One entry per
	// (principal, action, effect) tuple. Wildcard or external-principal
	// statements get explicit exposure classifications so the API can render
	// "public" / "cross_account" / "restricted" without re-parsing.
	IdentityGrants []S3IdentityGrant `json:"identity_grants,omitempty"`

	// Exposure summary computed across PAB, policy, and ACL signals.
	ExposureClassification string   `json:"exposure_classification,omitempty"`
	ExposureReasons        []string `json:"exposure_reasons,omitempty"`

	Tags map[string]string `json:"tags,omitempty"`

	// Sub-call diagnostics from upstream describe calls (e.g. denied
	// GetBucketPolicy) are surfaced via the collector's SourceError list and
	// are NOT included here so the record stays declarative.
}

// S3PublicAccessBlock mirrors the per-bucket public-access-block payload.
type S3PublicAccessBlock struct {
	BlockPublicACLs       bool `json:"block_public_acls"`
	IgnorePublicACLs      bool `json:"ignore_public_acls"`
	BlockPublicPolicy     bool `json:"block_public_policy"`
	RestrictPublicBuckets bool `json:"restrict_public_buckets"`
}

// S3AccessPointReference is the metadata-only fingerprint of a single access
// point. We deliberately omit policy bodies (those are captured indirectly
// via identity grants when downstream waves add access-point policy parsing).
type S3AccessPointReference struct {
	Name          string `json:"name"`
	ARN           string `json:"arn,omitempty"`
	NetworkOrigin string `json:"network_origin,omitempty"`
	VPCID         string `json:"vpc_id,omitempty"`
}

// S3IdentityGrant is one principal-to-bucket grant inferred from the bucket
// policy. Wildcards and explicit deny statements are surfaced rather than
// expanded so operators can see the exposure shape.
type S3IdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"` // aws, service, federated, canonical_user, *
	Effect            string   `json:"effect"`                   // Allow / Deny
	Actions           []string `json:"actions,omitempty"`
	NotAction         bool     `json:"not_action,omitempty"`
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

// S3BucketReachabilityPage is one page of normalized bucket records plus
// per-page collector diagnostics.
type S3BucketReachabilityPage struct {
	Records     []S3BucketReachability
	NextToken   string
	Diagnostics []providers.SourceError
}

// S3BucketReachabilityAPI is the narrow seam between the collector and the
// underlying SDK or fixture client. The collector iterates pages, normalizes,
// and dedupes; the API performs ListBuckets and per-bucket describe fan-out.
type S3BucketReachabilityAPI interface {
	ListBucketReachability(ctx context.Context, nextToken string, pageSize int32) (S3BucketReachabilityPage, error)
}

// S3BucketReachabilityCollector turns S3 bucket metadata into payload-safe
// normalized records and exposure-classified identity reachability evidence.
type S3BucketReachabilityCollector struct {
	client   S3BucketReachabilityAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

// S3BucketReachabilityOption tunes the collector.
type S3BucketReachabilityOption func(*S3BucketReachabilityCollector)

func WithS3BucketReachabilityPageSize(pageSize int32) S3BucketReachabilityOption {
	return func(c *S3BucketReachabilityCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithS3BucketReachabilityMaxPages(maxPages int) S3BucketReachabilityOption {
	return func(c *S3BucketReachabilityCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithS3BucketReachabilityRetryPolicy(policy RetryPolicy) S3BucketReachabilityOption {
	return func(c *S3BucketReachabilityCollector) {
		if policy.MaxRetries >= 0 {
			c.retry.MaxRetries = policy.MaxRetries
		}
		if policy.BaseDelay > 0 {
			c.retry.BaseDelay = policy.BaseDelay
		}
		if policy.MaxDelay > 0 {
			c.retry.MaxDelay = policy.MaxDelay
		}
	}
}

func WithS3BucketReachabilitySleeper(s Sleeper) S3BucketReachabilityOption {
	return func(c *S3BucketReachabilityCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func WithS3BucketReachabilityClock(now func() time.Time) S3BucketReachabilityOption {
	return func(c *S3BucketReachabilityCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewS3BucketReachabilityCollector constructs the collector with the same
// defaults as the rest of the AWS service collectors.
func NewS3BucketReachabilityCollector(client S3BucketReachabilityAPI, opts ...S3BucketReachabilityOption) *S3BucketReachabilityCollector {
	c := &S3BucketReachabilityCollector{
		client:   client,
		pageSize: defaultPageSize,
		maxPages: defaultMaxPages,
		retry: RetryPolicy{
			MaxRetries: defaultRetryCount,
			BaseDelay:  defaultBaseDelay,
			MaxDelay:   defaultMaxDelay,
		},
		jitter: defaultRetryJitterRatio,
		sleep:  defaultSleeper,
		randFn: rand.Float64,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ServiceName returns the canonical AWS service the collector covers.
func (c *S3BucketReachabilityCollector) ServiceName() string {
	return s3ServiceName
}

// Collect satisfies providers.Collector for callers without a scope.
func (c *S3BucketReachabilityCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: s3ServiceName})
	return assets, err
}

// CollectWithDiagnostics walks every S3 bucket, normalizes the metadata, and
// emits one raw asset per bucket. Per-call state lives in local variables so
// concurrent invocations on the same collector instance do not race.
func (c *S3BucketReachabilityCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("s3 bucket reachability collector requires client")
	}
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	assets := []providers.RawAsset{}
	issues := []providers.SourceError{}
	addIssue := func(issue providers.SourceError) {
		if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
			return
		}
		issues = append(issues, issue)
	}
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()
	for page := 1; ; page++ {
		if page > c.maxPages {
			addIssue(providers.SourceError{
				Collector: s3BucketReachabilityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "s3_bucket_reachability_page_limit_exceeded",
				Message:   fmt.Sprintf("s3 bucket reachability collection exceeded max pages (%d)", c.maxPages),
				Retryable: false,
			})
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("s3 bucket reachability collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (S3BucketReachabilityPage, error) {
			return c.client.ListBucketReachability(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list s3 buckets for reachability page %d: %w", page, err)
			addIssue(providers.SourceError{
				Collector: s3BucketReachabilityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "s3_bucket_reachability_page_failed",
				Message:   wrapped.Error(),
				Retryable: isRetryable(err),
			})
			snapshot := append([]providers.SourceError(nil), issues...)
			if len(assets) > 0 {
				return assets, snapshot, wrapped
			}
			return nil, snapshot, wrapped
		}
		for _, diagnostic := range response.Diagnostics {
			addIssue(diagnostic)
		}
		for _, record := range response.Records {
			normalized := normalizeS3BucketReachabilityScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.BucketARN) == "" && strings.TrimSpace(normalized.BucketName) == "" {
				addIssue(providers.SourceError{
					Collector: s3BucketReachabilityCollectorName,
					Code:      "malformed_s3_bucket_record",
					Message:   "skipped s3 bucket record without an ARN or name",
					Retryable: false,
				})
				continue
			}
			sourceID := s3BucketReachabilitySourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal s3 bucket reachability %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindS3BucketReachability,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}
		if strings.TrimSpace(response.NextToken) == "" {
			break
		}
		nextToken = strings.TrimSpace(response.NextToken)
	}
	return assets, append([]providers.SourceError(nil), issues...), nil
}

// normalizeS3BucketReachabilityScope fills in scope/contract fields and
// computes the exposure classification from the bucket's settings + grants.
func normalizeS3BucketReachabilityScope(scope AWSCollectorScope, record S3BucketReachability, collectedAt time.Time) S3BucketReachability {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID, accountIDFromARN(record.BucketARN))
	// Prefer the bucket's actual region (from GetBucketLocation) over the
	// scope region — S3 buckets are global resources whose home region may
	// differ from the scanner's connector region.
	normalized.BucketRegion = firstNonEmptyAWSValue(record.BucketRegion, scope.Region)
	normalized.Region = firstNonEmptyAWSValue(record.BucketRegion, record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, s3ServiceName)
	normalized.BucketName = strings.TrimSpace(record.BucketName)
	normalized.BucketARN = firstNonEmptyAWSValue(record.BucketARN, s3BucketARNFromName(normalized.BucketName, normalized.AccountID, normalized.Region))
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "s3_bucket")
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.BucketName)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.BucketARN, normalized.BucketName)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "s3_bucket_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.BucketARN, normalized.BucketName)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, s3BucketReachabilityCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-s3-bucket-reachability-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.OwnershipControls = strings.TrimSpace(record.OwnershipControls)
	normalized.DefaultEncryptionAlgorithm = strings.TrimSpace(record.DefaultEncryptionAlgorithm)
	normalized.DefaultEncryptionKMSKeyARN = strings.TrimSpace(record.DefaultEncryptionKMSKeyARN)
	normalized.AccessPoints = append([]S3AccessPointReference(nil), record.AccessPoints...)
	normalized.IdentityGrants = annotateS3Grants(record.IdentityGrants, normalized.AccountID)
	normalized.ExposureClassification, normalized.ExposureReasons = classifyS3BucketExposure(normalized)
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = s3BucketReachabilityConfidence(normalized)
	}
	return normalized
}

// annotateS3Grants enriches each grant with cross-account / public flags
// derived from the principal ARN and the bucket's owning account.
func annotateS3Grants(grants []S3IdentityGrant, accountID string) []S3IdentityGrant {
	if len(grants) == 0 {
		return nil
	}
	out := make([]S3IdentityGrant, 0, len(grants))
	for _, grant := range grants {
		grant.PrincipalARN = strings.TrimSpace(grant.PrincipalARN)
		grant.PrincipalType = strings.ToLower(strings.TrimSpace(grant.PrincipalType))
		grant.Effect = canonicalS3GrantEffect(grant.Effect)
		grant.Actions = normalizeStringList(grant.Actions)
		grant.ConditionKeys = normalizeStringList(grant.ConditionKeys)
		grant.WildcardPrincipal = grant.WildcardPrincipal || grant.PrincipalARN == "*"
		grant.IsPublic = grant.IsPublic || grant.WildcardPrincipal
		if !grant.IsCrossAccount && accountID != "" && grant.PrincipalARN != "" && grant.PrincipalARN != "*" {
			grantAccount := accountIDFromARN(grant.PrincipalARN)
			if grantAccount != "" && grantAccount != accountID {
				grant.IsCrossAccount = true
			}
		}
		grant.HasCondition = grant.HasCondition || len(grant.ConditionKeys) > 0
		out = append(out, grant)
	}
	return out
}

// classifyS3BucketExposure folds PAB, policy, and grant signals into one of
// "restricted", "private_with_grants", "cross_account", "public", or
// "unknown". The reasons slice explains the contributing signals so the API
// can render an audit-friendly summary.
func classifyS3BucketExposure(record S3BucketReachability) (string, []string) {
	reasons := []string{}
	public := false
	crossAccount := false
	denyAll := false
	for _, grant := range record.IdentityGrants {
		switch grant.Effect {
		case "Allow":
			if grant.IsPublic && !grant.HasCondition {
				public = true
				reasons = append(reasons, "bucket_policy_allow_to_wildcard_principal")
			}
			if grant.IsCrossAccount && !grant.HasCondition {
				crossAccount = true
				reasons = append(reasons, "bucket_policy_allow_to_cross_account_principal")
			}
		case "Deny":
			if grant.WildcardPrincipal && !grant.HasCondition {
				denyAll = true
				reasons = append(reasons, "bucket_policy_explicit_deny_to_all")
			}
		}
	}
	if record.PublicAccessBlock != nil &&
		record.PublicAccessBlock.BlockPublicACLs &&
		record.PublicAccessBlock.BlockPublicPolicy &&
		record.PublicAccessBlock.IgnorePublicACLs &&
		record.PublicAccessBlock.RestrictPublicBuckets {
		reasons = append(reasons, "public_access_block_fully_enabled")
		// PAB clamps policy-driven public exposure.
		public = false
	}
	// IAM semantics: an explicit Deny to all principals with no conditions
	// shadows any Allow regardless of the Allow's principals. Classify denyAll
	// first so a bucket with both an unconditional wildcard Deny and an
	// unconditional public/cross-account Allow is reported as restricted, not
	// public or cross_account.
	switch {
	case denyAll:
		return "restricted", dedupeStrings(reasons)
	case public:
		return "public", dedupeStrings(reasons)
	case crossAccount:
		return "cross_account", dedupeStrings(reasons)
	case record.HasBucketPolicy:
		return "private_with_grants", dedupeStrings(reasons)
	default:
		return "private", dedupeStrings(reasons)
	}
}

func canonicalS3GrantEffect(effect string) string {
	switch strings.ToLower(strings.TrimSpace(effect)) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return strings.TrimSpace(effect)
	}
}

func s3BucketReachabilityConfidence(record S3BucketReachability) float64 {
	switch record.ExposureClassification {
	case "public":
		return 0.95
	case "cross_account":
		return 0.92
	case "restricted":
		return 0.9
	case "private_with_grants":
		return 0.88
	case "private":
		return 0.86
	default:
		return 0.7
	}
}

func s3BucketReachabilitySourceID(record S3BucketReachability) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.BucketARN,
		record.BucketRegion,
	}), "|")
}

// s3BucketARNFromName synthesizes an S3 bucket ARN. The bucket name is
// global, so the partition is the only region-dependent piece. We pass the
// region so we can use the existing awsPartitionForRegion helper.
func s3BucketARNFromName(name, accountID, region string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	partition := awsPartitionForRegion(region)
	return fmt.Sprintf("arn:%s:s3:::%s", partition, trimmed)
}

// sortedAccessPoints returns a copy sorted by name, used by tests for
// deterministic comparison.
func sortedAccessPoints(points []S3AccessPointReference) []S3AccessPointReference {
	out := append([]S3AccessPointReference(nil), points...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var _ AWSServiceCollector = (*S3BucketReachabilityCollector)(nil)
var _ providers.Collector = (*S3BucketReachabilityCollector)(nil)
