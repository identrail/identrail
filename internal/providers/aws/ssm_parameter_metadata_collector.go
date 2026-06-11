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
	rawKindSSMParameterMetadata       = "ssm_parameter_metadata"
	ssmParameterMetadataCollectorName = "ssm_parameter_metadata"
	ssmServiceName                    = "ssm"

	// ssmParameterMetadataMaxPages bounds pagination for the SSM collector.
	// DescribeParameters caps page size at 50 items (ssmDescribeParametersMaxResults),
	// and an Advanced-tier account can hold up to 100,000 parameters, so the
	// budget must cover 100,000 / 50 = 2,000 pages — the shared 500-page
	// default would otherwise abort large accounts after only 25,000
	// parameters.
	ssmParameterMetadataMaxPages = 2000
)

// SSMParameterMetadata is the metadata-only view of one AWS Systems Manager
// Parameter Store parameter. It intentionally excludes parameter values and
// every API that can return them (GetParameter, GetParameters,
// GetParametersByPath, GetParameterHistory). SecureString parameters are
// treated as sensitive metadata only.
type SSMParameterMetadata struct {
	awscontract.ServiceCollectorRecord

	ParameterARN  string `json:"parameter_arn,omitempty"`
	ParameterName string `json:"parameter_name,omitempty"`
	ParameterPath string `json:"parameter_path,omitempty"`
	PathDepth     int    `json:"path_depth,omitempty"`
	ParameterType string `json:"parameter_type,omitempty"`
	Tier          string `json:"tier,omitempty"`
	DataType      string `json:"data_type,omitempty"`
	Version       int64  `json:"version,omitempty"`

	DescriptionPresent    bool `json:"description_present,omitempty"`
	AllowedPatternPresent bool `json:"allowed_pattern_present,omitempty"`

	KMSKeyID  string `json:"kms_key_id,omitempty"`
	KMSKeyARN string `json:"kms_key_arn,omitempty"`

	LastModifiedAt string `json:"last_modified_at,omitempty"`
	LastModifiedBy string `json:"last_modified_by,omitempty"`

	Policies []SSMParameterPolicy `json:"parameter_policies,omitempty"`
	Tags     map[string]string    `json:"tags,omitempty"`

	Sensitive                 bool     `json:"sensitive,omitempty"`
	SensitivityClassification string   `json:"sensitivity_classification,omitempty"`
	ExposureClassification    string   `json:"exposure_classification,omitempty"`
	ExposureReasons           []string `json:"exposure_reasons,omitempty"`

	ReferenceCount       int                       `json:"reference_count,omitempty"`
	ReferencedBy         []SecretWorkloadReference `json:"referenced_by,omitempty"`
	UnresolvedReferences []SecretWorkloadReference `json:"unresolved_references,omitempty"`
}

// SSMParameterPolicy summarizes one parameter policy without persisting the
// raw policy text. Expiration timestamps are operational metadata, not
// parameter values, so they stay inside the evidence boundary.
type SSMParameterPolicy struct {
	PolicyType   string `json:"policy_type,omitempty"`
	PolicyStatus string `json:"policy_status,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

type SSMParameterMetadataPage struct {
	Records     []SSMParameterMetadata
	NextToken   string
	Diagnostics []providers.SourceError
}

type SSMParameterMetadataAPI interface {
	ListParameterMetadata(ctx context.Context, nextToken string, pageSize int32) (SSMParameterMetadataPage, error)
}

type SSMParameterMetadataCollector struct {
	client   SSMParameterMetadataAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

type SSMParameterMetadataOption func(*SSMParameterMetadataCollector)

func WithSSMParameterMetadataPageSize(pageSize int32) SSMParameterMetadataOption {
	return func(c *SSMParameterMetadataCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithSSMParameterMetadataMaxPages(maxPages int) SSMParameterMetadataOption {
	return func(c *SSMParameterMetadataCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithSSMParameterMetadataClock(now func() time.Time) SSMParameterMetadataOption {
	return func(c *SSMParameterMetadataCollector) {
		if now != nil {
			c.now = now
		}
	}
}

func NewSSMParameterMetadataCollector(client SSMParameterMetadataAPI, opts ...SSMParameterMetadataOption) *SSMParameterMetadataCollector {
	c := &SSMParameterMetadataCollector{
		client:   client,
		pageSize: defaultPageSize,
		maxPages: ssmParameterMetadataMaxPages,
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

func (c *SSMParameterMetadataCollector) ServiceName() string {
	return ssmServiceName
}

func (c *SSMParameterMetadataCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: ssmServiceName})
	return assets, err
}

func (c *SSMParameterMetadataCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("ssm parameter metadata collector requires client")
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
			addIssue(ssmParameterMetadataDiagnostic("ssm_parameter_metadata_page_limit_exceeded", firstNonEmptyAWSValue(nextToken, "page"), fmt.Sprintf("ssm parameter metadata collection exceeded max pages (%d)", c.maxPages), false))
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("ssm parameter metadata collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (SSMParameterMetadataPage, error) {
			return c.client.ListParameterMetadata(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list ssm parameter metadata page %d: %w", page, err)
			addIssue(ssmParameterMetadataDiagnostic("ssm_parameter_metadata_page_failed", firstNonEmptyAWSValue(nextToken, "page"), wrapped.Error(), isRetryable(err)))
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
			normalized := normalizeSSMParameterMetadataScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.ParameterARN) == "" && strings.TrimSpace(normalized.ParameterName) == "" {
				addIssue(ssmParameterMetadataDiagnostic("malformed_ssm_parameter_record", "", "skipped ssm parameter record without an ARN or name", false))
				continue
			}
			sourceID := ssmParameterMetadataSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal ssm parameter metadata %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindSSMParameterMetadata,
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

func normalizeSSMParameterMetadataScope(scope AWSCollectorScope, record SSMParameterMetadata, collectedAt time.Time) SSMParameterMetadata {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID, accountIDFromARN(record.ParameterARN))
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region, regionFromARN(record.ParameterARN))
	normalized.Service = firstNonEmptyAWSValue(record.Service, ssmServiceName)
	normalized.ParameterName = firstNonEmptyAWSValue(record.ParameterName, ssmParameterNameFromARN(record.ParameterARN))
	normalized.ParameterARN = firstNonEmptyAWSValue(record.ParameterARN, ssmParameterARNFromName(normalized.ParameterName, normalized.AccountID, normalized.Region))
	normalized.ParameterPath, normalized.PathDepth = ssmParameterPathContext(normalized.ParameterName)
	normalized.ParameterType = canonicalSSMParameterType(record.ParameterType)
	normalized.Tier = canonicalSSMParameterTier(record.Tier)
	normalized.DataType = firstNonEmptyAWSValue(strings.TrimSpace(record.DataType), "text")
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "ssm_parameter")
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.ParameterName, normalized.ParameterARN)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.ParameterARN, normalized.ParameterName)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "ssm_parameter_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.ParameterARN, normalized.ParameterName)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, ssmParameterMetadataCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-ssm-parameter-metadata-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.KMSKeyID = strings.TrimSpace(record.KMSKeyID)
	if normalized.ParameterType == "secure_string" {
		normalized.KMSKeyARN = firstNonEmptyAWSValue(record.KMSKeyARN, resolveKMSKeyARN(normalized.KMSKeyID, normalized.AccountID, normalized.Region))
	} else {
		normalized.KMSKeyARN = strings.TrimSpace(record.KMSKeyARN)
	}
	normalized.LastModifiedAt = strings.TrimSpace(record.LastModifiedAt)
	normalized.LastModifiedBy = strings.TrimSpace(record.LastModifiedBy)
	normalized.Policies = normalizeSSMParameterPolicies(record.Policies)
	normalized.Tags = copyTags(record.Tags)
	normalized.ReferencedBy = normalizeSecretWorkloadReferences(record.ReferencedBy)
	normalized.UnresolvedReferences = normalizeSecretWorkloadReferences(record.UnresolvedReferences)
	normalized.ReferenceCount = len(normalized.ReferencedBy)
	normalized.Sensitive, normalized.SensitivityClassification = classifySSMParameterSensitivity(normalized)
	normalized.ExposureClassification, normalized.ExposureReasons = classifySSMParameterExposure(normalized)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = ssmParameterMetadataConfidence(normalized)
	}
	return normalized
}

func canonicalSSMParameterType(parameterType string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(parameterType), "_", "")) {
	case "securestring":
		return "secure_string"
	case "stringlist":
		return "string_list"
	case "string":
		return "string"
	case "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(parameterType))
	}
}

func canonicalSSMParameterTier(tier string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(tier), "-", ""), "_", "")) {
	case "advanced":
		return "advanced"
	case "intelligenttiering":
		return "intelligent_tiering"
	case "standard", "":
		return "standard"
	default:
		return strings.ToLower(strings.TrimSpace(tier))
	}
}

// ssmParameterPathContext derives the hierarchy prefix and depth for a
// parameter name. Hierarchical names start with "/" and use "/" separators;
// flat names have no path and depth one.
func ssmParameterPathContext(name string) (string, int) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", 0
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "", 1
	}
	segments := []string{}
	for _, segment := range strings.Split(strings.Trim(trimmed, "/"), "/") {
		if strings.TrimSpace(segment) != "" {
			segments = append(segments, segment)
		}
	}
	if len(segments) <= 1 {
		return "", len(segments)
	}
	return "/" + strings.Join(segments[:len(segments)-1], "/"), len(segments)
}

func normalizeSSMParameterPolicies(policies []SSMParameterPolicy) []SSMParameterPolicy {
	if len(policies) == 0 {
		return nil
	}
	out := make([]SSMParameterPolicy, 0, len(policies))
	for _, policy := range policies {
		policy.PolicyType = strings.TrimSpace(policy.PolicyType)
		policy.PolicyStatus = strings.ToLower(strings.TrimSpace(policy.PolicyStatus))
		policy.ExpiresAt = strings.TrimSpace(policy.ExpiresAt)
		if policy.PolicyType == "" && policy.PolicyStatus == "" && policy.ExpiresAt == "" {
			continue
		}
		out = append(out, policy)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PolicyType == out[j].PolicyType {
			return out[i].ExpiresAt < out[j].ExpiresAt
		}
		return out[i].PolicyType < out[j].PolicyType
	})
	return out
}

func classifySSMParameterSensitivity(record SSMParameterMetadata) (bool, string) {
	switch record.ParameterType {
	case "secure_string":
		if ssmParameterUsesCustomerKMSKey(record.KMSKeyID, record.KMSKeyARN) {
			return true, "secure_string_customer_kms"
		}
		return true, "secure_string_aws_managed_kms"
	case "string_list":
		return false, "string_list"
	default:
		return false, "plain_text"
	}
}

// ssmParameterUsesCustomerKMSKey reports whether a SecureString parameter is
// encrypted with a customer-managed key rather than the AWS-managed
// `alias/aws/ssm` default.
func ssmParameterUsesCustomerKMSKey(keyID string, keyARN string) bool {
	trimmedID := strings.ToLower(strings.TrimSpace(keyID))
	trimmedARN := strings.ToLower(strings.TrimSpace(keyARN))
	if trimmedID == "" && trimmedARN == "" {
		return false
	}
	return trimmedID != "alias/aws/ssm" && !strings.HasSuffix(trimmedARN, ":alias/aws/ssm")
}

func classifySSMParameterExposure(record SSMParameterMetadata) (string, []string) {
	reasons := []string{}
	if record.ReferenceCount > 0 {
		reasons = append(reasons, "workload_references_parameter")
		if record.ParameterType != "secure_string" {
			reasons = append(reasons, "plain_text_parameter_referenced_as_secret")
		}
	}
	if record.ParameterType == "secure_string" {
		reasons = append(reasons, "secure_string_kms_encrypted")
		if ssmParameterUsesCustomerKMSKey(record.KMSKeyID, record.KMSKeyARN) {
			reasons = append(reasons, "customer_kms_key_referenced")
		}
	}
	expiring := false
	for _, policy := range record.Policies {
		if strings.EqualFold(policy.PolicyType, "Expiration") {
			expiring = true
			reasons = append(reasons, "expiration_policy_present")
			break
		}
	}
	switch {
	case record.ReferenceCount > 0:
		return "referenced_by_workload", dedupeStrings(reasons)
	case expiring:
		return "scheduled_expiration", dedupeStrings(reasons)
	default:
		return "private", dedupeStrings(reasons)
	}
}

func ssmParameterMetadataConfidence(record SSMParameterMetadata) float64 {
	switch record.ExposureClassification {
	case "referenced_by_workload":
		return 0.9
	case "scheduled_expiration":
		return 0.87
	case "private":
		if record.Sensitive {
			return 0.86
		}
		return 0.85
	default:
		return 0.72
	}
}

func ssmParameterMetadataSourceID(record SSMParameterMetadata) string {
	// ParameterName is included alongside the ARN because name-only records
	// (fixtures, or records collected before an ARN is synthesized) would
	// otherwise collapse to `ssm||region` and deduplicate distinct
	// parameters away.
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.ParameterARN,
		record.ParameterName,
		record.Region,
	}), "|")
}

func ssmParameterResourceID(parameterARN string) string {
	return "aws:resource:ssm-parameter:" + strings.TrimSpace(parameterARN)
}

// ssmParameterNameFromARN extracts the parameter name from an SSM parameter
// ARN. Hierarchical names keep their leading slash:
// `arn:aws:ssm:us-east-1:123456789012:parameter/payments/db` -> `/payments/db`.
func ssmParameterNameFromARN(arn string) string {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) < 6 || !strings.EqualFold(parts[2], ssmServiceName) {
		return ""
	}
	resource := parts[5]
	if !strings.HasPrefix(resource, "parameter/") {
		return ""
	}
	name := strings.TrimPrefix(resource, "parameter")
	if strings.Count(strings.Trim(name, "/"), "/") == 0 {
		// Flat parameter names are stored without the leading slash.
		return strings.TrimPrefix(name, "/")
	}
	return name
}

// ssmParameterARNFromName synthesizes a parameter ARN when DescribeParameters
// does not return one. The resource segment always uses a single separator
// slash regardless of whether the name is hierarchical.
func ssmParameterARNFromName(name string, accountID string, region string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || strings.TrimSpace(accountID) == "" || strings.TrimSpace(region) == "" {
		return ""
	}
	partition := awsPartitionForRegion(region)
	return fmt.Sprintf("arn:%s:ssm:%s:%s:parameter/%s", partition, region, accountID, strings.TrimPrefix(trimmed, "/"))
}

// ssmParameterReferenceKeys returns every lookup key one parameter should be
// indexed under: the ARN plus slash and no-slash variants of the name, so
// `valueFrom: /payments/db` and `valueFrom: payments/db` both resolve.
func ssmParameterReferenceKeys(parameterARN string, parameterName string) []string {
	keys := []string{}
	if arn := strings.TrimSpace(parameterARN); arn != "" {
		keys = append(keys, arn)
		if name := ssmParameterNameFromARN(arn); name != "" {
			keys = append(keys, name)
		}
	}
	if name := strings.TrimSpace(parameterName); name != "" {
		keys = append(keys, name)
	}
	expanded := append([]string(nil), keys...)
	for _, key := range keys {
		if strings.HasPrefix(key, "arn:") {
			continue
		}
		expanded = append(expanded, strings.TrimPrefix(key, "/"), "/"+strings.TrimPrefix(key, "/"))
	}
	return dedupeStrings(expanded)
}

// ssmParameterReferenceKeysFromRef expands one workload reference (ECS
// `NAME=valueFrom`, CodeBuild `NAME=PARAMETER_STORE:ref`) into candidate
// lookup keys, stripping env-var assignment, source prefixes, and version or
// label suffixes. Parameter names cannot contain ":", so any colon in a
// non-ARN candidate separates a version/label suffix.
func ssmParameterReferenceKeysFromRef(ref string) []string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return nil
	}
	type referenceCandidate struct {
		value         string
		allowNameBase bool
	}
	candidates := []referenceCandidate{{value: trimmed}}
	if idx := strings.LastIndex(trimmed, "="); idx >= 0 && idx < len(trimmed)-1 {
		candidates = append(candidates, referenceCandidate{
			value:         strings.TrimSpace(trimmed[idx+1:]),
			allowNameBase: true,
		})
	}
	for _, prefix := range []string{"PARAMETER_STORE:", "parameter_store:", "ParameterStore:", "ssm:", "SSM:"} {
		for _, candidate := range append([]referenceCandidate(nil), candidates...) {
			if strings.HasPrefix(candidate.value, prefix) {
				candidates = append(candidates, referenceCandidate{
					value:         strings.TrimSpace(strings.TrimPrefix(candidate.value, prefix)),
					allowNameBase: true,
				})
			}
		}
	}
	out := []string{}
	for _, candidate := range candidates {
		value := strings.TrimSpace(candidate.value)
		if value == "" {
			continue
		}
		out = append(out, value)
		if base := ssmParameterReferenceBase(value, candidate.allowNameBase); base != "" && base != value {
			out = append(out, base)
			value = base
		}
		if name := ssmParameterNameFromARN(value); name != "" {
			out = append(out, name, strings.TrimPrefix(name, "/"))
		} else if !strings.HasPrefix(value, "arn:") {
			out = append(out, strings.TrimPrefix(value, "/"), "/"+strings.TrimPrefix(value, "/"))
		}
	}
	return dedupeStrings(out)
}

// ssmParameterReferenceBase strips a trailing `:version` or `:label` suffix.
// For ARNs the suffix follows the `parameter/...` resource segment; for bare
// names any colon starts the suffix because names cannot contain colons.
func ssmParameterReferenceBase(ref string, allowNameBase bool) string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, ":parameter/") {
		idx := strings.Index(trimmed, ":parameter/")
		resource := trimmed[idx+len(":parameter/"):]
		if colon := strings.Index(resource, ":"); colon > 0 {
			return trimmed[:idx+len(":parameter/")] + resource[:colon]
		}
		return trimmed
	}
	if allowNameBase && !strings.HasPrefix(trimmed, "arn:") {
		if idx := strings.Index(trimmed, ":"); idx > 0 {
			return strings.TrimSpace(trimmed[:idx])
		}
	}
	return trimmed
}

func ssmParameterMetadataDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: ssmParameterMetadataCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

var _ AWSServiceCollector = (*SSMParameterMetadataCollector)(nil)
var _ providers.Collector = (*SSMParameterMetadataCollector)(nil)
