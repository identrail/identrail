package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	rawKindSecretsManagerMetadata       = "secrets_manager_metadata"
	secretsManagerMetadataCollectorName = "secrets_manager_metadata"
	secretsManagerServiceName           = "secretsmanager"
)

// SecretsManagerSecretMetadata is the metadata-only view of one AWS Secrets
// Manager secret. It intentionally excludes SecretString, SecretBinary, and
// every API that can return secret material.
type SecretsManagerSecretMetadata struct {
	awscontract.ServiceCollectorRecord

	SecretARN          string `json:"secret_arn,omitempty"`
	SecretName         string `json:"secret_name,omitempty"`
	DescriptionPresent bool   `json:"description_present,omitempty"`
	KMSKeyID           string `json:"kms_key_id,omitempty"`
	KMSKeyARN          string `json:"kms_key_arn,omitempty"`
	OwningService      string `json:"owning_service,omitempty"`
	PrimaryRegion      string `json:"primary_region,omitempty"`
	SecretStatus       string `json:"secret_status,omitempty"`

	RotationEnabled        bool   `json:"rotation_enabled,omitempty"`
	RotationLambdaARN      string `json:"rotation_lambda_arn,omitempty"`
	RotationInterval       int64  `json:"rotation_interval_days,omitempty"`
	AutomaticallyAfterDays int64  `json:"automatically_after_days,omitempty"`

	CreatedAt      string `json:"created_at,omitempty"`
	LastChangedAt  string `json:"last_changed_at,omitempty"`
	LastAccessedAt string `json:"last_accessed_at,omitempty"`
	LastRotatedAt  string `json:"last_rotated_at,omitempty"`
	DeletedAt      string `json:"deleted_at,omitempty"`

	HasResourcePolicy            bool                          `json:"has_resource_policy,omitempty"`
	ResourcePolicyStatementCount int                           `json:"resource_policy_statement_count,omitempty"`
	IdentityGrants               []SecretsManagerIdentityGrant `json:"identity_grants,omitempty"`
	VersionStages                []SecretsManagerVersionStage  `json:"version_stages,omitempty"`
	ReplicaRegions               []SecretsManagerReplicaRegion `json:"replica_regions,omitempty"`
	Tags                         map[string]string             `json:"tags,omitempty"`

	ExposureClassification string                    `json:"exposure_classification,omitempty"`
	ExposureReasons        []string                  `json:"exposure_reasons,omitempty"`
	ReferenceCount         int                       `json:"reference_count,omitempty"`
	ReferencedBy           []SecretWorkloadReference `json:"referenced_by,omitempty"`
	UnresolvedReferences   []SecretWorkloadReference `json:"unresolved_references,omitempty"`

	Sensitive                         bool   `json:"sensitive,omitempty"`
	SensitivityClassification         string `json:"sensitivity_classification,omitempty"`
	SensitivityClassificationSource   string `json:"sensitivity_classification_source,omitempty"`
	SensitivityClassificationOverride string `json:"sensitivity_classification_override,omitempty"`
}

type SecretsManagerIdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"`
	Effect            string   `json:"effect"`
	Actions           []string `json:"actions,omitempty"`
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

type SecretsManagerVersionStage struct {
	VersionID    string   `json:"version_id,omitempty"`
	Stages       []string `json:"stages,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	LastAccessed string   `json:"last_accessed_at,omitempty"`
	KMSKeyIDs    []string `json:"kms_key_ids,omitempty"`
}

type SecretsManagerReplicaRegion struct {
	Region         string `json:"region,omitempty"`
	KMSKeyID       string `json:"kms_key_id,omitempty"`
	Status         string `json:"status,omitempty"`
	StatusMessage  string `json:"status_message,omitempty"`
	LastAccessedAt string `json:"last_accessed_at,omitempty"`
}

type SecretWorkloadReference struct {
	SourceService string  `json:"source_service,omitempty"`
	WorkloadID    string  `json:"workload_id,omitempty"`
	WorkloadType  string  `json:"workload_type,omitempty"`
	WorkloadName  string  `json:"workload_name,omitempty"`
	ResourceARN   string  `json:"resource_arn,omitempty"`
	ResourceID    string  `json:"resource_id,omitempty"`
	Reference     string  `json:"reference"`
	ReferenceKind string  `json:"reference_kind"`
	Confidence    float64 `json:"confidence"`
}

type SecretsManagerMetadataPage struct {
	Records     []SecretsManagerSecretMetadata
	NextToken   string
	Diagnostics []providers.SourceError
}

type SecretsManagerMetadataAPI interface {
	ListSecretMetadata(ctx context.Context, nextToken string, pageSize int32) (SecretsManagerMetadataPage, error)
}

type SecretsManagerMetadataCollector struct {
	client   SecretsManagerMetadataAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

type SecretsManagerMetadataOption func(*SecretsManagerMetadataCollector)

func WithSecretsManagerMetadataPageSize(pageSize int32) SecretsManagerMetadataOption {
	return func(c *SecretsManagerMetadataCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithSecretsManagerMetadataMaxPages(maxPages int) SecretsManagerMetadataOption {
	return func(c *SecretsManagerMetadataCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithSecretsManagerMetadataClock(now func() time.Time) SecretsManagerMetadataOption {
	return func(c *SecretsManagerMetadataCollector) {
		if now != nil {
			c.now = now
		}
	}
}

func NewSecretsManagerMetadataCollector(client SecretsManagerMetadataAPI, opts ...SecretsManagerMetadataOption) *SecretsManagerMetadataCollector {
	c := &SecretsManagerMetadataCollector{
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

func (c *SecretsManagerMetadataCollector) ServiceName() string {
	return secretsManagerServiceName
}

func (c *SecretsManagerMetadataCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: secretsManagerServiceName})
	return assets, err
}

func (c *SecretsManagerMetadataCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("secrets manager metadata collector requires client")
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
			addIssue(secretsManagerMetadataDiagnostic("secrets_manager_metadata_page_limit_exceeded", firstNonEmptyAWSValue(nextToken, "page"), fmt.Sprintf("secrets manager metadata collection exceeded max pages (%d)", c.maxPages), false))
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("secrets manager metadata collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (SecretsManagerMetadataPage, error) {
			return c.client.ListSecretMetadata(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list secrets manager metadata page %d: %w", page, err)
			addIssue(secretsManagerMetadataDiagnostic("secrets_manager_metadata_page_failed", firstNonEmptyAWSValue(nextToken, "page"), wrapped.Error(), isRetryable(err)))
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
			normalized := normalizeSecretsManagerMetadataScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.SecretARN) == "" && strings.TrimSpace(normalized.SecretName) == "" {
				addIssue(secretsManagerMetadataDiagnostic("malformed_secrets_manager_record", "", "skipped secrets manager record without an ARN or name", false))
				continue
			}
			sourceID := secretsManagerMetadataSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal secrets manager metadata %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindSecretsManagerMetadata,
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

func normalizeSecretsManagerMetadataScope(scope AWSCollectorScope, record SecretsManagerSecretMetadata, collectedAt time.Time) SecretsManagerSecretMetadata {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID, accountIDFromARN(record.SecretARN))
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region, regionFromARN(record.SecretARN))
	normalized.Service = firstNonEmptyAWSValue(record.Service, secretsManagerServiceName)
	normalized.SecretARN = strings.TrimSpace(record.SecretARN)
	normalized.SecretName = firstNonEmptyAWSValue(record.SecretName, secretNameFromARN(record.SecretARN))
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "secrets_manager_secret")
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.SecretName, normalized.SecretARN)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.SecretARN, normalized.SecretName)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "secrets_manager_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.SecretARN, normalized.SecretName)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, secretsManagerMetadataCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-secrets-manager-metadata-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.DescriptionPresent = record.DescriptionPresent
	normalized.KMSKeyID = strings.TrimSpace(record.KMSKeyID)
	normalized.KMSKeyARN = firstNonEmptyAWSValue(record.KMSKeyARN, secretsManagerKMSKeyARN(record.KMSKeyID, normalized.AccountID, normalized.Region))
	normalized.OwningService = strings.TrimSpace(record.OwningService)
	normalized.PrimaryRegion = strings.TrimSpace(record.PrimaryRegion)
	normalized.SecretStatus = firstNonEmptyAWSValue(record.SecretStatus, secretsManagerSecretStatus(record))
	normalized.IdentityGrants = annotateSecretsManagerGrants(record.IdentityGrants, normalized.AccountID)
	normalized.VersionStages = normalizeSecretsManagerVersionStages(record.VersionStages)
	normalized.ReplicaRegions = normalizeSecretsManagerReplicaRegions(record.ReplicaRegions)
	normalized.Tags = copyTags(record.Tags)
	normalized.ReferencedBy = normalizeSecretWorkloadReferences(record.ReferencedBy)
	normalized.UnresolvedReferences = normalizeSecretWorkloadReferences(record.UnresolvedReferences)
	normalized.ReferenceCount = len(normalized.ReferencedBy)
	normalized.Sensitive = true
	normalized.SensitivityClassification, normalized.SensitivityClassificationSource, normalized.SensitivityClassificationOverride = classifySecretsManagerSensitivity(normalized)
	normalized.ExposureClassification, normalized.ExposureReasons = classifySecretsManagerExposure(normalized)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = secretsManagerMetadataConfidence(normalized)
	}
	return normalized
}

// secretsManagerKMSKeyARN resolves a Secrets Manager KmsKeyId value to a key
// ARN. The field can carry a full ARN, an alias (`alias/...`), or a bare key
// id; only the bare id needs a synthesized key ARN.
func secretsManagerKMSKeyARN(keyID, accountID, region string) string {
	return resolveKMSKeyARN(keyID, accountID, region)
}

func annotateSecretsManagerGrants(grants []SecretsManagerIdentityGrant, accountID string) []SecretsManagerIdentityGrant {
	if len(grants) == 0 {
		return nil
	}
	out := make([]SecretsManagerIdentityGrant, 0, len(grants))
	for _, grant := range grants {
		grant.PrincipalARN = strings.TrimSpace(grant.PrincipalARN)
		grant.PrincipalType = strings.ToLower(strings.TrimSpace(grant.PrincipalType))
		grant.Effect = canonicalKMSGrantEffect(grant.Effect)
		grant.Actions = normalizeStringList(grant.Actions)
		grant.ConditionKeys = normalizeStringList(grant.ConditionKeys)
		grant.WildcardPrincipal = grant.WildcardPrincipal || grant.PrincipalARN == "*"
		grant.IsPublic = grant.IsPublic || grant.WildcardPrincipal
		if !grant.IsCrossAccount && accountID != "" && grant.PrincipalARN != "" && grant.PrincipalARN != "*" {
			grantAccount := accountIDFromPrincipal(grant.PrincipalARN)
			if grantAccount != "" && grantAccount != accountID {
				grant.IsCrossAccount = true
			}
		}
		grant.HasCondition = grant.HasCondition || len(grant.ConditionKeys) > 0
		out = append(out, grant)
	}
	return out
}

func normalizeSecretsManagerVersionStages(stages []SecretsManagerVersionStage) []SecretsManagerVersionStage {
	if len(stages) == 0 {
		return nil
	}
	out := append([]SecretsManagerVersionStage(nil), stages...)
	for i := range out {
		out[i].VersionID = strings.TrimSpace(out[i].VersionID)
		out[i].Stages = normalizeStringList(out[i].Stages)
		out[i].KMSKeyIDs = normalizeStringList(out[i].KMSKeyIDs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VersionID < out[j].VersionID })
	return out
}

func normalizeSecretsManagerReplicaRegions(replicas []SecretsManagerReplicaRegion) []SecretsManagerReplicaRegion {
	if len(replicas) == 0 {
		return nil
	}
	out := append([]SecretsManagerReplicaRegion(nil), replicas...)
	for i := range out {
		out[i].Region = strings.TrimSpace(out[i].Region)
		out[i].KMSKeyID = strings.TrimSpace(out[i].KMSKeyID)
		out[i].Status = strings.TrimSpace(out[i].Status)
		out[i].StatusMessage = strings.TrimSpace(out[i].StatusMessage)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Region < out[j].Region })
	return out
}

func normalizeSecretWorkloadReferences(refs []SecretWorkloadReference) []SecretWorkloadReference {
	if len(refs) == 0 {
		return nil
	}
	out := append([]SecretWorkloadReference(nil), refs...)
	for i := range out {
		out[i].SourceService = strings.TrimSpace(out[i].SourceService)
		out[i].WorkloadID = strings.TrimSpace(out[i].WorkloadID)
		out[i].WorkloadType = strings.TrimSpace(out[i].WorkloadType)
		out[i].WorkloadName = strings.TrimSpace(out[i].WorkloadName)
		out[i].ResourceARN = strings.TrimSpace(out[i].ResourceARN)
		out[i].ResourceID = strings.TrimSpace(out[i].ResourceID)
		out[i].Reference = strings.TrimSpace(out[i].Reference)
		out[i].ReferenceKind = strings.TrimSpace(out[i].ReferenceKind)
		if out[i].Confidence <= 0 {
			out[i].Confidence = 0.82
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].WorkloadID == out[j].WorkloadID {
			return out[i].Reference < out[j].Reference
		}
		return out[i].WorkloadID < out[j].WorkloadID
	})
	return out
}

func classifySecretsManagerExposure(record SecretsManagerSecretMetadata) (string, []string) {
	reasons := []string{}
	public := false
	crossAccount := false
	for _, grant := range record.IdentityGrants {
		if !strings.EqualFold(grant.Effect, "Allow") {
			continue
		}
		if grant.IsPublic && !grant.HasCondition {
			public = true
			reasons = append(reasons, "resource_policy_allow_to_wildcard_principal")
		}
		if grant.IsCrossAccount && !grant.HasCondition {
			crossAccount = true
			reasons = append(reasons, "resource_policy_allow_to_cross_account_principal")
		}
	}
	if record.RotationEnabled {
		reasons = append(reasons, "rotation_enabled")
	}
	if record.KMSKeyARN != "" {
		reasons = append(reasons, "customer_kms_key_referenced")
	}
	if record.ReferenceCount > 0 {
		reasons = append(reasons, "workload_references_secret")
	}
	switch {
	case public:
		return "public", dedupeStrings(reasons)
	case crossAccount:
		return "cross_account", dedupeStrings(reasons)
	case record.HasResourcePolicy:
		return "resource_policy_scoped", dedupeStrings(reasons)
	case record.ReferenceCount > 0:
		return "referenced_by_workload", dedupeStrings(reasons)
	case record.SecretStatus == "scheduled_deletion":
		return "scheduled_deletion", dedupeStrings(reasons)
	default:
		return "private", dedupeStrings(reasons)
	}
}

func secretsManagerSecretStatus(record SecretsManagerSecretMetadata) string {
	if strings.TrimSpace(record.DeletedAt) != "" {
		return "scheduled_deletion"
	}
	return "active"
}

func secretsManagerMetadataConfidence(record SecretsManagerSecretMetadata) float64 {
	switch record.ExposureClassification {
	case "public":
		return 0.95
	case "cross_account":
		return 0.92
	case "resource_policy_scoped":
		return 0.89
	case "referenced_by_workload":
		return 0.88
	case "private":
		return 0.86
	default:
		return 0.72
	}
}

func secretsManagerMetadataSourceID(record SecretsManagerSecretMetadata) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.SecretARN,
		record.Region,
	}), "|")
}

func secretsManagerSecretResourceID(secretARN string) string {
	return "aws:resource:secrets-manager-secret:" + strings.TrimSpace(secretARN)
}

func secretsManagerReferenceKeys(secretARN string, secretName string) []string {
	keys := []string{}
	if arn := strings.TrimSpace(secretARN); arn != "" {
		keys = append(keys, arn)
		if name := secretNameFromARN(arn); name != "" {
			keys = append(keys, name)
		}
	}
	if name := strings.TrimSpace(secretName); name != "" {
		keys = append(keys, name)
	}
	return dedupeStrings(keys)
}

func secretsManagerReferenceKeysFromRef(ref string) []string {
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
	for _, prefix := range []string{"SECRETS_MANAGER:", "secretsmanager:", "SecretsManager:"} {
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
		if base := secretsManagerReferenceBase(value, candidate.allowNameBase); base != "" && base != value {
			out = append(out, base)
			value = base
		}
		if strings.Contains(value, ":secretsmanager:") {
			out = append(out, secretNameFromARN(value))
		}
	}
	return dedupeStrings(out)
}

func secretsManagerReferenceBase(ref string, allowNameBase bool) string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, ":secretsmanager:") && strings.Contains(trimmed, ":secret:") {
		parts := strings.SplitN(trimmed, ":secret:", 2)
		if len(parts) != 2 {
			return trimmed
		}
		resource := strings.TrimSpace(parts[1])
		if idx := strings.Index(resource, ":"); idx > 0 {
			resource = resource[:idx]
		}
		return parts[0] + ":secret:" + resource
	}
	if allowNameBase {
		if idx := strings.Index(trimmed, ":"); idx > 0 {
			return strings.TrimSpace(trimmed[:idx])
		}
	}
	return trimmed
}

func secretNameFromARN(arn string) string {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 7)
	if len(parts) < 7 {
		return ""
	}
	resource := strings.TrimPrefix(parts[6], "secret:")
	if idx := strings.Index(resource, ":"); idx > 0 {
		resource = resource[:idx]
	}
	if idx := strings.LastIndex(resource, "-"); idx > 0 && len(resource)-idx == 7 {
		return resource[:idx]
	}
	return resource
}

func regionFromARN(arn string) string {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) < 4 {
		return ""
	}
	return strings.TrimSpace(parts[3])
}

func secretsManagerMetadataDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: secretsManagerMetadataCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

type secretsManagerPolicyDocument struct {
	Statement secretsManagerPolicyStmtList `json:"Statement"`
}

type secretsManagerPolicyStmtList []secretsManagerPolicyStatement

type secretsManagerPolicyStatement struct {
	Sid          string         `json:"Sid,omitempty"`
	Effect       string         `json:"Effect"`
	Principal    any            `json:"Principal,omitempty"`
	NotPrincipal any            `json:"NotPrincipal,omitempty"`
	Action       any            `json:"Action,omitempty"`
	NotAction    any            `json:"NotAction,omitempty"`
	Condition    map[string]any `json:"Condition,omitempty"`
}

func (s *secretsManagerPolicyStmtList) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}
	var single secretsManagerPolicyStatement
	if err := json.Unmarshal(data, &single); err == nil && single.Effect != "" {
		*s = []secretsManagerPolicyStatement{single}
		return nil
	}
	var many []secretsManagerPolicyStatement
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	return errors.New("invalid secrets manager policy statement shape")
}

func parseSecretsManagerResourcePolicyGrants(raw string, ownerAccountID string) ([]SecretsManagerIdentityGrant, int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, 0, nil
	}
	decoded := trimmed
	if strings.Contains(trimmed, "%") {
		if unescaped, err := url.QueryUnescape(trimmed); err == nil {
			decoded = unescaped
		}
	}
	var doc secretsManagerPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, 0, err
	}
	grants := []SecretsManagerIdentityGrant{}
	for _, statement := range doc.Statement {
		effect := canonicalKMSGrantEffect(statement.Effect)
		if effect == "" || statement.Principal == nil && statement.NotPrincipal != nil {
			continue
		}
		if len(parseStringList(statement.NotAction)) > 0 {
			continue
		}
		principals := kmsExtractPrincipals(statement.Principal)
		if len(principals) == 0 {
			continue
		}
		actions := normalizeStringList(parseStringList(statement.Action))
		conditionKeys := kmsCollectConditionKeys(statement.Condition)
		for _, principal := range principals {
			grant := SecretsManagerIdentityGrant{
				PrincipalARN:      principal.Value,
				PrincipalType:     principal.Type,
				Effect:            effect,
				Actions:           actions,
				ConditionKeys:     conditionKeys,
				HasCondition:      len(conditionKeys) > 0,
				StatementSid:      strings.TrimSpace(statement.Sid),
				WildcardPrincipal: principal.Wildcard,
			}
			if grant.WildcardPrincipal {
				grant.IsPublic = true
			}
			if ownerAccountID != "" && grant.PrincipalARN != "" && grant.PrincipalARN != "*" {
				grantAccount := accountIDFromPrincipal(grant.PrincipalARN)
				grant.IsCrossAccount = grantAccount != "" && grantAccount != ownerAccountID
			}
			grants = append(grants, grant)
		}
	}
	return grants, len(doc.Statement), nil
}

var _ AWSServiceCollector = (*SecretsManagerMetadataCollector)(nil)
var _ providers.Collector = (*SecretsManagerMetadataCollector)(nil)
