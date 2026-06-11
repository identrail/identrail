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
	rawKindKMSDecryptReachability       = "kms_decrypt_reachability"
	kmsDecryptReachabilityCollectorName = "kms_decrypt_reachability"
	kmsServiceName                      = "kms"
)

// KMSDecryptReachability is the normalized envelope describing one KMS key
// (and the inferred identity reachability into it). The collector captures
// metadata only — never plaintext material, never ciphertext, never
// CloudTrail event bodies — so this struct holds key configuration,
// rotation status, exposure signals, and inferred identity grants from the
// key policy *and* live KMS grants.
type KMSDecryptReachability struct {
	awscontract.ServiceCollectorRecord

	KeyARN       string `json:"key_arn,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	KeyManager   string `json:"key_manager,omitempty"` // AWS / CUSTOMER
	KeyState     string `json:"key_state,omitempty"`   // Enabled / Disabled / PendingDeletion / ...
	KeyUsage     string `json:"key_usage,omitempty"`   // ENCRYPT_DECRYPT / SIGN_VERIFY / ...
	KeySpec      string `json:"key_spec,omitempty"`    // SYMMETRIC_DEFAULT / RSA_4096 / ...
	Origin       string `json:"origin,omitempty"`      // AWS_KMS / EXTERNAL / AWS_CLOUDHSM
	Description  string `json:"description,omitempty"`
	Enabled      bool   `json:"enabled,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	DeletionDate string `json:"deletion_date,omitempty"`

	// Multi-region replica metadata. Reachability is mostly governed by the
	// per-region key policy, but multi-region keys propagate ciphertext across
	// regions and operators should see the replica relationship explicitly.
	MultiRegion        bool     `json:"multi_region,omitempty"`
	MultiRegionPrimary bool     `json:"multi_region_primary,omitempty"`
	PrimaryKeyARN      string   `json:"primary_key_arn,omitempty"`
	ReplicaKeyARNs     []string `json:"replica_key_arns,omitempty"`

	// Rotation surface. We surface whether rotation *is* enabled and whether
	// the key *can* be rotated — symmetric customer-managed keys without an
	// imported key material support automatic rotation; others do not.
	RotationEnabled   bool   `json:"rotation_enabled,omitempty"`
	RotationSupported bool   `json:"rotation_supported,omitempty"`
	LastRotatedAt     string `json:"last_rotated_at,omitempty"`

	// Aliases attached to the key. Aliases are how most callers reference KMS
	// keys, so surfacing them avoids ARN-only output.
	Aliases []string `json:"aliases,omitempty"`

	// Key policy + parsed grants.
	HasKeyPolicy            bool               `json:"has_key_policy,omitempty"`
	KeyPolicyStatementCount int                `json:"key_policy_statement_count,omitempty"`
	IAMDelegationEnabled    bool               `json:"iam_delegation_enabled,omitempty"`
	IdentityGrants          []KMSIdentityGrant `json:"identity_grants,omitempty"`

	// Live KMS grants (a separate AWS primitive from key policies).
	Grants []KMSGrant `json:"grants,omitempty"`

	// Exposure summary computed across policy, IAM delegation, and grant
	// signals.
	ExposureClassification string   `json:"exposure_classification,omitempty"`
	ExposureReasons        []string `json:"exposure_reasons,omitempty"`

	Tags map[string]string `json:"tags,omitempty"`
}

// KMSIdentityGrant is one principal-to-key grant inferred from the key
// policy. KMS specifies actions like kms:Decrypt, kms:Encrypt,
// kms:GenerateDataKey*, kms:ReEncrypt*, kms:CreateGrant, etc. We bucket the
// actions into capability classes so the API can render them without each
// caller re-deriving the mapping.
type KMSIdentityGrant struct {
	PrincipalARN      string   `json:"principal_arn,omitempty"`
	PrincipalType     string   `json:"principal_type,omitempty"` // aws / service / federated / canonical_user / *
	Effect            string   `json:"effect"`                   // Allow / Deny
	Actions           []string `json:"actions,omitempty"`
	NotAction         bool     `json:"not_action,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"` // decrypt / encrypt / admin / grant / sign / verify
	ConditionKeys     []string `json:"condition_keys,omitempty"`
	HasCondition      bool     `json:"has_condition,omitempty"`
	StatementSid      string   `json:"statement_sid,omitempty"`
	IsPublic          bool     `json:"is_public,omitempty"`
	IsCrossAccount    bool     `json:"is_cross_account,omitempty"`
	WildcardPrincipal bool     `json:"wildcard_principal,omitempty"`
}

// KMSGrant mirrors a single live KMS grant as returned by ListGrants. KMS
// grants are an out-of-policy reachability primitive: they allow a principal
// to use a key without editing the key policy, so missing them would leave a
// reachability blind spot. We never include the encryption-context values
// (those can be sensitive); only the constraint *keys* are surfaced.
type KMSGrant struct {
	GrantID                     string   `json:"grant_id,omitempty"`
	Name                        string   `json:"name,omitempty"`
	GranteePrincipal            string   `json:"grantee_principal,omitempty"`
	GranteePrincipalType        string   `json:"grantee_principal_type,omitempty"` // aws / service
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

// KMSDecryptReachabilityPage is one page of normalized key records plus
// per-page collector diagnostics.
type KMSDecryptReachabilityPage struct {
	Records     []KMSDecryptReachability
	NextToken   string
	Diagnostics []providers.SourceError
}

// KMSDecryptReachabilityAPI is the narrow seam between the collector and
// the underlying SDK or fixture client.
type KMSDecryptReachabilityAPI interface {
	ListKMSKeyReachability(ctx context.Context, nextToken string, pageSize int32) (KMSDecryptReachabilityPage, error)
}

// KMSDecryptReachabilityCollector turns KMS key metadata into payload-safe
// normalized records and exposure-classified identity reachability evidence.
type KMSDecryptReachabilityCollector struct {
	client   KMSDecryptReachabilityAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

// KMSDecryptReachabilityOption tunes the collector.
type KMSDecryptReachabilityOption func(*KMSDecryptReachabilityCollector)

func WithKMSDecryptReachabilityPageSize(pageSize int32) KMSDecryptReachabilityOption {
	return func(c *KMSDecryptReachabilityCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithKMSDecryptReachabilityMaxPages(maxPages int) KMSDecryptReachabilityOption {
	return func(c *KMSDecryptReachabilityCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithKMSDecryptReachabilityRetryPolicy(policy RetryPolicy) KMSDecryptReachabilityOption {
	return func(c *KMSDecryptReachabilityCollector) {
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

func WithKMSDecryptReachabilitySleeper(s Sleeper) KMSDecryptReachabilityOption {
	return func(c *KMSDecryptReachabilityCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func WithKMSDecryptReachabilityClock(now func() time.Time) KMSDecryptReachabilityOption {
	return func(c *KMSDecryptReachabilityCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewKMSDecryptReachabilityCollector constructs the collector with the same
// defaults as the rest of the AWS service collectors.
func NewKMSDecryptReachabilityCollector(client KMSDecryptReachabilityAPI, opts ...KMSDecryptReachabilityOption) *KMSDecryptReachabilityCollector {
	c := &KMSDecryptReachabilityCollector{
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
func (c *KMSDecryptReachabilityCollector) ServiceName() string {
	return kmsServiceName
}

// Collect satisfies providers.Collector for callers without a scope.
func (c *KMSDecryptReachabilityCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: kmsServiceName})
	return assets, err
}

// CollectWithDiagnostics walks every KMS key in the account, normalizes the
// metadata, and emits one raw asset per key. Per-call state lives in local
// variables so concurrent invocations on the same collector instance do not
// race.
func (c *KMSDecryptReachabilityCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("kms decrypt reachability collector requires client")
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
				Collector: kmsDecryptReachabilityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "kms_decrypt_reachability_page_limit_exceeded",
				Message:   fmt.Sprintf("kms decrypt reachability collection exceeded max pages (%d)", c.maxPages),
				Retryable: false,
			})
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("kms decrypt reachability collection exceeded max pages (%d)", c.maxPages)
		}
		response, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (KMSDecryptReachabilityPage, error) {
			return c.client.ListKMSKeyReachability(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list kms keys for reachability page %d: %w", page, err)
			addIssue(providers.SourceError{
				Collector: kmsDecryptReachabilityCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "kms_decrypt_reachability_page_failed",
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
			normalized := normalizeKMSDecryptReachabilityScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.KeyARN) == "" && strings.TrimSpace(normalized.KeyID) == "" {
				addIssue(providers.SourceError{
					Collector: kmsDecryptReachabilityCollectorName,
					Code:      "malformed_kms_decrypt_reachability_record",
					Message:   "skipped kms key record without an ARN or key id",
					Retryable: false,
				})
				continue
			}
			sourceID := kmsDecryptReachabilitySourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal kms decrypt reachability %q: %w", sourceID, err)
			}
			assets = append(assets, providers.RawAsset{
				Kind:      rawKindKMSDecryptReachability,
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

// normalizeKMSDecryptReachabilityScope fills in scope/contract fields and
// computes the exposure classification from the key's settings + grants.
func normalizeKMSDecryptReachabilityScope(scope AWSCollectorScope, record KMSDecryptReachability, collectedAt time.Time) KMSDecryptReachability {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID, accountIDFromARN(record.KeyARN))
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, kmsServiceName)
	normalized.KeyID = strings.TrimSpace(record.KeyID)
	normalized.KeyARN = strings.TrimSpace(record.KeyARN)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "kms_key")
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, normalized.KeyID, normalized.KeyARN)
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, normalized.KeyARN, normalized.KeyID)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "kms_key_metadata")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.KeyARN, normalized.KeyID)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, kmsDecryptReachabilityCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-kms-decrypt-reachability-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.KeyManager = strings.ToUpper(strings.TrimSpace(record.KeyManager))
	normalized.KeyState = strings.TrimSpace(record.KeyState)
	normalized.KeyUsage = strings.TrimSpace(record.KeyUsage)
	normalized.KeySpec = strings.TrimSpace(record.KeySpec)
	normalized.Origin = strings.TrimSpace(record.Origin)
	normalized.Aliases = dedupeStrings(normalizeStringList(record.Aliases))
	normalized.ReplicaKeyARNs = dedupeStrings(normalizeStringList(record.ReplicaKeyARNs))
	normalized.PrimaryKeyARN = strings.TrimSpace(record.PrimaryKeyARN)
	normalized.IdentityGrants = annotateKMSGrants(record.IdentityGrants, normalized.AccountID)
	normalized.Grants = annotateKMSLiveGrants(record.Grants, normalized.AccountID)
	normalized.ExposureClassification, normalized.ExposureReasons = classifyKMSKeyExposure(normalized)
	normalized.Tags = copyTags(record.Tags)
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = kmsDecryptReachabilityConfidence(normalized)
	}
	return normalized
}

// annotateKMSGrants enriches each key-policy grant with cross-account /
// public flags derived from the principal ARN and the key-owning account,
// and computes capability classes from the action list.
func annotateKMSGrants(grants []KMSIdentityGrant, accountID string) []KMSIdentityGrant {
	if len(grants) == 0 {
		return nil
	}
	out := make([]KMSIdentityGrant, 0, len(grants))
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
		grant.Capabilities = kmsCapabilitiesForActions(grant.Actions)
		out = append(out, grant)
	}
	return out
}

// annotateKMSLiveGrants enriches each live KMS grant with cross-account
// flags + capability classes.
func annotateKMSLiveGrants(grants []KMSGrant, accountID string) []KMSGrant {
	if len(grants) == 0 {
		return nil
	}
	out := make([]KMSGrant, 0, len(grants))
	for _, grant := range grants {
		grant.GranteePrincipal = strings.TrimSpace(grant.GranteePrincipal)
		grant.GranteePrincipalType = strings.ToLower(strings.TrimSpace(grant.GranteePrincipalType))
		grant.RetiringPrincipal = strings.TrimSpace(grant.RetiringPrincipal)
		grant.IssuingAccount = strings.TrimSpace(grant.IssuingAccount)
		grant.Operations = normalizeStringList(grant.Operations)
		grant.EncryptionContextKeys = dedupeStrings(normalizeStringList(grant.EncryptionContextKeys))
		grant.EncryptionContextSubsetKeys = dedupeStrings(normalizeStringList(grant.EncryptionContextSubsetKeys))
		grant.HasConstraints = grant.HasConstraints || len(grant.EncryptionContextKeys) > 0 || len(grant.EncryptionContextSubsetKeys) > 0
		grant.Capabilities = kmsCapabilitiesForActions(grant.Operations)
		if !grant.IsCrossAccount && accountID != "" && grant.GranteePrincipal != "" {
			granteeAccount := accountIDFromPrincipal(grant.GranteePrincipal)
			if granteeAccount != "" && granteeAccount != accountID {
				grant.IsCrossAccount = true
			}
		}
		out = append(out, grant)
	}
	return out
}

// kmsCapabilitiesForActions buckets KMS action strings into capability
// classes. Returned values are sorted and deduped so output is deterministic.
//
// The mapping is deliberately strict — a KMS action that does not appear here
// is *not* silently classed as "other"; instead it is omitted from the
// capability list so a future KMS API addition does not get hidden inside an
// opaque bucket.
func kmsCapabilitiesForActions(actions []string) []string {
	if len(actions) == 0 {
		return nil
	}
	caps := map[string]struct{}{}
	for _, action := range actions {
		trimmed := strings.TrimSpace(action)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case lower == "*", lower == "kms:*":
			caps["decrypt"] = struct{}{}
			caps["encrypt"] = struct{}{}
			caps["admin"] = struct{}{}
			caps["grant"] = struct{}{}
			caps["sign"] = struct{}{}
		case lower == "kms:decrypt", lower == "decrypt":
			caps["decrypt"] = struct{}{}
		case strings.HasPrefix(lower, "kms:reencrypt"), strings.HasPrefix(lower, "reencrypt"):
			caps["decrypt"] = struct{}{}
			caps["encrypt"] = struct{}{}
		case strings.HasPrefix(lower, "kms:generatedatakey"), strings.HasPrefix(lower, "generatedatakey"):
			caps["decrypt"] = struct{}{}
			caps["encrypt"] = struct{}{}
		case lower == "kms:encrypt", lower == "encrypt":
			caps["encrypt"] = struct{}{}
		case lower == "kms:sign", lower == "sign":
			caps["sign"] = struct{}{}
		case lower == "kms:verify", lower == "verify":
			caps["sign"] = struct{}{}
		case lower == "kms:creategrant", lower == "creategrant":
			caps["grant"] = struct{}{}
		case lower == "kms:retiregrant", lower == "retiregrant",
			lower == "kms:revokegrant", lower == "revokegrant",
			lower == "kms:listgrants", lower == "listgrants":
			caps["grant"] = struct{}{}
		case lower == "kms:putkeypolicy", lower == "putkeypolicy",
			lower == "kms:schedulekeydeletion", lower == "schedulekeydeletion",
			lower == "kms:disablekey", lower == "disablekey",
			lower == "kms:enablekey", lower == "enablekey",
			lower == "kms:cancelkeydeletion", lower == "cancelkeydeletion",
			lower == "kms:updatekeydescription", lower == "updatekeydescription",
			lower == "kms:enablekeyrotation", lower == "enablekeyrotation",
			lower == "kms:disablekeyrotation", lower == "disablekeyrotation",
			lower == "kms:tagresource", lower == "tagresource",
			lower == "kms:untagresource", lower == "untagresource",
			lower == "kms:replicatekey", lower == "replicatekey",
			lower == "kms:updateprimaryregion", lower == "updateprimaryregion":
			caps["admin"] = struct{}{}
		}
	}
	if len(caps) == 0 {
		return nil
	}
	out := make([]string, 0, len(caps))
	for cap := range caps {
		out = append(out, cap)
	}
	sort.Strings(out)
	return out
}

// classifyKMSKeyExposure folds policy, IAM delegation, and grant signals
// into one of "public" / "cross_account" / "restricted" /
// "managed_by_iam" / "private_with_grants" / "private". The reasons slice
// explains the contributing signals so the API can render an audit-friendly
// summary.
//
// Notes:
//   - AWS-managed keys (KeyManager=AWS) cannot have their policy changed by
//     the customer, so we always classify them as "managed_by_aws" — they
//     are a documented coverage class rather than a finding.
//   - "EnableIAMUserPermissions"-only key policies delegate access entirely
//     to IAM. That is the AWS default and is not, on its own, an exposure
//     finding, so it gets its own classification.
func classifyKMSKeyExposure(record KMSDecryptReachability) (string, []string) {
	reasons := []string{}
	if strings.EqualFold(record.KeyManager, "AWS") {
		reasons = append(reasons, "kms_managed_by_aws")
		return "managed_by_aws", dedupeStrings(reasons)
	}
	public := false
	crossAccount := false
	denyAll := false
	hasNonDelegationGrant := false
	for _, grant := range record.IdentityGrants {
		switch grant.Effect {
		case "Allow":
			if grant.IsPublic && !grant.HasCondition {
				public = true
				reasons = append(reasons, "kms_key_policy_allow_to_wildcard_principal")
			}
			if grant.IsCrossAccount && !grant.HasCondition {
				crossAccount = true
				reasons = append(reasons, "kms_key_policy_allow_to_cross_account_principal")
			}
			if !isIAMDelegationGrant(grant, record.AccountID) {
				hasNonDelegationGrant = true
			}
		case "Deny":
			if grant.WildcardPrincipal && !grant.HasCondition {
				denyAll = true
				reasons = append(reasons, "kms_key_policy_explicit_deny_to_all")
			}
		}
	}
	for _, g := range record.Grants {
		if g.IsCrossAccount {
			crossAccount = true
			reasons = append(reasons, "kms_live_grant_to_cross_account_principal")
			break
		}
	}
	// IAM semantics: an explicit Deny to all principals with no conditions
	// shadows any Allow regardless of the Allow's principals.
	switch {
	case denyAll:
		return "restricted", dedupeStrings(reasons)
	case public:
		return "public", dedupeStrings(reasons)
	case crossAccount:
		return "cross_account", dedupeStrings(reasons)
	case record.IAMDelegationEnabled && !hasNonDelegationGrant:
		reasons = append(reasons, "kms_key_policy_delegates_to_iam")
		return "managed_by_iam", dedupeStrings(reasons)
	case record.HasKeyPolicy || len(record.Grants) > 0:
		return "private_with_grants", dedupeStrings(reasons)
	default:
		return "private", dedupeStrings(reasons)
	}
}

// isIAMDelegationGrant reports whether the supplied policy grant is the
// canonical "EnableIAMUserPermissions" delegation: Allow kms:* to the
// account root principal with no conditions. We treat this as the AWS
// default delegation rather than a real exposure signal.
func isIAMDelegationGrant(grant KMSIdentityGrant, accountID string) bool {
	if !strings.EqualFold(grant.Effect, "Allow") {
		return false
	}
	if grant.HasCondition {
		return false
	}
	if grant.WildcardPrincipal {
		return false
	}
	if grant.PrincipalARN == "" {
		return false
	}
	expected := fmt.Sprintf(":iam::%s:root", strings.TrimSpace(accountID))
	if accountID == "" || !strings.Contains(grant.PrincipalARN, expected) {
		return false
	}
	for _, action := range grant.Actions {
		lower := strings.ToLower(strings.TrimSpace(action))
		if lower != "kms:*" && lower != "*" {
			return false
		}
	}
	return len(grant.Actions) > 0
}

func canonicalKMSGrantEffect(effect string) string {
	switch strings.ToLower(strings.TrimSpace(effect)) {
	case "allow":
		return "Allow"
	case "deny":
		return "Deny"
	default:
		return strings.TrimSpace(effect)
	}
}

func kmsDecryptReachabilityConfidence(record KMSDecryptReachability) float64 {
	switch record.ExposureClassification {
	case "public":
		return 0.95
	case "cross_account":
		return 0.92
	case "restricted":
		return 0.9
	case "managed_by_iam":
		return 0.88
	case "private_with_grants":
		return 0.87
	case "managed_by_aws":
		return 0.85
	case "private":
		return 0.84
	default:
		return 0.7
	}
}

func kmsDecryptReachabilitySourceID(record KMSDecryptReachability) string {
	return strings.Join(normalizeStringList([]string{
		record.Service,
		record.KeyARN,
		record.KeyID,
		record.Region,
	}), "|")
}

// resolveKMSKeyARN resolves a KMS key reference as AWS services report it.
// The value can carry a full ARN, an alias (`alias/...`), or a bare key id;
// only the bare id needs a synthesized key ARN.
func resolveKMSKeyARN(keyID, accountID, region string) string {
	trimmed := strings.TrimSpace(keyID)
	switch {
	case trimmed == "":
		return ""
	case strings.HasPrefix(trimmed, "arn:"):
		return trimmed
	case strings.HasPrefix(trimmed, "alias/"):
		if strings.TrimSpace(accountID) == "" || strings.TrimSpace(region) == "" {
			return ""
		}
		return fmt.Sprintf("arn:%s:kms:%s:%s:%s", awsPartitionForRegion(region), region, accountID, trimmed)
	default:
		return kmsKeyARNFromID(trimmed, accountID, region)
	}
}

// kmsKeyARNFromID synthesizes a KMS key ARN from the supplied id, region,
// and account. KMS key ARNs are partition + region + account scoped so we
// must have all three.
func kmsKeyARNFromID(keyID, accountID, region string) string {
	trimmed := strings.TrimSpace(keyID)
	if trimmed == "" || strings.TrimSpace(accountID) == "" || strings.TrimSpace(region) == "" {
		return ""
	}
	partition := awsPartitionForRegion(region)
	return fmt.Sprintf("arn:%s:kms:%s:%s:key/%s", partition, region, accountID, trimmed)
}

var _ AWSServiceCollector = (*KMSDecryptReachabilityCollector)(nil)
var _ providers.Collector = (*KMSDecryptReachabilityCollector)(nil)
