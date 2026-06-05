package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	rawKindEKSWorkloadIdentity       = "eks_workload_identity"
	eksWorkloadIdentityCollectorName = "eks_workload_identity"
	eksServiceName                   = "eks"

	eksRoleKindIRSA                = "irsa"
	eksRoleKindPodIdentity         = "pod_identity"
	eksRoleKindNodeRole            = "node_role"
	eksRoleKindFargatePodExecution = "fargate_pod_execution_role"
)

// EKSWorkloadIdentity captures EKS workload-to-IAM role evidence. It stores
// metadata only: Kubernetes secret values, pod logs, object contents, and
// customer payloads are never collected.
type EKSWorkloadIdentity struct {
	awscontract.ServiceCollectorRecord
	RoleName               string            `json:"role_name,omitempty"`
	RoleKind               string            `json:"role_kind"`
	ClusterARN             string            `json:"cluster_arn,omitempty"`
	ClusterName            string            `json:"cluster_name,omitempty"`
	ClusterStatus          string            `json:"cluster_status,omitempty"`
	KubernetesVersion      string            `json:"kubernetes_version,omitempty"`
	OIDCIssuer             string            `json:"oidc_issuer,omitempty"`
	OIDCProviderARN        string            `json:"oidc_provider_arn,omitempty"`
	Namespace              string            `json:"namespace,omitempty"`
	ServiceAccount         string            `json:"service_account,omitempty"`
	KubernetesSubject      string            `json:"kubernetes_subject,omitempty"`
	AssociationARN         string            `json:"association_arn,omitempty"`
	AssociationID          string            `json:"association_id,omitempty"`
	AssociationOwnerARN    string            `json:"association_owner_arn,omitempty"`
	ExternalID             string            `json:"external_id,omitempty"`
	DisableSessionTags     bool              `json:"disable_session_tags,omitempty"`
	TargetRoleARN          string            `json:"target_role_arn,omitempty"`
	NodegroupARN           string            `json:"nodegroup_arn,omitempty"`
	NodegroupName          string            `json:"nodegroup_name,omitempty"`
	NodegroupStatus        string            `json:"nodegroup_status,omitempty"`
	NodeRoleARN            string            `json:"node_role_arn,omitempty"`
	FargateProfileARN      string            `json:"fargate_profile_arn,omitempty"`
	FargateProfileName     string            `json:"fargate_profile_name,omitempty"`
	FargateProfileStatus   string            `json:"fargate_profile_status,omitempty"`
	PodExecutionRoleARN    string            `json:"pod_execution_role_arn,omitempty"`
	SelectorNamespaces     []string          `json:"selector_namespaces,omitempty"`
	SelectorLabels         []string          `json:"selector_labels,omitempty"`
	SubnetIDs              []string          `json:"subnet_ids,omitempty"`
	KubernetesAccessStatus string            `json:"kubernetes_access_status,omitempty"`
	IRSAAnnotationKeys     []string          `json:"irsa_annotation_keys,omitempty"`
	ClusterTags            map[string]string `json:"cluster_tags,omitempty"`
	Tags                   map[string]string `json:"tags,omitempty"`
}

// EKSWorkloadIdentityPage is one page of EKS workload identity inventory.
type EKSWorkloadIdentityPage struct {
	Records     []EKSWorkloadIdentity
	NextToken   string
	Diagnostics []providers.SourceError
}

// EKSWorkloadIdentityAPI defines the metadata-only EKS operations used by the collector.
type EKSWorkloadIdentityAPI interface {
	ListWorkloadIdentities(ctx context.Context, nextToken string, pageSize int32) (EKSWorkloadIdentityPage, error)
}

// EKSWorkloadIdentityCollector collects EKS Pod Identity, node-role, Fargate
// pod-execution-role, and Kubernetes-backed IRSA annotation machine identities.
// The AWS SDK adapter reports IRSA annotation coverage as degraded unless a
// Kubernetes-backed source supplies service-account annotation records.
type EKSWorkloadIdentityCollector struct {
	client   EKSWorkloadIdentityAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

// EKSWorkloadIdentityOption customizes EKSWorkloadIdentityCollector behavior.
type EKSWorkloadIdentityOption func(*EKSWorkloadIdentityCollector)

// WithEKSWorkloadIdentityPageSize configures EKS pagination size.
func WithEKSWorkloadIdentityPageSize(pageSize int32) EKSWorkloadIdentityOption {
	return func(c *EKSWorkloadIdentityCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithEKSWorkloadIdentityMaxPages limits list pagination to guard against runaways.
func WithEKSWorkloadIdentityMaxPages(maxPages int) EKSWorkloadIdentityOption {
	return func(c *EKSWorkloadIdentityCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithEKSWorkloadIdentityRetryPolicy customizes retry strategy for transient EKS errors.
func WithEKSWorkloadIdentityRetryPolicy(policy RetryPolicy) EKSWorkloadIdentityOption {
	return func(c *EKSWorkloadIdentityCollector) {
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

// WithEKSWorkloadIdentityRetryJitterRatio configures bounded random jitter around retry backoff.
func WithEKSWorkloadIdentityRetryJitterRatio(ratio float64) EKSWorkloadIdentityOption {
	return func(c *EKSWorkloadIdentityCollector) {
		if ratio < 0 {
			ratio = 0
		}
		c.jitter = ratio
	}
}

// WithEKSWorkloadIdentityRetryRandFunc injects deterministic randomness for retry jitter tests.
func WithEKSWorkloadIdentityRetryRandFunc(randFn func() float64) EKSWorkloadIdentityOption {
	return func(c *EKSWorkloadIdentityCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

// WithEKSWorkloadIdentitySleeper injects a testable sleep function.
func WithEKSWorkloadIdentitySleeper(s Sleeper) EKSWorkloadIdentityOption {
	return func(c *EKSWorkloadIdentityCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithEKSWorkloadIdentityClock injects a deterministic clock.
func WithEKSWorkloadIdentityClock(now func() time.Time) EKSWorkloadIdentityOption {
	return func(c *EKSWorkloadIdentityCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewEKSWorkloadIdentityCollector creates a read-only EKS workload identity collector.
func NewEKSWorkloadIdentityCollector(client EKSWorkloadIdentityAPI, opts ...EKSWorkloadIdentityOption) *EKSWorkloadIdentityCollector {
	c := &EKSWorkloadIdentityCollector{
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

func (c *EKSWorkloadIdentityCollector) ServiceName() string {
	return eksServiceName
}

// Collect pulls EKS workload identity assets using an empty scope.
func (c *EKSWorkloadIdentityCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: eksServiceName})
	return assets, err
}

// CollectWithDiagnostics pulls EKS workload identity assets and includes non-fatal source errors.
func (c *EKSWorkloadIdentityCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("eks workload identity collector requires client")
	}
	c.issues = c.issues[:0]

	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}

	assets := make([]providers.RawAsset, 0, c.pageSize)
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()

	for page := 1; ; page++ {
		if page > c.maxPages {
			return nil, nil, fmt.Errorf("eks workload identity collection exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.withRetry(ctx, func(callCtx context.Context) (EKSWorkloadIdentityPage, error) {
			return c.client.ListWorkloadIdentities(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list eks workload identities page %d: %w", page, err)
		}
		for _, diagnostic := range response.Diagnostics {
			c.addIssue(diagnostic)
		}

		for _, record := range response.Records {
			normalized := normalizeEKSWorkloadIdentityScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" || strings.TrimSpace(normalized.RoleKind) == "" {
				c.addIssue(providers.SourceError{
					Collector: eksWorkloadIdentityCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped EKS workload identity record without workload id or role kind",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: eksWorkloadIdentityCollectorName,
					SourceID:  firstNonEmptyAWSValue(normalized.AssociationARN, normalized.NodegroupARN, normalized.FargateProfileARN, normalized.WorkloadID),
					Code:      "missing_eks_role",
					Message:   "EKS workload identity record did not include an IAM role ARN",
					Retryable: false,
				})
				continue
			}

			sourceID := eksWorkloadIdentitySourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal eks workload identity %q: %w", sourceID, err)
			}

			assets = append(assets, providers.RawAsset{
				Kind:      rawKindEKSWorkloadIdentity,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}

		if response.NextToken == "" {
			break
		}
		nextToken = response.NextToken
	}

	issues := append([]providers.SourceError(nil), c.issues...)
	return assets, issues, nil
}

func (c *EKSWorkloadIdentityCollector) withRetry(ctx context.Context, fn func(context.Context) (EKSWorkloadIdentityPage, error)) (EKSWorkloadIdentityPage, error) {
	return retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, fn)
}

func (c *EKSWorkloadIdentityCollector) backoff(attempt int) time.Duration {
	return awsRetryBackoff(c.retry, c.jitter, c.randFn, attempt)
}

func (c *EKSWorkloadIdentityCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeEKSWorkloadIdentityScope(scope AWSCollectorScope, record EKSWorkloadIdentity, collectedAt time.Time) EKSWorkloadIdentity {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, eksServiceName)
	normalized.RoleKind = normalizeEKSRoleKind(record.RoleKind, record)
	normalized.RoleARN = strings.TrimSpace(firstNonEmptyAWSValue(record.RoleARN, roleARNForEKSKind(normalized.RoleKind, record)))
	normalized.RoleName = firstNonEmptyAWSValue(record.RoleName, roleNameFromARN(normalized.RoleARN))
	normalized.ClusterARN = strings.TrimSpace(record.ClusterARN)
	normalized.ClusterName = firstNonEmptyAWSValue(record.ClusterName, eksNameFromARN(record.ClusterARN))
	normalized.ClusterStatus = strings.TrimSpace(record.ClusterStatus)
	normalized.KubernetesVersion = strings.TrimSpace(record.KubernetesVersion)
	normalized.OIDCIssuer = strings.TrimSpace(record.OIDCIssuer)
	normalized.OIDCProviderARN = firstNonEmptyAWSValue(record.OIDCProviderARN, oidcProviderARNFromIssuer(normalized.AccountID, normalized.OIDCIssuer))
	normalized.Namespace = strings.TrimSpace(record.Namespace)
	normalized.ServiceAccount = strings.TrimSpace(record.ServiceAccount)
	normalized.KubernetesSubject = firstNonEmptyAWSValue(record.KubernetesSubject, eksKubernetesSubject(normalized.Namespace, normalized.ServiceAccount))
	normalized.AssociationARN = strings.TrimSpace(record.AssociationARN)
	normalized.AssociationID = strings.TrimSpace(record.AssociationID)
	normalized.AssociationOwnerARN = strings.TrimSpace(record.AssociationOwnerARN)
	normalized.ExternalID = strings.TrimSpace(record.ExternalID)
	normalized.TargetRoleARN = strings.TrimSpace(record.TargetRoleARN)
	normalized.NodegroupARN = strings.TrimSpace(record.NodegroupARN)
	normalized.NodegroupName = firstNonEmptyAWSValue(record.NodegroupName, eksNameFromARN(record.NodegroupARN))
	normalized.NodegroupStatus = strings.TrimSpace(record.NodegroupStatus)
	normalized.NodeRoleARN = strings.TrimSpace(record.NodeRoleARN)
	normalized.FargateProfileARN = strings.TrimSpace(record.FargateProfileARN)
	normalized.FargateProfileName = firstNonEmptyAWSValue(record.FargateProfileName, eksNameFromARN(record.FargateProfileARN))
	normalized.FargateProfileStatus = strings.TrimSpace(record.FargateProfileStatus)
	normalized.PodExecutionRoleARN = strings.TrimSpace(record.PodExecutionRoleARN)
	normalized.SelectorNamespaces = normalizeStringList(record.SelectorNamespaces)
	normalized.SelectorLabels = normalizeStringList(record.SelectorLabels)
	normalized.SubnetIDs = normalizeStringList(record.SubnetIDs)
	normalized.KubernetesAccessStatus = firstNonEmptyAWSValue(record.KubernetesAccessStatus, "aws_metadata_only")
	normalized.IRSAAnnotationKeys = normalizeStringList(record.IRSAAnnotationKeys)
	normalized.ClusterTags = copyTags(record.ClusterTags)
	normalized.Tags = copyTags(record.Tags)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, eksWorkloadTypeForRoleKind(normalized.RoleKind))
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, eksWorkloadIdentityWorkloadRef(normalized))
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, eksWorkloadIdentityName(normalized))
	normalized.Source = firstNonEmptyAWSValue(record.Source, eksSourceForRoleKind(normalized.RoleKind))
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, normalized.AssociationARN, normalized.NodegroupARN, normalized.FargateProfileARN, normalized.KubernetesSubject, normalized.ClusterARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, eksWorkloadIdentityCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-eks-workload-identity-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = eksWorkloadIdentityConfidence(normalized)
	}
	return normalized
}

func normalizeEKSRoleKind(roleKind string, record EKSWorkloadIdentity) string {
	if canonical, ok := canonicalEKSRoleKindAlias(roleKind); ok {
		return canonical
	}
	switch {
	case strings.TrimSpace(record.AssociationARN) != "" || strings.TrimSpace(record.AssociationID) != "":
		return eksRoleKindPodIdentity
	case strings.TrimSpace(record.NodeRoleARN) != "" || strings.TrimSpace(record.NodegroupARN) != "":
		return eksRoleKindNodeRole
	case strings.TrimSpace(record.PodExecutionRoleARN) != "" || strings.TrimSpace(record.FargateProfileARN) != "":
		return eksRoleKindFargatePodExecution
	default:
		return eksRoleKindIRSA
	}
}

func canonicalEKSRoleKindAlias(roleKind string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(roleKind)) {
	case eksRoleKindIRSA, "irsa_annotation", "service_account_role":
		return eksRoleKindIRSA, true
	case eksRoleKindPodIdentity, "podidentity", "pod_identity_association":
		return eksRoleKindPodIdentity, true
	case eksRoleKindNodeRole, "nodegroup_role", "node_group_role":
		return eksRoleKindNodeRole, true
	case eksRoleKindFargatePodExecution, "fargate_role", "pod_execution_role":
		return eksRoleKindFargatePodExecution, true
	default:
		return "", false
	}
}

func roleARNForEKSKind(roleKind string, record EKSWorkloadIdentity) string {
	switch roleKind {
	case eksRoleKindNodeRole:
		return record.NodeRoleARN
	case eksRoleKindFargatePodExecution:
		return record.PodExecutionRoleARN
	case eksRoleKindPodIdentity:
		return firstNonEmptyAWSValue(record.RoleARN, record.TargetRoleARN)
	default:
		return record.RoleARN
	}
}

func eksWorkloadTypeForRoleKind(roleKind string) string {
	switch roleKind {
	case eksRoleKindNodeRole:
		return "eks_node_group"
	case eksRoleKindFargatePodExecution:
		return "eks_fargate_pod_execution_role"
	default:
		return "eks_service_account"
	}
}

func eksWorkloadIdentityWorkloadRef(record EKSWorkloadIdentity) string {
	switch record.RoleKind {
	case eksRoleKindNodeRole:
		return firstNonEmptyAWSValue(record.NodegroupARN, record.NodegroupName)
	case eksRoleKindFargatePodExecution:
		return firstNonEmptyAWSValue(record.FargateProfileARN, record.FargateProfileName)
	default:
		return strings.Join([]string{
			firstNonEmptyAWSValue(record.ClusterName, "cluster"),
			firstNonEmptyAWSValue(record.Namespace, "namespace"),
			firstNonEmptyAWSValue(record.ServiceAccount, "service-account"),
		}, "/")
	}
}

func eksWorkloadIdentityName(record EKSWorkloadIdentity) string {
	normalized := record
	normalized.RoleKind = normalizeEKSRoleKind(record.RoleKind, record)
	switch normalized.RoleKind {
	case eksRoleKindNodeRole:
		return firstNonEmptyAWSValue(normalized.NodegroupName, eksNameFromARN(normalized.NodegroupARN), "eks node group")
	case eksRoleKindFargatePodExecution:
		return firstNonEmptyAWSValue(normalized.FargateProfileName, eksNameFromARN(normalized.FargateProfileARN), "eks fargate profile")
	default:
		return firstNonEmptyAWSValue(normalized.KubernetesSubject, eksKubernetesSubject(normalized.Namespace, normalized.ServiceAccount), "eks service account")
	}
}

func eksSourceForRoleKind(roleKind string) string {
	switch roleKind {
	case eksRoleKindPodIdentity:
		return "listpodidentityassociations"
	case eksRoleKindNodeRole:
		return "describenodegroup"
	case eksRoleKindFargatePodExecution:
		return "describefargateprofile"
	default:
		return "kubernetes_serviceaccount_annotation"
	}
}

func eksWorkloadIdentityConfidence(record EKSWorkloadIdentity) float64 {
	switch record.RoleKind {
	case eksRoleKindIRSA:
		if strings.EqualFold(record.KubernetesAccessStatus, "available") && len(record.IRSAAnnotationKeys) > 0 {
			return 0.95
		}
		return 0.78
	case eksRoleKindPodIdentity:
		return 0.97
	case eksRoleKindNodeRole:
		return 0.88
	case eksRoleKindFargatePodExecution:
		return 0.9
	default:
		return 0.82
	}
}

func eksWorkloadIdentitySourceID(record EKSWorkloadIdentity) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.ClusterName, record.ClusterARN, "cluster"),
		firstNonEmptyAWSValue(record.RoleKind, "role-kind"),
		firstNonEmptyAWSValue(record.WorkloadID, record.KubernetesSubject, record.AssociationID, record.NodegroupARN, record.FargateProfileARN, "workload"),
		firstNonEmptyAWSValue(record.RoleARN, "no-role"),
	}, "|")
}

func eksKubernetesSubject(namespace string, serviceAccount string) string {
	namespace = strings.TrimSpace(namespace)
	serviceAccount = strings.TrimSpace(serviceAccount)
	if namespace == "" || serviceAccount == "" {
		return ""
	}
	return namespace + "/" + serviceAccount
}

func oidcProviderARNFromIssuer(accountID string, issuer string) string {
	accountID = strings.TrimSpace(accountID)
	issuer = strings.TrimSpace(issuer)
	if accountID == "" || issuer == "" {
		return ""
	}
	issuer = strings.TrimPrefix(issuer, "https://")
	issuer = strings.TrimPrefix(issuer, "http://")
	issuer = strings.Trim(issuer, "/")
	if issuer == "" {
		return ""
	}
	return fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", accountID, issuer)
}

func eksNameFromARN(arn string) string {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return ""
	}
	resource := trimmed
	if idx := strings.LastIndex(resource, ":"); idx >= 0 && idx < len(resource)-1 {
		resource = resource[idx+1:]
	}
	parts := strings.Split(resource, "/")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) >= 3 {
		switch parts[0] {
		case "nodegroup", "fargateprofile", "podidentityassociation":
			return parts[2]
		}
	}
	if len(parts) >= 2 && parts[0] == "cluster" {
		return parts[1]
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 || idx == len(trimmed)-1 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[idx+1:])
}

var _ AWSServiceCollector = (*EKSWorkloadIdentityCollector)(nil)
var _ providers.Collector = (*EKSWorkloadIdentityCollector)(nil)
