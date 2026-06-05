package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	awsEKSWorkloadIdentityCurrentIssue = 1480
	awsEKSWorkloadIdentityVersion      = "aws-eks-workload-identity-inventory-v1"
)

// AWSEKSWorkloadIdentityInventoryRequest controls the deterministic inventory state.
type AWSEKSWorkloadIdentityInventoryRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
}

// AWSEKSWorkloadIdentityInventoryResult exposes scoped EKS workload identity evidence.
type AWSEKSWorkloadIdentityInventoryResult struct {
	TenantID                    string                               `json:"tenant_id"`
	WorkspaceID                 string                               `json:"workspace_id"`
	ProjectID                   string                               `json:"project_id"`
	ConnectorID                 string                               `json:"connector_id,omitempty"`
	AccountID                   string                               `json:"account_id,omitempty"`
	Region                      string                               `json:"region,omitempty"`
	ParentIssueNumber           int                                  `json:"parent_issue_number"`
	ParentIssueRef              string                               `json:"parent_issue_ref"`
	CurrentIssueNumber          int                                  `json:"current_issue_number"`
	CurrentIssueRef             string                               `json:"current_issue_ref"`
	Version                     string                               `json:"version"`
	Status                      string                               `json:"status"`
	FixtureState                string                               `json:"fixture_state"`
	Confidence                  float64                              `json:"confidence"`
	RecordCount                 int                                  `json:"record_count"`
	ClusterCount                int                                  `json:"cluster_count"`
	OIDCProviderCount           int                                  `json:"oidc_provider_count"`
	ServiceAccountCount         int                                  `json:"service_account_count"`
	PodIdentityAssociationCount int                                  `json:"pod_identity_association_count"`
	IRSAAnnotationCount         int                                  `json:"irsa_annotation_count"`
	NodeRoleCount               int                                  `json:"node_role_count"`
	FargateProfileCount         int                                  `json:"fargate_profile_count"`
	IdentityCount               int                                  `json:"identity_count"`
	ResourceCount               int                                  `json:"resource_count"`
	RelationshipCount           int                                  `json:"relationship_count"`
	FailureReasons              []string                             `json:"failure_reasons"`
	RemediationHints            []string                             `json:"remediation_hints"`
	EvidenceLinks               []string                             `json:"evidence_links"`
	Records                     []AWSEKSWorkloadIdentityRecord       `json:"records"`
	Relationships               []AWSEKSWorkloadIdentityRelationship `json:"relationships"`
	Diagnostics                 []AWSEKSWorkloadIdentityDiagnostic   `json:"diagnostics"`
	GeneratedAt                 time.Time                            `json:"generated_at"`
	UpdatedAt                   time.Time                            `json:"updated_at"`
}

// AWSEKSWorkloadIdentityRecord is the operator-facing row for one EKS workload/role link.
type AWSEKSWorkloadIdentityRecord struct {
	AccountID              string            `json:"account_id"`
	Region                 string            `json:"region"`
	Service                string            `json:"service"`
	WorkloadID             string            `json:"workload_id"`
	WorkloadType           string            `json:"workload_type"`
	WorkloadName           string            `json:"workload_name"`
	RoleKind               string            `json:"role_kind"`
	RoleARN                string            `json:"role_arn,omitempty"`
	RoleName               string            `json:"role_name,omitempty"`
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
	Tags                   map[string]string `json:"tags,omitempty"`
	Source                 string            `json:"source"`
	EvidenceRef            string            `json:"evidence_ref"`
	FromNodeID             string            `json:"from_node_id"`
	ToNodeID               string            `json:"to_node_id,omitempty"`
	RelationshipType       string            `json:"relationship_type"`
	Confidence             float64           `json:"confidence"`
	CollectedAt            time.Time         `json:"collected_at"`
	Status                 string            `json:"status"`
}

// AWSEKSWorkloadIdentityRelationship is the graph evidence exposed by the API.
type AWSEKSWorkloadIdentityRelationship struct {
	Type        string `json:"type"`
	FromNodeID  string `json:"from_node_id"`
	ToNodeID    string `json:"to_node_id"`
	EvidenceRef string `json:"evidence_ref"`
}

// AWSEKSWorkloadIdentityDiagnostic is one explicit non-success state.
type AWSEKSWorkloadIdentityDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

// GetAWSEKSWorkloadIdentityInventory returns scoped deterministic EKS workload identity inventory.
func (s *Service) GetAWSEKSWorkloadIdentityInventory(ctx context.Context, workspaceID string, projectID string, request AWSEKSWorkloadIdentityInventoryRequest) (AWSEKSWorkloadIdentityInventoryResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSEKSWorkloadIdentityInventoryResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSEKSWorkloadIdentityInventoryResult{}, err
	}
	return buildAWSEKSWorkloadIdentityInventory(scope, project, connection, hasConnection, request, s.Now().UTC())
}

func buildAWSEKSWorkloadIdentityInventory(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, request AWSEKSWorkloadIdentityInventoryRequest, checkedAt time.Time) (AWSEKSWorkloadIdentityInventoryResult, error) {
	fixtureState := normalizeAWSEKSWorkloadIdentityFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSEKSWorkloadIdentityInventoryResult{}, ErrInvalidAWSConnectionRequest
	}
	accountID := firstNonEmptyAWSValue(connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	records, diagnostics := awsEKSWorkloadIdentityFixtureRecords(scope, project, connectorID, accountID, region, fixtureState, checkedAt)

	for _, record := range records {
		if strings.TrimSpace(record.RoleARN) == "" {
			continue
		}
		if _, err := awscontract.NormalizeServiceCollectorRecord(awscontract.ServiceCollectorRecord{
			TenantID:      scope.TenantID,
			WorkspaceID:   project.WorkspaceID,
			ProjectID:     project.ProjectID,
			ConnectorID:   connectorID,
			AccountID:     record.AccountID,
			Region:        record.Region,
			Service:       record.Service,
			WorkloadID:    record.WorkloadID,
			WorkloadType:  record.WorkloadType,
			WorkloadName:  record.WorkloadName,
			RoleARN:       record.RoleARN,
			Source:        record.Source,
			EvidenceRef:   record.EvidenceRef,
			Confidence:    record.Confidence,
			ScanID:        "aws-eks-workload-identity-fixture",
			CollectorName: "eks_workload_identity",
			CollectedAt:   checkedAt,
		}); err != nil {
			return AWSEKSWorkloadIdentityInventoryResult{}, fmt.Errorf("validate eks workload identity contract record: %w", err)
		}
	}

	status, confidence, failures, remediations := summarizeAWSEKSWorkloadIdentityInventory(fixtureState, diagnostics)
	relationships := awsEKSWorkloadIdentityRelationships(records)
	result := AWSEKSWorkloadIdentityInventoryResult{
		TenantID:                    scope.TenantID,
		WorkspaceID:                 project.WorkspaceID,
		ProjectID:                   project.ProjectID,
		ConnectorID:                 connectorID,
		AccountID:                   accountID,
		Region:                      region,
		ParentIssueNumber:           awsPlatformDependencyParentIssue,
		ParentIssueRef:              awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber:          awsEKSWorkloadIdentityCurrentIssue,
		CurrentIssueRef:             awsIssueRef(awsEKSWorkloadIdentityCurrentIssue),
		Version:                     awsEKSWorkloadIdentityVersion,
		Status:                      status,
		FixtureState:                fixtureState,
		Confidence:                  confidence,
		RecordCount:                 len(records),
		ClusterCount:                awsEKSWorkloadIdentityClusterCount(records),
		OIDCProviderCount:           awsEKSWorkloadIdentityOIDCProviderCount(records),
		ServiceAccountCount:         awsEKSWorkloadIdentityServiceAccountCount(records),
		PodIdentityAssociationCount: awsEKSWorkloadIdentityRoleKindCount(records, "pod_identity"),
		IRSAAnnotationCount:         awsEKSWorkloadIdentityRoleKindCount(records, "irsa"),
		NodeRoleCount:               awsEKSWorkloadIdentityRoleKindCount(records, "node_role"),
		FargateProfileCount:         awsEKSWorkloadIdentityRoleKindCount(records, "fargate_pod_execution_role"),
		IdentityCount:               awsEKSWorkloadIdentityIdentityCount(records),
		ResourceCount:               awsEKSWorkloadIdentityResourceCount(records),
		RelationshipCount:           len(relationships),
		FailureReasons:              failures,
		RemediationHints:            remediations,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsEKSWorkloadIdentityCurrentIssue),
			"/docs/aws-eks-workload-identities",
			"/docs/aws-service-collector-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Records:       records,
		Relationships: relationships,
		Diagnostics:   awsEKSWorkloadIdentityDiagnostics(diagnostics),
		GeneratedAt:   checkedAt,
		UpdatedAt:     checkedAt,
	}
	return result, nil
}

func normalizeAWSEKSWorkloadIdentityFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "", "success":
		if hasConnection && !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func awsEKSWorkloadIdentityFixtureRecords(scope db.Scope, project db.TenancyProject, connectorID string, accountID string, region string, fixtureState string, checkedAt time.Time) ([]AWSEKSWorkloadIdentityRecord, []providers.SourceError) {
	clusterName := "prod-cluster"
	clusterARN := fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", region, accountID, clusterName)
	issuer := fmt.Sprintf("https://oidc.eks.%s.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE", region)
	oidcProviderARN := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/oidc.eks.%s.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE", accountID, region)

	baseRecord := func(roleKind string, workloadID string, workloadType string, workloadName string, roleARN string, source string, evidenceRef string) AWSEKSWorkloadIdentityRecord {
		roleName := roleNameFromARNForAPI(roleARN)
		status := "ready"
		if strings.TrimSpace(roleARN) == "" {
			status = "degraded"
		}
		relationshipType := "runs_as"
		if roleKind == "fargate_pod_execution_role" {
			relationshipType = "attached_to"
		}
		return AWSEKSWorkloadIdentityRecord{
			AccountID:              accountID,
			Region:                 region,
			Service:                "eks",
			WorkloadID:             workloadID,
			WorkloadType:           workloadType,
			WorkloadName:           workloadName,
			RoleKind:               roleKind,
			RoleARN:                roleARN,
			RoleName:               roleName,
			ClusterARN:             clusterARN,
			ClusterName:            clusterName,
			ClusterStatus:          "ACTIVE",
			KubernetesVersion:      "1.30",
			OIDCIssuer:             issuer,
			OIDCProviderARN:        oidcProviderARN,
			KubernetesAccessStatus: "aws_metadata_only",
			Source:                 source,
			EvidenceRef:            evidenceRef,
			FromNodeID:             awsEKSWorkloadNodeID(accountID, region, roleKind, workloadID),
			ToNodeID:               awsIdentityNodeIDForAPI(roleARN),
			RelationshipType:       relationshipType,
			Confidence:             0.9,
			CollectedAt:            checkedAt,
			Status:                 status,
		}
	}

	irsaRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-irsa", accountID)
	irsa := baseRecord("irsa", "prod-cluster/payments/payments-api", "eks_service_account", "payments/payments-api", irsaRoleARN, "kubernetes_serviceaccount_annotation", "payments/payments-api")
	irsa.Namespace = "payments"
	irsa.ServiceAccount = "payments-api"
	irsa.KubernetesSubject = "payments/payments-api"
	irsa.KubernetesAccessStatus = "available"
	irsa.IRSAAnnotationKeys = []string{"eks.amazonaws.com/role-arn"}
	irsa.Tags = map[string]string{"owner": "platform", "service": "payments"}
	irsa.Confidence = 0.95

	podRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/batch-pod-identity", accountID)
	podAssociationARN := fmt.Sprintf("arn:aws:eks:%s:%s:podidentityassociation/%s/a-1234567890abcdef0", region, accountID, clusterName)
	pod := baseRecord("pod_identity", podAssociationARN, "eks_service_account", "jobs/batch-worker", podRoleARN, "listpodidentityassociations", podAssociationARN)
	pod.Namespace = "jobs"
	pod.ServiceAccount = "batch-worker"
	pod.KubernetesSubject = "jobs/batch-worker"
	pod.AssociationARN = podAssociationARN
	pod.AssociationID = "a-1234567890abcdef0"
	pod.AssociationOwnerARN = fmt.Sprintf("arn:aws:eks:%s:%s:addon/%s/eks-pod-identity-agent", region, accountID, clusterName)
	pod.ExternalID = "eks-pod-identity-prod-cluster-jobs-batch-worker"
	pod.Tags = map[string]string{"owner": "data", "service": "jobs"}
	pod.Confidence = 0.97

	nodeRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/prod-eks-node-role", accountID)
	nodegroupARN := fmt.Sprintf("arn:aws:eks:%s:%s:nodegroup/%s/payments-ng/01234567-89ab-cdef-0123-456789abcdef", region, accountID, clusterName)
	node := baseRecord("node_role", nodegroupARN, "eks_node_group", "payments-ng", nodeRoleARN, "describenodegroup", nodegroupARN)
	node.NodegroupARN = nodegroupARN
	node.NodegroupName = "payments-ng"
	node.NodegroupStatus = "ACTIVE"
	node.NodeRoleARN = nodeRoleARN
	node.Tags = map[string]string{"owner": "platform", "capacity": "managed"}
	node.Confidence = 0.88

	fargateRoleARN := fmt.Sprintf("arn:aws:iam::%s:role/payments-fargate-pod-execution", accountID)
	fargateARN := fmt.Sprintf("arn:aws:eks:%s:%s:fargateprofile/%s/payments-fargate/01234567-89ab-cdef-0123-456789abcdef", region, accountID, clusterName)
	fargate := baseRecord("fargate_pod_execution_role", fargateARN, "eks_fargate_pod_execution_role", "payments-fargate", fargateRoleARN, "describefargateprofile", fargateARN)
	fargate.FargateProfileARN = fargateARN
	fargate.FargateProfileName = "payments-fargate"
	fargate.FargateProfileStatus = "ACTIVE"
	fargate.PodExecutionRoleARN = fargateRoleARN
	fargate.SelectorNamespaces = []string{"payments"}
	fargate.SelectorLabels = []string{"runtime=fargate"}
	fargate.SubnetIDs = []string{"subnet-a", "subnet-b"}
	fargate.Tags = map[string]string{"owner": "platform", "runtime": "fargate"}
	fargate.Confidence = 0.9

	switch fixtureState {
	case "empty":
		return nil, nil
	case "degraded":
		return []AWSEKSWorkloadIdentityRecord{pod, node, fargate}, []providers.SourceError{{
			Collector: "aws_eks/eks_workload_identity",
			SourceID:  clusterARN,
			Code:      "kubernetes_api_unavailable",
			Message:   "EKS cluster OIDC and AWS-side associations are visible, but Kubernetes service account annotations could not be collected",
			Retryable: false,
		}}
	case "partial_failure":
		return []AWSEKSWorkloadIdentityRecord{irsa, node}, []providers.SourceError{{
			Collector: "aws_eks/eks_workload_identity",
			SourceID:  fmt.Sprintf("service=eks|account=%s|region=%s|source=listpodidentityassociations", accountID, region),
			Code:      "pod_identity_association_list_failed",
			Message:   "EKS Pod Identity associations could not be listed for one cluster; successful IRSA and node role evidence remains visible",
			Retryable: true,
		}}
	case "permission_denied":
		return nil, []providers.SourceError{{
			Collector: "aws_eks/eks_workload_identity",
			SourceID:  fmt.Sprintf("service=eks|account=%s|region=%s|source=listclusters", accountID, region),
			Code:      "permission_denied",
			Message:   "Read-only EKS ListClusters, DescribeCluster, ListPodIdentityAssociations, DescribePodIdentityAssociation, ListNodegroups, DescribeNodegroup, ListFargateProfiles, or DescribeFargateProfile permission is missing",
			Retryable: false,
		}}
	default:
		return []AWSEKSWorkloadIdentityRecord{irsa, pod, node, fargate}, nil
	}
}

func summarizeAWSEKSWorkloadIdentityInventory(fixtureState string, diagnostics []providers.SourceError) (string, float64, []string, []string) {
	switch fixtureState {
	case "permission_denied":
		return awsPlatformDependencyStatusBlocked, 0.35, []string{"eks workload identity collection is blocked by missing read-only permission"}, []string{"Grant metadata-only EKS read permissions; do not add Kubernetes secret, pod log, object content, or mutation permissions."}
	case "degraded":
		return awsPlatformDependencyStatusDegraded, 0.72, []string{"kubernetes api access is missing, so IRSA annotation evidence is incomplete"}, []string{"Connect Kubernetes read access for service account annotation evidence while keeping AWS-side Pod Identity, node role, and Fargate evidence visible."}
	case "partial_failure":
		return awsPlatformDependencyStatusDegraded, 0.76, []string{"one EKS metadata partition failed while successful workload identity records remain visible"}, []string{"Retry the failed EKS cluster metadata call without discarding successful workload identity evidence."}
	default:
		if len(diagnostics) > 0 {
			return awsPlatformDependencyStatusDegraded, 0.8, []string{"eks workload identity collection returned diagnostics"}, []string{"Review diagnostics before treating EKS identity coverage as complete."}
		}
		return awsPlatformDependencyStatusReady, 0.97, nil, nil
	}
}

func awsEKSWorkloadIdentityRelationships(records []AWSEKSWorkloadIdentityRecord) []AWSEKSWorkloadIdentityRelationship {
	result := make([]AWSEKSWorkloadIdentityRelationship, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.FromNodeID) == "" || strings.TrimSpace(record.ToNodeID) == "" {
			continue
		}
		relationshipType := firstNonEmptyAWSValue(record.RelationshipType, "runs_as")
		result = append(result, AWSEKSWorkloadIdentityRelationship{
			Type:        relationshipType,
			FromNodeID:  record.FromNodeID,
			ToNodeID:    record.ToNodeID,
			EvidenceRef: record.EvidenceRef,
		})
	}
	return result
}

func awsEKSWorkloadIdentityClusterCount(records []AWSEKSWorkloadIdentityRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if key := firstNonEmptyAWSValue(record.ClusterARN, record.ClusterName); key != "" {
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

func awsEKSWorkloadIdentityOIDCProviderCount(records []AWSEKSWorkloadIdentityRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.OIDCProviderARN) != "" {
			seen[record.OIDCProviderARN] = struct{}{}
		}
	}
	return len(seen)
}

func awsEKSWorkloadIdentityServiceAccountCount(records []AWSEKSWorkloadIdentityRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if record.RoleKind != "irsa" && record.RoleKind != "pod_identity" {
			continue
		}
		if key := awsEKSWorkloadIdentityClusterSubjectKey(record); key != "" {
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

func awsEKSWorkloadIdentityRoleKindCount(records []AWSEKSWorkloadIdentityRecord, roleKind string) int {
	count := 0
	for _, record := range records {
		if record.RoleKind == roleKind {
			count++
		}
	}
	return count
}

func awsEKSWorkloadIdentityIdentityCount(records []AWSEKSWorkloadIdentityRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		if strings.TrimSpace(record.ToNodeID) != "" {
			seen[record.ToNodeID] = struct{}{}
		}
	}
	return len(seen)
}

func awsEKSWorkloadIdentityResourceCount(records []AWSEKSWorkloadIdentityRecord) int {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, value := range []string{record.ClusterARN, record.AssociationARN, record.NodegroupARN, record.FargateProfileARN} {
			if strings.TrimSpace(value) != "" {
				seen[value] = struct{}{}
			}
		}
		if key := awsEKSWorkloadIdentityClusterSubjectKey(record); key != "" {
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

func awsEKSWorkloadIdentityClusterSubjectKey(record AWSEKSWorkloadIdentityRecord) string {
	subject := firstNonEmptyAWSValue(record.KubernetesSubject, record.Namespace+"/"+record.ServiceAccount)
	subject = strings.Trim(subject, "/")
	if subject == "" {
		return ""
	}
	cluster := firstNonEmptyAWSValue(record.ClusterARN, record.ClusterName, strings.Join([]string{record.AccountID, record.Region}, "/"), "cluster")
	return cluster + "|" + subject
}

func awsEKSWorkloadIdentityDiagnostics(diagnostics []providers.SourceError) []AWSEKSWorkloadIdentityDiagnostic {
	result := make([]AWSEKSWorkloadIdentityDiagnostic, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, AWSEKSWorkloadIdentityDiagnostic{
			Collector:   diagnostic.Collector,
			SourceID:    diagnostic.SourceID,
			Code:        diagnostic.Code,
			Message:     diagnostic.Message,
			Remediation: awsEKSWorkloadIdentityDiagnosticRemediation(diagnostic.Code),
			Retryable:   diagnostic.Retryable,
		})
	}
	return result
}

func awsEKSWorkloadIdentityDiagnosticRemediation(code string) string {
	switch code {
	case "permission_denied":
		return "Grant metadata-only EKS read permissions; do not add mutation, Kubernetes secret, pod log, or object-content reads."
	case "kubernetes_api_unavailable":
		return "Connect Kubernetes read access for serviceaccounts so IRSA annotations can be proven; keep AWS-side EKS evidence visible as degraded until then."
	case "irsa_annotation_collection_unconfigured":
		return "Connect the Kubernetes service-account annotation collector before treating IRSA coverage as complete; AWS-only EKS metadata remains visible."
	case "pod_identity_association_list_failed", "pod_identity_association_describe_failed", "nodegroup_list_failed", "nodegroup_describe_failed", "fargate_profile_list_failed", "fargate_profile_describe_failed":
		return "Retry only the failed EKS metadata partition and keep successful workload identity records visible."
	case "missing_eks_role":
		return "Inspect the EKS workload identity source before using it for least-privilege reasoning."
	default:
		return "Review the EKS collector diagnostic and retry after the scoped AWS metadata issue is corrected."
	}
}

func awsEKSWorkloadNodeID(accountID string, region string, roleKind string, workloadID string) string {
	account := strings.TrimSpace(accountID)
	if account == "" {
		account = "account"
	}
	trimmedRegion := strings.TrimSpace(region)
	if trimmedRegion == "" {
		trimmedRegion = "region"
	}
	kind := strings.ReplaceAll(strings.TrimSpace(roleKind), "_", "-")
	if kind == "" {
		kind = "workload"
	}
	normalizedWorkload := strings.TrimSpace(workloadID)
	if normalizedWorkload == "" {
		normalizedWorkload = "workload"
	}
	return fmt.Sprintf("aws:workload:eks:%s:%s:%s/%s", account, trimmedRegion, kind, normalizedWorkload)
}
