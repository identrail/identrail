package api

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	awsGraphExplorerCurrentIssue = 1551
	awsGraphExplorerVersion      = "aws-graph-explorer-experience-v1"
	awsGraphExplorerDefaultLimit = 50
	awsGraphExplorerMaxLimit     = 200
)

var awsGraphExplorerTokenReplacer = strings.NewReplacer(" ", "_", "-", "_")

// AWSGraphExplorerRequest scopes the operator graph explorer to one AWS
// connector and optional graph drill-down filters. The response is read-only:
// remediation fields are links and previews, never AWS write intents.
type AWSGraphExplorerRequest struct {
	ConnectorID  string `json:"connector_id,omitempty"`
	FixtureState string `json:"fixture_state,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Region       string `json:"region,omitempty"`
	NodeType     string `json:"node_type,omitempty"`
	EdgeType     string `json:"edge_type,omitempty"`
	Status       string `json:"status,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Search       string `json:"search,omitempty"`
	Expand       string `json:"expand,omitempty"`
	Cursor       string `json:"cursor,omitempty"`
	Limit        int    `json:"limit,omitempty"`
}

type AWSGraphExplorerEvidence struct {
	EvidenceID        string    `json:"evidence_id"`
	Source            string    `json:"source"`
	EvidenceRef       string    `json:"evidence_ref"`
	Label             string    `json:"label"`
	Status            string    `json:"status"`
	Confidence        float64   `json:"confidence"`
	ObservedAt        time.Time `json:"observed_at,omitzero"`
	NodeIDs           []string  `json:"node_ids,omitempty"`
	EdgeIDs           []string  `json:"edge_ids,omitempty"`
	RedactionBoundary string    `json:"redaction_boundary"`
}

type AWSGraphExplorerNode struct {
	NodeID       string            `json:"node_id"`
	NodeType     string            `json:"node_type"`
	Label        string            `json:"label"`
	AccountID    string            `json:"account_id,omitempty"`
	Region       string            `json:"region,omitempty"`
	Source       string            `json:"source"`
	Status       string            `json:"status"`
	Confidence   float64           `json:"confidence"`
	EvidenceRefs []string          `json:"evidence_refs,omitempty"`
	LastSeenAt   time.Time         `json:"last_seen_at,omitzero"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type AWSGraphExplorerEdge struct {
	EdgeID        string            `json:"edge_id"`
	Type          string            `json:"type"`
	Label         string            `json:"label"`
	FromNodeID    string            `json:"from_node_id"`
	ToNodeID      string            `json:"to_node_id"`
	AccountID     string            `json:"account_id,omitempty"`
	Region        string            `json:"region,omitempty"`
	Source        string            `json:"source"`
	Status        string            `json:"status"`
	Confidence    float64           `json:"confidence"`
	EvidenceRef   string            `json:"evidence_ref,omitempty"`
	RuntimeAction string            `json:"runtime_action,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type AWSGraphExplorerPath struct {
	PathID         string   `json:"path_id"`
	PathType       string   `json:"path_type"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity,omitempty"`
	Status         string   `json:"status"`
	Confidence     float64  `json:"confidence"`
	NodeIDs        []string `json:"node_ids"`
	EdgeIDs        []string `json:"edge_ids"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
	NextAction     string   `json:"next_action,omitempty"`
	RemediationRef string   `json:"remediation_ref,omitempty"`
	Source         string   `json:"source"`
}

type AWSGraphExplorerDiagnostic struct {
	Collector   string `json:"collector"`
	SourceID    string `json:"source_id,omitempty"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
	Retryable   bool   `json:"retryable"`
}

type AWSGraphExplorerCoverageGap struct {
	Capability  string `json:"capability"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

type AWSGraphExplorerSummary struct {
	TotalNodes           int            `json:"total_nodes"`
	TotalEdges           int            `json:"total_edges"`
	TotalPaths           int            `json:"total_paths"`
	FilteredNodes        int            `json:"filtered_nodes"`
	FilteredEdges        int            `json:"filtered_edges"`
	FilteredPaths        int            `json:"filtered_paths"`
	IdentityCount        int            `json:"identity_count"`
	AgentCount           int            `json:"agent_count"`
	ResourceCount        int            `json:"resource_count"`
	SessionCount         int            `json:"session_count"`
	RuntimeActionCount   int            `json:"runtime_action_count"`
	TrustEdgeCount       int            `json:"trust_edge_count"`
	PassRolePathCount    int            `json:"passrole_path_count"`
	RemediationLinkCount int            `json:"remediation_link_count"`
	EvidenceCount        int            `json:"evidence_count"`
	NodeTypeCounts       map[string]int `json:"node_type_counts"`
	EdgeTypeCounts       map[string]int `json:"edge_type_counts"`
	StatusCounts         map[string]int `json:"status_counts"`
	PageSize             int            `json:"page_size"`
	NextCursor           string         `json:"next_cursor,omitempty"`
	HasMore              bool           `json:"has_more"`
}

type AWSGraphExplorerResult struct {
	TenantID           string                        `json:"tenant_id"`
	WorkspaceID        string                        `json:"workspace_id"`
	ProjectID          string                        `json:"project_id"`
	ConnectorID        string                        `json:"connector_id,omitempty"`
	AccountID          string                        `json:"account_id,omitempty"`
	Region             string                        `json:"region,omitempty"`
	ParentIssueNumber  int                           `json:"parent_issue_number"`
	ParentIssueRef     string                        `json:"parent_issue_ref"`
	CurrentIssueNumber int                           `json:"current_issue_number"`
	CurrentIssueRef    string                        `json:"current_issue_ref"`
	Version            string                        `json:"version"`
	Status             string                        `json:"status"`
	FixtureState       string                        `json:"fixture_state,omitempty"`
	Confidence         float64                       `json:"confidence"`
	AppliedFilters     map[string]string             `json:"applied_filters"`
	Summary            AWSGraphExplorerSummary       `json:"summary"`
	Nodes              []AWSGraphExplorerNode        `json:"nodes"`
	Edges              []AWSGraphExplorerEdge        `json:"edges"`
	Paths              []AWSGraphExplorerPath        `json:"paths"`
	Evidence           []AWSGraphExplorerEvidence    `json:"evidence"`
	FailureReasons     []string                      `json:"failure_reasons"`
	RemediationHints   []string                      `json:"remediation_hints"`
	EvidenceLinks      []string                      `json:"evidence_links"`
	CoverageGaps       []AWSGraphExplorerCoverageGap `json:"coverage_gaps"`
	Diagnostics        []AWSGraphExplorerDiagnostic  `json:"diagnostics"`
	GeneratedAt        time.Time                     `json:"generated_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
}

type awsGraphExplorerBuilder struct {
	nodes    map[string]AWSGraphExplorerNode
	edges    map[string]AWSGraphExplorerEdge
	paths    map[string]AWSGraphExplorerPath
	evidence map[string]AWSGraphExplorerEvidence
}

func (s *Service) GetAWSGraphExplorer(ctx context.Context, workspaceID string, projectID string, request AWSGraphExplorerRequest) (AWSGraphExplorerResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSGraphExplorerResult{}, err
	}
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, strings.TrimSpace(request.ConnectorID))
	if err != nil {
		return AWSGraphExplorerResult{}, err
	}
	now := s.Now().UTC()
	fixtureState := normalizeAWSGraphExplorerFixtureState(request.FixtureState, connection, hasConnection)
	if fixtureState == "" {
		return AWSGraphExplorerResult{}, ErrInvalidAWSConnectionRequest
	}

	accountID := firstNonEmptyAWSValue(strings.TrimSpace(request.AccountID), connection.AccountID, "123456789012")
	region := firstNonEmptyAWSValue(strings.TrimSpace(request.Region), connection.Region, "us-east-1")
	connectorID := firstNonEmptyAWSValue(connection.ConnectorID, strings.TrimSpace(request.ConnectorID), "aws-fixture")
	sourceFixtureState := fixtureState
	if strings.TrimSpace(request.FixtureState) == "" && hasConnection && connection.Connected {
		sourceFixtureState = ""
	}

	agents, err := s.GetAWSAIAgentIdentityInventory(ctx, workspaceID, projectID, AWSAIAgentIdentityInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    accountID,
		Region:       region,
	})
	if err != nil {
		return AWSGraphExplorerResult{}, fmt.Errorf("load graph agent identities: %w", err)
	}
	runtime, err := s.GetAWSRuntimeEvents(ctx, workspaceID, projectID, AWSRuntimeEventRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    accountID,
		Region:       region,
	})
	if err != nil {
		return AWSGraphExplorerResult{}, fmt.Errorf("load graph runtime events: %w", err)
	}
	passRole, err := s.GetAWSIAMPassRoleRelationshipInventory(ctx, workspaceID, projectID, AWSIAMPassRoleRelationshipInventoryRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
	})
	if err != nil {
		return AWSGraphExplorerResult{}, fmt.Errorf("load graph PassRole relationships: %w", err)
	}
	blastRadius, err := s.GetAWSBlastRadius(ctx, workspaceID, projectID, AWSBlastRadiusRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    accountID,
		Region:       region,
	})
	if err != nil {
		return AWSGraphExplorerResult{}, fmt.Errorf("load graph blast radius: %w", err)
	}
	leastPrivilege, err := s.GetAWSLeastPrivilegeRecommendations(ctx, workspaceID, projectID, AWSLeastPrivilegeRequest{
		ConnectorID:  connectorID,
		FixtureState: sourceFixtureState,
		AccountID:    accountID,
		Region:       region,
	})
	if err != nil {
		return AWSGraphExplorerResult{}, fmt.Errorf("load graph least privilege: %w", err)
	}

	builder := newAWSGraphExplorerBuilder()
	builder.addAgents(agents)
	builder.addRuntime(runtime)
	builder.addPassRole(passRole)
	builder.addBlastRadius(blastRadius)
	builder.addLeastPrivilege(leastPrivilege)

	allNodes := builder.sortedNodes()
	allEdges := builder.sortedEdges()
	allPaths := builder.sortedPaths()
	allEvidence := builder.sortedEvidence()
	filteredNodes, filteredEdges, filteredPaths, applied := filterAWSGraphExplorer(allNodes, allEdges, allPaths, request)
	pagedNodes, displayedEdges, displayedPaths, nextCursor, hasMore := paginateAWSGraphExplorer(filteredNodes, allNodes, allEdges, filteredEdges, filteredPaths, request)
	displayedEvidence := filterAWSGraphExplorerEvidence(allEvidence, pagedNodes, displayedEdges, displayedPaths, request.Evidence)
	filteredGraphEntries := len(filteredNodes) + len(filteredEdges) + len(filteredPaths)
	status, confidence := summarizeAWSGraphExplorerStatus([]string{agents.Status, runtime.Status, passRole.Status, blastRadius.Status, leastPrivilege.Status}, len(allNodes), filteredGraphEntries)

	return AWSGraphExplorerResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ConnectorID:        connectorID,
		AccountID:          accountID,
		Region:             region,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsGraphExplorerCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsGraphExplorerCurrentIssue),
		Version:            awsGraphExplorerVersion,
		Status:             status,
		FixtureState:       sourceFixtureState,
		Confidence:         confidence,
		AppliedFilters:     applied,
		Summary: summarizeAWSGraphExplorer(
			allNodes,
			allEdges,
			allPaths,
			filteredNodes,
			filteredEdges,
			filteredPaths,
			len(displayedEvidence),
			awsGraphExplorerLimit(request),
			nextCursor,
			hasMore,
		),
		Nodes:            pagedNodes,
		Edges:            displayedEdges,
		Paths:            displayedPaths,
		Evidence:         displayedEvidence,
		FailureReasons:   awsGraphExplorerFailureReasons(agents, runtime, passRole, blastRadius, leastPrivilege, status),
		RemediationHints: awsGraphExplorerRemediationHints(agents, runtime, passRole, blastRadius, leastPrivilege, status),
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsGraphExplorerCurrentIssue),
			awsIssueURL(awsAIAgentIdentityCurrentIssue),
			awsIssueURL(awsRuntimeEventsCurrentIssue),
			awsIssueURL(awsIAMPassRoleRelationshipCurrentIssue),
			awsIssueURL(awsBlastRadiusCurrentIssue),
			awsIssueURL(awsLeastPrivilegeCurrentIssue),
			"/docs/aws-graph-explorer",
			"/docs/graph-relationship-contract",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		CoverageGaps: awsGraphExplorerCoverageGaps(agents, runtime, passRole, blastRadius, leastPrivilege),
		Diagnostics:  awsGraphExplorerDiagnostics(agents, runtime, passRole, blastRadius, leastPrivilege),
		GeneratedAt:  now,
		UpdatedAt:    now,
	}, nil
}

func normalizeAWSGraphExplorerFixtureState(requested string, connection AWSConnectionStatus, hasConnection bool) string {
	switch strings.ToLower(strings.TrimSpace(requested)) {
	case "":
		if !hasConnection || !connection.Connected {
			return "permission_denied"
		}
		return "success"
	case "success", "ready":
		return "success"
	case "empty", "degraded", "partial_failure", "permission_denied":
		return strings.ToLower(strings.TrimSpace(requested))
	default:
		return ""
	}
}

func newAWSGraphExplorerBuilder() *awsGraphExplorerBuilder {
	return &awsGraphExplorerBuilder{
		nodes:    map[string]AWSGraphExplorerNode{},
		edges:    map[string]AWSGraphExplorerEdge{},
		paths:    map[string]AWSGraphExplorerPath{},
		evidence: map[string]AWSGraphExplorerEvidence{},
	}
}

func (b *awsGraphExplorerBuilder) addNode(node AWSGraphExplorerNode) {
	node.NodeID = strings.TrimSpace(node.NodeID)
	if node.NodeID == "" {
		return
	}
	node.NodeType = firstNonEmptyAWSValue(awsGraphExplorerCanonicalNodeType(node.NodeType), "unknown")
	node.Label = firstNonEmptyAWSValue(strings.TrimSpace(node.Label), shortAWSARN(node.NodeID), node.NodeID)
	node.Status = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(node.Status), "ready")
	node.Source = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(node.Source), "aws_graph_explorer")
	node.EvidenceRefs = dedupeStrings(node.EvidenceRefs)
	if existing, ok := b.nodes[node.NodeID]; ok {
		existing.EvidenceRefs = dedupeStrings(append(existing.EvidenceRefs, node.EvidenceRefs...))
		existing.Confidence = maxFloat(existing.Confidence, node.Confidence)
		existing.Status = awsGraphExplorerMergedStatus(existing.Status, node.Status)
		existing.Source = strings.Join(dedupeStrings([]string{existing.Source, node.Source}), ",")
		if existing.Label == existing.NodeID || existing.Label == shortAWSARN(existing.NodeID) {
			existing.Label = node.Label
		}
		if existing.AccountID == "" {
			existing.AccountID = node.AccountID
		}
		if existing.Region == "" {
			existing.Region = node.Region
		}
		if node.LastSeenAt.After(existing.LastSeenAt) {
			existing.LastSeenAt = node.LastSeenAt
		}
		if existing.Metadata == nil {
			existing.Metadata = map[string]string{}
		}
		for key, value := range node.Metadata {
			if strings.TrimSpace(value) != "" {
				existing.Metadata[key] = value
			}
		}
		b.nodes[node.NodeID] = existing
		return
	}
	b.nodes[node.NodeID] = node
}

func (b *awsGraphExplorerBuilder) addEdge(edge AWSGraphExplorerEdge) {
	edge.FromNodeID = strings.TrimSpace(edge.FromNodeID)
	edge.ToNodeID = strings.TrimSpace(edge.ToNodeID)
	if edge.FromNodeID == "" || edge.ToNodeID == "" {
		return
	}
	edge.Type = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(edge.Type), "relationship")
	edge.EdgeID = firstNonEmptyAWSValue(edge.EdgeID, "aws-graph-edge:"+stableAWSBlastRadiusToken(edge.Source, edge.Type, edge.FromNodeID, edge.ToNodeID, edge.EvidenceRef))
	edge.Label = firstNonEmptyAWSValue(strings.TrimSpace(edge.Label), formatAWSBlastRadiusLabel(edge.Type))
	edge.Status = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(edge.Status), "ready")
	edge.Source = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(edge.Source), "aws_graph_explorer")
	if existing, ok := b.edges[edge.EdgeID]; ok {
		existing.Confidence = maxFloat(existing.Confidence, edge.Confidence)
		existing.Status = awsGraphExplorerMergedStatus(existing.Status, edge.Status)
		if existing.EvidenceRef == "" {
			existing.EvidenceRef = edge.EvidenceRef
		}
		if existing.RuntimeAction == "" {
			existing.RuntimeAction = edge.RuntimeAction
		}
		b.edges[edge.EdgeID] = existing
		return
	}
	b.edges[edge.EdgeID] = edge
}

func (b *awsGraphExplorerBuilder) addPath(path AWSGraphExplorerPath) {
	path.PathID = strings.TrimSpace(path.PathID)
	if path.PathID == "" || len(path.NodeIDs) == 0 {
		return
	}
	path.PathType = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(path.PathType), "path")
	path.Title = firstNonEmptyAWSValue(strings.TrimSpace(path.Title), formatAWSBlastRadiusLabel(path.PathType))
	path.Status = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(path.Status), "ready")
	path.NodeIDs = dedupeStrings(path.NodeIDs)
	path.EdgeIDs = dedupeStrings(path.EdgeIDs)
	path.EvidenceRefs = dedupeStrings(path.EvidenceRefs)
	b.paths[path.PathID] = path
}

func (b *awsGraphExplorerBuilder) addEvidence(evidence AWSGraphExplorerEvidence) {
	evidence.EvidenceRef = strings.TrimSpace(evidence.EvidenceRef)
	if evidence.EvidenceRef == "" {
		return
	}
	evidence.EvidenceID = firstNonEmptyAWSValue(evidence.EvidenceID, "aws-graph-evidence:"+stableAWSBlastRadiusToken(evidence.Source, evidence.EvidenceRef))
	evidence.Source = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(evidence.Source), "aws_graph_explorer")
	evidence.Status = firstNonEmptyAWSValue(awsGraphExplorerAPIToken(evidence.Status), "ready")
	evidence.Label = firstNonEmptyAWSValue(strings.TrimSpace(evidence.Label), formatAWSBlastRadiusLabel(evidence.Source))
	evidence.NodeIDs = dedupeStrings(evidence.NodeIDs)
	evidence.EdgeIDs = dedupeStrings(evidence.EdgeIDs)
	evidence.RedactionBoundary = "metadata_only"
	if existing, ok := b.evidence[evidence.EvidenceID]; ok {
		existing.NodeIDs = dedupeStrings(append(existing.NodeIDs, evidence.NodeIDs...))
		existing.EdgeIDs = dedupeStrings(append(existing.EdgeIDs, evidence.EdgeIDs...))
		existing.Confidence = maxFloat(existing.Confidence, evidence.Confidence)
		existing.Status = awsGraphExplorerMergedStatus(existing.Status, evidence.Status)
		if evidence.ObservedAt.After(existing.ObservedAt) {
			existing.ObservedAt = evidence.ObservedAt
		}
		b.evidence[evidence.EvidenceID] = existing
		return
	}
	b.evidence[evidence.EvidenceID] = evidence
}

func (b *awsGraphExplorerBuilder) addAgents(result AWSAIAgentIdentityInventoryResult) {
	for _, record := range result.Records {
		b.addNode(AWSGraphExplorerNode{
			NodeID:       record.AgentNodeID,
			NodeType:     "agent",
			Label:        firstNonEmptyAWSValue(record.AgentName, record.AgentID, record.AgentNodeID),
			AccountID:    record.AccountID,
			Region:       record.Region,
			Source:       "ai_agent_identities",
			Status:       record.Status,
			Confidence:   record.Confidence,
			EvidenceRefs: []string{record.EvidenceRef},
			LastSeenAt:   record.CollectedAt,
			Metadata: map[string]string{
				"agent_id":   record.AgentID,
				"agent_type": record.AgentType,
				"runtime":    record.RuntimeVersion,
				"provider":   record.Provider,
			},
		})
		if record.RuntimeRoleNodeID != "" {
			b.addNode(AWSGraphExplorerNode{
				NodeID:       record.RuntimeRoleNodeID,
				NodeType:     "identity",
				Label:        firstNonEmptyAWSValue(record.RuntimeRoleName, shortAWSARN(record.RuntimeRoleARN), record.RuntimeRoleNodeID),
				AccountID:    firstNonEmptyAWSValue(record.RuntimeRoleAccountID, record.AccountID),
				Region:       record.Region,
				Source:       "ai_agent_identities",
				Status:       record.Status,
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   record.CollectedAt,
			})
		}
		if record.GatewayNodeID != "" {
			b.addNode(AWSGraphExplorerNode{
				NodeID:       record.GatewayNodeID,
				NodeType:     "agent_gateway",
				Label:        firstNonEmptyAWSValue(record.GatewayID, record.GatewayARN, record.GatewayNodeID),
				AccountID:    record.AccountID,
				Region:       record.Region,
				Source:       "ai_agent_identities",
				Status:       record.Status,
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   record.CollectedAt,
			})
		}
		targets := append(append([]string{}, record.ToolTargetRefs...), record.ResourceReferenceRefs...)
		if record.EncryptionKeyARN != "" {
			targets = append(targets, record.EncryptionKeyARN)
		}
		for _, target := range dedupeStrings(targets) {
			nodeID := awsGraphExplorerResourceNodeID(target)
			b.addNode(AWSGraphExplorerNode{
				NodeID:       nodeID,
				NodeType:     awsGraphExplorerNodeTypeForResource(target),
				Label:        firstNonEmptyAWSValue(shortAWSARN(target), target),
				AccountID:    record.AccountID,
				Region:       record.Region,
				Source:       "ai_agent_identities",
				Status:       record.Status,
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   record.CollectedAt,
			})
		}
		relationshipNodeIDs := b.addAIAgentRelationshipEndpointNodes(record)
		b.addEvidence(AWSGraphExplorerEvidence{
			Source:      "ai_agent_identities",
			EvidenceRef: record.EvidenceRef,
			Label:       "AI agent identity inventory",
			Status:      record.Status,
			Confidence:  record.Confidence,
			ObservedAt:  record.CollectedAt,
			NodeIDs:     dedupeStrings(append([]string{record.AgentNodeID, record.RuntimeRoleNodeID, record.GatewayNodeID}, relationshipNodeIDs...)),
		})
	}
	for _, rel := range result.Relationships {
		edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("ai_agent_identities", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
		b.addEdge(AWSGraphExplorerEdge{
			EdgeID:      edgeID,
			Type:        rel.Type,
			Label:       formatAWSBlastRadiusLabel(rel.Type),
			FromNodeID:  rel.FromNodeID,
			ToNodeID:    rel.ToNodeID,
			Source:      "ai_agent_identities",
			Status:      result.Status,
			Confidence:  result.Confidence,
			EvidenceRef: rel.EvidenceRef,
		})
		b.attachEvidenceEdge(rel.EvidenceRef, edgeID)
	}
}

func (b *awsGraphExplorerBuilder) addAIAgentRelationshipEndpointNodes(record AWSAIAgentIdentityRecord) []string {
	nodeIDs := []string{}
	if record.AgentNodeID != "" && record.RuntimeRoleNodeID != "" {
		workloadNodeID := awsAIAgentWorkloadNodeID(record)
		b.addNode(AWSGraphExplorerNode{
			NodeID:       workloadNodeID,
			NodeType:     "agent",
			Label:        firstNonEmptyAWSValue(record.AgentName, record.AgentID, workloadNodeID),
			AccountID:    record.AccountID,
			Region:       record.Region,
			Source:       "ai_agent_identities",
			Status:       record.Status,
			Confidence:   record.Confidence,
			EvidenceRefs: []string{record.EvidenceRef},
			LastSeenAt:   record.CollectedAt,
			Metadata: map[string]string{
				"agent_id":   record.AgentID,
				"agent_type": record.AgentType,
				"runtime":    record.RuntimeVersion,
			},
		})
		nodeIDs = append(nodeIDs, workloadNodeID)
	}
	for i, endpointARN := range record.ExecutionEndpointARNs {
		endpointARN = strings.TrimSpace(endpointARN)
		if record.AgentNodeID == "" || endpointARN == "" {
			continue
		}
		endpointNodeID := awsAIAgentExecutionEndpointNodeID(record.AgentNodeID, endpointARN)
		endpointName := endpointARN
		if i < len(record.ExecutionEndpointNames) {
			endpointName = firstNonEmptyAWSValue(record.ExecutionEndpointNames[i], endpointName)
		}
		endpointStatus := record.Status
		if i < len(record.ExecutionEndpointStatuses) {
			endpointStatus = firstNonEmptyAWSValue(record.ExecutionEndpointStatuses[i], endpointStatus)
		}
		b.addNode(AWSGraphExplorerNode{
			NodeID:       endpointNodeID,
			NodeType:     "resource",
			Label:        firstNonEmptyAWSValue(endpointName, shortAWSARN(endpointARN), endpointNodeID),
			AccountID:    record.AccountID,
			Region:       record.Region,
			Source:       "ai_agent_identities",
			Status:       endpointStatus,
			Confidence:   record.Confidence,
			EvidenceRefs: []string{record.EvidenceRef},
			LastSeenAt:   record.CollectedAt,
		})
		nodeIDs = append(nodeIDs, endpointNodeID)
	}
	toolNames := dedupeStrings(record.ToolNames)
	if record.AgentNodeID != "" && len(toolNames) > 0 {
		callsToolSource := firstNonEmptyAWSValue(record.GatewayNodeID, record.AgentNodeID)
		if strings.EqualFold(record.AgentType, "agent_gateway") {
			callsToolSource = record.AgentNodeID
		}
		for _, tool := range toolNames {
			tool = strings.TrimSpace(tool)
			if callsToolSource == "" || tool == "" {
				continue
			}
			toolNodeID := awsAIAgentToolNodeID(callsToolSource, tool)
			b.addNode(AWSGraphExplorerNode{
				NodeID:       toolNodeID,
				NodeType:     "resource",
				Label:        firstNonEmptyAWSValue(tool, toolNodeID),
				AccountID:    record.AccountID,
				Region:       record.Region,
				Source:       "ai_agent_identities",
				Status:       record.Status,
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   record.CollectedAt,
			})
			nodeIDs = append(nodeIDs, toolNodeID)
		}
	}
	for _, ref := range record.CredentialReferenceRefs {
		ref = strings.TrimSpace(ref)
		if record.AgentNodeID == "" || ref == "" {
			continue
		}
		credentialNodeID := awsCredentialReferenceNodeID(record.AgentNodeID, ref)
		b.addNode(AWSGraphExplorerNode{
			NodeID:       credentialNodeID,
			NodeType:     "credential_reference",
			Label:        firstNonEmptyAWSValue(ref, credentialNodeID),
			AccountID:    record.AccountID,
			Region:       record.Region,
			Source:       "ai_agent_identities",
			Status:       record.Status,
			Confidence:   record.Confidence,
			EvidenceRefs: []string{record.EvidenceRef},
			LastSeenAt:   record.CollectedAt,
		})
		nodeIDs = append(nodeIDs, credentialNodeID)
	}
	return dedupeStrings(nodeIDs)
}

func (b *awsGraphExplorerBuilder) addRuntime(result AWSRuntimeEventResult) {
	for _, record := range result.Records {
		b.addNode(AWSGraphExplorerNode{
			NodeID:       record.ActorIdentityNodeID,
			NodeType:     "identity",
			Label:        firstNonEmptyAWSValue(shortAWSARN(record.ActorPrincipalARN), record.ActorIdentityNodeID),
			AccountID:    firstNonEmptyAWSValue(roleAccountIDFromARNForAPI(record.ActorPrincipalARN), record.AccountID),
			Region:       record.Region,
			Source:       "runtime_events",
			Status:       record.Status,
			Confidence:   record.Confidence,
			EvidenceRefs: []string{record.EvidenceRef},
			LastSeenAt:   record.ObservedAt,
		})
		if record.Session.SessionNodeID != "" {
			b.addNode(AWSGraphExplorerNode{
				NodeID:       record.Session.SessionNodeID,
				NodeType:     "session",
				Label:        firstNonEmptyAWSValue(record.Session.RoleSessionName, record.Session.SessionID, record.Session.SessionNodeID),
				AccountID:    record.AccountID,
				Region:       record.Region,
				Source:       "runtime_events",
				Status:       firstNonEmptyAWSValue(record.Session.LineageStatus, record.Status),
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   firstNonZeroTime(record.Session.StartedAt, record.ObservedAt),
				Metadata: map[string]string{
					"source_identity": record.Session.SourceIdentity,
					"lineage_reason":  record.Session.LineageReason,
				},
			})
		}
		for _, lineage := range []struct {
			nodeID string
			arn    string
		}{
			{nodeID: record.Session.OriginalActorNodeID, arn: record.Session.OriginalActorARN},
			{nodeID: record.Session.ChainedFromNodeID, arn: record.Session.ChainedFromPrincipalARN},
		} {
			if lineage.nodeID == "" || lineage.nodeID == record.ActorIdentityNodeID {
				continue
			}
			b.addNode(AWSGraphExplorerNode{
				NodeID:       lineage.nodeID,
				NodeType:     "identity",
				Label:        firstNonEmptyAWSValue(shortAWSARN(lineage.arn), lineage.nodeID),
				AccountID:    firstNonEmptyAWSValue(roleAccountIDFromARNForAPI(lineage.arn), record.AccountID),
				Region:       record.Region,
				Source:       "runtime_events",
				Status:       firstNonEmptyAWSValue(record.Session.LineageStatus, record.Status),
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   firstNonZeroTime(record.Session.StartedAt, record.ObservedAt),
			})
		}
		if record.ResourceNodeID != "" {
			resourceAccountID, resourceRegion := awsGraphExplorerScopedARNParts(record.TargetResourceARN)
			b.addNode(AWSGraphExplorerNode{
				NodeID:       record.ResourceNodeID,
				NodeType:     awsGraphExplorerNodeTypeForResource(firstNonEmptyAWSValue(record.TargetResourceType, record.TargetResourceARN)),
				Label:        firstNonEmptyAWSValue(record.TargetResourceName, shortAWSARN(record.TargetResourceARN), record.ResourceNodeID),
				AccountID:    firstNonEmptyAWSValue(resourceAccountID, record.AccountID),
				Region:       firstNonEmptyAWSValue(resourceRegion, record.Region),
				Source:       "runtime_events",
				Status:       record.Status,
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   record.ObservedAt,
			})
		}
		if record.AgentNodeID != "" {
			b.addNode(AWSGraphExplorerNode{
				NodeID:       record.AgentNodeID,
				NodeType:     "agent",
				Label:        firstNonEmptyAWSValue(record.AgentID, record.AgentNodeID),
				AccountID:    record.AccountID,
				Region:       record.Region,
				Source:       "runtime_events",
				Status:       record.Status,
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   record.ObservedAt,
			})
		}
		b.addEvidence(AWSGraphExplorerEvidence{
			Source:      "runtime_events",
			EvidenceRef: record.EvidenceRef,
			Label:       firstNonEmptyAWSValue(record.Action, record.EventName, "Runtime event"),
			Status:      record.Status,
			Confidence:  record.Confidence,
			ObservedAt:  record.ObservedAt,
			NodeIDs:     dedupeStrings([]string{record.ActorIdentityNodeID, record.Session.SessionNodeID, record.Session.OriginalActorNodeID, record.Session.ChainedFromNodeID, record.ResourceNodeID, record.AgentNodeID}),
		})
	}
	for _, rel := range result.Relationships {
		action := awsGraphExplorerRuntimeActionForEvidence(result.Records, rel.EvidenceRef)
		edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("runtime_events", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
		b.addEdge(AWSGraphExplorerEdge{
			EdgeID:        edgeID,
			Type:          rel.Type,
			Label:         formatAWSBlastRadiusLabel(rel.Type),
			FromNodeID:    rel.FromNodeID,
			ToNodeID:      rel.ToNodeID,
			Source:        "runtime_events",
			Status:        result.Status,
			Confidence:    result.Confidence,
			EvidenceRef:   rel.EvidenceRef,
			RuntimeAction: action,
		})
		b.attachEvidenceEdge(rel.EvidenceRef, edgeID)
	}
}

func (b *awsGraphExplorerBuilder) addPassRole(result AWSIAMPassRoleRelationshipInventoryResult) {
	passRoleEdgeIDsByGrant := map[string][]string{}
	for _, rel := range result.Relationships {
		if rel.Type != "can_pass_role" || rel.FromNodeID == "" || rel.ToNodeID == "" {
			continue
		}
		key := awsGraphExplorerPassRoleGrantKey(rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
		edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("iam_passrole_relationships", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
		passRoleEdgeIDsByGrant[key] = append(passRoleEdgeIDsByGrant[key], edgeID)
	}
	for _, record := range result.Records {
		b.addNode(AWSGraphExplorerNode{
			NodeID:       record.FromNodeID,
			NodeType:     "identity",
			Label:        firstNonEmptyAWSValue(record.SourceRoleName, shortAWSARN(record.SourceRoleARN), record.FromNodeID),
			AccountID:    record.AccountID,
			Region:       record.Region,
			Source:       "iam_passrole_relationships",
			Status:       record.Status,
			Confidence:   record.Confidence,
			EvidenceRefs: []string{record.EvidenceRef},
			LastSeenAt:   record.CollectedAt,
		})
		if record.ToNodeID != "" {
			b.addNode(AWSGraphExplorerNode{
				NodeID:       record.ToNodeID,
				NodeType:     "identity",
				Label:        firstNonEmptyAWSValue(shortAWSARN(record.TargetResource), record.ToNodeID),
				AccountID:    record.AccountID,
				Region:       record.Region,
				Source:       "iam_passrole_relationships",
				Status:       record.Status,
				Confidence:   record.Confidence,
				EvidenceRefs: []string{record.EvidenceRef},
				LastSeenAt:   record.CollectedAt,
			})
		}
		b.addEvidence(AWSGraphExplorerEvidence{
			Source:      "iam_passrole_relationships",
			EvidenceRef: record.EvidenceRef,
			Label:       firstNonEmptyAWSValue(record.StatementSid, "PassRole policy statement"),
			Status:      record.Status,
			Confidence:  record.Confidence,
			ObservedAt:  record.CollectedAt,
			NodeIDs:     dedupeStrings([]string{record.FromNodeID, record.ToNodeID}),
		})
		if record.ToNodeID != "" && !record.UnresolvedTarget && strings.EqualFold(record.Effect, "Allow") {
			edgeIDs := dedupeStrings(passRoleEdgeIDsByGrant[awsGraphExplorerPassRoleGrantKey(record.FromNodeID, record.ToNodeID, record.EvidenceRef)])
			if len(edgeIDs) == 0 {
				edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("iam_passrole_relationships", "can_pass_role", record.FromNodeID, record.ToNodeID, record.EvidenceRef)
				b.addEdge(AWSGraphExplorerEdge{
					EdgeID:      edgeID,
					Type:        "can_pass_role",
					Label:       formatAWSBlastRadiusLabel("can_pass_role"),
					FromNodeID:  record.FromNodeID,
					ToNodeID:    record.ToNodeID,
					Source:      "iam_passrole_relationships",
					Status:      result.Status,
					Confidence:  result.Confidence,
					EvidenceRef: record.EvidenceRef,
				})
				edgeIDs = []string{edgeID}
				b.attachEvidenceEdge(record.EvidenceRef, edgeID)
			}
			b.addPath(AWSGraphExplorerPath{
				PathID:       "aws-graph-path:" + stableAWSBlastRadiusToken("passrole", record.FromNodeID, record.ToNodeID, record.EvidenceRef),
				PathType:     "passrole_path",
				Title:        fmt.Sprintf("%s can pass %s", firstNonEmptyAWSValue(record.SourceRoleName, shortAWSARN(record.SourceRoleARN)), shortAWSARN(record.TargetResource)),
				Status:       record.Status,
				Confidence:   record.Confidence,
				NodeIDs:      []string{record.FromNodeID, record.ToNodeID},
				EdgeIDs:      edgeIDs,
				EvidenceRefs: []string{record.EvidenceRef},
				NextAction:   "Inspect iam:PassedToService and tighten PassRole resources before treating this path as bounded.",
				Source:       "iam_passrole_relationships",
			})
		}
	}
	for _, rel := range result.Relationships {
		edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("iam_passrole_relationships", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
		b.addEdge(AWSGraphExplorerEdge{
			EdgeID:      edgeID,
			Type:        rel.Type,
			Label:       formatAWSBlastRadiusLabel(rel.Type),
			FromNodeID:  rel.FromNodeID,
			ToNodeID:    rel.ToNodeID,
			Source:      "iam_passrole_relationships",
			Status:      result.Status,
			Confidence:  result.Confidence,
			EvidenceRef: rel.EvidenceRef,
			Metadata: map[string]string{
				"effect":            rel.Effect,
				"passed_to_service": rel.PassedToService,
			},
		})
		b.attachEvidenceEdge(rel.EvidenceRef, edgeID)
	}
}

func (b *awsGraphExplorerBuilder) addBlastRadius(result AWSBlastRadiusResult) {
	for _, finding := range result.Findings {
		for _, step := range finding.ImpactedPath {
			b.addNode(AWSGraphExplorerNode{
				NodeID:       step.NodeID,
				NodeType:     step.NodeType,
				Label:        step.Label,
				AccountID:    firstNonEmptyAWSValue(step.AccountID, finding.AccountID),
				Region:       firstNonEmptyAWSValue(step.Region, finding.Region),
				Source:       "blast_radius",
				Status:       finding.Status,
				Confidence:   finding.Confidence,
				EvidenceRefs: awsGraphExplorerEvidenceRefs(finding.Evidence),
				LastSeenAt:   finding.UpdatedAt,
			})
		}
		edgeIDs := []string{}
		for i := 1; i < len(finding.ImpactedPath); i++ {
			from := finding.ImpactedPath[i-1].NodeID
			to := finding.ImpactedPath[i].NodeID
			evidenceRef := firstAWSGraphExplorerEvidenceRef(finding.Evidence)
			edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("blast_radius", finding.FindingID, from, to)
			b.addEdge(AWSGraphExplorerEdge{
				EdgeID:      edgeID,
				Type:        "impacted_path",
				Label:       "Impacted path",
				FromNodeID:  from,
				ToNodeID:    to,
				AccountID:   finding.AccountID,
				Region:      finding.Region,
				Source:      "blast_radius",
				Status:      finding.Status,
				Confidence:  finding.Confidence,
				EvidenceRef: evidenceRef,
			})
			edgeIDs = append(edgeIDs, edgeID)
		}
		for _, evidence := range finding.Evidence {
			b.addEvidence(AWSGraphExplorerEvidence{
				Source:      evidence.Source,
				EvidenceRef: evidence.EvidenceRef,
				Label:       evidence.Label,
				Status:      finding.Status,
				Confidence:  evidence.Confidence,
				ObservedAt:  evidence.ObservedAt,
				NodeIDs:     finding.ImpactedNodes,
				EdgeIDs:     edgeIDs,
			})
		}
		b.addPath(AWSGraphExplorerPath{
			PathID:         "aws-graph-path:" + stableAWSBlastRadiusToken("blast-radius", finding.FindingID),
			PathType:       finding.RiskType,
			Title:          finding.Rationale,
			Severity:       finding.Severity,
			Status:         finding.Status,
			Confidence:     finding.Confidence,
			NodeIDs:        awsGraphExplorerPathNodeIDs(finding.ImpactedPath),
			EdgeIDs:        edgeIDs,
			EvidenceRefs:   awsGraphExplorerEvidenceRefs(finding.Evidence),
			NextAction:     finding.NextAction,
			RemediationRef: finding.RemediationCase.CaseID,
			Source:         "blast_radius",
		})
	}
	for _, rel := range result.Relationships {
		edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("blast_radius", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
		b.addEdge(AWSGraphExplorerEdge{
			EdgeID:      edgeID,
			Type:        rel.Type,
			Label:       formatAWSBlastRadiusLabel(rel.Type),
			FromNodeID:  rel.FromNodeID,
			ToNodeID:    rel.ToNodeID,
			Source:      "blast_radius",
			Status:      result.Status,
			Confidence:  result.Confidence,
			EvidenceRef: rel.EvidenceRef,
		})
		b.attachEvidenceEdge(rel.EvidenceRef, edgeID)
	}
}

func (b *awsGraphExplorerBuilder) addLeastPrivilege(result AWSLeastPrivilegeResult) {
	recommendationEdgeRelationships := make(map[string][]AWSLeastPrivilegeRelationship, len(result.Relationships))
	for _, rel := range result.Relationships {
		recommendationEdgeRelationships[rel.RecommendationID] = append(
			recommendationEdgeRelationships[rel.RecommendationID],
			rel,
		)
	}
	for _, recommendation := range result.Recommendations {
		for _, step := range recommendation.ImpactedPath {
			b.addNode(AWSGraphExplorerNode{
				NodeID:       step.NodeID,
				NodeType:     step.NodeType,
				Label:        step.Label,
				AccountID:    firstNonEmptyAWSValue(step.AccountID, recommendation.AccountID),
				Region:       firstNonEmptyAWSValue(step.Region, recommendation.Region),
				Source:       "least_privilege",
				Status:       recommendation.Status,
				Confidence:   recommendation.Confidence,
				EvidenceRefs: awsGraphExplorerLeastPrivilegeEvidenceRefs(recommendation.Evidence),
				LastSeenAt:   recommendation.UpdatedAt,
			})
		}
		edgeIDs := []string{}
		for _, rel := range recommendationEdgeRelationships[recommendation.RecommendationID] {
			edgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("least_privilege", rel.Type, rel.FromNodeID, rel.ToNodeID, rel.EvidenceRef)
			b.addEdge(AWSGraphExplorerEdge{
				EdgeID:      edgeID,
				Type:        rel.Type,
				Label:       formatAWSBlastRadiusLabel(rel.Type),
				FromNodeID:  rel.FromNodeID,
				ToNodeID:    rel.ToNodeID,
				Source:      "least_privilege",
				Status:      recommendation.Status,
				Confidence:  recommendation.Confidence,
				EvidenceRef: rel.EvidenceRef,
			})
			edgeIDs = append(edgeIDs, edgeID)
		}
		for _, evidence := range recommendation.Evidence {
			b.addEvidence(AWSGraphExplorerEvidence{
				Source:      evidence.Source,
				EvidenceRef: evidence.EvidenceRef,
				Label:       evidence.Label,
				Status:      recommendation.Status,
				Confidence:  evidence.Confidence,
				ObservedAt:  evidence.ObservedAt,
				NodeIDs:     recommendation.ImpactedNodes,
				EdgeIDs:     edgeIDs,
			})
		}
		b.addPath(AWSGraphExplorerPath{
			PathID:         "aws-graph-path:" + stableAWSBlastRadiusToken("least-privilege", recommendation.RecommendationID),
			PathType:       "least_privilege_recommendation",
			Title:          recommendation.Rationale,
			Severity:       recommendation.Severity,
			Status:         recommendation.Status,
			Confidence:     recommendation.Confidence,
			NodeIDs:        awsGraphExplorerLeastPrivilegePathNodeIDs(recommendation.ImpactedPath),
			EdgeIDs:        edgeIDs,
			EvidenceRefs:   awsGraphExplorerLeastPrivilegeEvidenceRefs(recommendation.Evidence),
			NextAction:     recommendation.NextAction,
			RemediationRef: recommendation.RemediationCase.CaseID,
			Source:         "least_privilege",
		})
	}
}

func (b *awsGraphExplorerBuilder) attachEvidenceEdge(evidenceRef string, edgeID string) {
	for id, evidence := range b.evidence {
		if evidence.EvidenceRef == evidenceRef {
			evidence.EdgeIDs = dedupeStrings(append(evidence.EdgeIDs, edgeID))
			b.evidence[id] = evidence
		}
	}
}

func (b *awsGraphExplorerBuilder) sortedNodes() []AWSGraphExplorerNode {
	nodes := make([]AWSGraphExplorerNode, 0, len(b.nodes))
	for _, node := range b.nodes {
		nodes = append(nodes, node)
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].NodeType == nodes[j].NodeType {
			return nodes[i].NodeID < nodes[j].NodeID
		}
		return nodes[i].NodeType < nodes[j].NodeType
	})
	return nodes
}

func (b *awsGraphExplorerBuilder) sortedEdges() []AWSGraphExplorerEdge {
	edges := make([]AWSGraphExplorerEdge, 0, len(b.edges))
	for _, edge := range b.edges {
		edges = append(edges, edge)
	}
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].Type == edges[j].Type {
			return edges[i].EdgeID < edges[j].EdgeID
		}
		return edges[i].Type < edges[j].Type
	})
	return edges
}

func (b *awsGraphExplorerBuilder) sortedPaths() []AWSGraphExplorerPath {
	paths := make([]AWSGraphExplorerPath, 0, len(b.paths))
	for _, path := range b.paths {
		paths = append(paths, path)
	}
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Severity == paths[j].Severity {
			return paths[i].PathID < paths[j].PathID
		}
		return awsGraphExplorerSeverityRank(paths[i].Severity) > awsGraphExplorerSeverityRank(paths[j].Severity)
	})
	return paths
}

func (b *awsGraphExplorerBuilder) sortedEvidence() []AWSGraphExplorerEvidence {
	evidence := make([]AWSGraphExplorerEvidence, 0, len(b.evidence))
	for _, entry := range b.evidence {
		evidence = append(evidence, entry)
	}
	sort.SliceStable(evidence, func(i, j int) bool {
		return evidence[i].EvidenceID < evidence[j].EvidenceID
	})
	return evidence
}

func filterAWSGraphExplorer(nodes []AWSGraphExplorerNode, edges []AWSGraphExplorerEdge, paths []AWSGraphExplorerPath, request AWSGraphExplorerRequest) ([]AWSGraphExplorerNode, []AWSGraphExplorerEdge, []AWSGraphExplorerPath, map[string]string) {
	filters := map[string]string{
		"account_id": strings.TrimSpace(request.AccountID),
		"region":     strings.TrimSpace(request.Region),
		"node_type":  awsGraphExplorerCanonicalNodeType(request.NodeType),
		"edge_type":  awsGraphExplorerAPIToken(request.EdgeType),
		"status":     awsGraphExplorerAPIToken(request.Status),
		"evidence":   awsGraphExplorerAPIToken(request.Evidence),
		"search":     strings.TrimSpace(request.Search),
		"expand":     awsGraphExplorerAPIToken(request.Expand),
	}
	applied := map[string]string{}
	for key, value := range filters {
		if value != "" && value != "all" {
			applied[key] = value
		}
	}

	filteredNodes := make([]AWSGraphExplorerNode, 0, len(nodes))
	for _, node := range nodes {
		if filters["account_id"] != "" && !strings.EqualFold(node.AccountID, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && !strings.EqualFold(node.Region, filters["region"]) {
			continue
		}
		if filters["node_type"] != "" && filters["node_type"] != "all" && filters["node_type"] != awsGraphExplorerAPIToken(node.NodeType) {
			continue
		}
		if filters["status"] != "" && filters["status"] != "all" && filters["status"] != awsGraphExplorerAPIToken(node.Status) {
			continue
		}
		if filters["evidence"] != "" && filters["evidence"] != "all" && !awsGraphExplorerMatchesEvidence(filters["evidence"], node.EvidenceRefs, node.Source) {
			continue
		}
		if filters["search"] != "" && !awsGraphExplorerNodeMatchesSearch(filters["search"], node) {
			continue
		}
		filteredNodes = append(filteredNodes, node)
	}

	filteredNodeIDs := make(map[string]struct{}, len(filteredNodes))
	for _, node := range filteredNodes {
		filteredNodeIDs[node.NodeID] = struct{}{}
	}
	hardScopeFilter := filters["account_id"] != "" || filters["region"] != ""
	hardScopeNodeIDs := map[string]struct{}{}
	if hardScopeFilter {
		for _, node := range nodes {
			if filters["account_id"] != "" && !strings.EqualFold(node.AccountID, filters["account_id"]) {
				continue
			}
			if filters["region"] != "" && !strings.EqualFold(node.Region, filters["region"]) {
				continue
			}
			hardScopeNodeIDs[node.NodeID] = struct{}{}
		}
	}
	nodeTypeScopedFilter := filters["node_type"] != "" && filters["node_type"] != "all"

	filteredEdges := make([]AWSGraphExplorerEdge, 0, len(edges))
	neighborFallbackEdges := make([]AWSGraphExplorerEdge, 0)
	hasMatchingEdgeSearch := false
	for _, edge := range edges {
		if filters["account_id"] != "" && edge.AccountID != "" && !strings.EqualFold(edge.AccountID, filters["account_id"]) {
			continue
		}
		if filters["region"] != "" && edge.Region != "" && !strings.EqualFold(edge.Region, filters["region"]) {
			continue
		}
		if filters["edge_type"] != "" && filters["edge_type"] != "all" && filters["edge_type"] != awsGraphExplorerAPIToken(edge.Type) {
			continue
		}
		if filters["status"] != "" && filters["status"] != "all" && filters["status"] != awsGraphExplorerAPIToken(edge.Status) {
			continue
		}
		if filters["evidence"] != "" && filters["evidence"] != "all" && !awsGraphExplorerMatchesEvidence(filters["evidence"], []string{edge.EvidenceRef}, edge.Source) {
			continue
		}
		if filters["search"] != "" && !awsGraphExplorerEdgeMatchesSearch(filters["search"], edge) {
			if len(filteredNodeIDs) > 0 {
				_, fromMatch := filteredNodeIDs[edge.FromNodeID]
				_, toMatch := filteredNodeIDs[edge.ToNodeID]
				if fromMatch || toMatch {
					neighborFallbackEdges = append(neighborFallbackEdges, edge)
				}
			}
			continue
		}
		if hardScopeFilter && !awsGraphExplorerEdgeEndpointsInScope(edge, hardScopeNodeIDs) {
			continue
		}
		if nodeTypeScopedFilter && !awsGraphExplorerEdgeTouchesNode(edge, filteredNodeIDs) {
			continue
		}
		hasMatchingEdgeSearch = true
		filteredEdges = append(filteredEdges, edge)
	}
	filteredPaths := make([]AWSGraphExplorerPath, 0, len(paths))
	for _, path := range paths {
		if filters["status"] != "" && filters["status"] != "all" && filters["status"] != awsGraphExplorerAPIToken(path.Status) {
			continue
		}
		if filters["evidence"] != "" && filters["evidence"] != "all" && !awsGraphExplorerMatchesEvidence(filters["evidence"], path.EvidenceRefs, path.Source) {
			continue
		}
		if filters["search"] != "" && !awsGraphExplorerPathMatchesSearch(filters["search"], path) {
			continue
		}
		if hardScopeFilter && !awsGraphExplorerPathOnlyUsesNodes(path, hardScopeNodeIDs) {
			continue
		}
		if nodeTypeScopedFilter && (len(filteredNodeIDs) == 0 || !awsGraphExplorerPathTouchesNode(path, filteredNodeIDs)) {
			continue
		}
		filteredPaths = append(filteredPaths, path)
	}
	if filters["search"] != "" && len(neighborFallbackEdges) > 0 {
		expandNeighbors := awsGraphExplorerAPIToken(request.Expand) == "neighbors"
		if expandNeighbors || (len(filteredPaths) > 0 && !hasMatchingEdgeSearch) {
			filteredEdges = append(filteredEdges, neighborFallbackEdges...)
		}
	}
	return filteredNodes, filteredEdges, filteredPaths, applied
}

func paginateAWSGraphExplorer(nodes []AWSGraphExplorerNode, allNodes []AWSGraphExplorerNode, allEdges []AWSGraphExplorerEdge, edges []AWSGraphExplorerEdge, paths []AWSGraphExplorerPath, request AWSGraphExplorerRequest) ([]AWSGraphExplorerNode, []AWSGraphExplorerEdge, []AWSGraphExplorerPath, string, bool) {
	limit := awsGraphExplorerLimit(request)
	explicitEdgeFilter := awsGraphExplorerAPIToken(request.EdgeType) != "" && awsGraphExplorerAPIToken(request.EdgeType) != "all"
	pathFocused := len(nodes) == 0 && len(edges) == 0 && len(paths) > 0
	if pathFocused {
		offset := awsGraphExplorerOffset(request.Cursor)
		if offset > len(paths) {
			offset = len(paths)
		}
		end := offset + limit
		if end > len(paths) {
			end = len(paths)
		}
		displayedPaths := append([]AWSGraphExplorerPath{}, paths[offset:end]...)
		visibleNodeIDs := map[string]struct{}{}
		visibleEdgeIDs := map[string]struct{}{}
		for _, path := range displayedPaths {
			for _, nodeID := range path.NodeIDs {
				visibleNodeIDs[nodeID] = struct{}{}
			}
			for _, edgeID := range path.EdgeIDs {
				visibleEdgeIDs[edgeID] = struct{}{}
			}
		}
		paged := awsGraphExplorerNodesForIDs(allNodes, visibleNodeIDs)
		displayedEdges := awsGraphExplorerEdgesForIDs(allEdges, visibleEdgeIDs)
		nextCursor := ""
		hasMore := end < len(paths)
		if hasMore {
			nextCursor = strconv.Itoa(end)
		}
		return paged, displayedEdges, displayedPaths, nextCursor, hasMore
	}
	mixedSearch := strings.TrimSpace(request.Search) != "" &&
		!explicitEdgeFilter &&
		((len(nodes) > 0 && len(paths) > 0) ||
			(len(nodes) > 0 && len(edges) > 0) ||
			(len(paths) > 0 && len(edges) > 0))
	if mixedSearch {
		offset := awsGraphExplorerOffset(request.Cursor)
		searchTerm := strings.TrimSpace(request.Search)
		edgePageTotal := len(edges)
		if searchTerm != "" && len(paths) > 0 {
			edgePageTotal = 0
			for _, edge := range edges {
				if awsGraphExplorerEdgeMatchesSearch(searchTerm, edge) {
					edgePageTotal++
				}
				if edgePageTotal >= len(edges) {
					break
				}
			}
		}
		total := len(nodes) + len(paths) + edgePageTotal
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}

		paged := []AWSGraphExplorerNode{}
		displayedPaths := []AWSGraphExplorerPath{}
		displayedEdges := []AWSGraphExplorerEdge{}
		remaining := limit
		if offset < len(nodes) {
			nodeEnd := offset + remaining
			if nodeEnd > len(nodes) {
				nodeEnd = len(nodes)
			}
			paged = append(paged, nodes[offset:nodeEnd]...)
			remaining -= nodeEnd - offset
		}
		if remaining > 0 {
			pathOffset := 0
			if offset > len(nodes) {
				pathOffset = offset - len(nodes)
			}
			pathEnd := pathOffset + remaining
			if pathEnd > len(paths) {
				pathEnd = len(paths)
			}
			displayedPaths = append(displayedPaths, paths[pathOffset:pathEnd]...)
			remaining -= pathEnd - pathOffset
		}
		if remaining > 0 {
			edgeOffset := 0
			if offset > len(nodes)+len(paths) {
				edgeOffset = offset - len(nodes) - len(paths)
			}
			edgeEnd := edgeOffset + remaining
			if edgeEnd > edgePageTotal {
				edgeEnd = edgePageTotal
			}
			if edgeEnd > len(edges) {
				edgeEnd = len(edges)
			}
			displayedEdges = append(displayedEdges, edges[edgeOffset:edgeEnd]...)
		}

		visibleNodeIDs := map[string]struct{}{}
		visibleEdgeIDs := map[string]struct{}{}
		seedNodeIDs := map[string]struct{}{}
		for _, node := range paged {
			visibleNodeIDs[node.NodeID] = struct{}{}
			seedNodeIDs[node.NodeID] = struct{}{}
		}
		for _, path := range displayedPaths {
			for _, nodeID := range path.NodeIDs {
				visibleNodeIDs[nodeID] = struct{}{}
			}
			for _, edgeID := range path.EdgeIDs {
				visibleEdgeIDs[edgeID] = struct{}{}
			}
		}
		for _, edge := range displayedEdges {
			visibleEdgeIDs[edge.EdgeID] = struct{}{}
			visibleNodeIDs[edge.FromNodeID] = struct{}{}
			visibleNodeIDs[edge.ToNodeID] = struct{}{}
		}
		expandNeighbors := awsGraphExplorerAPIToken(request.Expand) == "neighbors"
		for _, edge := range edges {
			_, fromOK := seedNodeIDs[edge.FromNodeID]
			_, toOK := seedNodeIDs[edge.ToNodeID]
			if (fromOK && toOK) || (expandNeighbors && (fromOK || toOK)) {
				visibleEdgeIDs[edge.EdgeID] = struct{}{}
				if expandNeighbors {
					visibleNodeIDs[edge.FromNodeID] = struct{}{}
					visibleNodeIDs[edge.ToNodeID] = struct{}{}
				}
			}
		}
		paged = awsGraphExplorerNodesForIDs(allNodes, visibleNodeIDs)
		displayedEdges = awsGraphExplorerEdgesForIDs(allEdges, visibleEdgeIDs)
		nextCursor := ""
		hasMore := end < total
		if hasMore {
			nextCursor = strconv.Itoa(end)
		}
		return paged, displayedEdges, displayedPaths, nextCursor, hasMore
	}
	edgeFocused := explicitEdgeFilter || (strings.TrimSpace(request.Search) != "" && len(nodes) == 0 && len(edges) > 0)
	if edgeFocused {
		offset := awsGraphExplorerOffset(request.Cursor)
		if offset > len(edges) {
			offset = len(edges)
		}
		end := offset + limit
		if end > len(edges) {
			end = len(edges)
		}
		displayedEdges := append([]AWSGraphExplorerEdge{}, edges[offset:end]...)
		visibleNodeIDs := make(map[string]struct{}, len(displayedEdges)*2)
		for _, edge := range displayedEdges {
			visibleNodeIDs[edge.FromNodeID] = struct{}{}
			visibleNodeIDs[edge.ToNodeID] = struct{}{}
		}
		paged := awsGraphExplorerNodesForIDs(allNodes, visibleNodeIDs)
		displayedPaths := []AWSGraphExplorerPath{}
		if len(visibleNodeIDs) > 0 {
			for _, path := range paths {
				if awsGraphExplorerPathTouchesNode(path, visibleNodeIDs) {
					displayedPaths = append(displayedPaths, path)
				}
			}
		}
		nextCursor := ""
		hasMore := end < len(edges)
		if hasMore {
			nextCursor = strconv.Itoa(end)
		}
		return paged, displayedEdges, displayedPaths, nextCursor, hasMore
	}

	offset := awsGraphExplorerOffset(request.Cursor)
	if offset > len(nodes) {
		offset = len(nodes)
	}
	end := offset + limit
	if end > len(nodes) {
		end = len(nodes)
	}
	paged := append([]AWSGraphExplorerNode{}, nodes[offset:end]...)
	seedNodeIDs := make(map[string]struct{}, len(paged))
	for _, node := range paged {
		seedNodeIDs[node.NodeID] = struct{}{}
	}
	visibleNodeIDs := make(map[string]struct{}, len(seedNodeIDs))
	for nodeID := range seedNodeIDs {
		visibleNodeIDs[nodeID] = struct{}{}
	}

	expandNeighbors := awsGraphExplorerAPIToken(request.Expand) == "neighbors"
	displayedEdges := []AWSGraphExplorerEdge{}
	for _, edge := range edges {
		_, fromOK := seedNodeIDs[edge.FromNodeID]
		_, toOK := seedNodeIDs[edge.ToNodeID]
		if (fromOK && toOK) || (expandNeighbors && (fromOK || toOK)) {
			displayedEdges = append(displayedEdges, edge)
			if expandNeighbors {
				visibleNodeIDs[edge.FromNodeID] = struct{}{}
				visibleNodeIDs[edge.ToNodeID] = struct{}{}
			}
		}
	}
	if expandNeighbors {
		paged = awsGraphExplorerNodesForIDs(allNodes, visibleNodeIDs)
	}

	displayedPaths := []AWSGraphExplorerPath{}
	for _, path := range paths {
		if awsGraphExplorerPathTouchesNode(path, visibleNodeIDs) {
			displayedPaths = append(displayedPaths, path)
		}
	}
	nextCursor := ""
	hasMore := end < len(nodes)
	if hasMore {
		nextCursor = strconv.Itoa(end)
	}
	return paged, displayedEdges, displayedPaths, nextCursor, hasMore
}

func awsGraphExplorerPassRoleGrantKey(fromNodeID string, toNodeID string, evidenceRef string) string {
	return fromNodeID + "\x00" + toNodeID + "\x00" + evidenceRef
}

func awsGraphExplorerEdgesForIDs(edges []AWSGraphExplorerEdge, edgeIDs map[string]struct{}) []AWSGraphExplorerEdge {
	out := make([]AWSGraphExplorerEdge, 0, len(edgeIDs))
	for _, edge := range edges {
		if _, want := edgeIDs[edge.EdgeID]; want {
			out = append(out, edge)
		}
	}
	return out
}

func awsGraphExplorerNodesForIDs(nodes []AWSGraphExplorerNode, nodeIDs map[string]struct{}) []AWSGraphExplorerNode {
	out := make([]AWSGraphExplorerNode, 0, len(nodeIDs))
	for _, node := range nodes {
		if _, want := nodeIDs[node.NodeID]; want {
			out = append(out, node)
		}
	}
	return out
}

func filterAWSGraphExplorerEvidence(evidence []AWSGraphExplorerEvidence, nodes []AWSGraphExplorerNode, edges []AWSGraphExplorerEdge, paths []AWSGraphExplorerPath, evidenceFilter string) []AWSGraphExplorerEvidence {
	filter := awsGraphExplorerAPIToken(evidenceFilter)
	nodeIDs := map[string]struct{}{}
	edgeIDs := map[string]struct{}{}
	evidenceRefs := map[string]struct{}{}
	for _, node := range nodes {
		nodeIDs[node.NodeID] = struct{}{}
		for _, ref := range node.EvidenceRefs {
			evidenceRefs[ref] = struct{}{}
		}
	}
	for _, edge := range edges {
		edgeIDs[edge.EdgeID] = struct{}{}
		if edge.EvidenceRef != "" {
			evidenceRefs[edge.EvidenceRef] = struct{}{}
		}
	}
	for _, path := range paths {
		for _, ref := range path.EvidenceRefs {
			evidenceRefs[ref] = struct{}{}
		}
	}
	out := []AWSGraphExplorerEvidence{}
	for _, entry := range evidence {
		if filter != "" && filter != "all" && !awsGraphExplorerMatchesEvidence(filter, []string{entry.EvidenceRef}, entry.Source) {
			continue
		}
		if _, ok := evidenceRefs[entry.EvidenceRef]; ok {
			out = append(out, entry)
			continue
		}
		if awsGraphExplorerAnyOverlap(entry.NodeIDs, nodeIDs) || awsGraphExplorerAnyOverlap(entry.EdgeIDs, edgeIDs) {
			out = append(out, entry)
		}
	}
	return out
}

func summarizeAWSGraphExplorer(allNodes []AWSGraphExplorerNode, allEdges []AWSGraphExplorerEdge, allPaths []AWSGraphExplorerPath, filteredNodes []AWSGraphExplorerNode, filteredEdges []AWSGraphExplorerEdge, filteredPaths []AWSGraphExplorerPath, evidenceCount int, pageSize int, nextCursor string, hasMore bool) AWSGraphExplorerSummary {
	summary := AWSGraphExplorerSummary{
		TotalNodes:     len(allNodes),
		TotalEdges:     len(allEdges),
		TotalPaths:     len(allPaths),
		FilteredNodes:  len(filteredNodes),
		FilteredEdges:  len(filteredEdges),
		FilteredPaths:  len(filteredPaths),
		EvidenceCount:  evidenceCount,
		NodeTypeCounts: map[string]int{},
		EdgeTypeCounts: map[string]int{},
		StatusCounts:   map[string]int{},
		PageSize:       pageSize,
		NextCursor:     nextCursor,
		HasMore:        hasMore,
	}
	for _, node := range allNodes {
		summary.NodeTypeCounts[node.NodeType]++
		summary.StatusCounts[node.Status]++
		switch node.NodeType {
		case "identity":
			summary.IdentityCount++
		case "agent", "agent_gateway":
			summary.AgentCount++
		case "session":
			summary.SessionCount++
		default:
			summary.ResourceCount++
		}
	}
	for _, edge := range allEdges {
		summary.EdgeTypeCounts[edge.Type]++
		switch edge.Type {
		case "observed_runtime_action", "runtime_session_performed_action", "agent_invoked_runtime_action":
			summary.RuntimeActionCount++
		case "can_pass_role", "trusted_by", "can_assume":
			summary.TrustEdgeCount++
		}
	}
	for _, path := range allPaths {
		if strings.Contains(path.PathType, "passrole") {
			summary.PassRolePathCount++
		}
		if strings.TrimSpace(path.RemediationRef) != "" {
			summary.RemediationLinkCount++
		}
	}
	return summary
}

func summarizeAWSGraphExplorerStatus(sourceStatuses []string, totalNodes int, filteredGraphEntries int) (string, float64) {
	if totalNodes == 0 {
		if awsGraphExplorerAnyStatus(sourceStatuses, "blocked") || awsGraphExplorerAnyStatus(sourceStatuses, "permission_denied") {
			return "blocked", 0
		}
		return "empty", 0.8
	}
	if filteredGraphEntries == 0 {
		return "empty", 0.78
	}
	if awsGraphExplorerAnyStatus(sourceStatuses, "blocked") || awsGraphExplorerAnyStatus(sourceStatuses, "permission_denied") {
		return "degraded", 0.65
	}
	if awsGraphExplorerAnyStatus(sourceStatuses, "degraded") || awsGraphExplorerAnyStatus(sourceStatuses, "partial_failure") {
		return "degraded", 0.78
	}
	return "ready", 0.92
}

func awsGraphExplorerFailureReasons(agents AWSAIAgentIdentityInventoryResult, runtime AWSRuntimeEventResult, passRole AWSIAMPassRoleRelationshipInventoryResult, blastRadius AWSBlastRadiusResult, leastPrivilege AWSLeastPrivilegeResult, status string) []string {
	reasons := []string{}
	reasons = append(reasons, agents.FailureReasons...)
	reasons = append(reasons, runtime.FailureReasons...)
	reasons = append(reasons, passRole.FailureReasons...)
	reasons = append(reasons, blastRadius.FailureReasons...)
	reasons = append(reasons, leastPrivilege.FailureReasons...)
	if status == "empty" && len(reasons) == 0 {
		reasons = append(reasons, "graph explorer filters matched no AWS graph nodes")
	}
	return dedupeStrings(reasons)
}

func awsGraphExplorerRemediationHints(agents AWSAIAgentIdentityInventoryResult, runtime AWSRuntimeEventResult, passRole AWSIAMPassRoleRelationshipInventoryResult, blastRadius AWSBlastRadiusResult, leastPrivilege AWSLeastPrivilegeResult, status string) []string {
	hints := []string{}
	hints = append(hints, agents.RemediationHints...)
	hints = append(hints, runtime.RemediationHints...)
	hints = append(hints, passRole.RemediationHints...)
	hints = append(hints, blastRadius.RemediationHints...)
	hints = append(hints, leastPrivilege.RemediationHints...)
	if status == "empty" && len(hints) == 0 {
		hints = append(hints, "Clear graph filters or expand neighbors to inspect the full AWS graph.")
	}
	return dedupeStrings(hints)
}

func awsGraphExplorerDiagnostics(agents AWSAIAgentIdentityInventoryResult, runtime AWSRuntimeEventResult, passRole AWSIAMPassRoleRelationshipInventoryResult, blastRadius AWSBlastRadiusResult, leastPrivilege AWSLeastPrivilegeResult) []AWSGraphExplorerDiagnostic {
	out := []AWSGraphExplorerDiagnostic{}
	for _, diag := range agents.Diagnostics {
		out = append(out, AWSGraphExplorerDiagnostic(diag))
	}
	for _, diag := range runtime.Diagnostics {
		out = append(out, AWSGraphExplorerDiagnostic(diag))
	}
	for _, diag := range passRole.Diagnostics {
		out = append(out, AWSGraphExplorerDiagnostic(diag))
	}
	for _, diag := range blastRadius.Diagnostics {
		out = append(out, AWSGraphExplorerDiagnostic(diag))
	}
	for _, diag := range leastPrivilege.Diagnostics {
		out = append(out, AWSGraphExplorerDiagnostic(diag))
	}
	return out
}

func awsGraphExplorerCoverageGaps(agents AWSAIAgentIdentityInventoryResult, runtime AWSRuntimeEventResult, passRole AWSIAMPassRoleRelationshipInventoryResult, blastRadius AWSBlastRadiusResult, leastPrivilege AWSLeastPrivilegeResult) []AWSGraphExplorerCoverageGap {
	out := []AWSGraphExplorerCoverageGap{}
	for _, gap := range agents.CoverageGaps {
		out = append(out, AWSGraphExplorerCoverageGap(gap))
	}
	for _, gap := range runtime.CoverageGaps {
		out = append(out, AWSGraphExplorerCoverageGap(gap))
	}
	for _, gap := range passRole.CoverageGaps {
		out = append(out, AWSGraphExplorerCoverageGap(gap))
	}
	for _, gap := range blastRadius.CoverageGaps {
		out = append(out, AWSGraphExplorerCoverageGap(gap))
	}
	for _, gap := range leastPrivilege.CoverageGaps {
		out = append(out, AWSGraphExplorerCoverageGap(gap))
	}
	return out
}

func awsGraphExplorerLimit(request AWSGraphExplorerRequest) int {
	if request.Limit <= 0 {
		return awsGraphExplorerDefaultLimit
	}
	if request.Limit > awsGraphExplorerMaxLimit {
		return awsGraphExplorerMaxLimit
	}
	return request.Limit
}

func awsGraphExplorerOffset(cursor string) int {
	value, err := strconv.Atoi(strings.TrimSpace(cursor))
	if err != nil || value < 0 {
		return 0
	}
	return value
}

func awsGraphExplorerAPIToken(value string) string {
	return strings.ToLower(awsGraphExplorerTokenReplacer.Replace(strings.TrimSpace(value)))
}

func awsGraphExplorerCanonicalNodeType(value string) string {
	token := awsGraphExplorerAPIToken(value)
	switch token {
	case "", "all":
		return ""
	case "agent", "ai_agent", "runtime_agent", "bedrock_agent", "agentcore_runtime", "aws::bedrock::agent", "aws::bedrock_agentcore::runtime":
		return "agent"
	case "agent_gateway":
		return "agent_gateway"
	case "identity", "iam_role", "runtime_role", "role", "assumed_role", "aws::iam::role":
		return "identity"
	case "session", "runtime_session", "sts_session":
		return "session"
	case "secret", "secretsmanager_secret", "aws::secretsmanager::secret":
		return "secret"
	case "kms_key", "kmskey", "aws::kms::key":
		return "kms_key"
	case "s3_bucket", "s3bucket", "aws::s3::bucket":
		return "s3_bucket"
	case "credential_reference":
		return "credential_reference"
	case "resource", "target_resource", "aws_service", "service", "runtime_target", "tool", "tool_target", "execution_endpoint":
		return "resource"
	case "unknown":
		return "unknown"
	}
	switch {
	case strings.Contains(token, "credential"):
		return "credential_reference"
	case strings.Contains(token, "secret"):
		return "secret"
	case strings.Contains(token, "kms") || token == "key":
		return "kms_key"
	case strings.Contains(token, "s3") || strings.Contains(token, "bucket"):
		return "s3_bucket"
	case strings.Contains(token, "iam") && strings.Contains(token, "role"):
		return "identity"
	case strings.Contains(token, "session"):
		return "session"
	case strings.Contains(token, "gateway"):
		return "agent_gateway"
	case strings.Contains(token, "agent"):
		return "agent"
	default:
		return "resource"
	}
}

func awsGraphExplorerNodeMatchesSearch(search string, node AWSGraphExplorerNode) bool {
	return awsRuntimeEventMatchesAny(search, append(append([]string{node.NodeID, node.NodeType, node.Label, node.Source, node.Status, node.AccountID, node.Region}, node.EvidenceRefs...), awsGraphExplorerMetadataValues(node.Metadata)...)...)
}

func awsGraphExplorerEdgeMatchesSearch(search string, edge AWSGraphExplorerEdge) bool {
	return awsRuntimeEventMatchesAny(search, append([]string{edge.EdgeID, edge.Type, edge.Label, edge.FromNodeID, edge.ToNodeID, edge.Source, edge.Status, edge.EvidenceRef, edge.RuntimeAction}, awsGraphExplorerMetadataValues(edge.Metadata)...)...)
}

func awsGraphExplorerPathMatchesSearch(search string, path AWSGraphExplorerPath) bool {
	return awsRuntimeEventMatchesAny(search, append(append(append([]string{path.PathID, path.PathType, path.Title, path.Severity, path.Status, path.Source, path.NextAction, path.RemediationRef}, path.NodeIDs...), path.EdgeIDs...), path.EvidenceRefs...)...)
}

func awsGraphExplorerMatchesEvidence(filter string, refs []string, source string) bool {
	if filter == "" || filter == "all" {
		return true
	}
	if strings.Contains(awsGraphExplorerAPIToken(source), filter) {
		return true
	}
	for _, ref := range refs {
		if strings.Contains(awsGraphExplorerAPIToken(ref), filter) {
			return true
		}
	}
	return false
}

func awsGraphExplorerPathTouchesNode(path AWSGraphExplorerPath, nodes map[string]struct{}) bool {
	if len(nodes) == 0 {
		return true
	}
	for _, nodeID := range path.NodeIDs {
		if _, ok := nodes[nodeID]; ok {
			return true
		}
	}
	return false
}

func awsGraphExplorerPathOnlyUsesNodes(path AWSGraphExplorerPath, nodes map[string]struct{}) bool {
	if len(nodes) == 0 || len(path.NodeIDs) == 0 {
		return false
	}
	for _, nodeID := range path.NodeIDs {
		if _, ok := nodes[nodeID]; !ok {
			return false
		}
	}
	return true
}

func awsGraphExplorerEdgeTouchesNode(edge AWSGraphExplorerEdge, nodes map[string]struct{}) bool {
	if len(nodes) == 0 {
		return false
	}
	if _, ok := nodes[edge.FromNodeID]; ok {
		return true
	}
	_, ok := nodes[edge.ToNodeID]
	return ok
}

func awsGraphExplorerEdgeEndpointsInScope(edge AWSGraphExplorerEdge, nodes map[string]struct{}) bool {
	if len(nodes) == 0 {
		return false
	}
	if _, ok := nodes[edge.FromNodeID]; !ok {
		return false
	}
	if _, ok := nodes[edge.ToNodeID]; !ok {
		return false
	}
	return true
}

func awsGraphExplorerAnyOverlap(values []string, lookup map[string]struct{}) bool {
	for _, value := range values {
		if _, ok := lookup[value]; ok {
			return true
		}
	}
	return false
}

func awsGraphExplorerMetadataValues(metadata map[string]string) []string {
	values := make([]string, 0, len(metadata)*2)
	for key, value := range metadata {
		values = append(values, key, value)
	}
	return values
}

func awsGraphExplorerScopedARNParts(value string) (accountID string, region string) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) < 6 {
		return "", ""
	}
	return strings.TrimSpace(parts[4]), strings.TrimSpace(parts[3])
}

func awsGraphExplorerResourceNodeID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "aws:") || strings.HasPrefix(value, "tool:") {
		return value
	}
	return "aws:resource:" + sanitizeCredentialReferenceToken(value)
}

func awsGraphExplorerNodeTypeForResource(value string) string {
	service, resource := awsGraphExplorerARNServiceAndResource(value)
	switch service {
	case "s3", "s3express":
		return "s3_bucket"
	case "kms":
		return "kms_key"
	case "secretsmanager":
		return "secret"
	case "iam":
		if strings.Contains(awsGraphExplorerAPIToken(resource), "role") {
			return "identity"
		}
	case "sts":
		if strings.Contains(awsGraphExplorerAPIToken(resource), "assumed_role") {
			return "identity"
		}
	}

	token := awsGraphExplorerAPIToken(value)
	switch {
	case strings.Contains(token, "s3"):
		return "s3_bucket"
	case strings.Contains(token, "kms"):
		return "kms_key"
	case strings.Contains(token, "secret"):
		return "secret"
	case strings.Contains(token, "credential"):
		return "credential_reference"
	case strings.Contains(token, "iam") && strings.Contains(token, "role"):
		return "identity"
	case strings.Contains(token, "session"):
		return "session"
	case strings.Contains(token, "agent"):
		return "agent"
	default:
		return "resource"
	}
}

func awsGraphExplorerARNServiceAndResource(value string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(value), ":", 6)
	if len(parts) != 6 || !strings.EqualFold(parts[0], "arn") {
		return "", ""
	}
	return strings.ToLower(parts[2]), parts[5]
}

func awsGraphExplorerRuntimeActionForEvidence(records []AWSRuntimeEventRecord, evidenceRef string) string {
	for _, record := range records {
		if record.EvidenceRef == evidenceRef {
			return firstNonEmptyAWSValue(record.Action, record.EventName, record.EventType)
		}
	}
	return ""
}

func awsGraphExplorerPathNodeIDs(steps []AWSBlastRadiusPathStep) []string {
	out := make([]string, 0, len(steps))
	for _, step := range steps {
		out = append(out, step.NodeID)
	}
	return dedupeStrings(out)
}

func awsGraphExplorerLeastPrivilegePathNodeIDs(steps []AWSLeastPrivilegePathStep) []string {
	out := make([]string, 0, len(steps))
	for _, step := range steps {
		out = append(out, step.NodeID)
	}
	return dedupeStrings(out)
}

func awsGraphExplorerEvidenceRefs(evidence []AWSBlastRadiusEvidence) []string {
	out := make([]string, 0, len(evidence))
	for _, entry := range evidence {
		out = append(out, entry.EvidenceRef)
	}
	return dedupeStrings(out)
}

func awsGraphExplorerLeastPrivilegeEvidenceRefs(evidence []AWSLeastPrivilegeEvidence) []string {
	out := make([]string, 0, len(evidence))
	for _, entry := range evidence {
		out = append(out, entry.EvidenceRef)
	}
	return dedupeStrings(out)
}

func firstAWSGraphExplorerEvidenceRef(evidence []AWSBlastRadiusEvidence) string {
	for _, entry := range evidence {
		if strings.TrimSpace(entry.EvidenceRef) != "" {
			return strings.TrimSpace(entry.EvidenceRef)
		}
	}
	return ""
}

func awsGraphExplorerAnyStatus(statuses []string, targets ...string) bool {
	targetSet := map[string]struct{}{}
	for _, target := range targets {
		targetSet[awsGraphExplorerAPIToken(target)] = struct{}{}
	}
	for _, status := range statuses {
		if _, ok := targetSet[awsGraphExplorerAPIToken(status)]; ok {
			return true
		}
	}
	return false
}

func awsGraphExplorerMergedStatus(left string, right string) string {
	order := map[string]int{
		"blocked":           5,
		"permission_denied": 5,
		"degraded":          4,
		"partial_failure":   4,
		"action_required":   3,
		"review":            2,
		"ready":             1,
		"known":             1,
	}
	if order[awsGraphExplorerAPIToken(right)] > order[awsGraphExplorerAPIToken(left)] {
		return awsGraphExplorerAPIToken(right)
	}
	return awsGraphExplorerAPIToken(left)
}

func awsGraphExplorerSeverityRank(severity string) int {
	switch awsGraphExplorerAPIToken(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

func maxFloat(a float64, b float64) float64 {
	if b > a {
		return b
	}
	return a
}
