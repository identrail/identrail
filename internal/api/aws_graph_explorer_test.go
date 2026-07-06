package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGetAWSGraphExplorerBuildsOperatorContract(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-graph-explorer", now)

	result, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Limit:        200,
		Expand:       "neighbors",
	})
	if err != nil {
		t.Fatalf("get graph explorer: %v", err)
	}
	if result.CurrentIssueRef != "#1551" || result.Version != awsGraphExplorerVersion || result.Status != "ready" {
		t.Fatalf("unexpected contract metadata: %+v", result)
	}
	if len(result.Nodes) == 0 || len(result.Edges) == 0 || len(result.Paths) == 0 || len(result.Evidence) == 0 {
		t.Fatalf("expected graph nodes, edges, paths, and evidence: nodes=%d edges=%d paths=%d evidence=%d", len(result.Nodes), len(result.Edges), len(result.Paths), len(result.Evidence))
	}
	if result.Summary.IdentityCount == 0 || result.Summary.AgentCount == 0 || result.Summary.ResourceCount == 0 || result.Summary.SessionCount == 0 {
		t.Fatalf("expected identity, agent, resource, and session nodes in summary: %+v", result.Summary)
	}
	if result.Summary.RuntimeActionCount == 0 || result.Summary.TrustEdgeCount == 0 || result.Summary.PassRolePathCount == 0 || result.Summary.RemediationLinkCount == 0 {
		t.Fatalf("expected runtime, trust, PassRole, and remediation graph coverage: %+v", result.Summary)
	}
	for _, edgeType := range []string{"runs_as", "calls_tool", "uses_secret", "invokes"} {
		if result.Summary.EdgeTypeCounts[edgeType] == 0 {
			t.Fatalf("expected AI identity edge type %q in graph summary: %+v", edgeType, result.Summary.EdgeTypeCounts)
		}
	}
	nodeIDs := map[string]struct{}{}
	for _, node := range result.Nodes {
		nodeIDs[node.NodeID] = struct{}{}
	}
	edgeIDs := map[string]struct{}{}
	for _, edge := range result.Edges {
		if _, ok := nodeIDs[edge.FromNodeID]; !ok {
			t.Fatalf("edge %q references missing from_node_id %q: edge=%+v", edge.EdgeID, edge.FromNodeID, edge)
		}
		if _, ok := nodeIDs[edge.ToNodeID]; !ok {
			t.Fatalf("edge %q references missing to_node_id %q: edge=%+v", edge.EdgeID, edge.ToNodeID, edge)
		}
		edgeIDs[edge.EdgeID] = struct{}{}
	}
	passRolePathWithEdge := false
	for _, path := range result.Paths {
		if path.PathType != "passrole_path" {
			continue
		}
		if len(path.EdgeIDs) == 0 {
			t.Fatalf("PassRole path must include the matching edge id: %+v", path)
		}
		for _, edgeID := range path.EdgeIDs {
			if _, ok := edgeIDs[edgeID]; !ok {
				t.Fatalf("PassRole path references missing edge %q: path=%+v edges=%+v", edgeID, path, result.Edges)
			}
		}
		passRolePathWithEdge = true
	}
	if !passRolePathWithEdge {
		t.Fatalf("expected at least one PassRole path with edge_ids")
	}
	for _, evidence := range result.Evidence {
		if evidence.RedactionBoundary != "metadata_only" {
			t.Fatalf("evidence must stay metadata-only: %+v", evidence)
		}
	}
}

func TestGetAWSGraphExplorerHonorsExplicitAccountRegionFilters(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 2, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-graph-explorer-scope-filters", now)

	result, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-scope-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		AccountID:    "000000000000",
		Region:       "us-west-2",
		Limit:        200,
	})
	if err != nil {
		t.Fatalf("get scoped graph explorer: %v", err)
	}
	if result.AccountID != "000000000000" || result.Region != "us-west-2" {
		t.Fatalf("expected request scope to override connector defaults, got account=%q region=%q", result.AccountID, result.Region)
	}
	if result.AppliedFilters["account_id"] != "000000000000" || result.AppliedFilters["region"] != "us-west-2" {
		t.Fatalf("expected account and region applied filters, got %+v", result.AppliedFilters)
	}
	if len(result.Nodes) != 0 || len(result.Edges) != 0 || len(result.Paths) != 0 || len(result.Evidence) != 0 {
		t.Fatalf("expected mismatched account/region scope to return an empty graph page, got nodes=%d edges=%d paths=%d evidence=%d", len(result.Nodes), len(result.Edges), len(result.Paths), len(result.Evidence))
	}
}

func TestGetAWSGraphExplorerFiltersAndPaginates(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 5, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-graph-explorer-filters", now)

	sessions, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		NodeType:     "session",
	})
	if err != nil {
		t.Fatalf("session filter: %v", err)
	}
	if len(sessions.Nodes) == 0 {
		t.Fatalf("expected session nodes")
	}
	for _, node := range sessions.Nodes {
		if node.NodeType != "session" {
			t.Fatalf("node_type filter leaked %+v", node)
		}
	}
	expandedIdentities, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		NodeType:     "identity",
		Expand:       "neighbors",
		Limit:        5,
	})
	if err != nil {
		t.Fatalf("identity neighbor expansion: %v", err)
	}
	hasNeighbor := false
	for _, node := range expandedIdentities.Nodes {
		if node.NodeType != "identity" {
			hasNeighbor = true
			break
		}
	}
	if !hasNeighbor {
		t.Fatalf("expected expand=neighbors to include adjacent non-identity nodes: %+v", expandedIdentities.Nodes)
	}

	pageOne, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Limit:        3,
	})
	if err != nil {
		t.Fatalf("page one: %v", err)
	}
	if len(pageOne.Nodes) != 3 || pageOne.Summary.NextCursor == "" {
		t.Fatalf("expected first page with cursor: %+v", pageOne.Summary)
	}
	pageTwo, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Limit:        3,
		Cursor:       pageOne.Summary.NextCursor,
	})
	if err != nil {
		t.Fatalf("page two: %v", err)
	}
	if len(pageTwo.Nodes) == 0 || pageTwo.Nodes[0].NodeID == pageOne.Nodes[0].NodeID {
		t.Fatalf("expected second page to advance cursor: page1=%+v page2=%+v", pageOne.Nodes, pageTwo.Nodes)
	}

	passRole, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		EdgeType:     "can_pass_role",
		Expand:       "neighbors",
	})
	if err != nil {
		t.Fatalf("passrole edge filter: %v", err)
	}
	if len(passRole.Edges) == 0 {
		t.Fatalf("expected PassRole edges")
	}
	for _, edge := range passRole.Edges {
		if edge.Type != "can_pass_role" {
			t.Fatalf("edge_type filter leaked %+v", edge)
		}
	}

	passRoleSearch, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Search:       "can_pass_role",
		Limit:        1,
	})
	if err != nil {
		t.Fatalf("passrole edge search: %v", err)
	}
	if passRoleSearch.Status == "empty" || len(passRoleSearch.FailureReasons) != 0 {
		t.Fatalf("edge-only search must not be reported as empty: status=%q failures=%+v summary=%+v", passRoleSearch.Status, passRoleSearch.FailureReasons, passRoleSearch.Summary)
	}
	if len(passRoleSearch.Edges) == 0 || len(passRoleSearch.Nodes) == 0 {
		t.Fatalf("expected edge-only search to return matching edges and endpoints: nodes=%+v edges=%+v", passRoleSearch.Nodes, passRoleSearch.Edges)
	}

	runtimeEvidence, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-filters", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "success",
		Evidence:     "runtime_events",
		Limit:        200,
	})
	if err != nil {
		t.Fatalf("runtime evidence filter: %v", err)
	}
	if len(runtimeEvidence.Evidence) == 0 {
		t.Fatalf("expected runtime evidence filter to return evidence")
	}
	for _, evidence := range runtimeEvidence.Evidence {
		if !awsGraphExplorerMatchesEvidence("runtime_events", []string{evidence.EvidenceRef}, evidence.Source) {
			t.Fatalf("runtime evidence filter leaked evidence entry: %+v", evidence)
		}
	}
	if runtimeEvidence.Summary.EvidenceCount != len(runtimeEvidence.Evidence) {
		t.Fatalf("evidence_count must match displayed filtered evidence: summary=%+v evidence=%d", runtimeEvidence.Summary, len(runtimeEvidence.Evidence))
	}
}

func TestAWSGraphExplorerRuntimeLineageEndpointsAreMaterialized(t *testing.T) {
	now := time.Date(2026, 7, 5, 12, 20, 0, 0, time.UTC)
	record := AWSRuntimeEventRecord{
		AccountID:           "111111111111",
		Region:              "us-east-1",
		EventName:           "AssumeRole",
		Action:              "sts:AssumeRole",
		ActorPrincipalARN:   "arn:aws:sts::111111111111:assumed-role/current/deploy",
		ActorIdentityNodeID: "aws:identity:current",
		EvidenceRef:         "runtime-evidence://lineage",
		Confidence:          0.92,
		ObservedAt:          now,
		Status:              "ready",
		Session: AWSRuntimeEventSession{
			SessionID:               "session-1",
			SessionNodeID:           "aws:runtime-session:session-1",
			RoleSessionName:         "deploy",
			OriginalActorARN:        "arn:aws:iam::111111111111:role/original-operator",
			OriginalActorNodeID:     "aws:identity:original-operator",
			ChainedFromPrincipalARN: "arn:aws:iam::111111111111:role/chained-operator",
			ChainedFromNodeID:       "aws:identity:chained-operator",
			LineageStatus:           "ready",
			StartedAt:               now,
		},
	}

	builder := newAWSGraphExplorerBuilder()
	builder.addRuntime(AWSRuntimeEventResult{
		Status:        "ready",
		Confidence:    0.92,
		Records:       []AWSRuntimeEventRecord{record},
		Relationships: awsRuntimeEventRelationships([]AWSRuntimeEventRecord{record}),
	})

	nodeIDs := map[string]AWSGraphExplorerNode{}
	for _, node := range builder.sortedNodes() {
		nodeIDs[node.NodeID] = node
	}
	for _, nodeID := range []string{"aws:identity:original-operator", "aws:identity:chained-operator"} {
		node, ok := nodeIDs[nodeID]
		if !ok {
			t.Fatalf("expected runtime lineage endpoint node %q to be materialized; nodes=%+v", nodeID, nodeIDs)
		}
		if node.NodeType != "identity" || node.Source != "runtime_events" {
			t.Fatalf("expected lineage endpoint %q to be a runtime identity node, got %+v", nodeID, node)
		}
	}
	for _, edge := range builder.sortedEdges() {
		if _, ok := nodeIDs[edge.FromNodeID]; !ok {
			t.Fatalf("runtime lineage edge %q references missing from_node_id %q: edge=%+v", edge.EdgeID, edge.FromNodeID, edge)
		}
		if _, ok := nodeIDs[edge.ToNodeID]; !ok {
			t.Fatalf("runtime lineage edge %q references missing to_node_id %q: edge=%+v", edge.EdgeID, edge.ToNodeID, edge)
		}
	}
	evidence := builder.sortedEvidence()
	if len(evidence) != 1 {
		t.Fatalf("expected one runtime evidence entry, got %+v", evidence)
	}
	if !containsString(evidence[0].NodeIDs, "aws:identity:original-operator") || !containsString(evidence[0].NodeIDs, "aws:identity:chained-operator") {
		t.Fatalf("expected runtime evidence to include lineage endpoint node IDs, got %+v", evidence[0].NodeIDs)
	}
}

func TestAWSGraphExplorerRuntimeIdentityNodesUseARNAccountScope(t *testing.T) {
	now := time.Date(2026, 7, 5, 17, 45, 0, 0, time.UTC)
	record := AWSRuntimeEventRecord{
		AccountID:           "111111111111",
		Region:              "us-east-1",
		EventName:           "AssumeRole",
		Action:              "sts:AssumeRole",
		ActorPrincipalARN:   "arn:aws:iam::222222222222:role/external-deployer",
		ActorIdentityNodeID: "aws:identity:external-deployer",
		ResourceNodeID:      "aws:runtime-resource:iam-role:target",
		TargetResourceARN:   "arn:aws:iam::111111111111:role/target",
		TargetResourceType:  "iam_role",
		EvidenceRef:         "runtime-evidence://cross-account-actor",
		Confidence:          0.9,
		ObservedAt:          now,
		Status:              "ready",
		Session: AWSRuntimeEventSession{
			SessionID:               "target-session",
			SessionNodeID:           "aws:runtime-session:target-session",
			OriginalActorARN:        "arn:aws:iam::333333333333:role/original-actor",
			OriginalActorNodeID:     "aws:identity:original-actor",
			ChainedFromPrincipalARN: "arn:aws:iam::444444444444:role/chained-actor",
			ChainedFromNodeID:       "aws:identity:chained-actor",
			LineageStatus:           "ready",
			StartedAt:               now,
		},
	}

	builder := newAWSGraphExplorerBuilder()
	builder.addRuntime(AWSRuntimeEventResult{
		Status:        "ready",
		Confidence:    0.9,
		Records:       []AWSRuntimeEventRecord{record},
		Relationships: awsRuntimeEventRelationships([]AWSRuntimeEventRecord{record}),
	})

	nodesByID := map[string]AWSGraphExplorerNode{}
	for _, node := range builder.sortedNodes() {
		nodesByID[node.NodeID] = node
	}
	for nodeID, wantAccount := range map[string]string{
		"aws:identity:external-deployer": "222222222222",
		"aws:identity:original-actor":    "333333333333",
		"aws:identity:chained-actor":     "444444444444",
	} {
		if got := nodesByID[nodeID].AccountID; got != wantAccount {
			t.Fatalf("expected runtime identity node %q account %q, got %q in %+v", nodeID, wantAccount, got, nodesByID[nodeID])
		}
	}

	filteredNodes, filteredEdges, filteredPaths, _ := filterAWSGraphExplorer(builder.sortedNodes(), builder.sortedEdges(), builder.sortedPaths(), AWSGraphExplorerRequest{AccountID: "111111111111", Region: "us-east-1", Limit: 100, Expand: "neighbors"})
	for _, node := range filteredNodes {
		if strings.HasPrefix(node.NodeID, "aws:identity:") {
			t.Fatalf("connected-account scope should not include external runtime identity node: %+v", node)
		}
	}
	for _, edge := range filteredEdges {
		if strings.HasPrefix(edge.FromNodeID, "aws:identity:") || strings.HasPrefix(edge.ToNodeID, "aws:identity:") {
			t.Fatalf("connected-account scope should not include edges to external runtime identities: %+v", edge)
		}
	}
	if len(filteredPaths) != 0 {
		t.Fatalf("expected no scoped runtime paths in fixture, got %+v", filteredPaths)
	}
}

func TestAWSGraphExplorerRuntimeResourceNodeUsesTargetResourceARNScope(t *testing.T) {
	targetResourceNodeID := "aws:resource:s3/example-bucket"
	record := AWSRuntimeEventRecord{
		AccountID:           "111111111111",
		Region:              "us-east-1",
		EventName:           "AssumeRole",
		Action:              "sts:AssumeRole",
		ActorPrincipalARN:   "arn:aws:sts::111111111111:assumed-role/current/deploy",
		ActorIdentityNodeID: "aws:identity:current",
		ResourceNodeID:      "aws:resource:s3/example-bucket",
		TargetResourceARN:   "arn:aws:s3:us-west-2:222222222222:bucket/example-bucket",
		TargetResourceType:  "s3",
		EvidenceRef:         "runtime-evidence://target-resource-scope",
		Confidence:          0.9,
		ObservedAt:          time.Date(2026, 7, 5, 17, 50, 0, 0, time.UTC),
		Status:              "ready",
	}

	builder := newAWSGraphExplorerBuilder()
	builder.addRuntime(AWSRuntimeEventResult{
		Status:        "ready",
		Confidence:    0.9,
		Records:       []AWSRuntimeEventRecord{record},
		Relationships: awsRuntimeEventRelationships([]AWSRuntimeEventRecord{record}),
	})

	nodesByID := map[string]AWSGraphExplorerNode{}
	for _, node := range builder.sortedNodes() {
		nodesByID[node.NodeID] = node
	}
	resourceNode, ok := nodesByID[targetResourceNodeID]
	if !ok {
		t.Fatalf("expected runtime target resource node to be materialized; nodes=%+v", nodesByID)
	}
	if resourceNode.AccountID != "222222222222" {
		t.Fatalf("expected runtime target resource account to be derived from target ARN, got %q", resourceNode.AccountID)
	}
	if resourceNode.Region != "us-west-2" {
		t.Fatalf("expected runtime target resource region to be derived from target ARN, got %q", resourceNode.Region)
	}
	evidence := builder.sortedEvidence()
	if len(evidence) != 1 {
		t.Fatalf("expected one runtime evidence entry; got %+v", evidence)
	}
	if !containsString(evidence[0].NodeIDs, targetResourceNodeID) {
		t.Fatalf("expected runtime evidence to reference target resource node %q: %+v", targetResourceNodeID, evidence[0].NodeIDs)
	}
}

func TestFilterAWSGraphExplorerHardScopeDoesNotLeakNeighborEndpoints(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-in-a", NodeType: "identity", Label: "In A", AccountID: "111111111111", Region: "us-east-1"},
		{NodeID: "node-in-b", NodeType: "resource", Label: "In B", AccountID: "111111111111", Region: "us-east-1"},
		{NodeID: "node-other-account", NodeType: "identity", Label: "Other account", AccountID: "222222222222", Region: "us-east-1"},
		{NodeID: "node-other-region", NodeType: "resource", Label: "Other region", AccountID: "111111111111", Region: "us-west-2"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-in-scope", Type: "observed_runtime_action", FromNodeID: "node-in-a", ToNodeID: "node-in-b", Source: "runtime_events", Status: "ready"},
		{EdgeID: "edge-cross-account", Type: "observed_runtime_action", FromNodeID: "node-in-a", ToNodeID: "node-other-account", Source: "runtime_events", Status: "ready"},
		{EdgeID: "edge-cross-region", Type: "observed_runtime_action", FromNodeID: "node-in-a", ToNodeID: "node-other-region", Source: "runtime_events", Status: "ready"},
	}
	paths := []AWSGraphExplorerPath{
		{PathID: "path-in-scope", PathType: "runtime_path", Status: "ready", NodeIDs: []string{"node-in-a", "node-in-b"}, EdgeIDs: []string{"edge-in-scope"}},
		{PathID: "path-cross-account", PathType: "runtime_path", Status: "ready", NodeIDs: []string{"node-in-a", "node-other-account"}, EdgeIDs: []string{"edge-cross-account"}},
		{PathID: "path-cross-region", PathType: "runtime_path", Status: "ready", NodeIDs: []string{"node-in-a", "node-other-region"}, EdgeIDs: []string{"edge-cross-region"}},
	}
	request := AWSGraphExplorerRequest{
		AccountID: "111111111111",
		Region:    "us-east-1",
		Expand:    "neighbors",
		Limit:     10,
	}

	filteredNodes, filteredEdges, filteredPaths, _ := filterAWSGraphExplorer(nodes, edges, paths, request)
	if len(filteredEdges) != 1 || filteredEdges[0].EdgeID != "edge-in-scope" {
		t.Fatalf("expected hard scope to keep only fully scoped edges, got %+v", filteredEdges)
	}
	if len(filteredPaths) != 1 || filteredPaths[0].PathID != "path-in-scope" {
		t.Fatalf("expected hard scope to keep only fully scoped paths, got %+v", filteredPaths)
	}
	pagedNodes, displayedEdges, displayedPaths, _, _ := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, request)
	if len(displayedEdges) != 1 || displayedEdges[0].EdgeID != "edge-in-scope" {
		t.Fatalf("expected pagination to display only in-scope edge, got %+v", displayedEdges)
	}
	if len(displayedPaths) != 1 || displayedPaths[0].PathID != "path-in-scope" {
		t.Fatalf("expected pagination to display only in-scope path, got %+v", displayedPaths)
	}
	for _, node := range pagedNodes {
		if node.AccountID != "111111111111" || node.Region != "us-east-1" {
			t.Fatalf("hard scope leaked neighbor endpoint into page: %+v", node)
		}
	}
}

func TestAWSGraphExplorerPassRolePathEdgesStayEvidenceScoped(t *testing.T) {
	now := time.Date(2026, 7, 5, 17, 5, 0, 0, time.UTC)
	records := []AWSIAMPassRoleRelationshipRecord{
		{
			AccountID:        "111111111111",
			Region:           "us-east-1",
			SourceRoleARN:    "arn:aws:iam::111111111111:role/source",
			SourceRoleName:   "source",
			TargetResource:   "arn:aws:iam::111111111111:role/target",
			PolicyName:       "policy-a",
			StatementSid:     "AllowA",
			Effect:           "Allow",
			EvidenceRef:      "passrole-evidence://policy-a",
			FromNodeID:       "aws:identity:source",
			ToNodeID:         "aws:identity:target",
			RelationshipType: "can_pass_role",
			Confidence:       0.9,
			CollectedAt:      now,
			Status:           "ready",
		},
		{
			AccountID:        "111111111111",
			Region:           "us-east-1",
			SourceRoleARN:    "arn:aws:iam::111111111111:role/source",
			SourceRoleName:   "source",
			TargetResource:   "arn:aws:iam::111111111111:role/target",
			PolicyName:       "policy-b",
			StatementSid:     "AllowB",
			Effect:           "Allow",
			EvidenceRef:      "passrole-evidence://policy-b",
			FromNodeID:       "aws:identity:source",
			ToNodeID:         "aws:identity:target",
			RelationshipType: "can_pass_role",
			Confidence:       0.88,
			CollectedAt:      now,
			Status:           "ready",
		},
	}
	relationships := []AWSIAMPassRoleRelationshipEdge{
		{Type: "can_pass_role", FromNodeID: "aws:identity:source", ToNodeID: "aws:identity:target", EvidenceRef: "passrole-evidence://policy-a", Effect: "Allow"},
		{Type: "can_pass_role", FromNodeID: "aws:identity:source", ToNodeID: "aws:identity:target", EvidenceRef: "passrole-evidence://policy-b", Effect: "Allow"},
	}

	builder := newAWSGraphExplorerBuilder()
	builder.addPassRole(AWSIAMPassRoleRelationshipInventoryResult{
		Status:        "ready",
		Confidence:    0.9,
		Records:       records,
		Relationships: relationships,
	})

	edgeIDsByEvidence := map[string]string{}
	for _, edge := range builder.sortedEdges() {
		edgeIDsByEvidence[edge.EvidenceRef] = edge.EdgeID
	}
	if len(edgeIDsByEvidence) != 2 {
		t.Fatalf("expected one PassRole edge per evidence ref, got %+v", edgeIDsByEvidence)
	}
	for _, path := range builder.sortedPaths() {
		if path.PathType != "passrole_path" {
			continue
		}
		if len(path.EvidenceRefs) != 1 {
			t.Fatalf("expected PassRole path to carry one evidence ref, got %+v", path)
		}
		wantEdgeID := edgeIDsByEvidence[path.EvidenceRefs[0]]
		if wantEdgeID == "" {
			t.Fatalf("path evidence %q has no matching edge: path=%+v edges=%+v", path.EvidenceRefs[0], path, edgeIDsByEvidence)
		}
		if len(path.EdgeIDs) != 1 || path.EdgeIDs[0] != wantEdgeID {
			t.Fatalf("PassRole path must only reference its own evidence edge %q, got %+v", wantEdgeID, path.EdgeIDs)
		}
	}
}

func TestAWSGraphExplorerPassRolePathAddsSyntheticEdgeWhenRelationshipMissing(t *testing.T) {
	now := time.Date(2026, 7, 5, 18, 0, 0, 0, time.UTC)
	record := AWSIAMPassRoleRelationshipRecord{
		AccountID:        "111111111111",
		Region:           "us-east-1",
		SourceRoleARN:    "arn:aws:iam::111111111111:role/source",
		SourceRoleName:   "source",
		TargetResource:   "arn:aws:iam::111111111111:role/target",
		PolicyName:       "policy-a",
		StatementSid:     "AllowA",
		Effect:           "Allow",
		EvidenceRef:      "passrole-evidence://policy-a",
		FromNodeID:       "aws:identity:source",
		ToNodeID:         "aws:identity:target",
		RelationshipType: "can_pass_role",
		Confidence:       0.9,
		CollectedAt:      now,
		Status:           "ready",
	}
	expectedEdgeID := "aws-graph-edge:" + stableAWSBlastRadiusToken("iam_passrole_relationships", "can_pass_role", record.FromNodeID, record.ToNodeID, record.EvidenceRef)

	builder := newAWSGraphExplorerBuilder()
	builder.addPassRole(AWSIAMPassRoleRelationshipInventoryResult{
		Status:        "ready",
		Confidence:    0.9,
		Records:       []AWSIAMPassRoleRelationshipRecord{record},
		Relationships: nil,
	})

	if got := len(builder.sortedPaths()); got != 1 {
		t.Fatalf("expected one path to be created from pass-role record, got %d", got)
	}
	paths := builder.sortedPaths()
	if got := len(paths[0].EdgeIDs); got != 1 {
		t.Fatalf("expected synthetic path edge for missing relationship: %+v", paths[0])
	}
	if got, want := paths[0].EdgeIDs[0], expectedEdgeID; got != want {
		t.Fatalf("expected pass-role path to reference synthetic edge %q, got %q", want, got)
	}
	if got := len(builder.sortedEdges()); got != 1 {
		t.Fatalf("expected synthetic pass-role edge to be materialized, got %d", got)
	}
	edges := builder.sortedEdges()
	if got, want := edges[0].EdgeID, expectedEdgeID; got != want {
		t.Fatalf("expected synthetic edge %q, got %q", want, got)
	}
	if edges[0].Type != "can_pass_role" || edges[0].FromNodeID != record.FromNodeID || edges[0].ToNodeID != record.ToNodeID || edges[0].EvidenceRef != record.EvidenceRef {
		t.Fatalf("unexpected synthetic pass-role edge payload: %+v", edges[0])
	}
}

func TestAWSGraphExplorerAgentsUsesCredentialNodeForCredentialRefsAndGenericTargetForEncryptionKey(t *testing.T) {
	now := time.Date(2026, 7, 5, 18, 10, 0, 0, time.UTC)
	record := AWSAIAgentIdentityRecord{
		AccountID:               "111111111111",
		Region:                  "us-east-1",
		AgentNodeID:             "aws:agent:test",
		AgentName:               "test-agent",
		AgentType:               "custom",
		CredentialReferenceRefs: []string{"secretsmanager:prod/ai/openai-key"},
		EncryptionKeyARN:        "arn:aws:kms:us-east-1:111111111111:key/cmk",
		AgentID:                 "agent-1",
		EvidenceRef:             "ai-agent-evidence://agent-1",
		Confidence:              0.9,
		CollectedAt:             now,
		Status:                  "ready",
	}
	credentialRefNodeID := awsCredentialReferenceNodeID(record.AgentNodeID, record.CredentialReferenceRefs[0])
	encryptionNodeID := awsGraphExplorerResourceNodeID(record.EncryptionKeyARN)
	genericCredentialNodeID := awsGraphExplorerResourceNodeID(record.CredentialReferenceRefs[0])

	builder := newAWSGraphExplorerBuilder()
	builder.addAgents(AWSAIAgentIdentityInventoryResult{
		Status:  "ready",
		Records: []AWSAIAgentIdentityRecord{record},
	})

	nodes := builder.sortedNodes()
	nodeByID := map[string]AWSGraphExplorerNode{}
	for _, node := range nodes {
		nodeByID[node.NodeID] = node
	}
	if _, ok := nodeByID[credentialRefNodeID]; !ok {
		t.Fatalf("expected credential reference to render as dedicated credential node: %q", credentialRefNodeID)
	}
	if _, ok := nodeByID[genericCredentialNodeID]; ok {
		t.Fatalf("expected no generic resource node for credential references: %q", genericCredentialNodeID)
	}
	if _, ok := nodeByID[encryptionNodeID]; !ok {
		t.Fatalf("expected encryption key ARN to render as generic resource node: %q", encryptionNodeID)
	}
	if len(nodes) == 0 || nodeByID[credentialRefNodeID].NodeType != "credential_reference" {
		t.Fatalf("expected dedicated credential node type to be credential_reference, got %+v", nodeByID[credentialRefNodeID])
	}
}

func TestPaginateAWSGraphExplorerExpandsSingleHop(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "identity", Label: "A"},
		{NodeID: "node-b", NodeType: "resource", Label: "B"},
		{NodeID: "node-c", NodeType: "resource", Label: "C"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-a-b", Type: "observed_runtime_action", FromNodeID: "node-a", ToNodeID: "node-b"},
		{EdgeID: "edge-b-c", Type: "observed_runtime_action", FromNodeID: "node-b", ToNodeID: "node-c"},
	}

	paged, displayedEdges, _, _, _ := paginateAWSGraphExplorer(nodes, nodes, edges, edges, nil, AWSGraphExplorerRequest{
		Limit:  1,
		Expand: "neighbors",
	})
	if got, want := len(displayedEdges), 1; got != want {
		t.Fatalf("expected one-hop edge expansion, got %d edges: %+v", got, displayedEdges)
	}
	if displayedEdges[0].EdgeID != "edge-a-b" {
		t.Fatalf("expected only edge attached to seed node, got %+v", displayedEdges)
	}
	nodeIDs := map[string]bool{}
	for _, node := range paged {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["node-a"] || !nodeIDs["node-b"] || nodeIDs["node-c"] {
		t.Fatalf("expected seed plus one-hop neighbor only, got %+v", paged)
	}
}

func TestFilterAWSGraphExplorerKeepsNeighborEdgesForNodeSearch(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "agent", Label: "Needle Agent"},
		{NodeID: "node-b", NodeType: "resource", Label: "Target"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-a-b", Type: "calls_tool", FromNodeID: "node-a", ToNodeID: "node-b", Source: "ai_agent_identities", Status: "ready"},
	}

	filteredNodes, filteredEdges, filteredPaths, _ := filterAWSGraphExplorer(nodes, edges, nil, AWSGraphExplorerRequest{Search: "Needle Agent", Expand: "neighbors"})
	if len(filteredNodes) != 1 || filteredNodes[0].NodeID != "node-a" {
		t.Fatalf("expected node-only search to match node-a, got %+v", filteredNodes)
	}
	if len(filteredEdges) != 1 || filteredEdges[0].EdgeID != "edge-a-b" {
		t.Fatalf("expected node-only search to preserve adjacent edge for neighbor expansion, got %+v", filteredEdges)
	}
	pagedNodes, displayedEdges, displayedPaths, _, _ := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, AWSGraphExplorerRequest{Search: "Needle Agent", Expand: "neighbors"})
	if len(displayedEdges) != 1 || displayedEdges[0].EdgeID != "edge-a-b" {
		t.Fatalf("expected neighbor expansion to display preserved edge, got %+v", displayedEdges)
	}
	nodeIDs := map[string]bool{}
	for _, node := range pagedNodes {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["node-a"] || !nodeIDs["node-b"] {
		t.Fatalf("expected neighbor expansion to include matched node and adjacent endpoint, got %+v", pagedNodes)
	}
	if len(displayedPaths) != 0 {
		t.Fatalf("expected no paths for node-only search fixture, got %+v", displayedPaths)
	}
}

func TestPaginateAWSGraphExplorerKeepsFilteredEdgesWithoutSeededEndpoints(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "identity", Label: "A"},
		{NodeID: "node-b", NodeType: "resource", Label: "B"},
		{NodeID: "node-c", NodeType: "identity", Label: "C"},
		{NodeID: "node-d", NodeType: "resource", Label: "D"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-passrole-a", Type: "can_pass_role", FromNodeID: "node-a", ToNodeID: "node-b", Source: "iam_passrole_relationships", Status: "ready"},
		{EdgeID: "edge-passrole-b", Type: "can_pass_role", FromNodeID: "node-c", ToNodeID: "node-d", Source: "iam_passrole_relationships", Status: "ready"},
	}

	pagedNodes, pagedEdges, _, nextCursor, hasMore := paginateAWSGraphExplorer(nodes[:1], nodes, edges, edges, nil, AWSGraphExplorerRequest{Limit: 1, EdgeType: "can_pass_role"})
	if len(pagedEdges) != 1 {
		t.Fatalf("expected first can_pass_role page to contain one edge, got %+v", pagedEdges)
	}
	if got, want := pagedEdges[0].EdgeID, "edge-passrole-a"; got != want {
		t.Fatalf("expected edge %q, got %q", want, got)
	}
	nodeIDs := map[string]bool{}
	for _, node := range pagedNodes {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["node-a"] || !nodeIDs["node-b"] {
		t.Fatalf("expected edge-focused pagination to include matching edge endpoints, got %+v", pagedNodes)
	}
	if !hasMore || nextCursor == "" {
		t.Fatalf("expected edge-focused pagination to advance by relationship page, cursor=%q hasMore=%t", nextCursor, hasMore)
	}

	nextNodes, nextEdges, _, finalCursor, finalHasMore := paginateAWSGraphExplorer(nodes[:1], nodes, edges, edges, nil, AWSGraphExplorerRequest{Limit: 1, EdgeType: "can_pass_role", Cursor: nextCursor})
	if len(nextEdges) != 1 {
		t.Fatalf("expected second can_pass_role page to contain one edge, got %+v", nextEdges)
	}
	if got, want := nextEdges[0].EdgeID, "edge-passrole-b"; got != want {
		t.Fatalf("expected edge %q, got %q", want, got)
	}
	nodeIDs = map[string]bool{}
	for _, node := range nextNodes {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["node-c"] || !nodeIDs["node-d"] || nodeIDs["node-a"] || nodeIDs["node-b"] {
		t.Fatalf("expected second edge page to include only second edge endpoints, got %+v", nextNodes)
	}
	if finalHasMore || finalCursor != "" {
		t.Fatalf("expected final edge page to exhaust cursor, cursor=%q hasMore=%t", finalCursor, finalHasMore)
	}
}

func TestPaginateAWSGraphExplorerPreservesNodeMatchesForMixedSearch(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "identity", Label: "A", Status: "ready"},
		{NodeID: "node-b", NodeType: "resource", Label: "B", Status: "ready"},
		{NodeID: "node-c", NodeType: "resource", Label: "C", Status: "ready"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-a-b", Type: "observed_runtime_action", FromNodeID: "node-a", ToNodeID: "node-b", Source: "runtime_events", Status: "ready"},
		{EdgeID: "edge-b-c", Type: "least_privilege_scope", FromNodeID: "node-b", ToNodeID: "node-c", Source: "least_privilege", Status: "ready"},
	}

	pagedNodes, pagedEdges, _, nextCursor, hasMore := paginateAWSGraphExplorer(nodes, nodes, edges, edges, nil, AWSGraphExplorerRequest{Limit: 1, Search: "ready"})
	if len(pagedNodes) != 1 || pagedNodes[0].NodeID != "node-a" {
		t.Fatalf("expected mixed search to page matching nodes first, got %+v", pagedNodes)
	}
	if len(pagedEdges) != 0 {
		t.Fatalf("expected mixed search without neighbor expansion to preserve node page instead of edge page, got %+v", pagedEdges)
	}
	if !hasMore || nextCursor == "" {
		t.Fatalf("expected mixed node search to advance by node page, cursor=%q hasMore=%t", nextCursor, hasMore)
	}
}

func TestPaginateAWSGraphExplorerPagesMixedNodeAndEdgeSearch(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "identity", Label: "needle identity"},
		{NodeID: "edge-target-a", NodeType: "identity", Label: "Edge target A"},
		{NodeID: "edge-target-b", NodeType: "resource", Label: "Edge target B"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-needle", Type: "impacted_path", FromNodeID: "edge-target-a", ToNodeID: "edge-target-b", Label: "needle edge", Source: "blast_radius", Status: "ready"},
		{EdgeID: "edge-other", Type: "impacted_path", FromNodeID: "edge-target-b", ToNodeID: "node-a", Label: "other edge", Source: "blast_radius", Status: "ready"},
	}

	filteredNodes, filteredEdges, filteredPaths, _ := filterAWSGraphExplorer(nodes, edges, nil, AWSGraphExplorerRequest{Search: "needle"})
	if len(filteredNodes) != 1 || filteredNodes[0].NodeID != "node-a" {
		t.Fatalf("expected search to match node-a, got %+v", filteredNodes)
	}
	if len(filteredEdges) != 1 || filteredEdges[0].EdgeID != "edge-needle" {
		t.Fatalf("expected search to preserve matching edge, got %+v", filteredEdges)
	}
	if len(filteredPaths) != 0 {
		t.Fatalf("expected no matching paths, got %+v", filteredPaths)
	}

	pagedNodes, pagedEdges, pagedPaths, nextCursor, hasMore := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, AWSGraphExplorerRequest{Limit: 1, Search: "needle"})
	if len(pagedNodes) != 1 || pagedNodes[0].NodeID != "node-a" {
		t.Fatalf("expected first mixed node+edge page to contain node-a, got %+v", pagedNodes)
	}
	if len(pagedEdges) != 0 {
		t.Fatalf("expected first mixed node+edge page to contain only node-a, got %+v", pagedEdges)
	}
	if len(pagedPaths) != 0 {
		t.Fatalf("expected first mixed node+edge page to contain no paths, got %+v", pagedPaths)
	}
	if !hasMore || nextCursor == "" {
		t.Fatalf("expected mixed node+edge search to advance to edge page, cursor=%q hasMore=%t", nextCursor, hasMore)
	}

	nextNodes, nextEdges, nextPaths, finalCursor, finalHasMore := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, AWSGraphExplorerRequest{Limit: 1, Search: "needle", Cursor: nextCursor})
	if len(nextEdges) != 1 || nextEdges[0].EdgeID != "edge-needle" {
		t.Fatalf("expected second mixed node+edge page to include edge match, got %+v", nextEdges)
	}
	if len(nextPaths) != 0 {
		t.Fatalf("expected second mixed node+edge page to contain no paths, got %+v", nextPaths)
	}
	nodeIDs := map[string]bool{}
	for _, node := range nextNodes {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["edge-target-a"] || !nodeIDs["edge-target-b"] || nodeIDs["node-a"] {
		t.Fatalf("expected second mixed node+edge page to include edge endpoints only, got %+v", nextNodes)
	}
	if finalHasMore || finalCursor != "" {
		t.Fatalf("expected second mixed node+edge page to exhaust cursor, cursor=%q hasMore=%t", finalCursor, finalHasMore)
	}
}

func TestPaginateAWSGraphExplorerPagesMixedNodeAndPathSearch(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "identity", Label: "needle identity"},
		{NodeID: "node-a-neighbor", NodeType: "resource", Label: "Node neighbor"},
		{NodeID: "node-b", NodeType: "identity", Label: "Path source"},
		{NodeID: "node-c", NodeType: "resource", Label: "Path target"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-a-neighbor", Type: "observed_runtime_action", FromNodeID: "node-a", ToNodeID: "node-a-neighbor", Source: "runtime_events", Status: "ready"},
		{EdgeID: "edge-b-c", Type: "impacted_path", FromNodeID: "node-b", ToNodeID: "node-c", Source: "blast_radius", Status: "ready"},
	}
	paths := []AWSGraphExplorerPath{
		{PathID: "path-b-c", PathType: "blast_radius_path", Status: "ready", NodeIDs: []string{"node-b", "node-c"}, EdgeIDs: []string{"edge-b-c"}, NextAction: "Investigate needle path"},
	}

	filteredNodes, filteredEdges, filteredPaths, _ := filterAWSGraphExplorer(nodes, edges, paths, AWSGraphExplorerRequest{Search: "needle", Expand: "neighbors"})
	if len(filteredNodes) != 1 || filteredNodes[0].NodeID != "node-a" {
		t.Fatalf("expected search to match node-a, got %+v", filteredNodes)
	}
	if len(filteredEdges) != 1 || filteredEdges[0].EdgeID != "edge-a-neighbor" {
		t.Fatalf("expected search to preserve neighbor edge for node-a, got %+v", filteredEdges)
	}
	if len(filteredPaths) != 1 || filteredPaths[0].PathID != "path-b-c" {
		t.Fatalf("expected search to match the path next_action, got %+v", filteredPaths)
	}

	pagedNodes, pagedEdges, pagedPaths, nextCursor, hasMore := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, AWSGraphExplorerRequest{Limit: 1, Search: "needle", Expand: "neighbors"})
	if len(pagedPaths) != 0 {
		t.Fatalf("expected first mixed search page to contain the node match plus its neighbor edge only, paths=%+v edges=%+v", pagedPaths, pagedEdges)
	}
	if len(pagedEdges) != 1 || pagedEdges[0].EdgeID != "edge-a-neighbor" {
		t.Fatalf("expected first mixed search page to preserve node-page neighbor edge, got %+v", pagedEdges)
	}
	nodeIDs := map[string]bool{}
	for _, node := range pagedNodes {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["node-a"] || !nodeIDs["node-a-neighbor"] || nodeIDs["node-b"] || nodeIDs["node-c"] {
		t.Fatalf("expected first mixed search page to return node-a and its neighbor only, got %+v", pagedNodes)
	}
	if !hasMore || nextCursor == "" {
		t.Fatalf("expected mixed node/path search to advance to path page, cursor=%q hasMore=%t", nextCursor, hasMore)
	}

	nextNodes, nextEdges, nextPaths, finalCursor, finalHasMore := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, AWSGraphExplorerRequest{Limit: 1, Search: "needle", Expand: "neighbors", Cursor: nextCursor})
	if len(nextPaths) != 1 || nextPaths[0].PathID != "path-b-c" {
		t.Fatalf("expected second mixed search page to expose matching path, got %+v", nextPaths)
	}
	if len(nextEdges) != 1 || nextEdges[0].EdgeID != "edge-b-c" {
		t.Fatalf("expected second mixed search page to include referenced path edge, got %+v", nextEdges)
	}
	nodeIDs = map[string]bool{}
	for _, node := range nextNodes {
		nodeIDs[node.NodeID] = true
	}
	if nodeIDs["node-a"] || !nodeIDs["node-b"] || !nodeIDs["node-c"] {
		t.Fatalf("expected second mixed search page to include path nodes only, got %+v", nextNodes)
	}
	if finalHasMore || finalCursor != "" {
		t.Fatalf("expected second mixed search page to exhaust cursor, cursor=%q hasMore=%t", finalCursor, finalHasMore)
	}
}

func TestPaginateAWSGraphExplorerMixedSearchCapsEdgePageTotalForNeighborFallback(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "identity", Label: "needle identity"},
		{NodeID: "node-b", NodeType: "resource", Label: "B"},
		{NodeID: "node-c", NodeType: "resource", Label: "C"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-needle", Type: "impacted_path", FromNodeID: "node-a", ToNodeID: "node-b", Label: "needle edge", Source: "blast_radius", Status: "ready"},
		{EdgeID: "edge-fallback", Type: "observed_runtime_action", FromNodeID: "node-a", ToNodeID: "node-c", Label: "other edge", Source: "runtime_events", Status: "ready"},
	}
	paths := []AWSGraphExplorerPath{
		{PathID: "path-a", PathType: "blast_radius_path", Status: "ready", NodeIDs: []string{"node-b", "node-c"}, EdgeIDs: []string{"edge-needle"}, NextAction: "Investigate needle path"},
	}

	filteredNodes, filteredEdges, filteredPaths, _ := filterAWSGraphExplorer(nodes, edges, paths, AWSGraphExplorerRequest{Search: "needle", Expand: "neighbors"})
	if len(filteredNodes) != 1 || filteredNodes[0].NodeID != "node-a" {
		t.Fatalf("expected node filter match, got %+v", filteredNodes)
	}
	if len(filteredEdges) != 2 {
		t.Fatalf("expected matching edge plus fallback edge, got %d: %+v", len(filteredEdges), filteredEdges)
	}
	if len(filteredPaths) != 1 || filteredPaths[0].PathID != "path-a" {
		t.Fatalf("expected matching path, got %+v", filteredPaths)
	}

	_, firstPageEdges, _, cursor, hasMore := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, AWSGraphExplorerRequest{Search: "needle", Expand: "neighbors", Limit: 2})
	if len(firstPageEdges) != 2 {
		t.Fatalf("expected first mixed page to include node-expansion edges, got edges=%+v", firstPageEdges)
	}
	if !hasMore || cursor != "2" {
		t.Fatalf("expected first mixed page to advance cursor to path stage, cursor=%q hasMore=%t", cursor, hasMore)
	}

	_, secondPageEdges, _, finalCursor, finalHasMore := paginateAWSGraphExplorer(filteredNodes, nodes, edges, filteredEdges, filteredPaths, AWSGraphExplorerRequest{Search: "needle", Expand: "neighbors", Limit: 2, Cursor: cursor})
	if len(secondPageEdges) != 1 {
		t.Fatalf("expected only searchable edges to be paged, got %+v", secondPageEdges)
	}
	if got, want := secondPageEdges[0].EdgeID, "edge-needle"; got != want {
		t.Fatalf("expected edge %q, got %q", want, got)
	}
	if finalHasMore || finalCursor != "" {
		t.Fatalf("expected mixed search pages to finish after searchable edges, cursor=%q hasMore=%t", finalCursor, finalHasMore)
	}
}

func TestPaginateAWSGraphExplorerPagesPathOnlyMatches(t *testing.T) {
	nodes := []AWSGraphExplorerNode{
		{NodeID: "node-a", NodeType: "identity", Label: "A"},
		{NodeID: "node-b", NodeType: "resource", Label: "B"},
		{NodeID: "node-c", NodeType: "identity", Label: "C"},
		{NodeID: "node-d", NodeType: "resource", Label: "D"},
	}
	edges := []AWSGraphExplorerEdge{
		{EdgeID: "edge-a-b", Type: "impacted_path", FromNodeID: "node-a", ToNodeID: "node-b", Source: "blast_radius", Status: "ready"},
		{EdgeID: "edge-c-d", Type: "least_privilege_scope", FromNodeID: "node-c", ToNodeID: "node-d", Source: "least_privilege", Status: "review"},
	}
	paths := []AWSGraphExplorerPath{
		{PathID: "path-a", PathType: "blast_radius_path", Status: "ready", NodeIDs: []string{"node-a", "node-b"}, EdgeIDs: []string{"edge-a-b"}, NextAction: "Inspect first path-only action"},
		{PathID: "path-b", PathType: "least_privilege_path", Status: "review", NodeIDs: []string{"node-c", "node-d"}, EdgeIDs: []string{"edge-c-d"}, NextAction: "Inspect second path-only action"},
	}

	pagedNodes, pagedEdges, pagedPaths, nextCursor, hasMore := paginateAWSGraphExplorer(nil, nodes, edges, nil, paths, AWSGraphExplorerRequest{Limit: 1, Search: "path-only"})
	if len(pagedPaths) != 1 || pagedPaths[0].PathID != "path-a" {
		t.Fatalf("expected first path-only page to include path-a only, got %+v", pagedPaths)
	}
	if len(pagedEdges) != 1 || pagedEdges[0].EdgeID != "edge-a-b" {
		t.Fatalf("expected first path-only page to include referenced edge, got %+v", pagedEdges)
	}
	nodeIDs := map[string]bool{}
	for _, node := range pagedNodes {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["node-a"] || !nodeIDs["node-b"] || nodeIDs["node-c"] || nodeIDs["node-d"] {
		t.Fatalf("expected first path-only page to include only first path nodes, got %+v", pagedNodes)
	}
	if !hasMore || nextCursor == "" {
		t.Fatalf("expected path-only pagination to advance by path page, cursor=%q hasMore=%t", nextCursor, hasMore)
	}

	nextNodes, nextEdges, nextPaths, finalCursor, finalHasMore := paginateAWSGraphExplorer(nil, nodes, edges, nil, paths, AWSGraphExplorerRequest{Limit: 1, Search: "path-only", Cursor: nextCursor})
	if len(nextPaths) != 1 || nextPaths[0].PathID != "path-b" {
		t.Fatalf("expected second path-only page to include path-b only, got %+v", nextPaths)
	}
	if len(nextEdges) != 1 || nextEdges[0].EdgeID != "edge-c-d" {
		t.Fatalf("expected second path-only page to include referenced edge, got %+v", nextEdges)
	}
	nodeIDs = map[string]bool{}
	for _, node := range nextNodes {
		nodeIDs[node.NodeID] = true
	}
	if !nodeIDs["node-c"] || !nodeIDs["node-d"] || nodeIDs["node-a"] || nodeIDs["node-b"] {
		t.Fatalf("expected second path-only page to include only second path nodes, got %+v", nextNodes)
	}
	if finalHasMore || finalCursor != "" {
		t.Fatalf("expected final path-only page to exhaust cursor, cursor=%q hasMore=%t", finalCursor, finalHasMore)
	}
}

func TestAWSGraphExplorerNodeTypeForResourcePrefersResourceSemantics(t *testing.T) {
	cases := map[string]string{
		"arn:aws:s3:::my-agent-bucket":                                       "s3_bucket",
		"arn:aws:s3:::my-session-data":                                       "s3_bucket",
		"arn:aws:kms:us-east-1:111111111111:key/agent-key":                   "kms_key",
		"arn:aws:secretsmanager:us-east-1:111111111111:secret:session-token": "secret",
		"arn:aws:iam::111111111111:role/service-agent-role":                  "identity",
		"AWS::Bedrock::Agent":                                                "agent",
		"runtime-session":                                                    "session",
	}
	for value, want := range cases {
		if got := awsGraphExplorerNodeTypeForResource(value); got != want {
			t.Fatalf("node type for %q = %q, want %q", value, got, want)
		}
	}
}

func TestAWSGraphExplorerCanonicalNodeTypeAliases(t *testing.T) {
	cases := map[string]string{
		"ai_agent":                    "agent",
		"target_resource":             "resource",
		"aws_service":                 "resource",
		"iam_role":                    "identity",
		"runtime_session":             "session",
		"AWS::SecretsManager::Secret": "secret",
		"AWS::KMS::Key":               "kms_key",
		"AWS::S3::Bucket":             "s3_bucket",
		"AWS::IAM::Role":              "identity",
		"AWS::Bedrock::Agent":         "agent",
		"credential-reference":        "credential_reference",
	}
	for raw, want := range cases {
		builder := newAWSGraphExplorerBuilder()
		builder.addNode(AWSGraphExplorerNode{NodeID: raw, NodeType: raw, Label: raw})
		if got := builder.nodes[raw].NodeType; got != want {
			t.Fatalf("expected node_type %q to canonicalize to %q, got %q", raw, want, got)
		}
	}
}

func TestAWSGraphExplorerCanonicalNodeTypeAvoidsOverBroadKeyMatch(t *testing.T) {
	cases := map[string]string{
		"api_key":    "resource",
		"access_key": "resource",
		"ssh_key":    "resource",
		"secret_key": "secret",
	}
	for raw, want := range cases {
		if got := awsGraphExplorerCanonicalNodeType(raw); got != want {
			t.Fatalf("canonical node type %q = %q, want %q", raw, got, want)
		}
	}
}

func TestAWSGraphExplorerLeastPrivilegeIndexesRelationshipsByRecommendation(t *testing.T) {
	now := time.Date(2026, 7, 6, 10, 30, 0, 0, time.UTC)
	builder := newAWSGraphExplorerBuilder()
	builder.addLeastPrivilege(AWSLeastPrivilegeResult{
		Recommendations: []AWSLeastPrivilegeRecommendation{
			{
				RecommendationID: "recommendation-alpha",
				Status:           "ready",
				Confidence:       0.91,
				UpdatedAt:        now,
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: "aws:identity:alpha-user", NodeType: "identity", Label: "Alpha User"},
					{NodeID: "aws:resource:alpha-target", NodeType: "resource", Label: "Alpha Target"},
				},
				ImpactedNodes: []string{"aws:identity:alpha-user", "aws:resource:alpha-target"},
				Evidence: []AWSLeastPrivilegeEvidence{
					{
						Source:       "least_privilege",
						EvidenceRef:  "least-privilege-evidence-alpha",
						Label:        "Alpha recommendation evidence",
						Confidence:   0.91,
						ObservedAt:   now,
						Relationship: "policy-alpha",
					},
				},
				NextAction: "Review recommendation alpha",
				Rationale:  "Alpha rationale",
			},
			{
				RecommendationID: "recommendation-beta",
				Status:           "review",
				Confidence:       0.82,
				UpdatedAt:        now,
				ImpactedPath: []AWSLeastPrivilegePathStep{
					{NodeID: "aws:identity:beta-user", NodeType: "identity", Label: "Beta User"},
					{NodeID: "aws:resource:beta-target", NodeType: "resource", Label: "Beta Target"},
				},
				ImpactedNodes: []string{"aws:identity:beta-user", "aws:resource:beta-target"},
				Evidence: []AWSLeastPrivilegeEvidence{
					{
						Source:       "least_privilege",
						EvidenceRef:  "least-privilege-evidence-beta",
						Label:        "Beta recommendation evidence",
						Confidence:   0.82,
						ObservedAt:   now,
						Relationship: "policy-beta",
					},
				},
				NextAction: "Review recommendation beta",
				Rationale:  "Beta rationale",
			},
		},
		Relationships: []AWSLeastPrivilegeRelationship{
			{RecommendationID: "recommendation-alpha", Type: "least_privilege_scope", FromNodeID: "aws:identity:alpha-user", ToNodeID: "aws:resource:alpha-target", EvidenceRef: "least-privilege-edge-alpha"},
			{RecommendationID: "recommendation-alpha", Type: "least_privilege_scope", FromNodeID: "aws:identity:alpha-user", ToNodeID: "aws:resource:alpha-target", EvidenceRef: "least-privilege-edge-alpha-2"},
			{RecommendationID: "recommendation-beta", Type: "least_privilege_scope", FromNodeID: "aws:identity:beta-user", ToNodeID: "aws:resource:beta-target", EvidenceRef: "least-privilege-edge-beta"},
			{RecommendationID: "unrelated", Type: "least_privilege_scope", FromNodeID: "aws:identity:ignored", ToNodeID: "aws:resource:ignored", EvidenceRef: "least-privilege-edge-ignored"},
		},
	})

	edges := builder.sortedEdges()
	if len(edges) != 3 {
		t.Fatalf("expected least-privilege edges to be scoped by recommendation, got %d edges: %+v", len(edges), edges)
	}

	paths := builder.sortedPaths()
	if len(paths) != 2 {
		t.Fatalf("expected one path per recommendation, got %d", len(paths))
	}
	for _, path := range paths {
		switch path.Title {
		case "Alpha rationale":
			if len(path.EdgeIDs) != 2 {
				t.Fatalf("expected alpha path to reference two edges, got %+v", path)
			}
		case "Beta rationale":
			if len(path.EdgeIDs) != 1 {
				t.Fatalf("expected beta path to reference one edge, got %+v", path)
			}
		default:
			t.Fatalf("unexpected least-privilege path: %+v", path)
		}
	}
}

func TestGetAWSGraphExplorerPermissionDeniedIsExplicit(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 10, 0, 0, time.UTC)
	svc, ws := newBlastRadiusService(t, "project-graph-explorer-denied", now)

	result, err := svc.GetAWSGraphExplorer(defaultScopeContext(), ws, "project-graph-explorer-denied", AWSGraphExplorerRequest{
		ConnectorID:  "aws-prod",
		FixtureState: "permission_denied",
	})
	if err != nil {
		t.Fatalf("permission denied: %v", err)
	}
	if result.Status != "blocked" || result.Confidence != 0 {
		t.Fatalf("expected blocked permission-denied contract: %+v", result)
	}
	if len(result.Nodes) != 0 || len(result.Edges) != 0 || len(result.Paths) != 0 {
		t.Fatalf("permission denied must not fabricate graph entries: %+v", result)
	}
	if len(result.Diagnostics) == 0 || len(result.FailureReasons) == 0 {
		t.Fatalf("permission denied must surface diagnostics and failure reasons: %+v", result)
	}
}

func TestNormalizeAWSGraphExplorerFixtureStateHonorsExplicitRequest(t *testing.T) {
	disconnected := AWSConnectionStatus{Connected: false}

	if got := normalizeAWSGraphExplorerFixtureState("success", disconnected, true); got != "success" {
		t.Fatalf("expected explicit success to be preserved, got %q", got)
	}
	if got := normalizeAWSGraphExplorerFixtureState("ready", disconnected, false); got != "success" {
		t.Fatalf("expected explicit ready to be preserved, got %q", got)
	}
	if got := normalizeAWSGraphExplorerFixtureState("", disconnected, false); got != "permission_denied" {
		t.Fatalf("expected blank fixture_state to map to permission_denied without live connection, got %q", got)
	}
	if got := normalizeAWSGraphExplorerFixtureState("invalid", disconnected, true); got != "" {
		t.Fatalf("invalid fixture_state should return empty, got %q", got)
	}
}

func TestRouterAWSGraphExplorer(t *testing.T) {
	validator := &fakeAWSConnectorValidator{
		result: AWSConnectionValidationResult{
			AccountID:    "123456789012",
			PrincipalARN: "arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/identrail-connector-validation",
			UserID:       "AROATEST:identrail-connector-validation",
			Region:       "us-east-1",
			PermissionChecks: []AWSConnectionPermissionCheck{
				{Name: "sts:AssumeRole", Passed: true, Message: "Role assumption succeeded."},
				{Name: "iam:ListRoles", Passed: true, Message: "IAM role listing permission is available."},
			},
		},
	}
	r := newAWSConnectionTestRouter(t, validator)
	setup := doAWSConnectionAPI(t, r, http.MethodPost, "/v1/workspaces/workspace-a/projects/project-1/aws/connection", `{
		"connector_id":"aws-prod",
		"display_name":"Production AWS",
		"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly",
		"external_id":"tenant-external-id",
		"region":"us-east-1"
	}`)
	if setup.Code != http.StatusOK {
		t.Fatalf("seed aws connection failed: %d body=%s", setup.Code, setup.Body.String())
	}

	resp := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/graph-explorer?connector_id=aws-prod&fixture_state=success&limit=3&expand=neighbors", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected graph explorer 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var body struct {
		Graph AWSGraphExplorerResult `json:"graph"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode graph explorer response: %v", err)
	}
	if body.Graph.CurrentIssueRef != "#1551" || len(body.Graph.Nodes) == 0 || body.Graph.Summary.PageSize != 3 {
		t.Fatalf("unexpected graph explorer payload: %+v", body.Graph)
	}

	bad := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/graph-explorer?fixture_state=bogus", "")
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid fixture 400, got %d body=%s", bad.Code, bad.Body.String())
	}

	zeroLimit := doAWSConnectionAPI(t, r, http.MethodGet, "/v1/workspaces/workspace-a/projects/project-1/aws/graph-explorer?connector_id=aws-prod&limit=0", "")
	if zeroLimit.Code != http.StatusBadRequest {
		t.Fatalf("expected limit=0 to be 400, got %d body=%s", zeroLimit.Code, zeroLimit.Body.String())
	}
}
