package aws

import (
	"context"
	"testing"
)

func TestFixtureBedrockAgentsAPISeedAndQuery(t *testing.T) {
	api := NewFixtureBedrockAgentsAPI()
	api.Seed(
		[]BedrockAgentSummary{{AgentID: "A1", AgentARN: "arn:aws:bedrock:us-east-1:123456789012:agent/A1", AgentName: "agent"}},
		map[string]BedrockAgentDetail{"A1": {ActionGroupNames: []string{"x"}}},
	)
	page, err := api.ListAgents(context.Background(), "", 100)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(page.Agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(page.Agents))
	}
	detail, issues, err := api.GetAgentDetail(context.Background(), "A1")
	if err != nil {
		t.Fatalf("GetAgentDetail: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues for seeded agent, got %v", issues)
	}
	if len(detail.ActionGroupNames) != 1 {
		t.Fatalf("expected seeded detail, got %+v", detail)
	}
}

func TestFixtureBedrockAgentsAPIUnseededAgentReturnsSoftDiagnostic(t *testing.T) {
	api := NewFixtureBedrockAgentsAPI()
	_, issues, err := api.GetAgentDetail(context.Background(), "missing")
	if err != nil {
		t.Fatalf("GetAgentDetail: %v", err)
	}
	if !hasIssueCode(issues, "bedrock_agent_detail_not_seeded") {
		t.Fatalf("expected not-seeded diagnostic, got %v", issues)
	}
}

func TestFixtureBedrockAgentsAPIRejectsEmptyID(t *testing.T) {
	api := NewFixtureBedrockAgentsAPI()
	_, issues, err := api.GetAgentDetail(context.Background(), "")
	if err != nil {
		t.Fatalf("GetAgentDetail: %v", err)
	}
	if !hasIssueCode(issues, "bedrock_agent_detail_missing_id") {
		t.Fatalf("expected missing-id diagnostic, got %v", issues)
	}
}

func TestDefaultBedrockAgentsFixtureReturnsRecord(t *testing.T) {
	fixture, err := DefaultBedrockAgentsFixture("123456789012", "eu-west-1")
	if err != nil {
		t.Fatalf("DefaultBedrockAgentsFixture: %v", err)
	}
	page, err := fixture.ListAgents(context.Background(), "", 100)
	if err != nil || len(page.Agents) == 0 {
		t.Fatalf("expected default fixture to have at least one agent, got %d (err=%v)", len(page.Agents), err)
	}
	detail, issues, err := fixture.GetAgentDetail(context.Background(), page.Agents[0].AgentID)
	if err != nil {
		t.Fatalf("GetAgentDetail: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("default fixture should not emit diagnostics, got %v", issues)
	}
	if len(detail.ActionGroupNames) == 0 {
		t.Fatalf("default fixture detail should expose action groups")
	}
}
