package aws

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/identrail/identrail/internal/providers"
)

// FixtureBedrockAgentsAPI is a thin, in-memory implementation of BedrockAgentsAPI
// used for local dev, demos, and contract tests. It is intentionally separate
// from the live SDK adapter so deploying Identrail without the live Bedrock SDK
// stays first-class (some operators want metadata-only fixtures while they
// stage the live read-only permission grant).
//
// Runtime composition boundary: this fixture is the only BedrockAgentsAPI
// implementation in this PR. A live aws-sdk-go-v2 Bedrock adapter is
// deliberately not introduced here because the Bedrock SDK module is not yet
// listed in go.mod and pulling it in would balloon this PR's scope and audit
// surface. The follow-up issue that wires the SDK adapter must also (1) add a
// case for rawKindAIAgentIdentity to RoleNormalizer.Normalize so the collector
// is not silently dropped during scans, and (2) compose
// NewBedrockAgentsCollector(NewSDKBedrockAgentsAPI(...)) inside
// internal/runtime/service_builder.go alongside the other Wave 1 collectors.
// Until then the collector is reachable only through the inventory API at
// GET .../aws/bedrock-agents, which consumes RawAssets directly without going
// through the normalizer.
type FixtureBedrockAgentsAPI struct {
	mu      sync.RWMutex
	agents  []BedrockAgentSummary
	details map[string]BedrockAgentDetail
}

var _ BedrockAgentsAPI = (*FixtureBedrockAgentsAPI)(nil)

// NewFixtureBedrockAgentsAPI returns an empty fixture-backed Bedrock Agents API.
func NewFixtureBedrockAgentsAPI() *FixtureBedrockAgentsAPI {
	return &FixtureBedrockAgentsAPI{details: map[string]BedrockAgentDetail{}}
}

// Seed replaces the entire fixture state in one atomic update.
func (f *FixtureBedrockAgentsAPI) Seed(agents []BedrockAgentSummary, details map[string]BedrockAgentDetail) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents = append([]BedrockAgentSummary(nil), agents...)
	f.details = map[string]BedrockAgentDetail{}
	for id, detail := range details {
		f.details[id] = detail
	}
}

// ListAgents returns one page that exhausts the seeded agents.
func (f *FixtureBedrockAgentsAPI) ListAgents(_ context.Context, _ string, _ int32) (BedrockAgentsPage, error) {
	if f == nil {
		return BedrockAgentsPage{}, nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return BedrockAgentsPage{Agents: append([]BedrockAgentSummary(nil), f.agents...)}, nil
}

// GetAgentDetail returns the seeded detail for an agent. Missing agents return
// an empty detail plus a soft diagnostic so callers can tell the difference
// between an authorized empty result and a missing fixture.
func (f *FixtureBedrockAgentsAPI) GetAgentDetail(_ context.Context, agentID string) (BedrockAgentDetail, []providers.SourceError, error) {
	if f == nil {
		return BedrockAgentDetail{}, nil, errors.New("bedrock agents fixture is nil")
	}
	id := strings.TrimSpace(agentID)
	if id == "" {
		return BedrockAgentDetail{}, []providers.SourceError{{
			Collector: bedrockAgentsCollectorName,
			Code:      "bedrock_agent_detail_missing_id",
			Message:   "GetAgentDetail called without an agent id",
		}}, nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	detail, ok := f.details[id]
	if !ok {
		return BedrockAgentDetail{}, []providers.SourceError{{
			Collector: bedrockAgentsCollectorName,
			SourceID:  id,
			Code:      "bedrock_agent_detail_not_seeded",
			Message:   "no fixture detail seeded for agent",
		}}, nil
	}
	return detail, nil, nil
}

// DefaultBedrockAgentsFixture returns the canonical demo fixture set used by
// local dev/quickstart so a fresh deployment shows Bedrock agent coverage
// without requiring a live AWS connector.
func DefaultBedrockAgentsFixture(accountID, region string) (*FixtureBedrockAgentsAPI, error) {
	account := strings.TrimSpace(accountID)
	if account == "" {
		account = "123456789012"
	}
	regionCode := strings.TrimSpace(region)
	if regionCode == "" {
		regionCode = "us-east-1"
	}
	partition := bedrockFixturePartition(regionCode)
	fixture := NewFixtureBedrockAgentsAPI()
	fixture.Seed(
		[]BedrockAgentSummary{
			{
				AgentID:                     "PAYMENTSAGENT1",
				AgentARN:                    bedrockFixtureAgentARN(partition, regionCode, account, "PAYMENTSAGENT1"),
				AgentName:                   "payments-risk-agent",
				AgentStatus:                 "PREPARED",
				AgentVersion:                "1",
				FoundationModel:             "anthropic.claude-3-5-sonnet-20240620-v1:0",
				RoleARN:                     "arn:" + partition + ":iam::" + account + ":role/bedrock-payments-risk-agent",
				GuardrailID:                 "guard-payments",
				GuardrailVersion:            "1",
				CustomerEncryptionKMSKeyARN: "arn:" + partition + ":kms:" + regionCode + ":" + account + ":key/cmk-bedrock-payments",
			},
		},
		map[string]BedrockAgentDetail{
			"PAYMENTSAGENT1": {
				ActionGroupNames:        []string{"payments-case-search", "fraud-review-action-group"},
				ActionGroupExecutorARNs: []string{"arn:" + partition + ":lambda:" + regionCode + ":" + account + ":function:payments-fraud-review"},
				KnowledgeBaseIDs:        []string{"KBPAYMENTS1"},
				AliasNames:              []string{"production"},
				AliasARNs:               []string{bedrockFixtureAgentARN(partition, regionCode, account, "PAYMENTSAGENT1") + "/alias/production"},
				HasInstruction:          true,
				HasPromptOverride:       false,
			},
		},
	)
	return fixture, nil
}

func bedrockFixturePartition(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}

func bedrockFixtureAgentARN(partition, region, account, agentID string) string {
	return "arn:" + partition + ":bedrock:" + region + ":" + account + ":agent/" + agentID
}
