package aws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"

	"github.com/identrail/identrail/internal/providers"
)

type fakeAgentCoreCapabilitiesSDKClient struct {
	memoriesOutput       *bedrockagentcorecontrol.ListMemoriesOutput
	memoriesErr          error
	memoryDetail         map[string]*bedrockagentcorecontrol.GetMemoryOutput
	memoryDetailErr      map[string]error
	browsersOutput       *bedrockagentcorecontrol.ListBrowsersOutput
	browsersErr          error
	browserDetail        map[string]*bedrockagentcorecontrol.GetBrowserOutput
	browserDetailErr     map[string]error
	interpretersOutput   *bedrockagentcorecontrol.ListCodeInterpretersOutput
	interpretersErr      error
	interpreterDetail    map[string]*bedrockagentcorecontrol.GetCodeInterpreterOutput
	interpreterDetailErr map[string]error
}

func (f *fakeAgentCoreCapabilitiesSDKClient) ListMemories(_ context.Context, _ *bedrockagentcorecontrol.ListMemoriesInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListMemoriesOutput, error) {
	if f.memoriesErr != nil {
		return nil, f.memoriesErr
	}
	if f.memoriesOutput == nil {
		return &bedrockagentcorecontrol.ListMemoriesOutput{}, nil
	}
	return f.memoriesOutput, nil
}

func (f *fakeAgentCoreCapabilitiesSDKClient) GetMemory(_ context.Context, params *bedrockagentcorecontrol.GetMemoryInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetMemoryOutput, error) {
	id := awsv2.ToString(params.MemoryId)
	if err := f.memoryDetailErr[id]; err != nil {
		return nil, err
	}
	return f.memoryDetail[id], nil
}

func (f *fakeAgentCoreCapabilitiesSDKClient) ListBrowsers(_ context.Context, _ *bedrockagentcorecontrol.ListBrowsersInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListBrowsersOutput, error) {
	if f.browsersErr != nil {
		return nil, f.browsersErr
	}
	if f.browsersOutput == nil {
		return &bedrockagentcorecontrol.ListBrowsersOutput{}, nil
	}
	return f.browsersOutput, nil
}

func (f *fakeAgentCoreCapabilitiesSDKClient) GetBrowser(_ context.Context, params *bedrockagentcorecontrol.GetBrowserInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetBrowserOutput, error) {
	id := awsv2.ToString(params.BrowserId)
	if err := f.browserDetailErr[id]; err != nil {
		return nil, err
	}
	return f.browserDetail[id], nil
}

func (f *fakeAgentCoreCapabilitiesSDKClient) ListCodeInterpreters(_ context.Context, _ *bedrockagentcorecontrol.ListCodeInterpretersInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListCodeInterpretersOutput, error) {
	if f.interpretersErr != nil {
		return nil, f.interpretersErr
	}
	if f.interpretersOutput == nil {
		return &bedrockagentcorecontrol.ListCodeInterpretersOutput{}, nil
	}
	return f.interpretersOutput, nil
}

func (f *fakeAgentCoreCapabilitiesSDKClient) GetCodeInterpreter(_ context.Context, params *bedrockagentcorecontrol.GetCodeInterpreterInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetCodeInterpreterOutput, error) {
	id := awsv2.ToString(params.CodeInterpreterId)
	if err := f.interpreterDetailErr[id]; err != nil {
		return nil, err
	}
	return f.interpreterDetail[id], nil
}

func collectAllCapabilityRecords(t *testing.T, api AIAgentIdentityAPI) ([]AIAgentIdentity, []providers.SourceError) {
	t.Helper()
	records := []AIAgentIdentity{}
	diagnostics := []providers.SourceError{}
	token := ""
	for i := 0; i < 16; i++ {
		page, err := api.ListAgentIdentities(context.Background(), token, 50)
		if err != nil {
			t.Fatalf("ListAgentIdentities: %v", err)
		}
		records = append(records, page.Records...)
		diagnostics = append(diagnostics, page.Diagnostics...)
		if strings.TrimSpace(page.NextToken) == "" {
			return records, diagnostics
		}
		token = page.NextToken
	}
	t.Fatalf("pagination did not terminate")
	return nil, nil
}

func TestSDKAgentCoreCapabilitiesMapsAllSurfaces(t *testing.T) {
	client := &fakeAgentCoreCapabilitiesSDKClient{
		memoriesOutput: &bedrockagentcorecontrol.ListMemoriesOutput{
			Memories: []agentcoretypes.MemorySummary{{Id: awsv2.String("mem-1"), Arn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:memory/mem-1"), Status: agentcoretypes.MemoryStatusActive}},
		},
		memoryDetail: map[string]*bedrockagentcorecontrol.GetMemoryOutput{
			"mem-1": {Memory: &agentcoretypes.Memory{
				Id:                     awsv2.String("mem-1"),
				Arn:                    awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:memory/mem-1"),
				Name:                   awsv2.String("payments-memory"),
				Status:                 agentcoretypes.MemoryStatusActive,
				EventExpiryDuration:    awsv2.Int32(30),
				EncryptionKeyArn:       awsv2.String("arn:aws:kms:us-east-1:123456789012:key/cmk-mem"),
				MemoryExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/agentcore-memory"),
				Strategies:             []agentcoretypes.MemoryStrategy{{Name: awsv2.String("semantic"), Type: agentcoretypes.MemoryStrategyTypeSemantic}},
			}},
		},
		browsersOutput: &bedrockagentcorecontrol.ListBrowsersOutput{
			BrowserSummaries: []agentcoretypes.BrowserSummary{{BrowserId: awsv2.String("br-1"), BrowserArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:browser/br-1"), Name: awsv2.String("research-browser"), Status: agentcoretypes.BrowserStatusReady}},
		},
		browserDetail: map[string]*bedrockagentcorecontrol.GetBrowserOutput{
			"br-1": {
				BrowserId:        awsv2.String("br-1"),
				BrowserArn:       awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:browser/br-1"),
				Name:             awsv2.String("research-browser"),
				Status:           agentcoretypes.BrowserStatusReady,
				ExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/agentcore-browser"),
				NetworkConfiguration: &agentcoretypes.BrowserNetworkConfiguration{
					NetworkMode: agentcoretypes.BrowserNetworkModeVpc,
					VpcConfig:   &agentcoretypes.VpcConfig{Subnets: []string{"subnet-a", "subnet-b"}, SecurityGroups: []string{"sg-1"}},
				},
				Recording: &agentcoretypes.RecordingConfig{Enabled: true, S3Location: &agentcoretypes.S3Location{Bucket: awsv2.String("agent-recordings"), Prefix: awsv2.String("browser/")}},
			},
		},
		interpretersOutput: &bedrockagentcorecontrol.ListCodeInterpretersOutput{
			CodeInterpreterSummaries: []agentcoretypes.CodeInterpreterSummary{{CodeInterpreterId: awsv2.String("ci-1"), CodeInterpreterArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/ci-1"), Name: awsv2.String("python-sandbox"), Status: agentcoretypes.CodeInterpreterStatusReady}},
		},
		interpreterDetail: map[string]*bedrockagentcorecontrol.GetCodeInterpreterOutput{
			"ci-1": {
				CodeInterpreterId:  awsv2.String("ci-1"),
				CodeInterpreterArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:code-interpreter/ci-1"),
				Name:               awsv2.String("python-sandbox"),
				Status:             agentcoretypes.CodeInterpreterStatusReady,
				ExecutionRoleArn:   awsv2.String("arn:aws:iam::123456789012:role/agentcore-code"),
				NetworkConfiguration: &agentcoretypes.CodeInterpreterNetworkConfiguration{
					NetworkMode: agentcoretypes.CodeInterpreterNetworkModeSandbox,
				},
			},
		},
	}
	api := NewSDKAgentCoreCapabilitiesAPIFromClient(client, "123456789012", "us-east-1")
	records, diagnostics := collectAllCapabilityRecords(t, api)
	if len(diagnostics) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diagnostics)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 capability records, got %d", len(records))
	}
	byKind := map[string]AIAgentIdentity{}
	for _, r := range records {
		if r.AgentType != agentCoreCapabilityAgentType {
			t.Fatalf("expected agentcore_capability type, got %q", r.AgentType)
		}
		byKind[r.CapabilityKind] = r
	}

	memory := byKind[agentCoreCapabilityKindMemory]
	if memory.RuntimeRoleARN == "" || memory.EncryptionKeyARN == "" {
		t.Fatalf("memory capability missing role/encryption: %+v", memory)
	}
	browser := byKind[agentCoreCapabilityKindBrowser]
	if browser.NetworkMode != "vpc" {
		t.Fatalf("browser network mode wrong: %+v", browser)
	}
	storage := strings.Join(browser.StorageReferenceRefs, ",")
	if !strings.Contains(storage, "s3://agent-recordings/browser/") {
		t.Fatalf("browser recording storage ref missing: %v", browser.StorageReferenceRefs)
	}
	code := byKind[agentCoreCapabilityKindCodeInterpreter]
	if code.RuntimeRoleARN == "" || code.NetworkMode == "" {
		t.Fatalf("code interpreter missing role/network: %+v", code)
	}

	// Every record must validate against the shared contract once enriched.
	for _, r := range records {
		enriched := normalizeAIAgentIdentityScope(AWSCollectorScope{
			TenantID: "t", WorkspaceID: "w", ProjectID: "p", ConnectorID: "c", ScanID: "s", AccountID: "123456789012", Region: "us-east-1",
		}, r, r.CollectedAt)
		payload, err := json.Marshal(enriched)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"memory_record", "browser_page", "code_output", "conversation", "secret_value"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("metadata-only contract violated by %q: %s", forbidden, payload)
			}
		}
	}
}

func TestSDKAgentCoreCapabilitiesDegradesOnDescribeFailure(t *testing.T) {
	client := &fakeAgentCoreCapabilitiesSDKClient{
		memoriesOutput: &bedrockagentcorecontrol.ListMemoriesOutput{
			Memories: []agentcoretypes.MemorySummary{{Id: awsv2.String("mem-bad"), Arn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:memory/mem-bad"), Status: agentcoretypes.MemoryStatusActive}},
		},
		memoryDetailErr: map[string]error{"mem-bad": errors.New("AccessDenied: GetMemory")},
	}
	api := NewSDKAgentCoreCapabilitiesAPIFromClient(client, "123456789012", "us-east-1")
	records, diagnostics := collectAllCapabilityRecords(t, api)
	if len(records) != 1 {
		t.Fatalf("expected one degraded record, got %d", len(records))
	}
	if records[0].CoverageStatus != "degraded" {
		t.Fatalf("expected degraded coverage, got %+v", records[0])
	}
	found := false
	for _, d := range diagnostics {
		if d.Code == "agentcore_memory_describe_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected describe-failed diagnostic, got %v", diagnostics)
	}
}

func TestSDKAgentCoreCapabilitiesListFailureAdvancesToNextSource(t *testing.T) {
	// ListMemories is denied, but the account still has ListBrowsers /
	// ListCodeInterpreters permission. The adapter must record a diagnostic for
	// the failed memory source and still surface the browser record instead of
	// aborting the whole capabilities adapter.
	client := &fakeAgentCoreCapabilitiesSDKClient{
		memoriesErr: errors.New("AccessDenied: ListMemories"),
		browsersOutput: &bedrockagentcorecontrol.ListBrowsersOutput{
			BrowserSummaries: []agentcoretypes.BrowserSummary{{BrowserId: awsv2.String("br-1"), BrowserArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:browser/br-1"), Name: awsv2.String("research-browser"), Status: agentcoretypes.BrowserStatusReady}},
		},
		browserDetail: map[string]*bedrockagentcorecontrol.GetBrowserOutput{
			"br-1": {
				BrowserId:        awsv2.String("br-1"),
				BrowserArn:       awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:browser/br-1"),
				Name:             awsv2.String("research-browser"),
				Status:           agentcoretypes.BrowserStatusReady,
				ExecutionRoleArn: awsv2.String("arn:aws:iam::123456789012:role/agentcore-browser"),
			},
		},
	}
	api := NewSDKAgentCoreCapabilitiesAPIFromClient(client, "123456789012", "us-east-1")
	records, diagnostics := collectAllCapabilityRecords(t, api)

	foundBrowser := false
	for _, r := range records {
		if r.CapabilityKind == agentCoreCapabilityKindBrowser {
			foundBrowser = true
		}
	}
	if !foundBrowser {
		t.Fatalf("expected browser record to survive a ListMemories denial, got %+v", records)
	}
	foundDiag := false
	for _, d := range diagnostics {
		if d.Code == "agentcore_capability_list_failed" && d.SourceID == "memory" {
			foundDiag = true
		}
	}
	if !foundDiag {
		t.Fatalf("expected agentcore_capability_list_failed diagnostic for memory, got %v", diagnostics)
	}
}

func TestSDKAgentCoreCapabilitiesListFailureAbortsOnCancellation(t *testing.T) {
	client := &fakeAgentCoreCapabilitiesSDKClient{memoriesErr: context.Canceled}
	api := NewSDKAgentCoreCapabilitiesAPIFromClient(client, "123456789012", "us-east-1")
	if _, err := api.ListAgentIdentities(context.Background(), "", 50); err == nil {
		t.Fatalf("expected cancellation to abort the adapter")
	}
}

func TestSDKAgentCoreCapabilitiesEmptyAuthorized(t *testing.T) {
	client := &fakeAgentCoreCapabilitiesSDKClient{}
	api := NewSDKAgentCoreCapabilitiesAPIFromClient(client, "123456789012", "us-east-1")
	records, diagnostics := collectAllCapabilityRecords(t, api)
	if len(records) != 0 || len(diagnostics) != 0 {
		t.Fatalf("expected empty authorized result, got %d records %d diagnostics", len(records), len(diagnostics))
	}
}

func TestSDKAgentCoreCapabilitiesRejectsBadToken(t *testing.T) {
	client := &fakeAgentCoreCapabilitiesSDKClient{}
	api := NewSDKAgentCoreCapabilitiesAPIFromClient(client, "123456789012", "us-east-1")
	// Out-of-range source index, non-numeric prefix, and a malformed prefix that
	// a lenient %d scan would otherwise accept must all be rejected.
	for _, badToken := range []string{"9:tok", "x:tok", "1abc:tok", "nodelim"} {
		if _, err := api.ListAgentIdentities(context.Background(), badToken, 50); err == nil {
			t.Fatalf("expected invalid token error for %q", badToken)
		}
	}
}

func TestSDKAgentCoreCapabilitiesSkipsDescribeForArnOnlySummary(t *testing.T) {
	// An ARN-only memory summary (no short id) must not trigger GetMemory with an
	// empty id; instead it surfaces a degraded record with an explicit reason.
	client := &fakeAgentCoreCapabilitiesSDKClient{
		memoriesOutput: &bedrockagentcorecontrol.ListMemoriesOutput{
			Memories: []agentcoretypes.MemorySummary{{Arn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:memory/mem-arn-only"), Status: agentcoretypes.MemoryStatusActive}},
		},
		memoryDetailErr: map[string]error{"": errors.New("GetMemory should not be called with an empty id")},
	}
	api := NewSDKAgentCoreCapabilitiesAPIFromClient(client, "123456789012", "us-east-1")
	records, diagnostics := collectAllCapabilityRecords(t, api)
	if len(records) != 1 {
		t.Fatalf("expected one degraded record, got %d", len(records))
	}
	if records[0].CoverageStatus != "degraded" {
		t.Fatalf("expected degraded coverage for ARN-only summary, got %+v", records[0])
	}
	found := false
	for _, d := range diagnostics {
		if d.Code == "agentcore_memory_id_missing" {
			found = true
		}
		if d.Code == "agentcore_memory_describe_failed" {
			t.Fatalf("ARN-only summary must not emit a describe-failed diagnostic, got %+v", d)
		}
	}
	if !found {
		t.Fatalf("expected agentcore_memory_id_missing diagnostic, got %v", diagnostics)
	}
}
