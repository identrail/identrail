package aws

import (
	"context"
	"errors"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
)

type fakeAgentCoreRuntimeSDKClient struct {
	listOutput      *bedrockagentcorecontrol.ListAgentRuntimesOutput
	listErr         error
	detailOutput    *bedrockagentcorecontrol.GetAgentRuntimeOutput
	detailErr       error
	endpointsOutput *bedrockagentcorecontrol.ListAgentRuntimeEndpointsOutput
	endpointsErr    error
	onGetRuntime    func()
	onListEndpoints func()
}

func (f *fakeAgentCoreRuntimeSDKClient) ListAgentRuntimes(_ context.Context, _ *bedrockagentcorecontrol.ListAgentRuntimesInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listOutput == nil {
		return &bedrockagentcorecontrol.ListAgentRuntimesOutput{}, nil
	}
	return f.listOutput, nil
}

func (f *fakeAgentCoreRuntimeSDKClient) GetAgentRuntime(_ context.Context, _ *bedrockagentcorecontrol.GetAgentRuntimeInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	if f.onGetRuntime != nil {
		f.onGetRuntime()
	}
	if f.detailErr != nil {
		return nil, f.detailErr
	}
	if f.detailOutput == nil {
		return &bedrockagentcorecontrol.GetAgentRuntimeOutput{}, nil
	}
	return f.detailOutput, nil
}

func (f *fakeAgentCoreRuntimeSDKClient) ListAgentRuntimeEndpoints(_ context.Context, _ *bedrockagentcorecontrol.ListAgentRuntimeEndpointsInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimeEndpointsOutput, error) {
	if f.onListEndpoints != nil {
		f.onListEndpoints()
	}
	if f.endpointsErr != nil {
		return nil, f.endpointsErr
	}
	if f.endpointsOutput == nil {
		return &bedrockagentcorecontrol.ListAgentRuntimeEndpointsOutput{}, nil
	}
	return f.endpointsOutput, nil
}

func TestSDKAgentCoreRuntimeAPIIncludesAccountRegionAndObservedCapabilities(t *testing.T) {
	client := &fakeAgentCoreRuntimeSDKClient{
		listOutput: &bedrockagentcorecontrol.ListAgentRuntimesOutput{
			AgentRuntimes: []agentcoretypes.AgentRuntime{{
				AgentRuntimeId:      awsv2.String("runtime-1"),
				AgentRuntimeArn:     awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1"),
				AgentRuntimeName:    awsv2.String("runtime-1"),
				AgentRuntimeVersion: awsv2.String("2026-06-01"),
				Status:              agentcoretypes.AgentRuntimeStatusReady,
			}},
		},
		detailOutput: &bedrockagentcorecontrol.GetAgentRuntimeOutput{
			AgentRuntimeArn:     awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1"),
			AgentRuntimeVersion: awsv2.String("2026-06-01"),
			RoleArn:             awsv2.String("arn:aws:iam::123456789012:role/agentcore-runtime"),
			Status:              agentcoretypes.AgentRuntimeStatusReady,
			WorkloadIdentityDetails: &agentcoretypes.WorkloadIdentityDetails{
				WorkloadIdentityArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:workload-identity/runtime-1"),
			},
			NetworkConfiguration:  &agentcoretypes.NetworkConfiguration{NetworkMode: agentcoretypes.NetworkModeVpc},
			ProtocolConfiguration: &agentcoretypes.ProtocolConfiguration{ServerProtocol: agentcoretypes.ServerProtocolHttp},
		},
		endpointsOutput: &bedrockagentcorecontrol.ListAgentRuntimeEndpointsOutput{
			RuntimeEndpoints: []agentcoretypes.AgentRuntimeEndpoint{{
				AgentRuntimeEndpointArn: awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/runtime-1/blue"),
				Name:                    awsv2.String("blue"),
				Status:                  agentcoretypes.AgentRuntimeEndpointStatusReady,
			}},
		},
	}

	page, err := NewSDKAgentCoreRuntimeAPIFromClient(client, "123456789012", "us-east-1").ListAgentIdentities(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected one runtime record, got %+v", page.Records)
	}
	record := page.Records[0]
	if record.AccountID != "123456789012" || record.Region != "us-east-1" {
		t.Fatalf("expected account/region context on runtime record, got %+v", record)
	}
	if got := record.CapabilityNames; len(got) != 3 || got[0] != "runtime" || got[1] != "workload_identity" || got[2] != "execution_endpoint" {
		t.Fatalf("expected observed runtime capabilities, got %+v", got)
	}
}

func TestSDKAgentCoreRuntimeAPIDoesNotReportMissingCapabilities(t *testing.T) {
	client := &fakeAgentCoreRuntimeSDKClient{
		listOutput: &bedrockagentcorecontrol.ListAgentRuntimesOutput{
			AgentRuntimes: []agentcoretypes.AgentRuntime{{
				AgentRuntimeId:      awsv2.String("runtime-1"),
				AgentRuntimeArn:     awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1"),
				AgentRuntimeName:    awsv2.String("runtime-1"),
				AgentRuntimeVersion: awsv2.String("2026-06-01"),
				Status:              agentcoretypes.AgentRuntimeStatusReady,
			}},
		},
		detailOutput: &bedrockagentcorecontrol.GetAgentRuntimeOutput{
			AgentRuntimeArn:     awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1"),
			AgentRuntimeVersion: awsv2.String("2026-06-01"),
			RoleArn:             awsv2.String("arn:aws:iam::123456789012:role/agentcore-runtime"),
			Status:              agentcoretypes.AgentRuntimeStatusReady,
		},
		endpointsOutput: &bedrockagentcorecontrol.ListAgentRuntimeEndpointsOutput{},
	}

	page, err := NewSDKAgentCoreRuntimeAPIFromClient(client, "123456789012", "us-east-1").ListAgentIdentities(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListAgentIdentities: %v", err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("expected one runtime record, got %+v", page.Records)
	}
	if got := page.Records[0].CapabilityNames; len(got) != 1 || got[0] != "runtime" {
		t.Fatalf("expected only runtime capability when metadata is absent, got %+v", got)
	}
}

func TestSDKAgentCoreRuntimeAPIPropagatesContextCancellation(t *testing.T) {
	baseList := &bedrockagentcorecontrol.ListAgentRuntimesOutput{
		AgentRuntimes: []agentcoretypes.AgentRuntime{{
			AgentRuntimeId:      awsv2.String("runtime-1"),
			AgentRuntimeArn:     awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1"),
			AgentRuntimeName:    awsv2.String("runtime-1"),
			AgentRuntimeVersion: awsv2.String("2026-06-01"),
			Status:              agentcoretypes.AgentRuntimeStatusReady,
		}},
	}

	t.Run("describe runtime", func(t *testing.T) {
		client := &fakeAgentCoreRuntimeSDKClient{
			listOutput:   baseList,
			detailErr:    context.Canceled,
			onGetRuntime: func() {},
		}
		_, err := NewSDKAgentCoreRuntimeAPIFromClient(client, "123456789012", "us-east-1").ListAgentIdentities(context.Background(), "", 10)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation from describe, got %v", err)
		}
	})

	t.Run("list endpoints", func(t *testing.T) {
		client := &fakeAgentCoreRuntimeSDKClient{
			listOutput: baseList,
			detailOutput: &bedrockagentcorecontrol.GetAgentRuntimeOutput{
				AgentRuntimeArn:     awsv2.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/runtime-1"),
				AgentRuntimeVersion: awsv2.String("2026-06-01"),
				RoleArn:             awsv2.String("arn:aws:iam::123456789012:role/agentcore-runtime"),
				Status:              agentcoretypes.AgentRuntimeStatusReady,
			},
			endpointsErr: context.Canceled,
		}
		_, err := NewSDKAgentCoreRuntimeAPIFromClient(client, "123456789012", "us-east-1").ListAgentIdentities(context.Background(), "", 10)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation from endpoint listing, got %v", err)
		}
	})
}
