package aws

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

func TestCustomAgentDetectorFindsAWSWorkloadSignals(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	role := "arn:aws:iam::123456789012:role/custom-agent-runtime"
	raw := []providers.RawAsset{
		rawAsset(t, rawKindECSTaskRole, "ecs", ECSTaskRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "ecs", RoleARN: role, WorkloadID: "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant", WorkloadName: "support-assistant", WorkloadType: "ecs_service", CollectedAt: now},
			RoleKind:               ecsRoleKindTask,
			ServiceARN:             "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant",
			ServiceName:            "support-assistant",
			ContainerImages:        []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/langchain-agent:prod"},
			EnvironmentKeys:        []string{"OPENAI_API_KEY"},
		}),
		rawAsset(t, rawKindLambdaExecutionRole, "lambda", LambdaExecutionRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "lambda", RoleARN: role, WorkloadID: "arn:aws:lambda:us-east-1:123456789012:function:invoice-agent", WorkloadName: "invoice-agent", WorkloadType: "lambda_function", CollectedAt: now},
			FunctionARN:            "arn:aws:lambda:us-east-1:123456789012:function:invoice-agent",
			FunctionName:           "invoice-agent",
			Runtime:                "python3.13",
			Handler:                "agent.handler",
			EnvironmentKeys:        []string{"ANTHROPIC_API_KEY"},
		}),
		rawAsset(t, rawKindCodeBuildServiceRole, "codebuild", CodeBuildServiceRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "codebuild", RoleARN: role, WorkloadID: "arn:aws:codebuild:us-east-1:123456789012:project/agent-eval-builder", WorkloadName: "agent-eval-builder", WorkloadType: "codebuild_project", CollectedAt: now},
			ProjectARN:             "arn:aws:codebuild:us-east-1:123456789012:project/agent-eval-builder",
			ProjectName:            "agent-eval-builder",
			Image:                  "aws/codebuild/standard:llm-agent",
			EnvironmentKeys:        []string{"BEDROCK_API_KEY"},
		}),
		rawAsset(t, rawKindEKSWorkloadIdentity, "eks", EKSWorkloadIdentity{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "eks", RoleARN: role, WorkloadID: "system:serviceaccount:ai:research-agent", WorkloadName: "research-agent", WorkloadType: "eks_workload", CollectedAt: now},
			RoleKind:               eksRoleKindIRSA,
			ClusterName:            "prod",
			Namespace:              "ai",
			ServiceAccount:         "research-agent",
			KubernetesSubject:      "system:serviceaccount:ai:research-agent",
			Tags:                   map[string]string{"app": "ai-agent"},
		}),
		rawAsset(t, rawKindEC2InstanceProfile, "ec2", EC2InstanceProfile{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "ec2", RoleARN: role, WorkloadID: "i-1234567890abcdef0", WorkloadName: "langchain-agent-runner", WorkloadType: "ec2_instance", CollectedAt: now},
			InstanceID:             "i-1234567890abcdef0",
			InstanceName:           "langchain-agent-runner",
			Tags:                   map[string]string{"workload": "ai-agent"},
		}),
		rawAsset(t, rawKindSageMakerWorkloadRole, "sagemaker", SageMakerWorkloadRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "sagemaker", RoleARN: role, WorkloadID: "arn:aws:sagemaker:us-east-1:123456789012:model/customer-llm-agent", WorkloadName: "customer-llm-agent", WorkloadType: "sagemaker_workload", CollectedAt: now},
			WorkloadARN:            "arn:aws:sagemaker:us-east-1:123456789012:model/customer-llm-agent",
			ResourceType:           "model",
			ImageURIs:              []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/llm-agent:prod"},
		}),
		rawAsset(t, rawKindStepFunctionsStateMachineRole, "stepfunctions", StepFunctionsStateMachineRole{
			ServiceCollectorRecord:      awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "stepfunctions", RoleARN: role, WorkloadID: "arn:aws:states:us-east-1:123456789012:stateMachine:bedrock-agent-orchestrator", WorkloadName: "bedrock-agent-orchestrator", WorkloadType: "stepfunctions_state_machine", CollectedAt: now},
			StateMachineARN:             "arn:aws:states:us-east-1:123456789012:stateMachine:bedrock-agent-orchestrator",
			StateMachineName:            "bedrock-agent-orchestrator",
			ServiceIntegrationResources: []string{"arn:aws:states:::bedrock:invokeModel"},
		}),
	}

	derived := deriveCustomAIAgentIdentityAssets(raw)
	if len(derived) != 7 {
		t.Fatalf("expected seven custom agent detections, got %d: %+v", len(derived), derived)
	}

	services := map[string]AIAgentIdentity{}
	for _, asset := range derived {
		var record AIAgentIdentity
		if err := json.Unmarshal(asset.Payload, &record); err != nil {
			t.Fatalf("decode derived ai agent: %v", err)
		}
		services[record.Service] = record
		if record.AgentType != "custom_agent" || record.AgentID == "" || record.RuntimeRoleARN == "" {
			t.Fatalf("derived record missing custom identity fields: %+v", record)
		}
		if record.Tags["detector"] != customAgentDetectorVersion {
			t.Fatalf("expected detector tag on %+v", record)
		}
		if record.SensitiveBoundary != "metadata_only" {
			t.Fatalf("expected metadata-only boundary, got %+v", record)
		}
	}
	for _, service := range []string{"ecs", "lambda", "codebuild", "eks", "ec2", "sagemaker", "stepfunctions"} {
		if _, ok := services[service]; !ok {
			t.Fatalf("missing custom agent detection for service %q in %+v", service, services)
		}
	}
	if !containsString(services["ecs"].CredentialReferenceRefs, "OPENAI_API_KEY") {
		t.Fatalf("expected ECS provider key ref, got %+v", services["ecs"].CredentialReferenceRefs)
	}
	if services["eks"].Status != "candidate" {
		t.Fatalf("expected weak EKS metadata-only signal to stay candidate, got %+v", services["eks"])
	}
}

func TestCustomAgentDetectorSkipsGenericCredentialWorkload(t *testing.T) {
	raw := []providers.RawAsset{
		rawAsset(t, rawKindLambdaExecutionRole, "lambda-generic", LambdaExecutionRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "lambda", RoleARN: "arn:aws:iam::123456789012:role/payments-api", WorkloadID: "arn:aws:lambda:us-east-1:123456789012:function:payments-api", WorkloadName: "payments-api", WorkloadType: "lambda_function"},
			FunctionARN:            "arn:aws:lambda:us-east-1:123456789012:function:payments-api",
			FunctionName:           "payments-api",
			EnvironmentKeys:        []string{"DATABASE_URL"},
		}),
	}
	if derived := deriveCustomAIAgentIdentityAssets(raw); len(derived) != 0 {
		t.Fatalf("expected no generic workload detection, got %+v", derived)
	}
}

func TestRoleNormalizerDerivesCustomAgentCredentialGraph(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/support-agent-task"
	raw := []providers.RawAsset{
		rawAsset(t, rawKindECSTaskRole, "ecs-agent", ECSTaskRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "ecs", RoleARN: role, WorkloadID: "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant", WorkloadName: "support-assistant", WorkloadType: "ecs_service"},
			RoleKind:               ecsRoleKindTask,
			ServiceARN:             "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant",
			ServiceName:            "support-assistant",
			EnvironmentKeys:        []string{"OPENAI_API_KEY"},
		}),
	}

	bundle, err := NewRoleNormalizer().Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize custom agent workload: %v", err)
	}
	if len(bundle.Agents) != 1 {
		t.Fatalf("expected one derived custom agent, got %+v", bundle.Agents)
	}
	agent := bundle.Agents[0]
	if agent.Type != domain.AgentTypeAI || agent.Metadata["agent_type"] != "custom_agent" {
		t.Fatalf("expected custom ai agent, got %+v", agent)
	}
	refs, _ := MapBundleCredentialReferences(bundle)
	ref, ok := findCredentialReference(refs, "OPENAI_API_KEY")
	if !ok {
		t.Fatalf("expected mapped provider key reference, got %+v", refs)
	}
	if ref.WorkloadID != agent.ID || ref.TargetNodeID == "" {
		t.Fatalf("expected credential ref anchored to agent %q, got %+v", agent.ID, ref)
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("resolve relationships: %v", err)
	}
	foundRunsAs := false
	foundUsesSecret := false
	for _, relationship := range relationships {
		if relationship.Type == domain.RelationshipRunsAs && relationship.FromNodeID == agent.ID {
			foundRunsAs = true
		}
		if relationship.Type == domain.RelationshipUsesSecret && relationship.FromNodeID == agent.ID && relationship.ToNodeID == ref.TargetNodeID {
			foundUsesSecret = true
		}
	}
	if !foundRunsAs || !foundUsesSecret {
		t.Fatalf("expected runs_as and uses_secret for derived agent, got %+v", relationships)
	}
}

func TestCustomAgentAISignalUsesWordBoundariesForShortTokens(t *testing.T) {
	// Short, ambiguous tokens must only match at word boundaries so they do not
	// fire on unrelated substrings.
	for _, value := range []string{"storage-service", "fragment-cache", "gptable-store", "allment", "rage"} {
		if customAgentAISignal(value) {
			t.Fatalf("expected no AI signal for %q", value)
		}
	}
	// Delimited short tokens and distinctive vendor substrings must still match.
	for _, value := range []string{"rag-pipeline", "team_llm", "gpt.runner", "openai-proxy", "vector-index"} {
		if !customAgentAISignal(value) {
			t.Fatalf("expected AI signal for %q", value)
		}
	}
}

func TestCustomAgentProviderRefsDedupesSecretBackedEnvKeys(t *testing.T) {
	// A CodeBuild project records OPENAI_API_KEY both as a sourced secret ref and
	// as a bare environment key. The bare key must be suppressed so the downstream
	// mapper does not emit a spurious unresolved provider-key node alongside the
	// resolved secret reference.
	evidence := customAgentWorkloadEvidence{
		EnvironmentKeys: []string{"OPENAI_API_KEY"},
		SecretRefs:      []string{"OPENAI_API_KEY=PARAMETER_STORE:arn:aws:ssm:us-east-1:123456789012:parameter/openai"},
	}
	refs, providers := customAgentProviderCredentialRefs(evidence)
	if len(refs) != 1 {
		t.Fatalf("expected single deduped provider ref, got %+v", refs)
	}
	if _, source := splitCredentialReference(refs[0]); source == "" {
		t.Fatalf("expected the sourced secret ref to win, got bare key %q", refs[0])
	}
	if len(providers) != 1 || providers[0] != "openai" {
		t.Fatalf("expected single openai provider, got %+v", providers)
	}
}

func TestCustomAgentCredentialReferenceCarriesAgentWorkloadType(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/support-agent-task"
	raw := []providers.RawAsset{
		rawAsset(t, rawKindECSTaskRole, "ecs-agent", ECSTaskRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "ecs", RoleARN: role, WorkloadID: "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant", WorkloadName: "support-assistant", WorkloadType: "ecs_service"},
			RoleKind:               ecsRoleKindTask,
			ServiceARN:             "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant",
			ServiceName:            "support-assistant",
			EnvironmentKeys:        []string{"OPENAI_API_KEY"},
		}),
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize custom agent workload: %v", err)
	}
	if len(bundle.Agents) != 1 {
		t.Fatalf("expected one derived custom agent, got %+v", bundle.Agents)
	}
	agent := bundle.Agents[0]
	refs, _ := MapBundleCredentialReferences(bundle)
	ref, ok := findCredentialReference(refs, "OPENAI_API_KEY")
	if !ok {
		t.Fatalf("expected mapped provider key reference, got %+v", refs)
	}
	if ref.WorkloadType != string(agent.Type) {
		t.Fatalf("expected credential ref workload_type %q, got %q", string(agent.Type), ref.WorkloadType)
	}
}

func TestCustomAgentNormalizationPreservesWorkloadRoleIdentity(t *testing.T) {
	// The agent's runtime role is only present as an ECS asset (never as a
	// standalone iam_role asset). The richer workload-role identity (with tags) must
	// survive AI-agent normalization rather than be shadowed by the agent's minimal
	// runtime-role identity.
	role := "arn:aws:iam::123456789012:role/support-agent-task"
	raw := []providers.RawAsset{
		rawAsset(t, rawKindECSTaskRole, "ecs-agent", ECSTaskRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "ecs", RoleARN: role, WorkloadID: "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant", WorkloadName: "support-assistant", WorkloadType: "ecs_service"},
			RoleKind:               ecsRoleKindTask,
			ServiceARN:             "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant",
			ServiceName:            "support-assistant",
			EnvironmentKeys:        []string{"OPENAI_API_KEY"},
			Tags:                   map[string]string{"team": "support", "workload": "ai-agent"},
		}),
	}
	bundle, err := NewRoleNormalizer().Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize custom agent workload: %v", err)
	}
	var identity *domain.Identity
	for i := range bundle.Identities {
		if bundle.Identities[i].ARN == role {
			identity = &bundle.Identities[i]
			break
		}
	}
	if identity == nil {
		t.Fatalf("expected runtime-role identity for %q, got %+v", role, bundle.Identities)
	}
	if identity.Tags["team"] != "support" || identity.Tags["workload"] != "ai-agent" {
		t.Fatalf("expected workload-role tags to win over agent runtime identity, got %+v", identity.Tags)
	}
}

func TestCustomAgentDetectorPrefersECSTaskRoleOverExecutionRole(t *testing.T) {
	// The ECS SDK adapter sorts assets so the execution-role record is visited
	// before the task-role record for the same service. De-duplication must still
	// attribute the agent to the task role (what the container code runs as) rather
	// than the execution role (used only for image/secret retrieval).
	taskRole := "arn:aws:iam::123456789012:role/support-assistant-task"
	executionRole := "arn:aws:iam::123456789012:role/support-assistant-exec"
	service := "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant"
	base := func(roleKind, roleARN string) ECSTaskRole {
		return ECSTaskRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "ecs", RoleARN: roleARN, WorkloadID: service, WorkloadName: "support-assistant", WorkloadType: "ecs_service"},
			RoleKind:               roleKind,
			ServiceARN:             service,
			ServiceName:            "support-assistant",
			ContainerImages:        []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/langchain-agent:prod"},
			EnvironmentKeys:        []string{"OPENAI_API_KEY"},
		}
	}
	// Execution role first, then task role — matching the SDK adapter ordering.
	raw := []providers.RawAsset{
		rawAsset(t, rawKindECSTaskRole, "ecs-exec", base(ecsRoleKindExecution, executionRole)),
		rawAsset(t, rawKindECSTaskRole, "ecs-task", base(ecsRoleKindTask, taskRole)),
	}
	derived := deriveCustomAIAgentIdentityAssets(raw)
	if len(derived) != 1 {
		t.Fatalf("expected one deduped detection, got %d: %+v", len(derived), derived)
	}
	var record AIAgentIdentity
	if err := json.Unmarshal(derived[0].Payload, &record); err != nil {
		t.Fatalf("decode derived ai agent: %v", err)
	}
	if record.RuntimeRoleARN != taskRole {
		t.Fatalf("expected agent to run as task role %q, got %q", taskRole, record.RuntimeRoleARN)
	}
}

func TestCustomAgentDetectorSkipsECSExecutionRoleOnly(t *testing.T) {
	executionRole := "arn:aws:iam::123456789012:role/support-assistant-exec"
	raw := []providers.RawAsset{
		rawAsset(t, rawKindECSTaskRole, "ecs-exec", ECSTaskRole{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "ecs", RoleARN: executionRole, WorkloadID: "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant", WorkloadName: "support-assistant", WorkloadType: "ecs_service"},
			RoleKind:               ecsRoleKindExecution,
			ServiceARN:             "arn:aws:ecs:us-east-1:123456789012:service/prod/support-assistant",
			ServiceName:            "support-assistant",
			ContainerImages:        []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/langchain-agent:prod"},
			EnvironmentKeys:        []string{"OPENAI_API_KEY"},
		}),
	}
	if derived := deriveCustomAIAgentIdentityAssets(raw); len(derived) != 0 {
		t.Fatalf("expected execution-role-only ECS evidence to be skipped, got %+v", derived)
	}
}

func TestCustomAgentDetectorSkipsEKSFargatePodExecutionRole(t *testing.T) {
	podExecutionRole := "arn:aws:iam::123456789012:role/prod-fargate-pod-exec"
	raw := []providers.RawAsset{
		rawAsset(t, rawKindEKSWorkloadIdentity, "eks-fargate", EKSWorkloadIdentity{
			ServiceCollectorRecord: awscontract.ServiceCollectorRecord{AccountID: "123456789012", Region: "us-east-1", Service: "eks", RoleARN: podExecutionRole, WorkloadID: "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod/ai-agents", WorkloadName: "ai-agents", WorkloadType: "eks_fargate_pod_execution_role"},
			RoleKind:               eksRoleKindFargatePodExecution,
			ClusterName:            "prod",
			FargateProfileARN:      "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod/ai-agents",
			FargateProfileName:     "ai-agents",
			PodExecutionRoleARN:    podExecutionRole,
			SelectorLabels:         []string{"workload=ai-agent"},
			Tags:                   map[string]string{"workload": "ai-agent"},
		}),
	}
	if derived := deriveCustomAIAgentIdentityAssets(raw); len(derived) != 0 {
		t.Fatalf("expected EKS Fargate pod execution role evidence to be skipped, got %+v", derived)
	}
}

func rawAsset(t *testing.T, kind string, sourceID string, record any) providers.RawAsset {
	t.Helper()
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal raw asset %s: %v", sourceID, err)
	}
	return providers.RawAsset{Kind: kind, SourceID: sourceID, Payload: payload}
}
