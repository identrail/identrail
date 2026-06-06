package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	codepipelinetypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
	"github.com/identrail/identrail/internal/textutil"
)

// CodePipelineSDKClient defines the CodePipeline SDK calls required by the deployment-role adapter.
type CodePipelineSDKClient interface {
	ListPipelines(ctx context.Context, params *codepipeline.ListPipelinesInput, optFns ...func(*codepipeline.Options)) (*codepipeline.ListPipelinesOutput, error)
	GetPipeline(ctx context.Context, params *codepipeline.GetPipelineInput, optFns ...func(*codepipeline.Options)) (*codepipeline.GetPipelineOutput, error)
	GetPipelineState(ctx context.Context, params *codepipeline.GetPipelineStateInput, optFns ...func(*codepipeline.Options)) (*codepipeline.GetPipelineStateOutput, error)
}

// SDKCodePipelineDeploymentRoleAPI adapts AWS SDK CodePipeline calls to CodePipelineDeploymentRoleAPI.
type SDKCodePipelineDeploymentRoleAPI struct {
	codePipelineClient CodePipelineSDKClient
	accountID          string
	region             string
}

var _ CodePipelineDeploymentRoleAPI = (*SDKCodePipelineDeploymentRoleAPI)(nil)

// NewSDKCodePipelineDeploymentRoleAPI constructs a CodePipeline deployment-role API backed by the AWS SDK default credential chain.
func NewSDKCodePipelineDeploymentRoleAPI(region string, profile string, accountID string) (CodePipelineDeploymentRoleAPI, error) {
	return NewSDKCodePipelineDeploymentRoleAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKCodePipelineDeploymentRoleAPIWithContext constructs a CodePipeline deployment-role API using caller-provided context for config loading.
func NewSDKCodePipelineDeploymentRoleAPIWithContext(ctx context.Context, region string, profile string, accountID string) (CodePipelineDeploymentRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	return NewSDKCodePipelineDeploymentRoleAPIFromClient(codepipeline.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKCodePipelineDeploymentRoleAPIFromAssumeRole constructs a CodePipeline deployment-role API for an onboarded connector role.
func NewSDKCodePipelineDeploymentRoleAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (CodePipelineDeploymentRoleAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, fmt.Errorf("aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = textutil.FirstNonEmpty(strings.TrimSpace(sessionName), "identrail-recurring-scan")
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	return NewSDKCodePipelineDeploymentRoleAPIFromClient(codepipeline.NewFromConfig(cfg), accountID, region), nil
}

// NewSDKCodePipelineDeploymentRoleAPIFromClient creates a CodePipelineDeploymentRoleAPI from a provided CodePipeline client.
func NewSDKCodePipelineDeploymentRoleAPIFromClient(codePipelineClient CodePipelineSDKClient, accountID string, region string) CodePipelineDeploymentRoleAPI {
	return &SDKCodePipelineDeploymentRoleAPI{
		codePipelineClient: codePipelineClient,
		accountID:          strings.TrimSpace(accountID),
		region:             strings.TrimSpace(region),
	}
}

// ListServiceRoles returns one CodePipeline list page resolved to deployment-role metadata.
func (a *SDKCodePipelineDeploymentRoleAPI) ListServiceRoles(ctx context.Context, nextToken string, pageSize int32) (CodePipelineDeploymentRolePage, error) {
	if a.codePipelineClient == nil {
		return CodePipelineDeploymentRolePage{}, fmt.Errorf("codepipeline sdk client is required")
	}
	input := &codepipeline.ListPipelinesInput{
		MaxResults: awsv2.Int32(pageSize),
	}
	if token := strings.TrimSpace(nextToken); token != "" {
		input.NextToken = awsv2.String(token)
	}
	output, err := a.codePipelineClient.ListPipelines(ctx, input)
	if err != nil {
		return CodePipelineDeploymentRolePage{}, err
	}
	if output == nil || len(output.Pipelines) == 0 {
		return CodePipelineDeploymentRolePage{NextToken: nextTokenFromCodePipelineListPipelines(output)}, nil
	}

	records := []CodePipelineDeploymentRole{}
	diagnostics := []providers.SourceError{}
	for _, summary := range output.Pipelines {
		if err := ctx.Err(); err != nil {
			return CodePipelineDeploymentRolePage{}, err
		}
		pipelineName := strings.TrimSpace(awsv2.ToString(summary.Name))
		if pipelineName == "" {
			diagnostics = append(diagnostics, codePipelineSourceDiagnostic("missing_pipeline_name", "listpipelines", "CodePipeline list response included a pipeline without a name", false))
			continue
		}
		pipelineOutput, err := a.codePipelineClient.GetPipeline(ctx, &codepipeline.GetPipelineInput{Name: awsv2.String(pipelineName)})
		if err != nil {
			diagnostics = append(diagnostics, codePipelineSourceDiagnostic("pipeline_get_failed", pipelineName, fmt.Sprintf("CodePipeline pipeline %s could not be described: %v", pipelineName, err), true))
			continue
		}
		if pipelineOutput == nil || pipelineOutput.Pipeline == nil {
			diagnostics = append(diagnostics, codePipelineSourceDiagnostic("pipeline_not_found", pipelineName, "CodePipeline pipeline listed by ListPipelines was not returned by GetPipeline", true))
			continue
		}
		stateOutput, err := a.codePipelineClient.GetPipelineState(ctx, &codepipeline.GetPipelineStateInput{Name: awsv2.String(pipelineName)})
		if err != nil {
			diagnostics = append(diagnostics, codePipelineSourceDiagnostic("pipeline_state_get_failed", pipelineName, fmt.Sprintf("CodePipeline state for pipeline %s could not be described: %v", pipelineName, err), true))
		}
		records = append(records, a.recordsFromPipeline(*pipelineOutput.Pipeline, pipelineOutput.Metadata, stateOutput)...)
	}

	sort.SliceStable(records, func(i, j int) bool {
		return codePipelineDeploymentRoleSourceID(records[i]) < codePipelineDeploymentRoleSourceID(records[j])
	})
	return CodePipelineDeploymentRolePage{Records: records, NextToken: nextTokenFromCodePipelineListPipelines(output), Diagnostics: diagnostics}, nil
}

func (a *SDKCodePipelineDeploymentRoleAPI) recordsFromPipeline(pipeline codepipelinetypes.PipelineDeclaration, metadata *codepipelinetypes.PipelineMetadata, state *codepipeline.GetPipelineStateOutput) []CodePipelineDeploymentRole {
	pipelineName := strings.TrimSpace(awsv2.ToString(pipeline.Name))
	pipelineARN := strings.TrimSpace("")
	if metadata != nil {
		pipelineARN = strings.TrimSpace(awsv2.ToString(metadata.PipelineArn))
	}
	if pipelineARN == "" && pipelineName != "" && a.region != "" && a.accountID != "" {
		pipelineARN = fmt.Sprintf("arn:aws:codepipeline:%s:%s:%s", a.region, a.accountID, pipelineName)
	}
	disabledTransitions := codePipelineDisabledStageTransitions(state)
	storeTypes, storeLocations, storeRegions, kmsKeys := codePipelineArtifactStores(pipeline)
	base := CodePipelineDeploymentRole{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID:     a.accountID,
			Region:        a.region,
			Service:       codePipelineServiceName,
			WorkloadID:    firstNonEmptyAWSValue(pipelineARN, pipelineName),
			WorkloadType:  "codepipeline_pipeline",
			WorkloadName:  firstNonEmptyAWSValue(pipelineName, codePipelineNameFromARN(pipelineARN)),
			RoleARN:       strings.TrimSpace(awsv2.ToString(pipeline.RoleArn)),
			Source:        "getpipeline",
			EvidenceRef:   firstNonEmptyAWSValue(pipelineARN, pipelineName),
			Confidence:    0.96,
			CollectorName: codePipelineDeploymentRoleCollectorName,
		},
		RoleName:                  roleNameFromARN(awsv2.ToString(pipeline.RoleArn)),
		RoleKind:                  "pipeline_service_role",
		PipelineARN:               pipelineARN,
		PipelineName:              pipelineName,
		PipelineVersion:           awsv2.ToInt32(pipeline.Version),
		PipelineType:              string(pipeline.PipelineType),
		ExecutionMode:             string(pipeline.ExecutionMode),
		ArtifactStoreTypes:        storeTypes,
		ArtifactStoreLocations:    storeLocations,
		ArtifactStoreRegions:      storeRegions,
		ArtifactKMSKeyARNs:        kmsKeys,
		DisabledStageTransitions:  disabledTransitions,
		CrossRegionArtifactStores: len(storeRegions) > 1,
		PassRoleAdjacent:          true,
	}
	base.Confidence = codePipelineDeploymentRoleConfidence(base)

	records := []CodePipelineDeploymentRole{base}
	for _, stage := range pipeline.Stages {
		stageName := strings.TrimSpace(awsv2.ToString(stage.Name))
		for _, action := range stage.Actions {
			roleARN := strings.TrimSpace(awsv2.ToString(action.RoleArn))
			if roleARN == "" {
				continue
			}
			roleAccountID := roleAccountIDFromARN(roleARN)
			record := base
			record.RoleARN = roleARN
			record.RoleName = roleNameFromARN(roleARN)
			record.RoleAccountID = roleAccountID
			record.RoleKind = "action_role"
			record.DisabledStageTransitions = nil
			record.StageName = stageName
			record.ActionName = strings.TrimSpace(awsv2.ToString(action.Name))
			record.ActionRegion = strings.TrimSpace(awsv2.ToString(action.Region))
			record.RunOrder = awsv2.ToInt32(action.RunOrder)
			record.Namespace = strings.TrimSpace(awsv2.ToString(action.Namespace))
			if action.ActionTypeId != nil {
				record.ActionCategory = string(action.ActionTypeId.Category)
				record.ActionOwner = string(action.ActionTypeId.Owner)
				record.ActionProvider = strings.TrimSpace(awsv2.ToString(action.ActionTypeId.Provider))
				record.ActionVersion = strings.TrimSpace(awsv2.ToString(action.ActionTypeId.Version))
			}
			record.InputArtifactNames = codePipelineInputArtifactNames(action.InputArtifacts)
			record.OutputArtifactNames = codePipelineOutputArtifactNames(action.OutputArtifacts)
			record.ConfigurationKeys = codePipelineConfigurationKeys(action.Configuration)
			record.ProviderIdentifiers = codePipelineProviderIdentifiers(record)
			record.CrossRegionAction = record.ActionRegion != "" && !strings.EqualFold(record.ActionRegion, a.region)
			record.CrossAccountRole = roleAccountID != "" && a.accountID != "" && roleAccountID != a.accountID
			record.WorkloadID = codePipelineDeploymentRoleWorkloadRef(record)
			record.WorkloadType = "codepipeline_action"
			record.WorkloadName = codePipelineDeploymentRoleWorkloadName(record)
			record.EvidenceRef = firstNonEmptyAWSValue(pipelineARN, pipelineName) + "#stage/" + stageName + "/action/" + record.ActionName
			record.Confidence = codePipelineDeploymentRoleConfidence(record)
			records = append(records, record)
		}
	}
	return records
}

func nextTokenFromCodePipelineListPipelines(output *codepipeline.ListPipelinesOutput) string {
	if output == nil {
		return ""
	}
	return strings.TrimSpace(awsv2.ToString(output.NextToken))
}

func codePipelineSourceDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: codePipelineDeploymentRoleCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      code,
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func codePipelineArtifactStores(pipeline codepipelinetypes.PipelineDeclaration) ([]string, []string, []string, []string) {
	types := []string{}
	locations := []string{}
	regions := []string{}
	kmsKeys := []string{}
	addStore := func(region string, store codepipelinetypes.ArtifactStore) {
		if store.Type != "" {
			types = append(types, string(store.Type))
		}
		if location := strings.TrimSpace(awsv2.ToString(store.Location)); location != "" {
			locations = append(locations, location)
		}
		if trimmedRegion := strings.TrimSpace(region); trimmedRegion != "" {
			regions = append(regions, trimmedRegion)
		}
		if store.EncryptionKey != nil {
			if keyID := strings.TrimSpace(awsv2.ToString(store.EncryptionKey.Id)); keyID != "" {
				kmsKeys = append(kmsKeys, keyID)
			}
		}
	}
	if pipeline.ArtifactStore != nil {
		addStore("", *pipeline.ArtifactStore)
	}
	storeRegions := make([]string, 0, len(pipeline.ArtifactStores))
	for region := range pipeline.ArtifactStores {
		storeRegions = append(storeRegions, region)
	}
	sort.Strings(storeRegions)
	for _, region := range storeRegions {
		store := pipeline.ArtifactStores[region]
		addStore(region, store)
	}
	return normalizeStringList(types), normalizeStringList(locations), normalizeStringList(regions), normalizeStringList(kmsKeys)
}

func codePipelineDisabledStageTransitions(state *codepipeline.GetPipelineStateOutput) []string {
	if state == nil {
		return nil
	}
	result := []string{}
	for _, stage := range state.StageStates {
		if stage.InboundTransitionState == nil || stage.InboundTransitionState.Enabled {
			continue
		}
		name := strings.TrimSpace(awsv2.ToString(stage.StageName))
		reason := strings.TrimSpace(awsv2.ToString(stage.InboundTransitionState.DisabledReason))
		if reason != "" {
			result = append(result, name+": "+reason)
		} else {
			result = append(result, name)
		}
	}
	return normalizeStringList(result)
}

func codePipelineInputArtifactNames(artifacts []codepipelinetypes.InputArtifact) []string {
	result := []string{}
	for _, artifact := range artifacts {
		result = append(result, awsv2.ToString(artifact.Name))
	}
	return normalizeStringList(result)
}

func codePipelineOutputArtifactNames(artifacts []codepipelinetypes.OutputArtifact) []string {
	result := []string{}
	for _, artifact := range artifacts {
		result = append(result, awsv2.ToString(artifact.Name))
	}
	return normalizeStringList(result)
}

func codePipelineConfigurationKeys(config map[string]string) []string {
	result := make([]string, 0, len(config))
	for key := range config {
		result = append(result, key)
	}
	sort.Strings(result)
	return normalizeStringList(result)
}

func codePipelineProviderIdentifiers(record CodePipelineDeploymentRole) []string {
	return normalizeStringList([]string{
		record.ActionCategory,
		record.ActionOwner,
		record.ActionProvider,
		strings.Join(normalizeStringList([]string{record.ActionCategory, record.ActionOwner, record.ActionProvider, record.ActionVersion}), "/"),
	})
}

func roleAccountIDFromARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
