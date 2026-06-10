package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
)

// FixtureOption customizes fixture collector behavior.
type FixtureOption func(*FixtureCollector)

// FixtureCollector reads role payload fixtures and emits raw assets.
type FixtureCollector struct {
	paths []string
	now   func() time.Time
}

var _ providers.Collector = (*FixtureCollector)(nil)

// NewFixtureCollector constructs a fixture-based collector for local deterministic scans.
func NewFixtureCollector(paths []string, opts ...FixtureOption) *FixtureCollector {
	collector := &FixtureCollector{
		paths: append([]string(nil), paths...),
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(collector)
	}
	return collector
}

// WithFixtureClock injects deterministic time for tests.
func WithFixtureClock(now func() time.Time) FixtureOption {
	return func(c *FixtureCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// Collect loads role fixtures from files/directories and converts them to raw assets.
func (c *FixtureCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	if len(c.paths) == 0 {
		return nil, fmt.Errorf("fixture collector requires at least one fixture path")
	}

	expanded, err := expandFixturePaths(c.paths)
	if err != nil {
		return nil, err
	}

	assets := make([]providers.RawAsset, 0, len(expanded))
	seen := map[string]struct{}{}
	collectedAt := c.now().UTC().Format(time.RFC3339Nano)

	for _, path := range expanded {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		payload, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read fixture %s: %w", path, err)
		}

		assetKind, sourceID := fixtureAssetKindAndSourceID(payload)
		if assetKind == "" || sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}

		assets = append(assets, providers.RawAsset{
			Kind:      assetKind,
			SourceID:  sourceID,
			Payload:   payload,
			Collected: collectedAt,
		})
		seen[sourceID] = struct{}{}
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("no valid fixture assets found")
	}

	return assets, nil
}

func fixtureAssetKindAndSourceID(payload []byte) (string, string) {
	var role IAMRole
	if err := json.Unmarshal(payload, &role); err == nil {
		if sourceID := strings.TrimSpace(role.ARN); sourceID != "" {
			return "iam_role", sourceID
		}
	}

	var eksIdentity EKSWorkloadIdentity
	if err := json.Unmarshal(payload, &eksIdentity); err == nil {
		sourceID := eksWorkloadIdentitySourceID(eksIdentity)
		if isEKSWorkloadIdentityFixture(eksIdentity) {
			return rawKindEKSWorkloadIdentity, sourceID
		}
	}

	// SageMaker must be checked before ManagedComputeRole. The latter returns
	// true on any record with a non-empty ResourceARN (because every managed-
	// compute service synthesizes one), so a SageMaker fixture whose
	// ResourceARN is set would otherwise unmarshal into ManagedComputeRole
	// successfully and short-circuit before reaching the SageMaker matcher.
	// The SageMaker matcher itself is strict (sagemaker_* service/collector,
	// sagemaker_* workload type, sagemaker_* role kind, or an ARN whose
	// service segment is literally "sagemaker") so it only claims real
	// SageMaker fixtures.
	var sageMakerRole SageMakerWorkloadRole
	if err := json.Unmarshal(payload, &sageMakerRole); err == nil {
		sourceID := sageMakerWorkloadRoleSourceID(sageMakerRole)
		if isSageMakerWorkloadRoleFixture(sageMakerRole) {
			return rawKindSageMakerWorkloadRole, sourceID
		}
	}

	// IAM PassRole relationships carry a distinctive workload type
	// (iam_passrole_relationship) plus PassRole-specific fields that no other
	// classifier emits, so this matcher is unambiguous and order-insensitive.
	var passRoleRel IAMPassRoleRelationship
	if err := json.Unmarshal(payload, &passRoleRel); err == nil {
		if isIAMPassRoleRelationshipFixture(passRoleRel) {
			return rawKindIAMPassRoleRelationship, iamPassRoleRecordSourceID(passRoleRel)
		}
	}

	// S3 reachability records carry s3 service and s3_bucket workload type.
	var s3Reach S3BucketReachability
	if err := json.Unmarshal(payload, &s3Reach); err == nil {
		if isS3BucketReachabilityFixture(s3Reach) {
			return rawKindS3BucketReachability, s3BucketReachabilitySourceID(s3Reach)
		}
	}

	var managedComputeRole ManagedComputeRole
	if err := json.Unmarshal(payload, &managedComputeRole); err == nil {
		sourceID := managedComputeRoleSourceID(managedComputeRole)
		if isManagedComputeRoleFixture(managedComputeRole) {
			return rawKindManagedComputeRole, sourceID
		}
	}

	var ecsRole ECSTaskRole
	if err := json.Unmarshal(payload, &ecsRole); err == nil {
		sourceID := ecsTaskRoleSourceID(ecsRole)
		if isECSTaskRoleFixture(ecsRole) {
			return rawKindECSTaskRole, sourceID
		}
	}

	var lambdaRole LambdaExecutionRole
	if err := json.Unmarshal(payload, &lambdaRole); err == nil {
		sourceID := lambdaExecutionRoleSourceID(lambdaRole)
		if isLambdaExecutionRoleFixture(lambdaRole) {
			return rawKindLambdaExecutionRole, sourceID
		}
	}

	var codeBuildRole CodeBuildServiceRole
	if err := json.Unmarshal(payload, &codeBuildRole); err == nil {
		sourceID := codeBuildServiceRoleSourceID(codeBuildRole)
		if isCodeBuildServiceRoleFixture(codeBuildRole) {
			return rawKindCodeBuildServiceRole, sourceID
		}
	}

	var codePipelineRole CodePipelineDeploymentRole
	if err := json.Unmarshal(payload, &codePipelineRole); err == nil {
		sourceID := codePipelineDeploymentRoleSourceID(codePipelineRole)
		if isCodePipelineDeploymentRoleFixture(codePipelineRole) {
			return rawKindCodePipelineDeploymentRole, sourceID
		}
	}

	var stepFunctionsRole StepFunctionsStateMachineRole
	if err := json.Unmarshal(payload, &stepFunctionsRole); err == nil {
		sourceID := stepFunctionsStateMachineRoleSourceID(stepFunctionsRole)
		if isStepFunctionsStateMachineRoleFixture(stepFunctionsRole) {
			return rawKindStepFunctionsStateMachineRole, sourceID
		}
	}

	var eventDrivenRole EventDrivenRole
	if err := json.Unmarshal(payload, &eventDrivenRole); err == nil {
		sourceID := eventDrivenRoleSourceID(eventDrivenRole)
		if isEventDrivenRoleFixture(eventDrivenRole) {
			return rawKindEventDrivenRole, sourceID
		}
	}

	var profile EC2InstanceProfile
	if err := json.Unmarshal(payload, &profile); err == nil {
		sourceID := ec2InstanceProfileSourceID(profile)
		if isEC2InstanceProfileFixture(profile) {
			return rawKindEC2InstanceProfile, sourceID
		}
	}

	return "", ""
}

func isECSTaskRoleFixture(record ECSTaskRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), ecsServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), ecsTaskRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "ecs_service", "service", "ecs_task_definition", "task_definition":
		return true
	}
	return strings.TrimSpace(record.RoleKind) != "" ||
		strings.TrimSpace(record.ClusterARN) != "" ||
		strings.TrimSpace(record.ServiceARN) != "" ||
		strings.TrimSpace(record.ServiceName) != "" ||
		strings.TrimSpace(record.TaskDefinitionARN) != "" ||
		strings.TrimSpace(record.TaskDefinitionFamily) != "" ||
		strings.TrimSpace(record.TaskRoleARN) != "" ||
		strings.TrimSpace(record.ExecutionRoleARN) != ""
}

func isLambdaExecutionRoleFixture(record LambdaExecutionRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), lambdaServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), lambdaExecutionRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "lambda_function", "function":
		return true
	}
	return strings.TrimSpace(record.FunctionARN) != "" ||
		strings.TrimSpace(record.FunctionName) != "" ||
		strings.TrimSpace(record.FunctionVersion) != "" ||
		strings.TrimSpace(record.Runtime) != "" ||
		strings.TrimSpace(record.PackageType) != "" ||
		strings.TrimSpace(record.Handler) != "" ||
		strings.TrimSpace(record.KMSKeyARN) != "" ||
		len(record.EventSourceARNs) > 0 ||
		len(record.DisabledEventSourceARNs) > 0
}

func isCodeBuildServiceRoleFixture(record CodeBuildServiceRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), codeBuildServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), codeBuildServiceRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "codebuild_project", "project":
		return true
	}
	return strings.TrimSpace(record.ProjectARN) != "" ||
		strings.TrimSpace(record.ProjectName) != "" ||
		strings.TrimSpace(record.ProjectVisibility) != "" ||
		strings.TrimSpace(record.SourceType) != "" ||
		strings.TrimSpace(record.EnvironmentType) != "" ||
		strings.TrimSpace(record.ComputeType) != "" ||
		strings.TrimSpace(record.Image) != "" ||
		strings.TrimSpace(record.CacheType) != "" ||
		len(record.ArtifactTypes) > 0 ||
		len(record.SourceIdentifiers) > 0
}

func isCodePipelineDeploymentRoleFixture(record CodePipelineDeploymentRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), codePipelineServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), codePipelineDeploymentRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "codepipeline_pipeline", "codepipeline_action", "pipeline", "action":
		return true
	}
	return strings.TrimSpace(record.PipelineARN) != "" ||
		strings.TrimSpace(record.PipelineName) != "" ||
		strings.TrimSpace(record.StageName) != "" ||
		strings.TrimSpace(record.ActionName) != "" ||
		strings.TrimSpace(record.ActionProvider) != "" ||
		len(record.ArtifactStoreLocations) > 0 ||
		len(record.ConfigurationKeys) > 0 ||
		len(record.DisabledStageTransitions) > 0
}

func isStepFunctionsStateMachineRoleFixture(record StepFunctionsStateMachineRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), stepFunctionsServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), stepFunctionsStateMachineRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "stepfunctions_state_machine", "state_machine", "workflow":
		return true
	}
	return strings.TrimSpace(record.StateMachineARN) != "" ||
		strings.TrimSpace(record.StateMachineName) != "" ||
		strings.TrimSpace(record.StateMachineType) != "" ||
		len(record.ServiceIntegrationResources) > 0 ||
		len(record.NestedStateMachineARNs) > 0 ||
		len(record.LogGroupARNs) > 0
}

func isEventDrivenRoleFixture(record EventDrivenRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), eventDrivenServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), eventDrivenRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.Service)) {
	case "scheduler", "pipes":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "eventbridge_rule", "scheduler_schedule", "eventbridge_pipe", "rule", "schedule", "pipe":
		return true
	}
	return strings.TrimSpace(record.WorkloadARN) != "" ||
		strings.TrimSpace(record.EventBusName) != "" ||
		strings.TrimSpace(record.EventBusARN) != "" ||
		strings.TrimSpace(record.ScheduleGroupName) != "" ||
		strings.TrimSpace(record.ScheduleExpression) != "" ||
		strings.TrimSpace(record.PipeSourceARN) != "" ||
		strings.TrimSpace(record.PipeTargetARN) != "" ||
		strings.TrimSpace(record.TargetARN) != "" ||
		strings.TrimSpace(record.TargetID) != "" ||
		len(record.DeadLetterARNs) > 0
}

func isManagedComputeRoleFixture(record ManagedComputeRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), managedComputeServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), managedComputeRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.Service)) {
	case "apprunner", "batch", "glue", "emr":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "apprunner_service", "batch_compute_environment", "batch_job_definition", "glue_job", "glue_crawler", "emr_cluster", "managed_compute_workload":
		return true
	}
	return strings.TrimSpace(record.ResourceARN) != "" ||
		strings.TrimSpace(record.ComputeEngine) != "" ||
		strings.TrimSpace(record.JobDefinitionARN) != "" ||
		strings.TrimSpace(record.UnsupportedService) != "" ||
		strings.TrimSpace(record.CoverageStatus) != ""
}

func isSageMakerWorkloadRoleFixture(record SageMakerWorkloadRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), sageMakerServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), sageMakerWorkloadRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "sagemaker_notebook_instance", "sagemaker_training_job", "sagemaker_processing_job",
		"sagemaker_transform_job", "sagemaker_model", "sagemaker_endpoint",
		"sagemaker_pipeline", "sagemaker_domain", "sagemaker_workload":
		return true
	}
	// Discriminators below are SageMaker-specific only when the field value is
	// itself a SageMaker ARN. ARN-shaped fields like PipelineARN/ModelARN/
	// DomainARN are reused by other AWS services (CodePipeline pipeline ARNs,
	// Bedrock model ARNs) so classifying SageMaker on the field being non-empty
	// alone would misroute those fixtures.
	if isSageMakerARN(record.DomainARN) ||
		isSageMakerARN(record.PipelineARN) ||
		isSageMakerARN(record.ModelARN) ||
		isSageMakerARN(record.WorkloadARN) ||
		isSageMakerARN(record.ResourceARN) {
		return true
	}
	roleKind := strings.TrimSpace(record.RoleKind)
	if strings.HasPrefix(roleKind, "sagemaker_") {
		return true
	}
	// DomainID and EndpointConfig are SageMaker-only operator-facing fields.
	return strings.TrimSpace(record.DomainID) != "" || strings.TrimSpace(record.EndpointConfig) != ""
}

// isIAMPassRoleRelationshipFixture identifies records that look like PassRole
// edges. The matcher is strict (service or collector name match, or the
// dedicated workload type), so it never claims unrelated records that happen
// to embed similar field names.
func isIAMPassRoleRelationshipFixture(record IAMPassRoleRelationship) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), iamPassRoleServiceName) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(record.CollectorName), iamPassRoleRelationshipCollectorName) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(record.WorkloadType), "iam_passrole_relationship") {
		return true
	}
	return false
}

func isSageMakerARN(arn string) bool {
	trimmed := strings.TrimSpace(arn)
	if trimmed == "" {
		return false
	}
	// Parse the ARN service segment instead of substring matching so a
	// resource ARN containing ":sagemaker:" as part of an unrelated component
	// can't false-positive (e.g. tag values, resource paths). Require the
	// full ARN shape (arn:partition:service:region:account:resource) so
	// malformed strings like ":a:sagemaker:..." or "foo:bar:sagemaker:..."
	// also reject.
	parts := strings.SplitN(trimmed, ":", 6)
	return len(parts) == 6 && strings.EqualFold(parts[0], "arn") && strings.EqualFold(parts[2], "sagemaker")
}

func isEKSWorkloadIdentityFixture(record EKSWorkloadIdentity) bool {
	if service := strings.TrimSpace(record.Service); service != "" {
		return strings.EqualFold(service, eksServiceName)
	}
	if collectorName := strings.TrimSpace(record.CollectorName); collectorName != "" {
		return strings.EqualFold(collectorName, eksWorkloadIdentityCollectorName)
	}
	if isExplicitEKSRoleKind(record.RoleKind) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "eks_service_account", "eks_node_group", "eks_fargate_profile", "eks_fargate_pod_execution_role":
		return true
	}
	return strings.TrimSpace(record.OIDCIssuer) != "" ||
		strings.TrimSpace(record.Namespace) != "" ||
		strings.TrimSpace(record.ServiceAccount) != "" ||
		strings.TrimSpace(record.AssociationARN) != "" ||
		strings.TrimSpace(record.NodegroupARN) != "" ||
		strings.TrimSpace(record.FargateProfileARN) != ""
}

func isExplicitEKSRoleKind(roleKind string) bool {
	_, ok := canonicalEKSRoleKindAlias(roleKind)
	return ok
}

func isEC2InstanceProfileFixture(record EC2InstanceProfile) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), ec2ServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), ec2InstanceProfileCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "ec2_instance", "instance", "ec2_launch_template", "launch_template":
		return true
	}
	return strings.TrimSpace(record.InstanceID) != "" ||
		strings.TrimSpace(record.InstanceARN) != "" ||
		strings.TrimSpace(record.InstanceName) != "" ||
		strings.TrimSpace(record.InstanceProfileARN) != "" ||
		strings.TrimSpace(record.InstanceProfileID) != "" ||
		strings.TrimSpace(record.InstanceProfileName) != "" ||
		strings.TrimSpace(record.LaunchTemplateID) != "" ||
		strings.TrimSpace(record.LaunchTemplateName) != ""
}

func expandFixturePaths(inputs []string) ([]string, error) {
	expanded := make([]string, 0, len(inputs))
	for _, input := range inputs {
		cleaned := strings.TrimSpace(input)
		if cleaned == "" {
			continue
		}

		info, err := os.Stat(cleaned)
		if err != nil {
			return nil, fmt.Errorf("stat fixture path %s: %w", cleaned, err)
		}
		if !info.IsDir() {
			expanded = append(expanded, cleaned)
			continue
		}

		entries, err := os.ReadDir(cleaned)
		if err != nil {
			return nil, fmt.Errorf("read fixture directory %s: %w", cleaned, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
				expanded = append(expanded, filepath.Join(cleaned, entry.Name()))
			}
		}
	}

	sort.Strings(expanded)
	if len(expanded) == 0 {
		return nil, fmt.Errorf("no fixture files found")
	}
	return expanded, nil
}

// isS3BucketReachabilityFixture identifies a record that looks like an S3
// bucket reachability fixture. Strict match on service (s3) or workload type
// (s3_bucket) so it never claims unrelated assets.
func isS3BucketReachabilityFixture(record S3BucketReachability) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), s3ServiceName) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(record.CollectorName), s3BucketReachabilityCollectorName) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(record.WorkloadType), "s3_bucket") {
		return true
	}
	return false
}
