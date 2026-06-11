package domain

import "time"

// Provider identifies the source platform of identity and workload data.
type Provider string

const (
	ProviderAWS        Provider = "aws"
	ProviderKubernetes Provider = "kubernetes"
	ProviderAzure      Provider = "azure"
)

// IdentityType describes a machine identity category.
type IdentityType string

const (
	IdentityTypeRole           IdentityType = "role"
	IdentityTypeUser           IdentityType = "user"
	IdentityTypeServiceAccount IdentityType = "service_account"
	IdentityTypePrincipal      IdentityType = "principal"
)

// RelationshipType captures graph edge semantics used by path and blast radius analysis.
type RelationshipType string

const (
	RelationshipCanAssume      RelationshipType = "can_assume"
	RelationshipAttachedPolicy RelationshipType = "attached_policy"
	RelationshipAttachedTo     RelationshipType = "attached_to"
	RelationshipBoundTo        RelationshipType = "bound_to"
	RelationshipCanAccess      RelationshipType = "can_access"
	RelationshipCanImpersonate RelationshipType = "can_impersonate"
	RelationshipRunsAs         RelationshipType = "runs_as"
	RelationshipUsesSecret     RelationshipType = "uses_secret"
	RelationshipUsesImage      RelationshipType = "uses_image"
	RelationshipCanDecrypt     RelationshipType = "can_decrypt"
	RelationshipCanPassRole    RelationshipType = "can_pass_role"
	RelationshipInvokes        RelationshipType = "invokes"
	RelationshipCallsTool      RelationshipType = "calls_tool"
	RelationshipActsForUser    RelationshipType = "acts_for_user"
	RelationshipRuntimeSession RelationshipType = "has_runtime_session"
	RelationshipObservedAction RelationshipType = "observed_action"
)

// FindingSeverity aligns risk scoring with operator expectations.
type FindingSeverity string

const (
	SeverityCritical FindingSeverity = "critical"
	SeverityHigh     FindingSeverity = "high"
	SeverityMedium   FindingSeverity = "medium"
	SeverityLow      FindingSeverity = "low"
	SeverityInfo     FindingSeverity = "info"
)

// ResourceType identifies normalized cloud/resource-like nodes in the scan graph.
type ResourceType string

const (
	ResourceTypeS3Bucket            ResourceType = "s3_bucket"
	ResourceTypeSQSQueue            ResourceType = "sqs_queue"
	ResourceTypeSNSTopic            ResourceType = "sns_topic"
	ResourceTypeKMSKey              ResourceType = "kms_key"
	ResourceTypeSecretsManager      ResourceType = "secrets_manager_secret"
	ResourceTypeSSMParameter        ResourceType = "ssm_parameter"
	ResourceTypeECRRepository       ResourceType = "ecr_repository"
	ResourceTypeDynamoDBTable       ResourceType = "dynamodb_table"
	ResourceTypeDynamoDBStream      ResourceType = "dynamodb_stream"
	ResourceTypeRDSInstance         ResourceType = "rds_instance"
	ResourceTypeRDSCluster          ResourceType = "rds_cluster"
	ResourceTypeRDSProxy            ResourceType = "rds_proxy"
	ResourceTypeLambdaFunction      ResourceType = "lambda_function"
	ResourceTypeEC2Instance         ResourceType = "ec2_instance"
	ResourceTypeEC2InstanceProfile  ResourceType = "ec2_instance_profile"
	ResourceTypeECSService          ResourceType = "ecs_service"
	ResourceTypeECSTask             ResourceType = "ecs_task"
	ResourceTypeEKSCluster          ResourceType = "eks_cluster"
	ResourceTypeEKSWorkload         ResourceType = "eks_workload"
	ResourceTypeCodeBuildProject    ResourceType = "codebuild_project"
	ResourceTypeCodePipeline        ResourceType = "codepipeline_pipeline"
	ResourceTypeStepFunctions       ResourceType = "stepfunctions_state_machine"
	ResourceTypeEventBridgeRule     ResourceType = "eventbridge_rule"
	ResourceTypeSchedulerSchedule   ResourceType = "scheduler_schedule"
	ResourceTypeEventBridgePipe     ResourceType = "eventbridge_pipe"
	ResourceTypeAppRunnerService    ResourceType = "apprunner_service"
	ResourceTypeBatchComputeEnv     ResourceType = "batch_compute_environment"
	ResourceTypeBatchJobDefinition  ResourceType = "batch_job_definition"
	ResourceTypeGlueJob             ResourceType = "glue_job"
	ResourceTypeGlueCrawler         ResourceType = "glue_crawler"
	ResourceTypeEMRCluster          ResourceType = "emr_cluster"
	ResourceTypeManagedCompute      ResourceType = "managed_compute_workload"
	ResourceTypeSageMakerNotebook   ResourceType = "sagemaker_notebook_instance"
	ResourceTypeSageMakerTraining   ResourceType = "sagemaker_training_job"
	ResourceTypeSageMakerProcessing ResourceType = "sagemaker_processing_job"
	ResourceTypeSageMakerTransform  ResourceType = "sagemaker_transform_job"
	ResourceTypeSageMakerModel      ResourceType = "sagemaker_model"
	ResourceTypeSageMakerEndpoint   ResourceType = "sagemaker_endpoint"
	ResourceTypeSageMakerPipeline   ResourceType = "sagemaker_pipeline"
	ResourceTypeSageMakerDomain     ResourceType = "sagemaker_domain"
	ResourceTypeSageMakerWorkload   ResourceType = "sagemaker_workload"
	ResourceTypeBedrockAgentCore    ResourceType = "bedrock_agentcore"
	ResourceTypeTool                ResourceType = "tool"
	ResourceTypeAccessNode          ResourceType = "access_node"
	ResourceTypeRuntimeSession      ResourceType = "runtime_session"
	ResourceTypeUnknown             ResourceType = "resource"
)

// CredentialType identifies secrets/keys usable by identities and agents.
type CredentialType string

const (
	CredentialTypeAccessKey       CredentialType = "access_key"
	CredentialTypeAPIKey          CredentialType = "api_key"
	CredentialTypeOAuthToken      CredentialType = "oauth_token"
	CredentialTypeCertificate     CredentialType = "certificate"
	CredentialTypeSecretReference CredentialType = "secret_reference"
	CredentialTypeSessionToken    CredentialType = "session_token"
	CredentialTypeUnknown         CredentialType = "credential"
)

// AgentType identifies runtime-capable actors in normalized scans.
type AgentType string

const (
	AgentTypeAI      AgentType = "ai_agent"
	AgentTypeTool    AgentType = "tool_agent"
	AgentTypeRuntime AgentType = "runtime_agent"
	AgentTypeUnknown AgentType = "agent"
)

// RuntimeEventType identifies observed action semantics during scan execution.
type RuntimeEventType string

const (
	RuntimeEventTypeAssumeRole     RuntimeEventType = "sts_assume_role"
	RuntimeEventTypeSecretRead     RuntimeEventType = "secret_read"
	RuntimeEventTypeDecrypt        RuntimeEventType = "kms_decrypt"
	RuntimeEventTypeToolCall       RuntimeEventType = "tool_call"
	RuntimeEventTypeInvoke         RuntimeEventType = "invoke"
	RuntimeEventTypeAuthDecision   RuntimeEventType = "authorization_decision"
	RuntimeEventTypeRuntimeSession RuntimeEventType = "runtime_session"
	RuntimeEventTypeUnknown        RuntimeEventType = "runtime_event"
)

// FindingType keeps rule output strongly typed for filtering and remediation.
type FindingType string

const (
	FindingOverPrivileged   FindingType = "overprivileged_identity"
	FindingEscalationPath   FindingType = "escalation_path"
	FindingStaleIdentity    FindingType = "stale_identity"
	FindingOwnerless        FindingType = "ownerless_identity"
	FindingRiskyTrustPolicy FindingType = "risky_trust_policy"
	FindingSecretExposure   FindingType = "secret_exposure"
	FindingRepoMisconfig    FindingType = "repo_misconfiguration"
)

// FindingLifecycleStatus tracks operator triage state over time.
type FindingLifecycleStatus string

const (
	FindingLifecycleOpen       FindingLifecycleStatus = "open"
	FindingLifecycleAck        FindingLifecycleStatus = "ack"
	FindingLifecycleSuppressed FindingLifecycleStatus = "suppressed"
	FindingLifecycleResolved   FindingLifecycleStatus = "resolved"
)

// RepoFindingLifecycleStatus tracks scanner-observed state for a repository
// finding across repeated scans.
type RepoFindingLifecycleStatus string

const (
	RepoFindingLifecycleOpen          RepoFindingLifecycleStatus = "open"
	RepoFindingLifecycleFixed         RepoFindingLifecycleStatus = "fixed"
	RepoFindingLifecycleReopened      RepoFindingLifecycleStatus = "reopened"
	RepoFindingLifecycleSuppressed    RepoFindingLifecycleStatus = "suppressed"
	RepoFindingLifecycleRiskAccepted  RepoFindingLifecycleStatus = "risk_accepted"
	RepoFindingLifecycleFalsePositive RepoFindingLifecycleStatus = "false_positive"
)

// FindingTriage stores mutable workflow metadata for one finding id.
type FindingTriage struct {
	Status               FindingLifecycleStatus `json:"status"`
	Assignee             string                 `json:"assignee,omitempty"`
	SuppressionExpiresAt *time.Time             `json:"suppression_expires_at,omitempty"`
	// ResolvedAt records when the finding most recently entered the resolved
	// state. It is nil unless Status is resolved, so reopened findings never
	// report a stale resolution time and MTTR reporting stays trustworthy.
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	UpdatedBy  string     `json:"updated_by,omitempty"`
}

// DefaultFindingTriage returns the baseline lifecycle state for new findings.
func DefaultFindingTriage() FindingTriage {
	return FindingTriage{Status: FindingLifecycleOpen}
}

// Identity is a normalized machine identity across providers.
type Identity struct {
	ID         string            `json:"id"`
	Provider   Provider          `json:"provider"`
	Type       IdentityType      `json:"type"`
	Name       string            `json:"name"`
	ARN        string            `json:"arn"`
	OwnerHint  string            `json:"owner_hint"`
	CreatedAt  time.Time         `json:"created_at"`
	LastUsedAt *time.Time        `json:"last_used_at,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	RawRef     string            `json:"raw_ref"`
}

// Workload is a compute entity that can execute with one or more identities.
type Workload struct {
	ID        string   `json:"id"`
	Provider  Provider `json:"provider"`
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	AccountID string   `json:"account_id"`
	Region    string   `json:"region"`
	RawRef    string   `json:"raw_ref"`
}

// Policy stores provider-native policy documents and parsed summaries.
type Policy struct {
	ID         string         `json:"id"`
	Provider   Provider       `json:"provider"`
	Name       string         `json:"name"`
	Document   []byte         `json:"document"`
	Normalized map[string]any `json:"normalized,omitempty"`
	RawRef     string         `json:"raw_ref"`
}

// Resource represents first-class cloud and runtime resources.
type Resource struct {
	ID             string            `json:"id"`
	Provider       Provider          `json:"provider"`
	Type           ResourceType      `json:"type"`
	Name           string            `json:"name"`
	ARN            string            `json:"arn"`
	Region         string            `json:"region"`
	AccountID      string            `json:"account_id"`
	Labels         map[string]string `json:"labels,omitempty"`
	Metadata       map[string]any    `json:"metadata,omitempty"`
	RawRef         string            `json:"raw_ref"`
	SourceEntityID string            `json:"source_entity_id,omitempty"`
}

// Credential stores machine credential references and metadata.
type Credential struct {
	ID          string            `json:"id"`
	Provider    Provider          `json:"provider"`
	Type        CredentialType    `json:"type"`
	Name        string            `json:"name"`
	OwnerID     string            `json:"owner_id"`
	ResourceID  string            `json:"resource_id"`
	Reference   string            `json:"reference"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	RawRef      string            `json:"raw_ref"`
	RawValue    string            `json:"-"`
	SourceInfo  map[string]any    `json:"source_info,omitempty"`
}

// Agent describes tool or AI-capable actors discovered during normalization.
type Agent struct {
	ID       string            `json:"id"`
	Provider Provider          `json:"provider"`
	Type     AgentType         `json:"type"`
	Name     string            `json:"name"`
	Model    string            `json:"model,omitempty"`
	Runtime  string            `json:"runtime,omitempty"`
	OwnerID  string            `json:"owner_id,omitempty"`
	RawRef   string            `json:"raw_ref"`
	Metadata map[string]any    `json:"metadata,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// RuntimeEvent captures observed runtime activity without retaining secret values.
type RuntimeEvent struct {
	ID           string           `json:"id"`
	Provider     Provider         `json:"provider"`
	Type         RuntimeEventType `json:"type"`
	ActorID      string           `json:"actor_id"`
	TargetID     string           `json:"target_id,omitempty"`
	CredentialID string           `json:"credential_id,omitempty"`
	SourceRef    string           `json:"source_ref"`
	Action       string           `json:"action,omitempty"`
	Decision     string           `json:"decision,omitempty"`
	ObservedAt   time.Time        `json:"observed_at"`
	RawRef       string           `json:"raw_ref"`
	Evidence     map[string]any   `json:"evidence,omitempty"`
}

// Relationship models directional edges in the permission graph.
type Relationship struct {
	ID           string           `json:"id"`
	Type         RelationshipType `json:"type"`
	FromNodeID   string           `json:"from_node_id"`
	ToNodeID     string           `json:"to_node_id"`
	EvidenceRef  string           `json:"evidence_ref"`
	DiscoveredAt time.Time        `json:"discovered_at"`
}

// Finding is a typed risk detected by the analysis engine.
type Finding struct {
	ID                   string                     `json:"id"`
	ScanID               string                     `json:"scan_id"`
	Type                 FindingType                `json:"type"`
	Severity             FindingSeverity            `json:"severity"`
	ConfidenceScore      float64                    `json:"confidence_score,omitempty"`
	Title                string                     `json:"title"`
	HumanSummary         string                     `json:"human_summary"`
	Path                 []string                   `json:"path,omitempty"`
	Repository           string                     `json:"repository,omitempty"`
	Commit               string                     `json:"commit,omitempty"`
	FilePath             string                     `json:"file_path,omitempty"`
	LineNumber           int                        `json:"line_number,omitempty"`
	Detector             string                     `json:"detector,omitempty"`
	LineSnippet          string                     `json:"line_snippet,omitempty"`
	LineSnippetRedacted  *bool                      `json:"line_snippet_redacted,omitempty"`
	SourceURL            string                     `json:"source_url,omitempty"`
	LifecycleKey         string                     `json:"lifecycle_key,omitempty"`
	LifecycleStatus      RepoFindingLifecycleStatus `json:"lifecycle_status,omitempty"`
	Owner                string                     `json:"owner,omitempty"`
	FirstSeenAt          *time.Time                 `json:"first_seen_at,omitempty"`
	LastSeenAt           *time.Time                 `json:"last_seen_at,omitempty"`
	FixedAt              *time.Time                 `json:"fixed_at,omitempty"`
	ReopenedAt           *time.Time                 `json:"reopened_at,omitempty"`
	DismissedAt          *time.Time                 `json:"dismissed_at,omitempty"`
	SuppressionExpiresAt *time.Time                 `json:"suppression_expires_at,omitempty"`
	RuleVersion          string                     `json:"rule_version,omitempty"`
	DetectorVersion      string                     `json:"detector_version,omitempty"`
	AdapterSource        string                     `json:"adapter_source,omitempty"`
	ConfidenceState      string                     `json:"confidence_state,omitempty"`
	VerificationStatus   string                     `json:"verification_status,omitempty"`
	ScanMode             string                     `json:"scan_mode,omitempty"`
	EvidenceVersion      string                     `json:"evidence_version,omitempty"`
	Evidence             map[string]any             `json:"evidence,omitempty"`
	Remediation          string                     `json:"remediation"`
	CreatedAt            time.Time                  `json:"created_at"`
	Triage               FindingTriage              `json:"triage,omitzero"`
}

// OwnershipSignal tracks ownership hints and confidence.
type OwnershipSignal struct {
	ID         string  `json:"id"`
	IdentityID string  `json:"identity_id"`
	Team       string  `json:"team"`
	Repository string  `json:"repository"`
	Source     string  `json:"source"`
	Confidence float64 `json:"confidence"`
}

// Scan tracks one full ingestion and analysis run.
type Scan struct {
	ID         string     `json:"id"`
	Provider   Provider   `json:"provider"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
}
