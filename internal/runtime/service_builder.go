package runtime

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/config"
	awsconnector "github.com/identrail/identrail/internal/connectors/aws"
	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	awsprovider "github.com/identrail/identrail/internal/providers/aws"
	k8sprovider "github.com/identrail/identrail/internal/providers/kubernetes"
	"github.com/identrail/identrail/internal/scheduler"
	"github.com/identrail/identrail/internal/secretstore"
	"github.com/identrail/identrail/internal/userexport"
)

// BuildScanService constructs store + scanner + API service from runtime config.
func BuildScanService(cfg config.Config) (*api.Service, func() error, error) {
	return BuildScanServiceWithContext(context.Background(), cfg)
}

// BuildScanServiceWithContext constructs store + scanner + API service from runtime config
// and uses caller context for startup operations that may block.
func BuildScanServiceWithContext(ctx context.Context, cfg config.Config) (*api.Service, func() error, error) {
	var store db.Store
	var pgStore *db.PostgresStore
	if cfg.DatabaseURL == "" {
		if !cfg.AllowMemoryStore {
			return nil, nil, fmt.Errorf("IDENTRAIL_DATABASE_URL is required unless IDENTRAIL_ALLOW_MEMORY_STORE=true")
		}
		store = db.NewMemoryStore()
	} else {
		var pgErr error
		pgStore, pgErr = db.NewPostgresStore(cfg.DatabaseURL)
		if pgErr != nil {
			return nil, nil, fmt.Errorf("initialize postgres store: %w", pgErr)
		}
		if cfg.RunMigrations {
			migrateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if migrateErr := pgStore.ApplyMigrations(migrateCtx, cfg.MigrationsDir); migrateErr != nil {
				_ = pgStore.Close()
				return nil, nil, fmt.Errorf("apply migrations: %w", migrateErr)
			}
		}
		pgStore.SetScopeRLSEnforcement(cfg.PostgresRLSEnforced)
		store = pgStore
	}

	var scanner app.Scanner
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "aws":
		switch strings.ToLower(strings.TrimSpace(cfg.AWSSource)) {
		case "", "fixture":
			scanner = app.Scanner{
				Collector:            awsprovider.NewFixtureCollector(cfg.AWSFixturePath),
				Normalizer:           awsprovider.NewRoleNormalizer(),
				PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
				RelationshipResolver: awsprovider.NewRelationshipBuilder(),
				RiskRuleSet:          awsprovider.NewRuleSet(),
			}
		case "sdk":
			iamAPI, iamErr := awsprovider.NewSDKIAMAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile)
			if iamErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws sdk collector: %w", iamErr)
			}
			ec2API, ec2Err := awsprovider.NewSDKEC2InstanceProfileAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if ec2Err != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws ec2 instance profile collector: %w", ec2Err)
			}
			ecsAPI, ecsErr := awsprovider.NewSDKECSTaskRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if ecsErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws ecs task role collector: %w", ecsErr)
			}
			lambdaAPI, lambdaErr := awsprovider.NewSDKLambdaExecutionRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if lambdaErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws lambda execution role collector: %w", lambdaErr)
			}
			codeBuildAPI, codeBuildErr := awsprovider.NewSDKCodeBuildServiceRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if codeBuildErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws codebuild service role collector: %w", codeBuildErr)
			}
			codePipelineAPI, codePipelineErr := awsprovider.NewSDKCodePipelineDeploymentRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if codePipelineErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws codepipeline deployment role collector: %w", codePipelineErr)
			}
			stepFunctionsAPI, stepFunctionsErr := awsprovider.NewSDKStepFunctionsStateMachineRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if stepFunctionsErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws stepfunctions state machine role collector: %w", stepFunctionsErr)
			}
			eventDrivenAPI, eventDrivenErr := awsprovider.NewSDKEventDrivenRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if eventDrivenErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws event-driven role collector: %w", eventDrivenErr)
			}
			managedComputeAPI, managedComputeErr := awsprovider.NewSDKManagedComputeRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if managedComputeErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws managed compute role collector: %w", managedComputeErr)
			}
			sageMakerAPI, sageMakerErr := awsprovider.NewSDKSageMakerWorkloadRoleAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if sageMakerErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws sagemaker workload role collector: %w", sageMakerErr)
			}
			eksAPI, eksErr := awsprovider.NewSDKEKSWorkloadIdentityAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if eksErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws eks workload identity collector: %w", eksErr)
			}
			s3API, s3Err := awsprovider.NewSDKS3BucketReachabilityAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if s3Err != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws s3 bucket reachability collector: %w", s3Err)
			}
			kmsAPI, kmsErr := awsprovider.NewSDKKMSDecryptReachabilityAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if kmsErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws kms decrypt reachability collector: %w", kmsErr)
			}
			sqsSNSAPI, sqsSNSErr := awsprovider.NewSDKSQSSNSReachabilityAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if sqsSNSErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws sqs/sns reachability collector: %w", sqsSNSErr)
			}
			dynamoDBRDSAPI, dynamoDBRDSErr := awsprovider.NewSDKDynamoDBRDSReachabilityAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if dynamoDBRDSErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws dynamodb/rds reachability collector: %w", dynamoDBRDSErr)
			}
			secretsAPI, secretsErr := awsprovider.NewSDKSecretsManagerMetadataAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if secretsErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws secrets manager metadata collector: %w", secretsErr)
			}
			ssmAPI, ssmErr := awsprovider.NewSDKSSMParameterMetadataAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if ssmErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws ssm parameter metadata collector: %w", ssmErr)
			}
			ecrAPI, ecrErr := awsprovider.NewSDKECRRepositoryMetadataAPIWithContext(ctx, cfg.AWSRegion, cfg.AWSProfile, cfg.AWSAccountID)
			if ecrErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws ecr repository metadata collector: %w", ecrErr)
			}
			scanner = newAWSScanner(
				iamAPI,
				cfg.AWSAccountID,
				cfg.AWSRegion,
				awsprovider.NewEC2InstanceProfileCollector(ec2API),
				awsprovider.NewECSTaskRoleCollector(ecsAPI),
				awsprovider.NewLambdaExecutionRoleCollector(lambdaAPI),
				awsprovider.NewCodeBuildServiceRoleCollector(codeBuildAPI),
				awsprovider.NewCodePipelineDeploymentRoleCollector(codePipelineAPI),
				awsprovider.NewStepFunctionsStateMachineRoleCollector(stepFunctionsAPI),
				awsprovider.NewEventDrivenRoleCollector(eventDrivenAPI),
				awsprovider.NewManagedComputeRoleCollector(managedComputeAPI),
				awsprovider.NewSageMakerWorkloadRoleCollector(sageMakerAPI),
				awsprovider.NewIAMPassRoleRelationshipCollector(iamAPI),
				awsprovider.NewEKSWorkloadIdentityCollector(eksAPI),
				awsprovider.NewS3BucketReachabilityCollector(s3API),
				awsprovider.NewKMSDecryptReachabilityCollector(kmsAPI),
				awsprovider.NewSQSSNSReachabilityCollector(sqsSNSAPI),
				awsprovider.NewDynamoDBRDSReachabilityCollector(dynamoDBRDSAPI),
				awsprovider.NewSecretsManagerMetadataCollector(secretsAPI),
				awsprovider.NewSSMParameterMetadataCollector(ssmAPI),
				awsprovider.NewECRRepositoryMetadataCollector(ecrAPI),
			)
		default:
			_ = store.Close()
			return nil, nil, fmt.Errorf("unsupported aws source %q", cfg.AWSSource)
		}
	case "kubernetes":
		var collector app.Scanner
		switch strings.ToLower(strings.TrimSpace(cfg.KubernetesSource)) {
		case "", "fixture":
			collector = app.Scanner{
				Collector:            k8sprovider.NewFixtureCollector(cfg.KubernetesFixturePath),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}
		case "kubectl":
			collector = app.Scanner{
				Collector:            k8sprovider.NewKubectlCollector(cfg.KubectlPath, cfg.KubeContext, nil),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}
		default:
			_ = store.Close()
			return nil, nil, fmt.Errorf("unsupported kubernetes source %q", cfg.KubernetesSource)
		}
		scanner = collector
	default:
		_ = store.Close()
		return nil, nil, fmt.Errorf("unsupported provider %q", cfg.Provider)
	}

	svc := api.NewService(store, scanner, cfg.Provider)
	if strings.TrimSpace(cfg.ConnectorSecretKeys) != "" {
		materials, parseErr := secretstore.ParseKeySet(cfg.ConnectorSecretKeys)
		if parseErr != nil {
			_ = store.Close()
			return nil, nil, fmt.Errorf("parse connector secret keys: %w", parseErr)
		}
		manager, managerErr := secretstore.NewManager(materials)
		if managerErr != nil {
			_ = store.Close()
			return nil, nil, fmt.Errorf("initialize connector secret manager: %w", managerErr)
		}
		svc.ConnectorSecretManager = manager
	}
	svc.KubernetesPreflightFactory = func(contextName string) api.KubernetesConnectorPreflightRunner {
		effectiveContext := strings.TrimSpace(contextName)
		if effectiveContext == "" {
			effectiveContext = cfg.KubeContext
		}
		return k8sprovider.NewKubectlPreflightDriver(cfg.KubectlPath, effectiveContext, nil)
	}
	svc.AWSConnectorValidator = awsprovider.NewConnectionValidator(cfg.AWSRegion, cfg.AWSProfile)
	svc.AWSCloudFormationTemplateURL = cfg.AWSCloudFormationTemplateURL
	svc.AWSAccountID = cfg.AWSAccountID
	svc.AWSBaselineGitSHA = cfg.BaselineGitSHA
	svc.AWSBaselineSourceMode = cfg.AWSSource
	svc.AWSBaselineFixturePaths = append([]string(nil), cfg.AWSFixturePath...)
	svc.AWSBaselineConnectorProfileVersion = "aws-readonly-iam-v1"
	svc.AWSBaselineGraphContractVersion = "relationship-contract-v1"
	svc.AWSConnectorCapabilityPolicy = awsconnector.NewCapabilityPolicyFromStrings(cfg.AWSConnectorCapabilities)
	svc.GitHubAppID = parseInt64Config(cfg.GitHubAppID)
	svc.GitHubAppName = cfg.GitHubAppName
	svc.GitHubAppPrivateKey = cfg.GitHubAppPrivateKey
	svc.GitHubAppWebhookSecret = cfg.GitHubAppWebhookSecret
	svc.GitHubPATValidator = githubconnector.PATValidator{AllowedBaseURLs: cfg.GitHubPATAllowedBaseURLs}
	tokenClient := &githubconnector.InstallationTokenClient{
		Credentials: githubconnector.AppCredentials{
			AppID:         svc.GitHubAppID,
			AppSlug:       svc.GitHubAppName,
			PrivateKeyPEM: svc.GitHubAppPrivateKey,
		},
	}
	repositoryClient := githubconnector.RepositoryClient{TokenClient: tokenClient}
	svc.GitHubRepositoryLister = repositoryClient
	svc.GitHubRepositoryPostureCollector = repositoryClient
	svc.GitHubCodeScanningAlertCollector = repositoryClient
	svc.GitHubSecretScanningAlertCollector = repositoryClient
	svc.GitHubDependabotAlertCollector = repositoryClient
	svc.GitHubInstallationTokenMinter = tokenClient
	svc.AWSScannerFactory = func(ctx context.Context, connection api.AWSConnectionStatus) (api.ScannerRunner, error) {
		iamAPI, iamErr := awsprovider.NewSDKIAMAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan")
		if iamErr != nil {
			return nil, iamErr
		}
		ec2API, ec2Err := awsprovider.NewSDKEC2InstanceProfileAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if ec2Err != nil {
			return nil, ec2Err
		}
		ecsAPI, ecsErr := awsprovider.NewSDKECSTaskRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if ecsErr != nil {
			return nil, ecsErr
		}
		lambdaAPI, lambdaErr := awsprovider.NewSDKLambdaExecutionRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if lambdaErr != nil {
			return nil, lambdaErr
		}
		codeBuildAPI, codeBuildErr := awsprovider.NewSDKCodeBuildServiceRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if codeBuildErr != nil {
			return nil, codeBuildErr
		}
		codePipelineAPI, codePipelineErr := awsprovider.NewSDKCodePipelineDeploymentRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if codePipelineErr != nil {
			return nil, codePipelineErr
		}
		stepFunctionsAPI, stepFunctionsErr := awsprovider.NewSDKStepFunctionsStateMachineRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if stepFunctionsErr != nil {
			return nil, stepFunctionsErr
		}
		eventDrivenAPI, eventDrivenErr := awsprovider.NewSDKEventDrivenRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if eventDrivenErr != nil {
			return nil, eventDrivenErr
		}
		managedComputeAPI, managedComputeErr := awsprovider.NewSDKManagedComputeRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if managedComputeErr != nil {
			return nil, managedComputeErr
		}
		sageMakerAPI, sageMakerErr := awsprovider.NewSDKSageMakerWorkloadRoleAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if sageMakerErr != nil {
			return nil, sageMakerErr
		}
		eksAPI, eksErr := awsprovider.NewSDKEKSWorkloadIdentityAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if eksErr != nil {
			return nil, eksErr
		}
		s3API, s3Err := awsprovider.NewSDKS3BucketReachabilityAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if s3Err != nil {
			return nil, s3Err
		}
		kmsAPI, kmsErr := awsprovider.NewSDKKMSDecryptReachabilityAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if kmsErr != nil {
			return nil, kmsErr
		}
		sqsSNSAPI, sqsSNSErr := awsprovider.NewSDKSQSSNSReachabilityAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if sqsSNSErr != nil {
			return nil, sqsSNSErr
		}
		dynamoDBRDSAPI, dynamoDBRDSErr := awsprovider.NewSDKDynamoDBRDSReachabilityAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if dynamoDBRDSErr != nil {
			return nil, dynamoDBRDSErr
		}
		secretsAPI, secretsErr := awsprovider.NewSDKSecretsManagerMetadataAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if secretsErr != nil {
			return nil, secretsErr
		}
		ssmAPI, ssmErr := awsprovider.NewSDKSSMParameterMetadataAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if ssmErr != nil {
			return nil, ssmErr
		}
		ecrAPI, ecrErr := awsprovider.NewSDKECRRepositoryMetadataAPIFromAssumeRole(ctx, connection.Region, cfg.AWSProfile, connection.RoleARN, connection.ExternalID, "identrail-recurring-scan", connection.AccountID)
		if ecrErr != nil {
			return nil, ecrErr
		}
		scanner := newAWSScanner(
			iamAPI,
			connection.AccountID,
			connection.Region,
			awsprovider.NewEC2InstanceProfileCollector(ec2API),
			awsprovider.NewECSTaskRoleCollector(ecsAPI),
			awsprovider.NewLambdaExecutionRoleCollector(lambdaAPI),
			awsprovider.NewCodeBuildServiceRoleCollector(codeBuildAPI),
			awsprovider.NewCodePipelineDeploymentRoleCollector(codePipelineAPI),
			awsprovider.NewStepFunctionsStateMachineRoleCollector(stepFunctionsAPI),
			awsprovider.NewEventDrivenRoleCollector(eventDrivenAPI),
			awsprovider.NewManagedComputeRoleCollector(managedComputeAPI),
			awsprovider.NewSageMakerWorkloadRoleCollector(sageMakerAPI),
			awsprovider.NewIAMPassRoleRelationshipCollector(iamAPI),
			awsprovider.NewEKSWorkloadIdentityCollector(eksAPI),
			awsprovider.NewS3BucketReachabilityCollector(s3API),
			awsprovider.NewKMSDecryptReachabilityCollector(kmsAPI),
			awsprovider.NewSQSSNSReachabilityCollector(sqsSNSAPI),
			awsprovider.NewDynamoDBRDSReachabilityCollector(dynamoDBRDSAPI),
			awsprovider.NewSecretsManagerMetadataCollector(secretsAPI),
			awsprovider.NewSSMParameterMetadataCollector(ssmAPI),
			awsprovider.NewECRRepositoryMetadataCollector(ecrAPI),
		)
		return scanner, nil
	}
	svc.DefaultScope = db.Scope{
		TenantID:    cfg.DefaultTenantID,
		WorkspaceID: cfg.DefaultWorkspaceID,
	}.Normalize()
	svc.LockNamespace = strings.TrimSpace(cfg.LockNamespace)
	// Self-serve "Download my data" (#1421). Bundle storage is opt-in via a
	// local path for dev/test or S3 for hosted API+worker deployments.
	storage, storageErr := buildUserExportStorage(ctx, cfg)
	if storageErr != nil {
		_ = store.Close()
		return nil, nil, storageErr
	}
	if storage != nil {
		svc.UserExportStorage = storage
		if sessionKey := strings.TrimSpace(cfg.SessionKey); sessionKey != "" {
			if keyErr := config.ValidateSessionKeyMaterial("IDENTRAIL_SESSION_KEY", sessionKey); keyErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("validate user export signing key: %w", keyErr)
			}
			svc.UserExportTokenSecret = []byte(sessionKey)
		}
	}
	lockBackend := strings.ToLower(strings.TrimSpace(cfg.LockBackend))
	switch lockBackend {
	case "", "auto":
		if pgStore != nil {
			svc.Locker = scheduler.NewPostgresAdvisoryLocker(pgStore.DB())
		}
	case "postgres":
		if pgStore != nil {
			svc.Locker = scheduler.NewPostgresAdvisoryLocker(pgStore.DB())
		}
	case "inmemory":
		svc.Locker = scheduler.NewInMemoryLocker()
	default:
		// Validation should catch this; keep in-memory as safe fallback.
		svc.Locker = scheduler.NewInMemoryLocker()
	}
	if pgStore != nil {
		svc.ReadinessCheck = func(ctx context.Context) error {
			pingCtx := ctx
			cancel := func() {}
			if _, hasDeadline := ctx.Deadline(); !hasDeadline {
				pingCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
			}
			defer cancel()
			if err := pgStore.DB().PingContext(pingCtx); err != nil {
				return fmt.Errorf("ping postgres: %w", err)
			}
			return nil
		}
	}
	svc.RepoScanEnabled = cfg.RepoScanEnabled
	if cfg.RepoScanHistoryLimit > 0 {
		svc.RepoScanDefaultHistoryLimit = cfg.RepoScanHistoryLimit
	}
	if cfg.RepoScanMaxFindings > 0 {
		svc.RepoScanDefaultMaxFindings = cfg.RepoScanMaxFindings
	}
	if cfg.RepoScanHistoryLimitMax > 0 {
		svc.RepoScanMaxHistoryLimit = cfg.RepoScanHistoryLimitMax
	}
	if cfg.RepoScanMaxFindingsMax > 0 {
		svc.RepoScanMaxFindingsLimit = cfg.RepoScanMaxFindingsMax
	}
	svc.RepoScanAllowedTargets = append([]string(nil), cfg.RepoScanAllowlist...)
	if cfg.ScanQueueMaxPending > 0 {
		svc.ScanQueueMaxPending = cfg.ScanQueueMaxPending
	}
	if cfg.RepoQueueMaxPending > 0 {
		svc.RepoQueueMaxPending = cfg.RepoQueueMaxPending
	}
	if cfg.AlertWebhookURL != "" {
		alerter, alertErr := api.NewWebhookAlerter(
			cfg.AlertWebhookURL,
			cfg.AlertTimeout,
			cfg.AlertMinSeverity,
			cfg.AlertHMACSecret,
			cfg.AlertMaxFindings,
			cfg.AlertMaxRetries,
			cfg.AlertRetryBackoff,
		)
		if alertErr != nil {
			_ = store.Close()
			return nil, nil, fmt.Errorf("initialize alert webhook: %w", alertErr)
		}
		svc.Alerter = alerter
	}
	return svc, store.Close, nil
}

func parseInt64Config(value string) int64 {
	parsed, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return parsed
}

func buildUserExportStorage(ctx context.Context, cfg config.Config) (userexport.Storage, error) {
	exportPath := strings.TrimSpace(cfg.UserDataExportPath)
	exportBucket := strings.TrimSpace(cfg.UserDataExportS3Bucket)
	if exportPath != "" && exportBucket != "" {
		return nil, fmt.Errorf("IDENTRAIL_USER_DATA_EXPORT_PATH and IDENTRAIL_USER_DATA_EXPORT_S3_BUCKET cannot both be set")
	}
	if exportBucket != "" {
		loadOptions := []func(*awsconfig.LoadOptions) error{}
		if region := firstNonEmpty(cfg.UserDataExportS3Region, cfg.AWSRegion); region != "" {
			loadOptions = append(loadOptions, awsconfig.WithRegion(region))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
		if err != nil {
			return nil, fmt.Errorf("initialize user export s3 config: %w", err)
		}
		storage, err := userexport.NewS3Storage(s3.NewFromConfig(awsCfg), exportBucket, cfg.UserDataExportS3Prefix)
		if err != nil {
			return nil, fmt.Errorf("initialize user export s3 storage: %w", err)
		}
		return storage, nil
	}
	if exportPath != "" {
		storage, err := userexport.NewLocalDiskStorage(exportPath)
		if err != nil {
			return nil, fmt.Errorf("initialize user export storage: %w", err)
		}
		return storage, nil
	}
	return nil, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func newAWSScanner(iamAPI awsprovider.IAMAPI, accountID string, region string, services ...awsprovider.AWSServiceCollector) app.Scanner {
	return awsprovider.NewAWSScannerWithServices(iamAPI, accountID, region, services)
}

// NewStore returns memory store by default, Postgres when database URL is provided.
func NewStore(databaseURL string) (db.Store, error) {
	if databaseURL == "" {
		return db.NewMemoryStore(), nil
	}
	store, err := db.NewPostgresStore(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("initialize postgres store: %w", err)
	}
	return store, nil
}
