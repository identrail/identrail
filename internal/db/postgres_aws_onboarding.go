package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const awsConnectorOnboardingAttemptColumns = `
    attempt_id, tenant_id, workspace_id, project_id, connector_id, status,
    token_hash, token_key_version, provider_topic_arn, template_version,
    template_checksum, deployment_region, COALESCE(stack_id, ''),
    COALESCE(aws_account_id, ''), COALESCE(aws_partition, ''),
    COALESCE(role_arn, ''), COALESCE(bootstrap_request_id, ''),
    COALESCE(register_request_id, ''), COALESCE(failure_code, ''),
    COALESCE(failure_message, ''), expires_at, registered_at, validated_at,
    created_at, updated_at, version`

func (p *PostgresStore) CreateAWSConnectorOnboardingAttempt(ctx context.Context, attempt AWSConnectorOnboardingAttempt) (AWSConnectorOnboardingAttempt, error) {
	normalized, err := normalizeAWSConnectorOnboardingAttempt(ctx, attempt)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	row := p.queryRowContext(ctx, `
        INSERT INTO aws_connector_onboarding_attempts (
            attempt_id, tenant_id, workspace_id, project_id, connector_id,
            status, token_hash, token_key_version, provider_topic_arn,
            template_version, template_checksum, deployment_region, stack_id,
            aws_account_id, aws_partition, role_arn, bootstrap_request_id,
            register_request_id, failure_code, failure_message, expires_at,
            registered_at, validated_at, created_at, updated_at, version
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''), NULLIF($16, ''),
            NULLIF($17, ''), NULLIF($18, ''), NULLIF($19, ''), NULLIF($20, ''),
            $21, $22, $23, $24, $25, $26
        )
        ON CONFLICT DO NOTHING
        RETURNING `+awsConnectorOnboardingAttemptColumns,
		normalized.AttemptID,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.ConnectorID,
		normalized.Status,
		normalized.TokenHash,
		normalized.TokenKeyVersion,
		normalized.ProviderTopicARN,
		normalized.TemplateVersion,
		normalized.TemplateChecksum,
		normalized.DeploymentRegion,
		normalized.StackID,
		normalized.AWSAccountID,
		normalized.AWSPartition,
		normalized.RoleARN,
		normalized.BootstrapRequestID,
		normalized.RegisterRequestID,
		normalized.FailureCode,
		normalized.FailureMessage,
		normalized.ExpiresAt,
		normalized.RegisteredAt,
		normalized.ValidatedAt,
		normalized.CreatedAt,
		normalized.UpdatedAt,
		normalized.Version,
	)
	created, err := scanAWSConnectorOnboardingAttempt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSConnectorOnboardingAttempt{}, ErrConflict
	}
	if isTenancyFKViolation(err) {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return created, err
}

func (p *PostgresStore) GetAWSConnectorOnboardingAttempt(ctx context.Context, workspaceID string, projectID string, attemptID string) (AWSConnectorOnboardingAttempt, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	row := p.queryRowContext(ctx, `SELECT `+awsConnectorOnboardingAttemptColumns+`
        FROM aws_connector_onboarding_attempts
        WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND attempt_id = $4`,
		scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(attemptID))
	attempt, err := scanAWSConnectorOnboardingAttempt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return attempt, err
}

func (p *PostgresStore) GetAWSConnectorOnboardingAttemptAnyScope(ctx context.Context, attemptID string) (AWSConnectorOnboardingAttempt, error) {
	row := p.queryRowContextAnyScope(ctx, `SELECT `+awsConnectorOnboardingAttemptColumns+`
        FROM aws_connector_onboarding_attempts WHERE attempt_id = $1`, strings.TrimSpace(attemptID))
	attempt, err := scanAWSConnectorOnboardingAttempt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return attempt, err
}

func (p *PostgresStore) GetActiveAWSConnectorOnboardingAttempt(ctx context.Context, workspaceID string, projectID string, connectorID string) (AWSConnectorOnboardingAttempt, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	row := p.queryRowContext(ctx, `SELECT `+awsConnectorOnboardingAttemptColumns+`
        FROM aws_connector_onboarding_attempts
        WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3
          AND connector_id = $4
          AND status IN ('waiting_for_aws', 'registering', 'validating')
        ORDER BY created_at DESC
        LIMIT 1`,
		scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
	attempt, err := scanAWSConnectorOnboardingAttempt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSConnectorOnboardingAttempt{}, ErrNotFound
	}
	return attempt, err
}

func (p *PostgresStore) UpdateAWSConnectorOnboardingAttempt(ctx context.Context, attempt AWSConnectorOnboardingAttempt, expectedVersion int64) (AWSConnectorOnboardingAttempt, error) {
	normalized, err := normalizeAWSConnectorOnboardingAttempt(ctx, attempt)
	if err != nil {
		return AWSConnectorOnboardingAttempt{}, err
	}
	row := p.queryRowContext(ctx, `
        UPDATE aws_connector_onboarding_attempts
        SET status = $6,
            token_hash = $7,
            token_key_version = $8,
            provider_topic_arn = $9,
            template_version = $10,
            template_checksum = $11,
            deployment_region = $12,
            stack_id = NULLIF($13, ''),
            aws_account_id = NULLIF($14, ''),
            aws_partition = NULLIF($15, ''),
            role_arn = NULLIF($16, ''),
            bootstrap_request_id = NULLIF($17, ''),
            register_request_id = NULLIF($18, ''),
            failure_code = NULLIF($19, ''),
            failure_message = NULLIF($20, ''),
            expires_at = $21,
            registered_at = $22,
            validated_at = $23,
            updated_at = $24,
            version = version + 1
        WHERE attempt_id = $1 AND tenant_id = $2 AND workspace_id = $3
          AND project_id = $4 AND connector_id = $5 AND version = $25
        RETURNING `+awsConnectorOnboardingAttemptColumns,
		normalized.AttemptID,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.ConnectorID,
		normalized.Status,
		normalized.TokenHash,
		normalized.TokenKeyVersion,
		normalized.ProviderTopicARN,
		normalized.TemplateVersion,
		normalized.TemplateChecksum,
		normalized.DeploymentRegion,
		normalized.StackID,
		normalized.AWSAccountID,
		normalized.AWSPartition,
		normalized.RoleARN,
		normalized.BootstrapRequestID,
		normalized.RegisterRequestID,
		normalized.FailureCode,
		normalized.FailureMessage,
		normalized.ExpiresAt,
		normalized.RegisteredAt,
		normalized.ValidatedAt,
		normalized.UpdatedAt,
		expectedVersion,
	)
	updated, err := scanAWSConnectorOnboardingAttempt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSConnectorOnboardingAttempt{}, ErrConflict
	}
	return updated, err
}

func scanAWSConnectorOnboardingAttempt(row rowScanner) (AWSConnectorOnboardingAttempt, error) {
	var attempt AWSConnectorOnboardingAttempt
	err := row.Scan(
		&attempt.AttemptID,
		&attempt.TenantID,
		&attempt.WorkspaceID,
		&attempt.ProjectID,
		&attempt.ConnectorID,
		&attempt.Status,
		&attempt.TokenHash,
		&attempt.TokenKeyVersion,
		&attempt.ProviderTopicARN,
		&attempt.TemplateVersion,
		&attempt.TemplateChecksum,
		&attempt.DeploymentRegion,
		&attempt.StackID,
		&attempt.AWSAccountID,
		&attempt.AWSPartition,
		&attempt.RoleARN,
		&attempt.BootstrapRequestID,
		&attempt.RegisterRequestID,
		&attempt.FailureCode,
		&attempt.FailureMessage,
		&attempt.ExpiresAt,
		&attempt.RegisteredAt,
		&attempt.ValidatedAt,
		&attempt.CreatedAt,
		&attempt.UpdatedAt,
		&attempt.Version,
	)
	return attempt, err
}
