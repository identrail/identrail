package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const awsOrganizationRolloutColumns = `
    rollout_id, tenant_id, workspace_id, project_id, controlling_connector_id,
    controlling_role, organization_id, management_account_id, partition,
    deployment_mode, stack_set_name, expected_role_name, template_version,
    template_checksum, registration_secret_hash, registration_secret_key_version,
    COALESCE(selected_ou_ids, '[]'::jsonb),
    COALESCE(selected_account_ids, '[]'::jsonb),
    COALESCE(excluded_account_ids, '[]'::jsonb),
    COALESCE(target_regions, '[]'::jsonb),
    auto_deploy_new_accounts, status,
    COALESCE(failure_code, ''), COALESCE(failure_message, ''),
    expires_at, created_at, updated_at, version,
    controlling_connector_lifecycle_generation`

func (p *PostgresStore) CreateAWSOrganizationRollout(ctx context.Context, rollout AWSOrganizationRollout) (AWSOrganizationRollout, error) {
	normalized, err := normalizeAWSOrganizationRollout(ctx, rollout)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	selectedOUs, selectedAccounts, excludedAccounts, regions, err := marshalAWSOrganizationRolloutJSON(normalized)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	row := p.queryRowContext(ctx, `
        WITH eligible_connector AS (
            SELECT connector_id
            FROM tenancy_connectors
            WHERE tenant_id = $2
              AND workspace_id = $3
              AND project_id = $4
              AND connector_id = $5
              AND type = 'aws'
              AND status = 'active'
              AND disabled = FALSE
              AND lifecycle_generation = $29
            FOR UPDATE
        )
        INSERT INTO aws_organization_rollouts (
            rollout_id, tenant_id, workspace_id, project_id, controlling_connector_id,
            controlling_role, organization_id, management_account_id, partition,
            deployment_mode, stack_set_name, expected_role_name, template_version,
            template_checksum, registration_secret_hash, registration_secret_key_version,
            selected_ou_ids, selected_account_ids, excluded_account_ids, target_regions,
            auto_deploy_new_accounts, status, failure_code, failure_message,
            expires_at, created_at, updated_at, version,
            controlling_connector_lifecycle_generation
        ) SELECT
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
            $17::jsonb, $18::jsonb, $19::jsonb, $20::jsonb,
            $21, $22, NULLIF($23, ''), NULLIF($24, ''),
            $25, $26, $27, $28, $29
        FROM eligible_connector
        ON CONFLICT DO NOTHING
        RETURNING `+awsOrganizationRolloutColumns,
		normalized.RolloutID,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.ControllingConnectorID,
		normalized.ControllingRole,
		normalized.OrganizationID,
		normalized.ManagementAccountID,
		normalized.Partition,
		normalized.DeploymentMode,
		normalized.StackSetName,
		normalized.ExpectedRoleName,
		normalized.TemplateVersion,
		normalized.TemplateChecksum,
		normalized.RegistrationSecretHash,
		normalized.RegistrationSecretKeyVersion,
		selectedOUs,
		selectedAccounts,
		excludedAccounts,
		regions,
		normalized.AutoDeployNewAccounts,
		normalized.Status,
		normalized.FailureCode,
		normalized.FailureMessage,
		normalized.ExpiresAt,
		normalized.CreatedAt,
		normalized.UpdatedAt,
		normalized.Version,
		normalized.ControllingConnectorLifecycleGeneration,
	)
	created, err := scanAWSOrganizationRollout(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSOrganizationRollout{}, ErrConflict
	}
	if isTenancyFKViolation(err) {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	return created, err
}

func (p *PostgresStore) GetAWSOrganizationRollout(ctx context.Context, workspaceID string, projectID string, rolloutID string) (AWSOrganizationRollout, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	row := p.queryRowContext(ctx, `SELECT `+awsOrganizationRolloutColumns+`
        FROM aws_organization_rollouts
        WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND rollout_id = $4`,
		scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(rolloutID))
	rollout, err := scanAWSOrganizationRollout(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	return rollout, err
}

func (p *PostgresStore) GetAWSOrganizationRolloutAnyScope(ctx context.Context, rolloutID string) (AWSOrganizationRollout, error) {
	row := p.queryRowContextAnyScope(ctx, `SELECT `+awsOrganizationRolloutColumns+`
        FROM aws_organization_rollouts WHERE rollout_id = $1`, strings.TrimSpace(rolloutID))
	rollout, err := scanAWSOrganizationRollout(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSOrganizationRollout{}, ErrNotFound
	}
	return rollout, err
}

func (p *PostgresStore) ListAWSOrganizationRollouts(ctx context.Context, workspaceID string, projectID string, connectorID string, limit int) ([]AWSOrganizationRollout, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	trimmedConnector := strings.TrimSpace(connectorID)
	effectiveLimit := limit
	if effectiveLimit <= 0 || effectiveLimit > 200 {
		effectiveLimit = 50
	}
	query := `SELECT ` + awsOrganizationRolloutColumns + `
        FROM aws_organization_rollouts
        WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3
          AND ($4 = '' OR controlling_connector_id = $4)
        ORDER BY created_at DESC
        LIMIT $5`
	rows, err := p.queryContext(ctx, query, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), trimmedConnector, effectiveLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AWSOrganizationRollout, 0)
	for rows.Next() {
		rollout, scanErr := scanAWSOrganizationRollout(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, rollout)
	}
	return out, rows.Err()
}

// ListMonitoredAWSOrganizationRollouts is reserved for the internal worker. It
// selects only the newest rollout for each connector, including a completed
// rollout, so live drift remains visible without replaying rollout history.
func (p *PostgresStore) ListMonitoredAWSOrganizationRollouts(ctx context.Context, limit int) ([]AWSOrganizationRollout, error) {
	effectiveLimit := limit
	if effectiveLimit <= 0 || effectiveLimit > 200 {
		effectiveLimit = 50
	}
	// Apply the monitored-status filter inside the subquery so DISTINCT ON
	// selects the newest monitored rollout per connector. Filtering after
	// DISTINCT ON would drop a connector entirely whenever its latest row is
	// retired (canceled/expired), even though an earlier monitored rollout
	// still needs drift reconciliation.
	rows, err := p.queryContextAnyScope(ctx, `SELECT `+awsOrganizationRolloutColumns+`
        FROM aws_organization_rollouts AS rollout
        WHERE rollout.rollout_id IN (
            SELECT DISTINCT ON (tenant_id, workspace_id, project_id, controlling_connector_id) rollout_id
            FROM aws_organization_rollouts
            WHERE status IN ('created', 'launching', 'in_progress', 'reconciling', 'completed', 'partial', 'failed')
            ORDER BY tenant_id, workspace_id, project_id, controlling_connector_id, created_at DESC, rollout_id DESC
        )
        ORDER BY updated_at ASC
        LIMIT $1`, effectiveLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AWSOrganizationRollout, 0, effectiveLimit)
	for rows.Next() {
		rollout, scanErr := scanAWSOrganizationRollout(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, rollout)
	}
	return out, rows.Err()
}

func (p *PostgresStore) UpdateAWSOrganizationRollout(ctx context.Context, rollout AWSOrganizationRollout, expectedVersion int64) (AWSOrganizationRollout, error) {
	normalized, err := normalizeAWSOrganizationRollout(ctx, rollout)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	selectedOUs, selectedAccounts, excludedAccounts, regions, err := marshalAWSOrganizationRolloutJSON(normalized)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	row := p.queryRowContext(ctx, `
        UPDATE aws_organization_rollouts AS rollout
        SET controlling_role = $6,
            organization_id = $7,
            management_account_id = $8,
            partition = $9,
            deployment_mode = $10,
            stack_set_name = $11,
            expected_role_name = $12,
            template_version = $13,
            template_checksum = $14,
            registration_secret_hash = $15,
            registration_secret_key_version = $16,
            selected_ou_ids = $17::jsonb,
            selected_account_ids = $18::jsonb,
            excluded_account_ids = $19::jsonb,
            target_regions = $20::jsonb,
            auto_deploy_new_accounts = $21,
            status = $22,
            failure_code = NULLIF($23, ''),
            failure_message = NULLIF($24, ''),
            expires_at = $25,
            updated_at = $26,
            version = version + 1
        WHERE rollout.rollout_id = $1 AND rollout.tenant_id = $2 AND rollout.workspace_id = $3
          AND rollout.project_id = $4 AND rollout.controlling_connector_id = $5 AND rollout.version = $27
          AND (
              $22 NOT IN ('created', 'launching', 'in_progress', 'reconciling', 'completed', 'partial', 'failed')
              OR EXISTS (
                  SELECT 1
                  FROM tenancy_connectors AS controlling_connector
                  WHERE controlling_connector.tenant_id = rollout.tenant_id
                    AND controlling_connector.workspace_id = rollout.workspace_id
                    AND controlling_connector.project_id = rollout.project_id
                    AND controlling_connector.connector_id = rollout.controlling_connector_id
                    AND controlling_connector.type = 'aws'
                    AND controlling_connector.status = 'active'
                    AND controlling_connector.disabled = FALSE
                    AND controlling_connector.lifecycle_generation = rollout.controlling_connector_lifecycle_generation
                  FOR UPDATE
              )
          )
        RETURNING `+awsOrganizationRolloutColumns,
		normalized.RolloutID,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.ControllingConnectorID,
		normalized.ControllingRole,
		normalized.OrganizationID,
		normalized.ManagementAccountID,
		normalized.Partition,
		normalized.DeploymentMode,
		normalized.StackSetName,
		normalized.ExpectedRoleName,
		normalized.TemplateVersion,
		normalized.TemplateChecksum,
		normalized.RegistrationSecretHash,
		normalized.RegistrationSecretKeyVersion,
		selectedOUs,
		selectedAccounts,
		excludedAccounts,
		regions,
		normalized.AutoDeployNewAccounts,
		normalized.Status,
		normalized.FailureCode,
		normalized.FailureMessage,
		normalized.ExpiresAt,
		normalized.UpdatedAt,
		expectedVersion,
	)
	updated, err := scanAWSOrganizationRollout(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSOrganizationRollout{}, ErrConflict
	}
	if isTenancyUniqueViolation(err) {
		return AWSOrganizationRollout{}, ErrConflict
	}
	return updated, err
}

const awsOrganizationRolloutTargetColumns = `
    rollout_id, account_id, region, tenant_id, workspace_id, project_id,
    COALESCE(account_name, ''), COALESCE(ou_path, ''), is_management, state,
    COALESCE(stack_instance_id, ''), COALESCE(stack_id, ''), COALESCE(role_arn, ''),
    COALESCE(failure_code, ''), COALESCE(failure_message, ''),
    retryable, COALESCE(evidence_ref, ''), COALESCE(register_request_id, ''),
    last_transition_at, last_validation_at, created_at, updated_at, version`

func (p *PostgresStore) UpsertAWSOrganizationRolloutTarget(ctx context.Context, target AWSOrganizationRolloutTarget) (AWSOrganizationRolloutTarget, error) {
	normalized, err := normalizeAWSOrganizationRolloutTarget(ctx, target)
	if err != nil {
		return AWSOrganizationRolloutTarget{}, err
	}
	now := time.Now().UTC()
	if normalized.LastTransitionAt.IsZero() {
		normalized.LastTransitionAt = now
	}
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = now
	}
	normalized.UpdatedAt = now
	row := p.queryRowContext(ctx, `
        WITH eligible_rollout AS (
            SELECT rollout.rollout_id
            FROM aws_organization_rollouts AS rollout
            JOIN tenancy_connectors AS controlling_connector
              ON controlling_connector.tenant_id = rollout.tenant_id
             AND controlling_connector.workspace_id = rollout.workspace_id
             AND controlling_connector.project_id = rollout.project_id
             AND controlling_connector.connector_id = rollout.controlling_connector_id
            WHERE rollout.rollout_id = $1
              AND rollout.tenant_id = $4
              AND rollout.workspace_id = $5
              AND rollout.project_id = $6
              AND rollout.status IN ('created', 'launching', 'in_progress', 'reconciling', 'completed', 'partial', 'failed')
              AND controlling_connector.type = 'aws'
              AND controlling_connector.status = 'active'
              AND controlling_connector.disabled = FALSE
              AND controlling_connector.lifecycle_generation = rollout.controlling_connector_lifecycle_generation
            FOR UPDATE OF rollout, controlling_connector
        )
        INSERT INTO aws_organization_rollout_targets (
            rollout_id, account_id, region, tenant_id, workspace_id, project_id,
            account_name, ou_path, is_management, state, stack_instance_id, stack_id,
            role_arn, failure_code, failure_message, retryable, evidence_ref,
            register_request_id, last_transition_at, last_validation_at,
            created_at, updated_at, version
        ) SELECT
            $1, $2, $3, $4, $5, $6, NULLIF($7, ''), NULLIF($8, ''), $9, $10,
            NULLIF($11, ''), NULLIF($12, ''), NULLIF($13, ''),
            NULLIF($14, ''), NULLIF($15, ''), $16, NULLIF($17, ''), NULLIF($18, ''),
            $19, $20, $21, $22, 1
        FROM eligible_rollout
        ON CONFLICT (rollout_id, account_id, region) DO UPDATE
        SET account_name = COALESCE(EXCLUDED.account_name, aws_organization_rollout_targets.account_name),
            ou_path = COALESCE(EXCLUDED.ou_path, aws_organization_rollout_targets.ou_path),
            is_management = EXCLUDED.is_management,
            -- Promote-only state. A terminal state (connected, failed,
            -- partial, suspended, removed, excluded) is only replaced by
            -- another terminal state; a late in-flight callback or SQS
            -- redelivery cannot demote a reconciled target back to
            -- validating/registering/pending. Deploying is the sole
            -- non-terminal exception: inventory reconciliation may reopen
            -- a terminal target as deploying when CloudFormation reports
            -- an active StackSet operation, so the aggregate does not
            -- report completed while a live deployment is still in flight.
            state = CASE
                WHEN aws_organization_rollout_targets.state IN ('connected','failed','partial','suspended','removed','excluded')
                     AND EXCLUDED.state NOT IN ('connected','failed','partial','suspended','removed','excluded','deploying')
                THEN aws_organization_rollout_targets.state
                ELSE EXCLUDED.state
            END,
            stack_instance_id = COALESCE(EXCLUDED.stack_instance_id, aws_organization_rollout_targets.stack_instance_id),
            stack_id = COALESCE(EXCLUDED.stack_id, aws_organization_rollout_targets.stack_id),
            role_arn = COALESCE(EXCLUDED.role_arn, aws_organization_rollout_targets.role_arn),
            failure_code = EXCLUDED.failure_code,
            failure_message = EXCLUDED.failure_message,
            retryable = EXCLUDED.retryable,
            evidence_ref = COALESCE(EXCLUDED.evidence_ref, aws_organization_rollout_targets.evidence_ref),
            register_request_id = COALESCE(EXCLUDED.register_request_id, aws_organization_rollout_targets.register_request_id),
            last_transition_at = CASE
                WHEN aws_organization_rollout_targets.state IN ('connected','failed','partial','suspended','removed','excluded')
                     AND EXCLUDED.state NOT IN ('connected','failed','partial','suspended','removed','excluded','deploying')
                THEN aws_organization_rollout_targets.last_transition_at
                WHEN aws_organization_rollout_targets.state <> EXCLUDED.state
                THEN EXCLUDED.last_transition_at
                ELSE aws_organization_rollout_targets.last_transition_at
            END,
            last_validation_at = COALESCE(EXCLUDED.last_validation_at, aws_organization_rollout_targets.last_validation_at),
            updated_at = EXCLUDED.updated_at,
            version = aws_organization_rollout_targets.version + 1
        RETURNING `+awsOrganizationRolloutTargetColumns,
		normalized.RolloutID,
		normalized.AccountID,
		normalized.Region,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.AccountName,
		normalized.OUPath,
		normalized.IsManagement,
		normalized.State,
		normalized.StackInstanceID,
		normalized.StackID,
		normalized.RoleARN,
		normalized.FailureCode,
		normalized.FailureMessage,
		normalized.Retryable,
		normalized.EvidenceRef,
		normalized.RegisterRequestID,
		normalized.LastTransitionAt,
		normalized.LastValidationAt,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	upserted, err := scanAWSOrganizationRolloutTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSOrganizationRolloutTarget{}, ErrConflict
	}
	if isTenancyFKViolation(err) {
		return AWSOrganizationRolloutTarget{}, ErrNotFound
	}
	return upserted, err
}

func (p *PostgresStore) ResetAWSOrganizationRolloutTarget(ctx context.Context, target AWSOrganizationRolloutTarget, expectedVersion int64) (AWSOrganizationRolloutTarget, error) {
	normalized, err := normalizeAWSOrganizationRolloutTarget(ctx, target)
	if err != nil {
		return AWSOrganizationRolloutTarget{}, err
	}
	now := time.Now().UTC()
	row := p.queryRowContext(ctx, `
        UPDATE aws_organization_rollout_targets
		SET state = CASE WHEN NULLIF(role_arn, '') IS NULL THEN 'pending' ELSE 'validating' END,
            failure_code = NULL,
            failure_message = NULL,
            retryable = TRUE,
            last_transition_at = $8,
            updated_at = $8,
            version = version + 1
        WHERE rollout_id = $1 AND account_id = $2 AND region = $3
          AND tenant_id = $4 AND workspace_id = $5 AND project_id = $6
          AND version = $7
          AND retryable = TRUE
          AND state IN ('failed', 'partial')
          AND EXISTS (
              SELECT 1
              FROM aws_organization_rollouts AS rollout
              JOIN tenancy_connectors AS controlling_connector
                ON controlling_connector.tenant_id = rollout.tenant_id
               AND controlling_connector.workspace_id = rollout.workspace_id
               AND controlling_connector.project_id = rollout.project_id
               AND controlling_connector.connector_id = rollout.controlling_connector_id
              WHERE rollout.rollout_id = aws_organization_rollout_targets.rollout_id
                AND rollout.tenant_id = aws_organization_rollout_targets.tenant_id
                AND rollout.workspace_id = aws_organization_rollout_targets.workspace_id
                AND rollout.project_id = aws_organization_rollout_targets.project_id
                AND rollout.status IN ('created', 'launching', 'in_progress', 'reconciling', 'partial', 'failed')
                AND rollout.expires_at > $8
                AND controlling_connector.type = 'aws'
                AND controlling_connector.status = 'active'
                AND controlling_connector.disabled = FALSE
                AND controlling_connector.lifecycle_generation = rollout.controlling_connector_lifecycle_generation
              FOR UPDATE OF rollout, controlling_connector
          )
        RETURNING `+awsOrganizationRolloutTargetColumns,
		normalized.RolloutID,
		normalized.AccountID,
		normalized.Region,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		expectedVersion,
		now,
	)
	updated, err := scanAWSOrganizationRolloutTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSOrganizationRolloutTarget{}, ErrConflict
	}
	return updated, err
}

func (p *PostgresStore) GetAWSOrganizationRolloutTarget(ctx context.Context, rolloutID string, accountID string, region string) (AWSOrganizationRolloutTarget, error) {
	row := p.queryRowContextAnyScope(ctx, `SELECT `+awsOrganizationRolloutTargetColumns+`
        FROM aws_organization_rollout_targets
        WHERE rollout_id = $1 AND account_id = $2 AND region = $3`,
		strings.TrimSpace(rolloutID),
		strings.TrimSpace(accountID),
		strings.ToLower(strings.TrimSpace(region)))
	target, err := scanAWSOrganizationRolloutTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AWSOrganizationRolloutTarget{}, ErrNotFound
	}
	return target, err
}

func (p *PostgresStore) ListAWSOrganizationRolloutTargets(ctx context.Context, workspaceID string, projectID string, rolloutID string) ([]AWSOrganizationRolloutTarget, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(ctx, `SELECT `+awsOrganizationRolloutTargetColumns+`
        FROM aws_organization_rollout_targets
        WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND rollout_id = $4
        ORDER BY account_id ASC, region ASC`,
		scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(rolloutID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AWSOrganizationRolloutTarget, 0)
	for rows.Next() {
		target, scanErr := scanAWSOrganizationRolloutTarget(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, target)
	}
	return out, rows.Err()
}

func marshalAWSOrganizationRolloutJSON(rollout AWSOrganizationRollout) ([]byte, []byte, []byte, []byte, error) {
	selectedOUs, err := json.Marshal(rollout.SelectedOUIDs)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	selectedAccounts, err := json.Marshal(rollout.SelectedAccountIDs)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	excludedAccounts, err := json.Marshal(rollout.ExcludedAccountIDs)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	regions, err := json.Marshal(rollout.TargetRegions)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return selectedOUs, selectedAccounts, excludedAccounts, regions, nil
}

func scanAWSOrganizationRollout(row rowScanner) (AWSOrganizationRollout, error) {
	var rollout AWSOrganizationRollout
	var selectedOUs, selectedAccounts, excludedAccounts, regions []byte
	err := row.Scan(
		&rollout.RolloutID,
		&rollout.TenantID,
		&rollout.WorkspaceID,
		&rollout.ProjectID,
		&rollout.ControllingConnectorID,
		&rollout.ControllingRole,
		&rollout.OrganizationID,
		&rollout.ManagementAccountID,
		&rollout.Partition,
		&rollout.DeploymentMode,
		&rollout.StackSetName,
		&rollout.ExpectedRoleName,
		&rollout.TemplateVersion,
		&rollout.TemplateChecksum,
		&rollout.RegistrationSecretHash,
		&rollout.RegistrationSecretKeyVersion,
		&selectedOUs,
		&selectedAccounts,
		&excludedAccounts,
		&regions,
		&rollout.AutoDeployNewAccounts,
		&rollout.Status,
		&rollout.FailureCode,
		&rollout.FailureMessage,
		&rollout.ExpiresAt,
		&rollout.CreatedAt,
		&rollout.UpdatedAt,
		&rollout.Version,
		&rollout.ControllingConnectorLifecycleGeneration,
	)
	if err != nil {
		return AWSOrganizationRollout{}, err
	}
	if unmarshalErr := unmarshalStringSlice(selectedOUs, &rollout.SelectedOUIDs); unmarshalErr != nil {
		return AWSOrganizationRollout{}, unmarshalErr
	}
	if unmarshalErr := unmarshalStringSlice(selectedAccounts, &rollout.SelectedAccountIDs); unmarshalErr != nil {
		return AWSOrganizationRollout{}, unmarshalErr
	}
	if unmarshalErr := unmarshalStringSlice(excludedAccounts, &rollout.ExcludedAccountIDs); unmarshalErr != nil {
		return AWSOrganizationRollout{}, unmarshalErr
	}
	if unmarshalErr := unmarshalStringSlice(regions, &rollout.TargetRegions); unmarshalErr != nil {
		return AWSOrganizationRollout{}, unmarshalErr
	}
	return rollout, nil
}

func scanAWSOrganizationRolloutTarget(row rowScanner) (AWSOrganizationRolloutTarget, error) {
	var target AWSOrganizationRolloutTarget
	err := row.Scan(
		&target.RolloutID,
		&target.AccountID,
		&target.Region,
		&target.TenantID,
		&target.WorkspaceID,
		&target.ProjectID,
		&target.AccountName,
		&target.OUPath,
		&target.IsManagement,
		&target.State,
		&target.StackInstanceID,
		&target.StackID,
		&target.RoleARN,
		&target.FailureCode,
		&target.FailureMessage,
		&target.Retryable,
		&target.EvidenceRef,
		&target.RegisterRequestID,
		&target.LastTransitionAt,
		&target.LastValidationAt,
		&target.CreatedAt,
		&target.UpdatedAt,
		&target.Version,
	)
	return target, err
}

func unmarshalStringSlice(data []byte, out *[]string) error {
	if len(data) == 0 {
		*out = []string{}
		return nil
	}
	return json.Unmarshal(data, out)
}
