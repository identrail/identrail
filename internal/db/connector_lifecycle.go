package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/audit"
)

func connectorLifecycleNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC()
	}
	return now.UTC()
}

func connectorLifecycleMetadata(action string, now time.Time) map[string]any {
	return map[string]any{
		"lifecycle_state": action,
		"lifecycle_at":    now.Format(time.RFC3339Nano),
	}
}

func cancelAWSOrganizationRolloutsTx(ctx context.Context, tx *sql.Tx, tenantID string, workspaceID string, projectID string, connectorID string, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE aws_organization_rollouts
		   SET status = 'canceled',
		       failure_code = 'controlling_connector_lifecycle_changed',
		       failure_message = 'The controlling AWS connector was paused or disconnected.',
		       updated_at = $5,
		       version = version + 1
		 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND controlling_connector_id = $4
		   AND status IN ('created', 'launching', 'in_progress', 'reconciling', 'partial', 'failed')`,
		tenantID, workspaceID, projectID, connectorID, now)
	return err
}

// DisconnectTenancyConnector is the authoritative local disconnect action.
// It advances the lifecycle generation, invalidates stored connector secrets,
// and records that provider-side cleanup is still pending. It never claims an
// AWS stack/role was deleted because this operation cannot prove that fact.
func (p *PostgresStore) DisconnectTenancyConnector(ctx context.Context, workspaceID string, projectID string, connectorID string, now time.Time) (TenancyConnectorWithState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	now = connectorLifecycleNow(now)
	metadataPayload, err := json.Marshal(map[string]any{
		"lifecycle_state":        "disconnected",
		"lifecycle_at":           now.Format(time.RFC3339Nano),
		"cleanup_status":         "pending",
		"cleanup_required":       true,
		"external_id_configured": false,
	})
	if err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("marshal disconnect lifecycle metadata: %w", err)
	}

	tx, err := p.beginTx(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	defer tx.Rollback()
	args := []any{scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now}
	result, err := tx.ExecContext(ctx, `
		UPDATE tenancy_connectors
		   SET status = 'disconnected',
		       disabled = FALSE,
		       lifecycle_generation = lifecycle_generation + 1,
		       updated_at = $5
		 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4
		   AND status <> 'disconnected'`, args...)
	if err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("disconnect tenancy connector: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	if affected == 0 {
		var status string
		if err := tx.QueryRowContext(ctx, `
			SELECT status FROM tenancy_connectors
			 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4`, args[:4]...).Scan(&status); err != nil {
			if err == sql.ErrNoRows {
				return TenancyConnectorWithState{}, ErrNotFound
			}
			return TenancyConnectorWithState{}, err
		}
		if status == "disconnected" {
			if err := cancelAWSOrganizationRolloutsTx(ctx, tx, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now); err != nil {
				return TenancyConnectorWithState{}, fmt.Errorf("cancel disconnected connector rollouts: %w", err)
			}
			if err := tx.Commit(); err != nil {
				return TenancyConnectorWithState{}, fmt.Errorf("commit idempotent connector disconnect: %w", err)
			}
			return p.GetTenancyConnector(ctx, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
		}
		return TenancyConnectorWithState{}, ErrConflict
	}
	stateResult, err := tx.ExecContext(ctx, `
		UPDATE tenancy_connector_states
		   SET health_status = 'error',
		       last_error_code = 'connector_disconnected',
		       last_error_message = 'Connector disconnected by an operator.',
		       metadata = (COALESCE(metadata, '{}'::jsonb) - 'external_id') || $5::jsonb,
		       observed_at = $6,
		       updated_at = $6
		 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4`,
		scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), metadataPayload, now)
	if err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("record disconnected connector state: %w", err)
	}
	stateAffected, err := stateResult.RowsAffected()
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	if stateAffected == 0 {
		return TenancyConnectorWithState{}, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM tenancy_connector_secret_envelopes
		 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4`, args[:4]...); err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("invalidate connector secrets: %w", err)
	}
	if err := cancelAWSOrganizationRolloutsTx(ctx, tx, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now); err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("cancel connector rollouts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("commit connector disconnect: %w", err)
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.connector.disconnect",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_connector",
		ResourceID:   strings.TrimSpace(connectorID),
		Outcome:      "success",
	})
	return p.GetTenancyConnector(ctx, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
}

// SetTenancyConnectorDisabled changes the operator eligibility gate atomically.
// A disconnected connector cannot be toggled back into service through this
// method; reactivation must create a fresh onboarding/validation decision.
func (p *PostgresStore) SetTenancyConnectorDisabled(ctx context.Context, workspaceID string, projectID string, connectorID string, disabled bool, now time.Time) (TenancyConnectorWithState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	now = connectorLifecycleNow(now)
	action := "enabled"
	if disabled {
		action = "disabled"
	}
	metadataPayload, err := json.Marshal(connectorLifecycleMetadata(action, now))
	if err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("marshal connector gate metadata: %w", err)
	}
	args := []any{scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), disabled, now}
	tx, err := p.beginTx(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE tenancy_connectors
		   SET disabled = $5,
		       lifecycle_generation = lifecycle_generation + 1,
		       updated_at = $6
		 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4
		   AND status <> 'disconnected'
		   AND disabled <> $5`, args...)
	if err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("set connector disabled state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	if affected == 0 {
		var status string
		var currentDisabled bool
		if err := tx.QueryRowContext(ctx, `
			SELECT status, disabled FROM tenancy_connectors
			 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4`, args[:4]...).Scan(&status, &currentDisabled); err != nil {
			if err == sql.ErrNoRows {
				return TenancyConnectorWithState{}, ErrNotFound
			}
			return TenancyConnectorWithState{}, err
		}
		if status == "disconnected" {
			return TenancyConnectorWithState{}, ErrConflict
		}
		if currentDisabled == disabled {
			if disabled {
				if err := cancelAWSOrganizationRolloutsTx(ctx, tx, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now); err != nil {
					return TenancyConnectorWithState{}, fmt.Errorf("cancel disabled connector rollouts: %w", err)
				}
			}
			if err := tx.Commit(); err != nil {
				return TenancyConnectorWithState{}, fmt.Errorf("commit idempotent connector gate: %w", err)
			}
			return p.GetTenancyConnector(ctx, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
		}
		return TenancyConnectorWithState{}, ErrConflict
	}
	stateResult, err := tx.ExecContext(ctx, `
		UPDATE tenancy_connector_states
		   SET metadata = COALESCE(metadata, '{}'::jsonb) || $5::jsonb,
		       observed_at = $6,
		       updated_at = $6
		 WHERE tenant_id = $1 AND workspace_id = $2 AND project_id = $3 AND connector_id = $4`,
		scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), metadataPayload, now)
	if err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("record connector gate state: %w", err)
	}
	stateAffected, err := stateResult.RowsAffected()
	if err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("inspect connector gate state: %w", err)
	}
	if stateAffected == 0 {
		return TenancyConnectorWithState{}, ErrNotFound
	}
	if disabled {
		if err := cancelAWSOrganizationRolloutsTx(ctx, tx, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now); err != nil {
			return TenancyConnectorWithState{}, fmt.Errorf("cancel disabled connector rollouts: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return TenancyConnectorWithState{}, fmt.Errorf("commit connector gate state: %w", err)
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "tenancy.connector." + action,
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_connector",
		ResourceID:   strings.TrimSpace(connectorID),
		Outcome:      "success",
	})
	return p.GetTenancyConnector(ctx, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
}

// MemoryStore implements the same fenced lifecycle contract used by Postgres.
func (m *MemoryStore) DisconnectTenancyConnector(ctx context.Context, workspaceID string, projectID string, connectorID string, now time.Time) (TenancyConnectorWithState, error) {
	m.mu.Lock()
	var auditEvent *audit.AuditEvent
	defer func() {
		m.mu.Unlock()
		if auditEvent != nil {
			audit.WriteAction(ctx, *auditEvent)
		}
	}()
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	key := tenancyConnectorKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
	connector, ok := m.connectors[key]
	if !ok {
		return TenancyConnectorWithState{}, ErrNotFound
	}
	now = connectorLifecycleNow(now)
	if connector.Status == "disconnected" {
		cancelAWSOrganizationRolloutsLocked(m, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now)
		return TenancyConnectorWithState{Connector: connector, State: cloneTenancyConnectorState(m.connStates[key])}, nil
	}
	connector.Status = "disconnected"
	connector.Disabled = false
	connector.LifecycleGeneration++
	connector.UpdatedAt = now
	state := m.connStates[key]
	state.HealthStatus = "error"
	state.LastErrorCode = "connector_disconnected"
	state.LastErrorMessage = "Connector disconnected by an operator."
	state.Metadata = cloneMetadataMap(state.Metadata)
	state.Metadata["lifecycle_state"] = "disconnected"
	state.Metadata["lifecycle_at"] = now.Format(time.RFC3339Nano)
	state.Metadata["cleanup_status"] = "pending"
	state.Metadata["cleanup_required"] = true
	state.Metadata["external_id_configured"] = false
	delete(state.Metadata, "external_id")
	state.ObservedAt = now
	state.UpdatedAt = now
	m.connectors[key] = connector
	m.connStates[key] = state
	for secretKey := range m.connSecrets {
		if strings.HasPrefix(secretKey, key) {
			delete(m.connSecrets, secretKey)
		}
	}
	cancelAWSOrganizationRolloutsLocked(m, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now)
	auditEvent = &audit.AuditEvent{
		Action:       "tenancy.connector.disconnect",
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_connector",
		ResourceID:   strings.TrimSpace(connectorID),
		Outcome:      "success",
	}
	return TenancyConnectorWithState{Connector: connector, State: cloneTenancyConnectorState(state)}, nil
}

func (m *MemoryStore) SetTenancyConnectorDisabled(ctx context.Context, workspaceID string, projectID string, connectorID string, disabled bool, now time.Time) (TenancyConnectorWithState, error) {
	m.mu.Lock()
	var auditEvent *audit.AuditEvent
	defer func() {
		m.mu.Unlock()
		if auditEvent != nil {
			audit.WriteAction(ctx, *auditEvent)
		}
	}()
	scope, err := RequireScope(ctx)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	resolvedWorkspaceID, err := ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return TenancyConnectorWithState{}, err
	}
	key := tenancyConnectorKey(scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID))
	connector, ok := m.connectors[key]
	if !ok {
		return TenancyConnectorWithState{}, ErrNotFound
	}
	now = connectorLifecycleNow(now)
	if connector.Status == "disconnected" {
		return TenancyConnectorWithState{}, ErrConflict
	}
	if connector.Disabled == disabled {
		if disabled {
			cancelAWSOrganizationRolloutsLocked(m, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now)
		}
		return TenancyConnectorWithState{Connector: connector, State: cloneTenancyConnectorState(m.connStates[key])}, nil
	}
	connector.Disabled = disabled
	connector.LifecycleGeneration++
	connector.UpdatedAt = now
	state := m.connStates[key]
	state.Metadata = cloneMetadataMap(state.Metadata)
	action := "enabled"
	if disabled {
		action = "disabled"
	}
	state.Metadata["lifecycle_state"] = action
	state.Metadata["lifecycle_at"] = now.Format(time.RFC3339Nano)
	state.ObservedAt = now
	state.UpdatedAt = now
	m.connectors[key] = connector
	m.connStates[key] = state
	if disabled {
		cancelAWSOrganizationRolloutsLocked(m, scope.TenantID, resolvedWorkspaceID, strings.TrimSpace(projectID), strings.TrimSpace(connectorID), now)
	}
	auditEvent = &audit.AuditEvent{
		Action:       "tenancy.connector." + action,
		TenantID:     scope.TenantID,
		WorkspaceID:  resolvedWorkspaceID,
		ResourceType: "tenancy_connector",
		ResourceID:   strings.TrimSpace(connectorID),
		Outcome:      "success",
	}
	return TenancyConnectorWithState{Connector: connector, State: cloneTenancyConnectorState(state)}, nil
}

func cancelAWSOrganizationRolloutsLocked(m *MemoryStore, tenantID string, workspaceID string, projectID string, connectorID string, now time.Time) {
	for id, rollout := range m.awsOrgRollouts {
		if rollout.TenantID != tenantID || rollout.WorkspaceID != workspaceID || rollout.ProjectID != projectID || rollout.ControllingConnectorID != connectorID {
			continue
		}
		if !awsOrganizationRolloutTargetMutationAllowed(rollout.Status) {
			continue
		}
		rollout.Status = AWSOrganizationRolloutStatusCanceled
		rollout.FailureCode = "controlling_connector_lifecycle_changed"
		rollout.FailureMessage = "The controlling AWS connector was paused or disconnected."
		rollout.UpdatedAt = now
		rollout.Version++
		m.awsOrgRollouts[id] = cloneAWSOrganizationRollout(rollout)
	}
}

func cloneTenancyConnectorState(state TenancyConnectorState) TenancyConnectorState {
	state.Metadata = cloneMetadataMap(state.Metadata)
	return state
}
