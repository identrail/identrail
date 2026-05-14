package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/identrail/identrail/internal/audit"
)

func scanOnboardingState(row rowScanner) (OnboardingState, error) {
	var state OnboardingState
	var orgID, workspaceID, projectID, connectorID, connectorType sql.NullString
	var dashboardTourDismissedAt, completedAt sql.NullTime
	if err := row.Scan(
		&state.UserID,
		&state.CurrentStep,
		&orgID,
		&workspaceID,
		&projectID,
		&connectorID,
		&connectorType,
		&state.ConnectorSkipped,
		&state.ScanSkipped,
		&dashboardTourDismissedAt,
		&completedAt,
		&state.StartedAt,
		&state.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OnboardingState{}, ErrNotFound
		}
		return OnboardingState{}, err
	}
	state.OrgID = orgID.String
	state.WorkspaceID = workspaceID.String
	state.ProjectID = projectID.String
	state.ConnectorID = connectorID.String
	state.ConnectorType = connectorType.String
	if dashboardTourDismissedAt.Valid {
		state.DashboardTourDismissedAt = &dashboardTourDismissedAt.Time
	}
	if completedAt.Valid {
		state.CompletedAt = &completedAt.Time
	}
	return state, nil
}

// UpsertOnboardingState persists one user-scoped onboarding progress row.
func (p *PostgresStore) UpsertOnboardingState(ctx context.Context, state OnboardingState) (OnboardingState, error) {
	normalized, err := NormalizeOnboardingStateForWrite(state)
	if err != nil {
		return OnboardingState{}, err
	}
	row := p.queryRowContextAnyScope(
		ctx,
		`INSERT INTO onboarding_state (
		     user_id, current_step, org_id, workspace_id, project_id, connector_id, connector_type,
		     connector_skipped, scan_skipped, dashboard_tour_dismissed_at, completed_at, started_at, updated_at
		 )
		 VALUES (
		     NULLIF($1, '')::uuid, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''),
		     NULLIF($6, ''), NULLIF($7, ''), $8, $9, $10, $11, $12, $13
		 )
		 ON CONFLICT (user_id) DO UPDATE
		 SET current_step = EXCLUDED.current_step,
		     org_id = EXCLUDED.org_id,
		     workspace_id = EXCLUDED.workspace_id,
		     project_id = EXCLUDED.project_id,
		     connector_id = EXCLUDED.connector_id,
		     connector_type = EXCLUDED.connector_type,
		     connector_skipped = EXCLUDED.connector_skipped,
		     scan_skipped = EXCLUDED.scan_skipped,
		     dashboard_tour_dismissed_at = EXCLUDED.dashboard_tour_dismissed_at,
		     completed_at = EXCLUDED.completed_at,
		     updated_at = EXCLUDED.updated_at
		 RETURNING user_id::text, current_step, org_id, workspace_id, project_id, connector_id, connector_type,
		           connector_skipped, scan_skipped, dashboard_tour_dismissed_at, completed_at, started_at, updated_at`,
		normalized.UserID,
		normalized.CurrentStep,
		normalized.OrgID,
		normalized.WorkspaceID,
		normalized.ProjectID,
		normalized.ConnectorID,
		normalized.ConnectorType,
		normalized.ConnectorSkipped,
		normalized.ScanSkipped,
		nullTime(normalized.DashboardTourDismissedAt),
		nullTime(normalized.CompletedAt),
		normalized.StartedAt,
		normalized.UpdatedAt,
	)
	saved, err := scanOnboardingState(row)
	if err != nil {
		if isTenancyFKViolation(err) {
			return OnboardingState{}, ErrNotFound
		}
		return OnboardingState{}, err
	}
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "onboarding.state.upsert",
		ResourceType: "onboarding_state",
		ResourceID:   saved.UserID,
		Outcome:      "success",
	})
	return saved, nil
}

// GetOnboardingState returns one user's onboarding progress row.
func (p *PostgresStore) GetOnboardingState(ctx context.Context, userID string) (OnboardingState, error) {
	return scanOnboardingState(p.queryRowContextAnyScope(
		ctx,
		`SELECT user_id::text, current_step, org_id, workspace_id, project_id, connector_id, connector_type,
		        connector_skipped, scan_skipped, dashboard_tour_dismissed_at, completed_at, started_at, updated_at
		 FROM onboarding_state
		 WHERE user_id = NULLIF($1, '')::uuid`,
		strings.TrimSpace(userID),
	))
}
