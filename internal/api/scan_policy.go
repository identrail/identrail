package api

import (
	"context"
	"errors"
	"strings"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/scheduler"
)

// ErrInvalidScanPolicyRequest indicates invalid scan policy API input.
var ErrInvalidScanPolicyRequest = errors.New("invalid scan policy request")

// ErrScanPolicyStoreUnavailable indicates the configured store does not support scan policies.
var ErrScanPolicyStoreUnavailable = errors.New("scan policy store unavailable")

// ScanPolicyUpsertRequest captures one project scan policy write payload.
type ScanPolicyUpsertRequest struct {
	PolicyID           string `json:"policy_id"`
	Name               string `json:"name"`
	Enabled            *bool  `json:"enabled,omitempty"`
	TriggerMode        string `json:"trigger_mode,omitempty"`
	Cron               string `json:"cron,omitempty"`
	MaxConcurrentScans int    `json:"max_concurrent_scans,omitempty"`
	HistoryLimit       int    `json:"history_limit,omitempty"`
	MaxFindings        int    `json:"max_findings,omitempty"`
}

// ScanPolicyListFilter narrows scan policy list queries.
type ScanPolicyListFilter struct {
	TriggerMode string
	Enabled     *bool
	SortBy      string
	SortDesc    bool
	Limit       int
}

type scanPolicyStore interface {
	UpsertTenancyScanPolicy(ctx context.Context, policy db.TenancyScanPolicy) error
	GetTenancyScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) (db.TenancyScanPolicy, error)
	ListTenancyScanPolicies(ctx context.Context, workspaceID string, projectID string, triggerMode domain.ScanTriggerMode, enabled *bool, sortBy string, sortDesc bool, limit int) ([]db.TenancyScanPolicy, error)
	DeleteTenancyScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) error
}

func (s *Service) resolveScanPolicyStore() (scanPolicyStore, error) {
	store, ok := s.Store.(scanPolicyStore)
	if !ok {
		return nil, ErrScanPolicyStoreUnavailable
	}
	return store, nil
}

// ListScanPolicies lists project-scoped scan policies.
func (s *Service) ListScanPolicies(ctx context.Context, workspaceID string, projectID string, filter ScanPolicyListFilter) ([]db.TenancyScanPolicy, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return nil, err
	}
	scopedCtx := db.WithScope(ctx, scope)
	store, err := s.resolveScanPolicyStore()
	if err != nil {
		return nil, err
	}
	triggerMode, err := normalizeScanTriggerMode(filter.TriggerMode, true)
	if err != nil {
		return nil, err
	}
	return store.ListTenancyScanPolicies(scopedCtx, project.WorkspaceID, project.ProjectID, triggerMode, filter.Enabled, filter.SortBy, filter.SortDesc, filter.Limit)
}

// GetScanPolicy returns one project-scoped scan policy by id.
func (s *Service) GetScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) (db.TenancyScanPolicy, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return db.TenancyScanPolicy{}, err
	}
	scopedCtx := db.WithScope(ctx, scope)
	store, err := s.resolveScanPolicyStore()
	if err != nil {
		return db.TenancyScanPolicy{}, err
	}
	return store.GetTenancyScanPolicy(scopedCtx, project.WorkspaceID, project.ProjectID, strings.TrimSpace(policyID))
}

// UpsertScanPolicy creates or updates one project-scoped scan policy.
func (s *Service) UpsertScanPolicy(ctx context.Context, workspaceID string, projectID string, request ScanPolicyUpsertRequest) (db.TenancyScanPolicy, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return db.TenancyScanPolicy{}, err
	}
	scopedCtx := db.WithScope(ctx, scope)
	store, err := s.resolveScanPolicyStore()
	if err != nil {
		return db.TenancyScanPolicy{}, err
	}
	triggerMode, err := normalizeScanTriggerMode(request.TriggerMode, false)
	if err != nil {
		return db.TenancyScanPolicy{}, err
	}
	if triggerMode == domain.ScanTriggerModeScheduled || triggerMode == domain.ScanTriggerModeHybrid {
		if _, err := scheduler.ParseCronSchedule(request.Cron); err != nil {
			return db.TenancyScanPolicy{}, ErrInvalidScanPolicyRequest
		}
	}
	historyLimit, err := sanitizeScanPolicyLimit(request.HistoryLimit, s.RepoScanDefaultHistoryLimit, s.RepoScanMaxHistoryLimit)
	if err != nil {
		return db.TenancyScanPolicy{}, err
	}
	maxFindings, err := sanitizeScanPolicyLimit(request.MaxFindings, s.RepoScanDefaultMaxFindings, s.RepoScanMaxFindingsLimit)
	if err != nil {
		return db.TenancyScanPolicy{}, err
	}
	enabled := true
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	maxConcurrent := request.MaxConcurrentScans
	if maxConcurrent < 0 {
		return db.TenancyScanPolicy{}, ErrInvalidScanPolicyRequest
	}
	if maxConcurrent == 0 {
		maxConcurrent = 1
	}
	policy, err := db.NormalizeTenancyScanPolicyForWrite(db.TenancyScanPolicy{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		PolicyID:           strings.TrimSpace(request.PolicyID),
		Name:               strings.TrimSpace(request.Name),
		Enabled:            enabled,
		TriggerMode:        triggerMode,
		Cron:               strings.TrimSpace(request.Cron),
		MaxConcurrentScans: maxConcurrent,
		HistoryLimit:       historyLimit,
		MaxFindings:        maxFindings,
	})
	if err != nil {
		return db.TenancyScanPolicy{}, ErrInvalidScanPolicyRequest
	}
	if err := store.UpsertTenancyScanPolicy(scopedCtx, policy); err != nil {
		return db.TenancyScanPolicy{}, err
	}
	return store.GetTenancyScanPolicy(scopedCtx, policy.WorkspaceID, policy.ProjectID, policy.PolicyID)
}

// DeleteScanPolicy removes one project-scoped scan policy by id.
func (s *Service) DeleteScanPolicy(ctx context.Context, workspaceID string, projectID string, policyID string) error {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return err
	}
	scopedCtx := db.WithScope(ctx, scope)
	store, err := s.resolveScanPolicyStore()
	if err != nil {
		return err
	}
	return store.DeleteTenancyScanPolicy(scopedCtx, project.WorkspaceID, project.ProjectID, strings.TrimSpace(policyID))
}

func normalizeScanTriggerMode(raw string, allowEmpty bool) (domain.ScanTriggerMode, error) {
	mode := domain.ScanTriggerMode(strings.ToLower(strings.TrimSpace(raw)))
	if mode == "" {
		if allowEmpty {
			return "", nil
		}
		return domain.ScanTriggerModeManual, nil
	}
	switch mode {
	case domain.ScanTriggerModeManual, domain.ScanTriggerModeScheduled, domain.ScanTriggerModeEvent, domain.ScanTriggerModeHybrid:
		return mode, nil
	default:
		return "", ErrInvalidScanPolicyRequest
	}
}

func sanitizeScanPolicyLimit(candidate int, fallback int, maxAllowed int) (int, error) {
	if fallback <= 0 {
		fallback = 1
	}
	if maxAllowed <= 0 {
		maxAllowed = fallback
	}
	if candidate < 0 {
		return 0, ErrInvalidScanPolicyRequest
	}
	if candidate == 0 {
		candidate = fallback
	}
	if candidate > maxAllowed {
		return 0, ErrInvalidScanPolicyRequest
	}
	return candidate, nil
}
