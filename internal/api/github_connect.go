package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/google/uuid"
)

const (
	defaultGitHubAppSlug  = "identrail"
	githubConnectStateTTL = 15 * time.Minute
)

var githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// ErrInvalidGitHubConnectionRequest indicates invalid GitHub connect request input.
var ErrInvalidGitHubConnectionRequest = errors.New("invalid github connection request")

// ErrGitHubConnectionNotFound indicates one scoped project GitHub connection does not exist.
var ErrGitHubConnectionNotFound = errors.New("github connection not found")

// ErrGitHubConnectStateNotFound indicates an expired or unknown connect state token.
var ErrGitHubConnectStateNotFound = errors.New("github connect state not found")

// ErrGitHubWebhookSignatureInvalid indicates a webhook signature mismatch.
var ErrGitHubWebhookSignatureInvalid = errors.New("github webhook signature invalid")

// ErrInvalidGitHubWebhookPayload indicates an invalid webhook payload.
var ErrInvalidGitHubWebhookPayload = errors.New("invalid github webhook payload")

// GitHubConnectionStartRequest captures one project-scoped connection bootstrap request.
type GitHubConnectionStartRequest struct {
	AppSlug     string `json:"app_slug,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// GitHubConnectionStartResponse returns state and install URL used to complete setup.
type GitHubConnectionStartResponse struct {
	State      string    `json:"state"`
	ConnectURL string    `json:"connect_url"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// GitHubConnectionCompleteRequest captures one connect completion payload.
type GitHubConnectionCompleteRequest struct {
	State                  string   `json:"state"`
	InstallationID         int64    `json:"installation_id"`
	AccountLogin           string   `json:"account_login"`
	TokenReference         string   `json:"token_reference"`
	WebhookSecret          string   `json:"webhook_secret"`
	WebhookSecretReference string   `json:"webhook_secret_reference"`
	SelectedRepositories   []string `json:"selected_repositories"`
}

// GitHubConnectionRepositorySelectionRequest updates selected repositories for one project.
type GitHubConnectionRepositorySelectionRequest struct {
	Repositories []string `json:"repositories"`
}

// GitHubConnectionStatus describes current GitHub integration state for one project.
type GitHubConnectionStatus struct {
	Provider               string     `json:"provider"`
	Connected              bool       `json:"connected"`
	AccountLogin           string     `json:"account_login,omitempty"`
	InstallationID         int64      `json:"installation_id,omitempty"`
	TokenReference         string     `json:"token_reference,omitempty"`
	WebhookSecretReference string     `json:"webhook_secret_reference,omitempty"`
	SelectedRepositories   []string   `json:"selected_repositories"`
	CreatedAt              *time.Time `json:"created_at,omitempty"`
	UpdatedAt              *time.Time `json:"updated_at,omitempty"`
	LastWebhookEventType   string     `json:"last_webhook_event_type,omitempty"`
	LastWebhookDeliveryID  string     `json:"last_webhook_delivery_id,omitempty"`
	LastWebhookEventAt     *time.Time `json:"last_webhook_event_at,omitempty"`
}

// GitHubWebhookResult summarizes how one webhook event was processed.
type GitHubWebhookResult struct {
	EventType       string `json:"event_type"`
	Repository      string `json:"repository,omitempty"`
	MatchedProjects int    `json:"matched_projects"`
	QueuedScans     int    `json:"queued_scans"`
	SkippedScans    int    `json:"skipped_scans"`
}

type githubConnectState struct {
	TenantID    string
	WorkspaceID string
	ProjectID   string
	ExpiresAt   time.Time
}

type githubProjectConnection struct {
	TenantID               string
	WorkspaceID            string
	ProjectID              string
	AccountLogin           string
	InstallationID         int64
	TokenReference         string
	WebhookSecretReference string
	WebhookSecret          string
	SelectedRepositories   []string
	CreatedAt              time.Time
	UpdatedAt              time.Time
	LastWebhookEventType   string
	LastWebhookDeliveryID  string
	LastWebhookEventAt     *time.Time
}

type githubWebhookEnvelope struct {
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func (s *Service) StartGitHubConnection(ctx context.Context, workspaceID string, projectID string, request GitHubConnectionStartRequest) (GitHubConnectionStartResponse, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubConnectionStartResponse{}, err
	}

	now := s.Now().UTC()
	state := uuid.NewString()
	expiresAt := now.Add(githubConnectStateTTL)
	appSlug := strings.TrimSpace(request.AppSlug)
	if appSlug == "" {
		appSlug = defaultGitHubAppSlug
	}

	values := url.Values{}
	values.Set("state", state)
	if redirect := strings.TrimSpace(request.RedirectURI); redirect != "" {
		values.Set("redirect_uri", redirect)
	}
	connectURL := "https://github.com/apps/" + appSlug + "/installations/new?" + values.Encode()

	s.githubConnectMu.Lock()
	s.ensureGitHubConnectionState()
	s.pruneExpiredGitHubStatesLocked(now)
	s.githubConnectStates[state] = githubConnectState{
		TenantID:    scope.TenantID,
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
		ExpiresAt:   expiresAt,
	}
	s.githubConnectMu.Unlock()

	return GitHubConnectionStartResponse{
		State:      state,
		ConnectURL: connectURL,
		ExpiresAt:  expiresAt,
	}, nil
}

func (s *Service) CompleteGitHubConnection(ctx context.Context, workspaceID string, projectID string, request GitHubConnectionCompleteRequest) (GitHubConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

	normalizedState := strings.TrimSpace(request.State)
	if normalizedState == "" {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}
	normalizedTokenRef := strings.TrimSpace(request.TokenReference)
	normalizedSecretRef := strings.TrimSpace(request.WebhookSecretReference)
	normalizedSecret := strings.TrimSpace(request.WebhookSecret)
	if normalizedTokenRef == "" || normalizedSecretRef == "" || normalizedSecret == "" || request.InstallationID <= 0 {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}

	repositories, err := normalizeGitHubRepositories(request.SelectedRepositories)
	if err != nil {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}

	now := s.Now().UTC()
	key := githubConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)

	s.githubConnectMu.Lock()
	s.ensureGitHubConnectionState()
	s.pruneExpiredGitHubStatesLocked(now)
	stateRecord, ok := s.githubConnectStates[normalizedState]
	if !ok {
		s.githubConnectMu.Unlock()
		return GitHubConnectionStatus{}, ErrGitHubConnectStateNotFound
	}
	if stateRecord.TenantID != scope.TenantID || stateRecord.WorkspaceID != project.WorkspaceID || stateRecord.ProjectID != project.ProjectID {
		s.githubConnectMu.Unlock()
		return GitHubConnectionStatus{}, ErrGitHubConnectStateNotFound
	}
	delete(s.githubConnectStates, normalizedState)

	s.ensureGitHubConnectionsState()
	createdAt := now
	if existing, exists := s.githubConnections[key]; exists {
		createdAt = existing.CreatedAt
	}

	s.githubConnections[key] = githubProjectConnection{
		TenantID:               scope.TenantID,
		WorkspaceID:            project.WorkspaceID,
		ProjectID:              project.ProjectID,
		AccountLogin:           strings.TrimSpace(request.AccountLogin),
		InstallationID:         request.InstallationID,
		TokenReference:         normalizedTokenRef,
		WebhookSecretReference: normalizedSecretRef,
		WebhookSecret:          normalizedSecret,
		SelectedRepositories:   repositories,
		CreatedAt:              createdAt,
		UpdatedAt:              now,
	}
	status := toGitHubConnectionStatus(s.githubConnections[key])
	s.githubConnectMu.Unlock()

	return status, nil
}

func (s *Service) GetGitHubConnection(ctx context.Context, workspaceID string, projectID string) (GitHubConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

	key := githubConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)
	s.githubConnectMu.RLock()
	connection, exists := s.githubConnections[key]
	s.githubConnectMu.RUnlock()
	if !exists {
		return GitHubConnectionStatus{Provider: "github_app", Connected: false, SelectedRepositories: []string{}}, nil
	}
	return toGitHubConnectionStatus(connection), nil
}

func (s *Service) UpdateGitHubConnectionRepositories(ctx context.Context, workspaceID string, projectID string, request GitHubConnectionRepositorySelectionRequest) (GitHubConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

	repositories, err := normalizeGitHubRepositories(request.Repositories)
	if err != nil {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}
	if len(repositories) == 0 {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}

	key := githubConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)
	now := s.Now().UTC()

	s.githubConnectMu.Lock()
	connection, exists := s.githubConnections[key]
	if !exists {
		s.githubConnectMu.Unlock()
		return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
	}
	connection.SelectedRepositories = repositories
	connection.UpdatedAt = now
	s.githubConnections[key] = connection
	status := toGitHubConnectionStatus(connection)
	s.githubConnectMu.Unlock()

	return status, nil
}

func (s *Service) HandleGitHubWebhook(ctx context.Context, eventType string, deliveryID string, signature string, payload []byte) (GitHubWebhookResult, error) {
	normalizedEventType := strings.ToLower(strings.TrimSpace(eventType))
	if normalizedEventType == "" || len(payload) == 0 {
		return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
	}

	var envelope githubWebhookEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
	}
	repository := normalizeGitHubRepository(envelope.Repository.FullName)
	if repository == "" {
		return GitHubWebhookResult{EventType: normalizedEventType}, nil
	}

	installationID := envelope.Installation.ID
	normalizedSignature := strings.TrimSpace(signature)

	if !s.verifyGitHubWebhookSignatureForInstallation(installationID, payload, normalizedSignature) {
		return GitHubWebhookResult{}, ErrGitHubWebhookSignatureInvalid
	}

	candidates := s.lookupGitHubConnectionsByRepository(repository, installationID)
	if len(candidates) == 0 {
		return GitHubWebhookResult{EventType: normalizedEventType, Repository: repository}, nil
	}

	validConnections := make([]githubProjectConnection, 0, len(candidates))
	for _, candidate := range candidates {
		if validateGitHubWebhookSignature(candidate.WebhookSecret, payload, normalizedSignature) {
			validConnections = append(validConnections, candidate)
		}
	}
	if len(validConnections) == 0 {
		return GitHubWebhookResult{}, ErrGitHubWebhookSignatureInvalid
	}

	result := GitHubWebhookResult{
		EventType:       normalizedEventType,
		Repository:      repository,
		MatchedProjects: len(validConnections),
	}

	now := s.Now().UTC()
	s.recordGitHubWebhookDelivery(validConnections, normalizedEventType, strings.TrimSpace(deliveryID), now)

	if !githubWebhookTriggersScan(normalizedEventType) {
		return result, nil
	}

	for _, connection := range validConnections {
		scopedCtx := db.WithScope(ctx, db.Scope{TenantID: connection.TenantID, WorkspaceID: connection.WorkspaceID})
		_, err := s.EnqueueRepoScan(scopedCtx, RepoScanRequest{Repository: repository})
		if err != nil {
			if errors.Is(err, ErrRepoScanInProgress) ||
				errors.Is(err, ErrRepoScanQueueFull) ||
				errors.Is(err, ErrRepoScanDisabled) ||
				errors.Is(err, ErrRepoTargetNotAllowed) ||
				errors.Is(err, ErrInvalidRepoScanRequest) {
				result.SkippedScans++
				continue
			}
			return GitHubWebhookResult{}, err
		}
		result.QueuedScans++
	}

	return result, nil
}

func (s *Service) verifyGitHubWebhookSignatureForInstallation(installationID int64, payload []byte, signature string) bool {
	s.githubConnectMu.RLock()
	defer s.githubConnectMu.RUnlock()

	for _, connection := range s.githubConnections {
		if connection.InstallationID != installationID {
			continue
		}
		if validateGitHubWebhookSignature(connection.WebhookSecret, payload, signature) {
			return true
		}
	}
	return false
}

func (s *Service) lookupGitHubConnectionsByRepository(repository string, installationID int64) []githubProjectConnection {
	s.githubConnectMu.RLock()
	defer s.githubConnectMu.RUnlock()

	matches := make([]githubProjectConnection, 0)
	for _, connection := range s.githubConnections {
		if connection.InstallationID != installationID {
			continue
		}
		if !repositorySelected(connection.SelectedRepositories, repository) {
			continue
		}
		matches = append(matches, connection)
	}
	return matches
}

func (s *Service) recordGitHubWebhookDelivery(connections []githubProjectConnection, eventType string, deliveryID string, now time.Time) {
	s.githubConnectMu.Lock()
	defer s.githubConnectMu.Unlock()
	for _, connection := range connections {
		key := githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)
		current, exists := s.githubConnections[key]
		if !exists {
			continue
		}
		current.LastWebhookEventType = eventType
		current.LastWebhookDeliveryID = deliveryID
		eventAt := now
		current.LastWebhookEventAt = &eventAt
		current.UpdatedAt = now
		s.githubConnections[key] = current
	}
}

func (s *Service) requireScopedProject(ctx context.Context, workspaceID string, projectID string) (db.TenancyProject, db.Scope, error) {
	ctx = s.scopeContext(ctx)
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return db.TenancyProject{}, db.Scope{}, err
	}

	normalizedWorkspaceID, err := db.ResolveScopedWorkspaceID(scope, workspaceID)
	if err != nil {
		return db.TenancyProject{}, db.Scope{}, err
	}
	normalizedProjectID := strings.TrimSpace(projectID)
	if normalizedProjectID == "" {
		return db.TenancyProject{}, db.Scope{}, ErrInvalidGitHubConnectionRequest
	}

	project, err := s.Store.GetProject(ctx, normalizedWorkspaceID, normalizedProjectID)
	if err != nil {
		return db.TenancyProject{}, db.Scope{}, err
	}
	return project, db.Scope{TenantID: scope.TenantID, WorkspaceID: normalizedWorkspaceID}, nil
}

func (s *Service) ensureGitHubConnectionState() {
	if s.githubConnectStates == nil {
		s.githubConnectStates = make(map[string]githubConnectState)
	}
}

func (s *Service) ensureGitHubConnectionsState() {
	if s.githubConnections == nil {
		s.githubConnections = make(map[string]githubProjectConnection)
	}
}

func (s *Service) pruneExpiredGitHubStatesLocked(now time.Time) {
	for state, record := range s.githubConnectStates {
		if record.ExpiresAt.After(now) {
			continue
		}
		delete(s.githubConnectStates, state)
	}
}

func githubConnectionKey(tenantID string, workspaceID string, projectID string) string {
	return strings.ToLower(strings.TrimSpace(tenantID)) + "::" + strings.ToLower(strings.TrimSpace(workspaceID)) + "::" + strings.ToLower(strings.TrimSpace(projectID))
}

func normalizeGitHubRepositories(repositories []string) ([]string, error) {
	if len(repositories) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(repositories))
	normalized := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		item := normalizeGitHubRepository(repository)
		if item == "" || !githubRepositoryPattern.MatchString(item) {
			return nil, fmt.Errorf("invalid repository %q", repository)
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeGitHubRepository(repository string) string {
	return strings.ToLower(strings.TrimSpace(repository))
}

func toGitHubConnectionStatus(connection githubProjectConnection) GitHubConnectionStatus {
	createdAt := connection.CreatedAt
	updatedAt := connection.UpdatedAt
	status := GitHubConnectionStatus{
		Provider:               "github_app",
		Connected:              true,
		AccountLogin:           connection.AccountLogin,
		InstallationID:         connection.InstallationID,
		TokenReference:         connection.TokenReference,
		WebhookSecretReference: connection.WebhookSecretReference,
		SelectedRepositories:   append([]string(nil), connection.SelectedRepositories...),
		CreatedAt:              &createdAt,
		UpdatedAt:              &updatedAt,
		LastWebhookEventType:   connection.LastWebhookEventType,
		LastWebhookDeliveryID:  connection.LastWebhookDeliveryID,
		LastWebhookEventAt:     connection.LastWebhookEventAt,
	}
	if status.SelectedRepositories == nil {
		status.SelectedRepositories = []string{}
	}
	return status
}

func validateGitHubWebhookSignature(secret string, payload []byte, signature string) bool {
	normalizedSecret := strings.TrimSpace(secret)
	normalizedSignature := strings.TrimSpace(signature)
	if normalizedSecret == "" || normalizedSignature == "" {
		return false
	}
	parts := strings.SplitN(normalizedSignature, "=", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "sha256" {
		return false
	}
	provided := strings.ToLower(strings.TrimSpace(parts[1]))
	if provided == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(normalizedSecret))
	_, _ = mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

func githubWebhookTriggersScan(eventType string) bool {
	switch strings.ToLower(strings.TrimSpace(eventType)) {
	case "push", "pull_request", "repository_dispatch", "workflow_dispatch":
		return true
	default:
		return false
	}
}

func repositorySelected(selected []string, repository string) bool {
	normalizedTarget := normalizeGitHubRepository(repository)
	for _, candidate := range selected {
		if normalizeGitHubRepository(candidate) == normalizedTarget {
			return true
		}
	}
	return false
}

func parseGitHubInstallationID(value string) (int64, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("invalid installation id")
	}
	return parsed, nil
}
