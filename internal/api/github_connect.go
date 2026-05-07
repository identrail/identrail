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

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/secretstore"
)

const (
	defaultGitHubAppSlug              = "identrail"
	githubConnectStateTTL             = 15 * time.Minute
	githubWebhookSecretRotationWindow = 90 * 24 * time.Hour
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

// ErrGitHubConnectorSecretUnavailable indicates connector secret crypto failed.
var ErrGitHubConnectorSecretUnavailable = errors.New("github connector secret unavailable")

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

// GitHubConnectionSecretRotationRequest captures one webhook secret rotation.
type GitHubConnectionSecretRotationRequest struct {
	WebhookSecret          string `json:"webhook_secret"`
	WebhookSecretReference string `json:"webhook_secret_reference"`
}

// GitHubConnectionStatus describes current GitHub integration state for one project.
type GitHubConnectionStatus struct {
	Provider                      string     `json:"provider"`
	Connected                     bool       `json:"connected"`
	AccountLogin                  string     `json:"account_login,omitempty"`
	InstallationID                int64      `json:"installation_id,omitempty"`
	TokenReference                string     `json:"token_reference,omitempty"`
	WebhookSecretReference        string     `json:"webhook_secret_reference,omitempty"`
	WebhookSecretKeyVersion       string     `json:"webhook_secret_key_version,omitempty"`
	WebhookSecretAlgorithm        string     `json:"webhook_secret_algorithm,omitempty"`
	WebhookSecretRotatedAt        *time.Time `json:"webhook_secret_rotated_at,omitempty"`
	WebhookSecretRotationDueAt    *time.Time `json:"webhook_secret_rotation_due_at,omitempty"`
	WebhookSecretRotationRequired bool       `json:"webhook_secret_rotation_required"`
	SelectedRepositories          []string   `json:"selected_repositories"`
	CreatedAt                     *time.Time `json:"created_at,omitempty"`
	UpdatedAt                     *time.Time `json:"updated_at,omitempty"`
	LastWebhookEventType          string     `json:"last_webhook_event_type,omitempty"`
	LastWebhookDeliveryID         string     `json:"last_webhook_delivery_id,omitempty"`
	LastWebhookEventAt            *time.Time `json:"last_webhook_event_at,omitempty"`
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
	WebhookSecretEnvelope  secretstore.Envelope
	WebhookSecretRotatedAt time.Time
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
	envelope, err := s.encryptGitHubWebhookSecret(scope, project.ProjectID, normalizedSecret)
	if err != nil {
		return GitHubConnectionStatus{}, ErrGitHubConnectorSecretUnavailable
	}

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
		WebhookSecretEnvelope:  envelope,
		WebhookSecretRotatedAt: now,
		SelectedRepositories:   repositories,
		CreatedAt:              createdAt,
		UpdatedAt:              now,
	}
	status := s.toGitHubConnectionStatus(s.githubConnections[key])
	s.githubConnectMu.Unlock()

	auditGitHubConnectorAction(ctx, "connector.github.connection.complete", scope, project.ProjectID, "success")
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
	return s.toGitHubConnectionStatus(connection), nil
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
	status := s.toGitHubConnectionStatus(connection)
	s.githubConnectMu.Unlock()

	auditGitHubConnectorAction(ctx, "connector.github.repositories.update", scope, project.ProjectID, "success")
	return status, nil
}

func (s *Service) RotateGitHubConnectionSecret(ctx context.Context, workspaceID string, projectID string, request GitHubConnectionSecretRotationRequest) (GitHubConnectionStatus, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

	normalizedSecretRef := strings.TrimSpace(request.WebhookSecretReference)
	normalizedSecret := strings.TrimSpace(request.WebhookSecret)
	if normalizedSecretRef == "" || normalizedSecret == "" {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}

	envelope, err := s.encryptGitHubWebhookSecret(scope, project.ProjectID, normalizedSecret)
	if err != nil {
		return GitHubConnectionStatus{}, ErrGitHubConnectorSecretUnavailable
	}

	key := githubConnectionKey(scope.TenantID, project.WorkspaceID, project.ProjectID)
	now := s.Now().UTC()
	s.githubConnectMu.Lock()
	connection, exists := s.githubConnections[key]
	if !exists {
		s.githubConnectMu.Unlock()
		return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
	}
	connection.WebhookSecretReference = normalizedSecretRef
	connection.WebhookSecretEnvelope = envelope
	connection.WebhookSecretRotatedAt = now
	connection.UpdatedAt = now
	s.githubConnections[key] = connection
	status := s.toGitHubConnectionStatus(connection)
	s.githubConnectMu.Unlock()

	auditGitHubConnectorAction(ctx, "connector.github.webhook_secret.rotate", scope, project.ProjectID, "success")
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
	installationID := envelope.Installation.ID
	normalizedSignature := strings.TrimSpace(signature)

	if !s.verifyGitHubWebhookSignatureForInstallation(installationID, payload, normalizedSignature) {
		return GitHubWebhookResult{}, ErrGitHubWebhookSignatureInvalid
	}

	repository := normalizeGitHubRepository(envelope.Repository.FullName)
	if repository == "" {
		return GitHubWebhookResult{EventType: normalizedEventType}, nil
	}

	candidates := s.lookupGitHubConnectionsByRepository(repository, installationID)
	if len(candidates) == 0 {
		return GitHubWebhookResult{EventType: normalizedEventType, Repository: repository}, nil
	}

	validConnections := make([]githubProjectConnection, 0, len(candidates))
	for _, candidate := range candidates {
		if s.validateGitHubWebhookSignatureForConnection(candidate, payload, normalizedSignature) {
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
		if s.validateGitHubWebhookSignatureForConnection(connection, payload, signature) {
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
	return gitHubConnectionStatus(connection, nil, time.Now().UTC())
}

func (s *Service) toGitHubConnectionStatus(connection githubProjectConnection) GitHubConnectionStatus {
	now := time.Now().UTC()
	if s != nil && s.Now != nil {
		now = s.Now().UTC()
	}
	return gitHubConnectionStatus(connection, s.connectorSecretManager(), now)
}

func gitHubConnectionStatus(connection githubProjectConnection, manager *secretstore.Manager, now time.Time) GitHubConnectionStatus {
	createdAt := connection.CreatedAt
	updatedAt := connection.UpdatedAt
	rotatedAt := connection.WebhookSecretRotatedAt
	var rotatedAtPtr *time.Time
	var rotationDueAtPtr *time.Time
	if !rotatedAt.IsZero() {
		rotatedAtPtr = &rotatedAt
		rotationDueAt := rotatedAt.Add(githubWebhookSecretRotationWindow)
		rotationDueAtPtr = &rotationDueAt
	}
	status := GitHubConnectionStatus{
		Provider:                      "github_app",
		Connected:                     true,
		AccountLogin:                  connection.AccountLogin,
		InstallationID:                connection.InstallationID,
		TokenReference:                connection.TokenReference,
		WebhookSecretReference:        connection.WebhookSecretReference,
		WebhookSecretKeyVersion:       connection.WebhookSecretEnvelope.KeyVersion,
		WebhookSecretAlgorithm:        connection.WebhookSecretEnvelope.Algorithm,
		WebhookSecretRotatedAt:        rotatedAtPtr,
		WebhookSecretRotationDueAt:    rotationDueAtPtr,
		WebhookSecretRotationRequired: connectorSecretRotationRequired(manager, connection.WebhookSecretEnvelope, rotatedAt, now),
		SelectedRepositories:          append([]string(nil), connection.SelectedRepositories...),
		CreatedAt:                     &createdAt,
		UpdatedAt:                     &updatedAt,
		LastWebhookEventType:          connection.LastWebhookEventType,
		LastWebhookDeliveryID:         connection.LastWebhookDeliveryID,
		LastWebhookEventAt:            connection.LastWebhookEventAt,
	}
	if status.SelectedRepositories == nil {
		status.SelectedRepositories = []string{}
	}
	return status
}

func connectorSecretRotationRequired(manager *secretstore.Manager, envelope secretstore.Envelope, rotatedAt time.Time, now time.Time) bool {
	if strings.TrimSpace(envelope.KeyVersion) == "" || strings.TrimSpace(envelope.Algorithm) == "" {
		return true
	}
	if manager != nil && manager.NeedsRotation(envelope) {
		return true
	}
	if rotatedAt.IsZero() {
		return true
	}
	return now.UTC().After(rotatedAt.Add(githubWebhookSecretRotationWindow))
}

func (s *Service) encryptGitHubWebhookSecret(scope db.Scope, projectID string, secret string) (secretstore.Envelope, error) {
	manager := s.connectorSecretManager()
	return manager.Encrypt([]byte(secret), githubWebhookSecretAAD(scope, projectID))
}

func (s *Service) decryptGitHubWebhookSecret(connection githubProjectConnection) (string, error) {
	manager := s.connectorSecretManager()
	plaintext, err := manager.Decrypt(connection.WebhookSecretEnvelope, githubWebhookSecretAAD(
		db.Scope{TenantID: connection.TenantID, WorkspaceID: connection.WorkspaceID},
		connection.ProjectID,
	))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (s *Service) validateGitHubWebhookSignatureForConnection(connection githubProjectConnection, payload []byte, signature string) bool {
	secret, err := s.decryptGitHubWebhookSecret(connection)
	if err != nil {
		return false
	}
	return validateGitHubWebhookSignature(secret, payload, signature)
}

func (s *Service) connectorSecretManager() *secretstore.Manager {
	if s != nil && s.ConnectorSecretManager != nil {
		return s.ConnectorSecretManager
	}
	return secretstore.NewEphemeralManager()
}

func githubWebhookSecretAAD(scope db.Scope, projectID string) []byte {
	parts := []string{
		"github",
		"webhook_secret",
		strings.ToLower(strings.TrimSpace(scope.TenantID)),
		strings.ToLower(strings.TrimSpace(scope.WorkspaceID)),
		strings.ToLower(strings.TrimSpace(projectID)),
	}
	return []byte(strings.Join(parts, "\x00"))
}

func auditGitHubConnectorAction(ctx context.Context, action string, scope db.Scope, projectID string, outcome string) {
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       action,
		TenantID:     scope.TenantID,
		WorkspaceID:  scope.WorkspaceID,
		ResourceType: "github_connector",
		ResourceID:   strings.TrimSpace(projectID),
		Outcome:      outcome,
	})
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
