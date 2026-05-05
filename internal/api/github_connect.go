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

	"github.com/Oluwatobi-Mustapha/identrail/internal/audit"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/secretstore"
	"github.com/google/uuid"
)

const (
	defaultGitHubAppSlug              = "identrail"
	persistedGitHubConnectorID        = "github-app"
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

type persistedGitHubConnectorState struct {
	AccountLogin           string               `json:"account_login,omitempty"`
	InstallationID         int64                `json:"installation_id,omitempty"`
	TokenReference         string               `json:"token_reference,omitempty"`
	WebhookSecretReference string               `json:"webhook_secret_reference,omitempty"`
	WebhookSecretEnvelope  secretstore.Envelope `json:"webhook_secret_envelope"`
	SelectedRepositories   []string             `json:"selected_repositories,omitempty"`
	LastWebhookEventType   string               `json:"last_webhook_event_type,omitempty"`
	LastWebhookDeliveryID  string               `json:"last_webhook_delivery_id,omitempty"`
	LastWebhookEventAt     *time.Time           `json:"last_webhook_event_at,omitempty"`
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
	s.githubConnectMu.Unlock()

	status, err := s.persistGitHubConnection(ctx, project.WorkspaceID, project.ProjectID, githubProjectConnection{
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
		UpdatedAt:              now,
	})
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

	auditGitHubConnectorAction(ctx, "connector.github.connection.complete", scope, project.ProjectID, "success")
	return status, nil
}

func (s *Service) GetGitHubConnection(ctx context.Context, workspaceID string, projectID string) (GitHubConnectionStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

	connection, err := s.loadGitHubConnection(ctx, project.WorkspaceID, project.ProjectID)
	if errors.Is(err, db.ErrNotFound) {
		return GitHubConnectionStatus{Provider: "github_app", Connected: false, SelectedRepositories: []string{}}, nil
	}
	if err != nil {
		return GitHubConnectionStatus{}, err
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

	now := s.Now().UTC()
	connection, err := s.loadGitHubConnection(ctx, project.WorkspaceID, project.ProjectID)
	if errors.Is(err, db.ErrNotFound) {
		return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
	}
	if err != nil {
		return GitHubConnectionStatus{}, err
	}
	connection.SelectedRepositories = repositories
	connection.UpdatedAt = now
	status, err := s.persistGitHubConnection(ctx, project.WorkspaceID, project.ProjectID, connection)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

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

	now := s.Now().UTC()
	connection, err := s.loadGitHubConnection(ctx, project.WorkspaceID, project.ProjectID)
	if errors.Is(err, db.ErrNotFound) {
		return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
	}
	if err != nil {
		return GitHubConnectionStatus{}, err
	}
	connection.WebhookSecretReference = normalizedSecretRef
	connection.WebhookSecretEnvelope = envelope
	connection.WebhookSecretRotatedAt = now
	connection.UpdatedAt = now
	status, err := s.persistGitHubConnection(ctx, project.WorkspaceID, project.ProjectID, connection)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}

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
	connections, err := s.listAllGitHubConnections(context.Background())
	if err != nil {
		return false
	}
	for _, connection := range connections {
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
	connections, err := s.listAllGitHubConnections(context.Background())
	if err != nil {
		return []githubProjectConnection{}
	}
	matches := make([]githubProjectConnection, 0)
	for _, connection := range connections {
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
	for _, connection := range connections {
		current := connection
		current.LastWebhookEventType = eventType
		current.LastWebhookDeliveryID = deliveryID
		eventAt := now
		current.LastWebhookEventAt = &eventAt
		current.UpdatedAt = now
		_, _ = s.persistGitHubConnection(
			db.WithScope(context.Background(), db.Scope{TenantID: current.TenantID, WorkspaceID: current.WorkspaceID}),
			current.WorkspaceID,
			current.ProjectID,
			current,
		)
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

func (s *Service) pruneExpiredGitHubStatesLocked(now time.Time) {
	for state, record := range s.githubConnectStates {
		if record.ExpiresAt.After(now) {
			continue
		}
		delete(s.githubConnectStates, state)
	}
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

func (s *Service) persistGitHubConnection(ctx context.Context, workspaceID string, projectID string, connection githubProjectConnection) (GitHubConnectionStatus, error) {
	now := s.Now().UTC()
	metadata, err := persistedGitHubConnectorState{
		AccountLogin:           connection.AccountLogin,
		InstallationID:         connection.InstallationID,
		TokenReference:         connection.TokenReference,
		WebhookSecretReference: connection.WebhookSecretReference,
		WebhookSecretEnvelope:  connection.WebhookSecretEnvelope,
		SelectedRepositories:   append([]string(nil), connection.SelectedRepositories...),
		LastWebhookEventType:   connection.LastWebhookEventType,
		LastWebhookDeliveryID:  connection.LastWebhookDeliveryID,
		LastWebhookEventAt:     connection.LastWebhookEventAt,
	}.toMap()
	if err != nil {
		return GitHubConnectionStatus{}, fmt.Errorf("encode github connector metadata: %w", err)
	}
	var rotatedAt *time.Time
	if !connection.WebhookSecretRotatedAt.IsZero() {
		value := connection.WebhookSecretRotatedAt.UTC()
		rotatedAt = &value
	}
	state := db.TenancyConnectorState{
		WorkspaceID:  workspaceID,
		ProjectID:    projectID,
		ConnectorID:  persistedGitHubConnectorID,
		HealthStatus: "healthy",
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    connection.UpdatedAt,
	}
	connector := db.TenancyConnector{
		WorkspaceID:         workspaceID,
		ProjectID:           projectID,
		ConnectorID:         persistedGitHubConnectorID,
		Type:                domain.ConnectorTypeGitHub,
		DisplayName:         firstNonEmptyGitHubValue(connection.AccountLogin, "GitHub App"),
		Status:              domain.ConnectorStatusActive,
		SecretLastRotatedAt: rotatedAt,
		CreatedAt:           connection.CreatedAt,
		UpdatedAt:           connection.UpdatedAt,
	}
	if err := s.Store.UpsertTenancyConnector(ctx, connector, state); err != nil {
		return GitHubConnectionStatus{}, fmt.Errorf("persist github connector: %w", err)
	}
	stored, err := s.Store.GetTenancyConnector(ctx, workspaceID, projectID, persistedGitHubConnectorID)
	if err != nil {
		return GitHubConnectionStatus{}, fmt.Errorf("load github connector: %w", err)
	}
	decoded, err := githubConnectionFromStored(stored)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}
	return s.toGitHubConnectionStatus(decoded), nil
}

func (s *Service) loadGitHubConnection(ctx context.Context, workspaceID string, projectID string) (githubProjectConnection, error) {
	stored, err := s.Store.GetTenancyConnector(ctx, workspaceID, projectID, persistedGitHubConnectorID)
	if err != nil {
		return githubProjectConnection{}, err
	}
	return githubConnectionFromStored(stored)
}

func (s *Service) listAllGitHubConnections(ctx context.Context) ([]githubProjectConnection, error) {
	items, err := s.Store.ListAllTenancyConnectorsByType(ctx, domain.ConnectorTypeGitHub, 0)
	if err != nil {
		return nil, err
	}
	result := make([]githubProjectConnection, 0, len(items))
	for _, item := range items {
		connection, convErr := githubConnectionFromStored(item)
		if convErr != nil {
			continue
		}
		result = append(result, connection)
	}
	return result, nil
}

func githubConnectionFromStored(stored db.TenancyConnectorWithState) (githubProjectConnection, error) {
	metadata, err := decodePersistedGitHubConnectorState(stored.State.Metadata)
	if err != nil {
		return githubProjectConnection{}, fmt.Errorf("decode github connector metadata: %w", err)
	}
	connection := githubProjectConnection{
		TenantID:               stored.Connector.TenantID,
		WorkspaceID:            stored.Connector.WorkspaceID,
		ProjectID:              stored.Connector.ProjectID,
		AccountLogin:           metadata.AccountLogin,
		InstallationID:         metadata.InstallationID,
		TokenReference:         metadata.TokenReference,
		WebhookSecretReference: metadata.WebhookSecretReference,
		WebhookSecretEnvelope:  metadata.WebhookSecretEnvelope,
		SelectedRepositories:   append([]string(nil), metadata.SelectedRepositories...),
		CreatedAt:              stored.Connector.CreatedAt,
		UpdatedAt:              stored.Connector.UpdatedAt,
		LastWebhookEventType:   metadata.LastWebhookEventType,
		LastWebhookDeliveryID:  metadata.LastWebhookDeliveryID,
		LastWebhookEventAt:     metadata.LastWebhookEventAt,
	}
	if !stored.Connector.SecretLastRotatedAt.IsZero() {
		connection.WebhookSecretRotatedAt = stored.Connector.SecretLastRotatedAt.UTC()
	}
	return connection, nil
}

func (state persistedGitHubConnectorState) toMap() (map[string]any, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var metadata map[string]any
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func decodePersistedGitHubConnectorState(metadata map[string]any) (persistedGitHubConnectorState, error) {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return persistedGitHubConnectorState{}, err
	}
	var state persistedGitHubConnectorState
	if err := json.Unmarshal(payload, &state); err != nil {
		return persistedGitHubConnectorState{}, err
	}
	if state.SelectedRepositories == nil {
		state.SelectedRepositories = []string{}
	}
	return state, nil
}

func firstNonEmptyGitHubValue(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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
