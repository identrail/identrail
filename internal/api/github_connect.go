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
	githubconnector "github.com/identrail/identrail/internal/connectors/github"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	defaultGitHubAppSlug              = "identrail"
	githubConnectStateTTL             = 15 * time.Minute
	githubWebhookSecretRotationWindow = 90 * 24 * time.Hour
	githubConnectorID                 = "github-app"
	githubWebhookSecretName           = "webhook_secret"
	githubPATSecretName               = "pat_token"
	githubConnectorDisplayName        = "GitHub App"
	githubPATConnectorDisplayName     = "GitHub Enterprise"
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

// ErrGitHubAppConfigUnavailable indicates the hosted GitHub App flow is not configured.
var ErrGitHubAppConfigUnavailable = errors.New("github app config unavailable")

// ErrGitHubRepositoryListUnavailable indicates the GitHub App repository list could not be loaded.
var ErrGitHubRepositoryListUnavailable = errors.New("github repository list unavailable")

// ErrGitHubPATValidatorUnavailable indicates PAT validation is not configured.
var ErrGitHubPATValidatorUnavailable = errors.New("github pat validator unavailable")

// GitHubPATValidator validates a GitHub.com or GHES personal access token.
type GitHubPATValidator interface {
	ValidateGitHubPAT(ctx context.Context, baseURL string, token string) (githubconnector.PATValidationResult, error)
}

// GitHubRepositoryLister lists repositories available to a GitHub App installation.
type GitHubRepositoryLister interface {
	ListInstallationRepositories(ctx context.Context, installationID int64) ([]githubconnector.Repository, error)
}

// GitHubConnectorStartRequest captures the flat connector GitHub App bootstrap request.
type GitHubConnectorStartRequest struct {
	WorkspaceID string `json:"workspace_id,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	ConnectorID string `json:"connector_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// GitHubConnectorStartResponse returns the hosted GitHub App installation flow.
type GitHubConnectorStartResponse struct {
	Connection  GitHubConnectionStatus `json:"connection"`
	ConnectorID string                 `json:"connector_id"`
	State       string                 `json:"state"`
	InstallURL  string                 `json:"install_url"`
	WebhookURL  string                 `json:"webhook_url,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at"`
}

// GitHubConnectorCompleteRequest captures the GitHub App installation callback payload.
type GitHubConnectorCompleteRequest struct {
	State          string `json:"state"`
	InstallationID int64  `json:"installation_id"`
	SetupAction    string `json:"setup_action,omitempty"`
	AccountLogin   string `json:"account_login,omitempty"`
}

// GitHubConnectorCompleteResponse returns the activated connector and app redirect target.
type GitHubConnectorCompleteResponse struct {
	Connection   GitHubConnectionStatus `json:"connection"`
	TenantID     string                 `json:"tenant_id"`
	WorkspaceID  string                 `json:"workspace_id"`
	ProjectID    string                 `json:"project_id"`
	RedirectPath string                 `json:"redirect_path"`
}

// GitHubPATConnectorRequest captures the self-hosted GitHub Enterprise fallback flow.
type GitHubPATConnectorRequest struct {
	WorkspaceID          string   `json:"workspace_id,omitempty"`
	ProjectID            string   `json:"project_id,omitempty"`
	ConnectorID          string   `json:"connector_id,omitempty"`
	DisplayName          string   `json:"display_name,omitempty"`
	BaseURL              string   `json:"base_url,omitempty"`
	Token                string   `json:"token"`
	SelectedRepositories []string `json:"selected_repositories,omitempty"`
}

// GitHubRepositoryStatus is returned by the flat connector repository list.
type GitHubRepositoryStatus struct {
	FullName string `json:"full_name"`
	Private  bool   `json:"private,omitempty"`
}

// GitHubRepositoryListResponse lists stored or provider-visible repositories.
type GitHubRepositoryListResponse struct {
	ConnectorID  string                   `json:"connector_id"`
	Provider     string                   `json:"provider"`
	Repositories []GitHubRepositoryStatus `json:"repositories"`
}

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
	Provider                      string                 `json:"provider"`
	Connected                     bool                   `json:"connected"`
	ConnectorID                   string                 `json:"connector_id,omitempty"`
	DisplayName                   string                 `json:"display_name,omitempty"`
	Status                        domain.ConnectorStatus `json:"status,omitempty"`
	HealthStatus                  string                 `json:"health_status,omitempty"`
	AccountLogin                  string                 `json:"account_login,omitempty"`
	InstallationID                int64                  `json:"installation_id,omitempty"`
	BaseURL                       string                 `json:"base_url,omitempty"`
	Scopes                        []string               `json:"scopes,omitempty"`
	TokenReference                string                 `json:"token_reference,omitempty"`
	WebhookSecretReference        string                 `json:"webhook_secret_reference,omitempty"`
	WebhookSecretKeyVersion       string                 `json:"webhook_secret_key_version,omitempty"`
	WebhookSecretAlgorithm        string                 `json:"webhook_secret_algorithm,omitempty"`
	WebhookSecretRotatedAt        *time.Time             `json:"webhook_secret_rotated_at,omitempty"`
	WebhookSecretRotationDueAt    *time.Time             `json:"webhook_secret_rotation_due_at,omitempty"`
	WebhookSecretRotationRequired bool                   `json:"webhook_secret_rotation_required"`
	SelectedRepositories          []string               `json:"selected_repositories"`
	CreatedAt                     *time.Time             `json:"created_at,omitempty"`
	UpdatedAt                     *time.Time             `json:"updated_at,omitempty"`
	LastWebhookEventType          string                 `json:"last_webhook_event_type,omitempty"`
	LastWebhookDeliveryID         string                 `json:"last_webhook_delivery_id,omitempty"`
	LastWebhookEventAt            *time.Time             `json:"last_webhook_event_at,omitempty"`
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
	TenantID                  string
	WorkspaceID               string
	ProjectID                 string
	ConnectorID               string
	DisplayName               string
	Status                    domain.ConnectorStatus
	HealthStatus              string
	Provider                  string
	AccountLogin              string
	InstallationID            int64
	BaseURL                   string
	Scopes                    []string
	TokenReference            string
	WebhookSecretReference    string
	WebhookSecretEnvelope     secretstore.Envelope
	WebhookSecretRotatedAt    time.Time
	SelectedRepositories      []string
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
	LastWebhookEventType      string
	LastWebhookDeliveryID     string
	LastWebhookEventAt        *time.Time
	LastWebhookScanRepository string
	LastWebhookScanQueuedAt   *time.Time
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

func (s *Service) StartGitHubConnector(ctx context.Context, request GitHubConnectorStartRequest) (GitHubConnectorStartResponse, error) {
	if strings.TrimSpace(request.ProjectID) == "" {
		return GitHubConnectorStartResponse{}, ErrInvalidGitHubConnectionRequest
	}
	project, scope, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return GitHubConnectorStartResponse{}, err
	}
	appSlug := strings.TrimSpace(s.GitHubAppName)
	if appSlug == "" || strings.TrimSpace(s.GitHubAppWebhookSecret) == "" {
		return GitHubConnectorStartResponse{}, ErrGitHubAppConfigUnavailable
	}
	now := s.Now().UTC()
	state := uuid.NewString()
	expiresAt := now.Add(githubConnectStateTTL)
	installURL, err := githubconnector.BuildInstallURL(appSlug, state, request.RedirectURI)
	if err != nil {
		return GitHubConnectorStartResponse{}, ErrInvalidGitHubConnectionRequest
	}
	connectorID := strings.TrimSpace(request.ConnectorID)
	if connectorID == "" {
		connectorID = githubConnectorID
	}
	displayName := firstNonEmptyString(strings.TrimSpace(request.DisplayName), githubConnectorDisplayName)

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

	metadata := map[string]any{
		"provider":              "github_app",
		"state":                 state,
		"install_url":           installURL,
		"app_slug":              appSlug,
		"redirect_uri":          strings.TrimSpace(request.RedirectURI),
		"state_expires_at":      expiresAt.Format(time.RFC3339Nano),
		"selected_repositories": []string{},
		"last_started_at":       now.Format(time.RFC3339Nano),
	}
	connector := db.TenancyConnector{
		TenantID:    scope.TenantID,
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
		ConnectorID: connectorID,
		Type:        domain.ConnectorTypeGitHub,
		DisplayName: displayName,
		Status:      domain.ConnectorStatusPending,
		UpdatedAt:   now,
	}
	stateRecord := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  connectorID,
		HealthStatus: "unknown",
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	if err := s.Store.UpsertTenancyConnector(ctx, connector, stateRecord); err != nil {
		return GitHubConnectorStartResponse{}, fmt.Errorf("persist github connector start: %w", err)
	}
	status := GitHubConnectionStatus{
		Provider:             "github_app",
		Connected:            false,
		ConnectorID:          connectorID,
		DisplayName:          displayName,
		Status:               domain.ConnectorStatusPending,
		HealthStatus:         "unknown",
		SelectedRepositories: []string{},
		CreatedAt:            &now,
		UpdatedAt:            &now,
	}
	return GitHubConnectorStartResponse{
		Connection:  status,
		ConnectorID: connectorID,
		State:       state,
		InstallURL:  installURL,
		WebhookURL:  "/auth/webhooks/github",
		ExpiresAt:   expiresAt,
	}, nil
}

func (s *Service) CompleteGitHubConnector(ctx context.Context, request GitHubConnectorCompleteRequest) (GitHubConnectorCompleteResponse, error) {
	normalizedState := strings.TrimSpace(request.State)
	if normalizedState == "" || request.InstallationID <= 0 {
		return GitHubConnectorCompleteResponse{}, ErrInvalidGitHubConnectionRequest
	}
	if strings.TrimSpace(s.GitHubAppWebhookSecret) == "" {
		return GitHubConnectorCompleteResponse{}, ErrGitHubAppConfigUnavailable
	}
	if s.Store == nil {
		return GitHubConnectorCompleteResponse{}, db.ErrNotFound
	}
	now := s.Now().UTC()
	items, err := s.Store.ListTenancyConnectorsUnscoped(ctx, domain.ConnectorTypeGitHub, 0)
	if err != nil {
		return GitHubConnectorCompleteResponse{}, fmt.Errorf("list github connector states: %w", err)
	}
	var pending *db.TenancyConnectorWithState
	for index := range items {
		item := items[index]
		if item.Connector.Status != domain.ConnectorStatusPending {
			continue
		}
		if firstNonEmptyString(metadataString(item.State.Metadata, "provider"), "github_app") != "github_app" {
			continue
		}
		if metadataString(item.State.Metadata, "state") != normalizedState {
			continue
		}
		pending = &item
		break
	}
	if pending == nil {
		return GitHubConnectorCompleteResponse{}, ErrGitHubConnectStateNotFound
	}
	expiresAt := metadataTime(pending.State.Metadata, "state_expires_at")
	if !expiresAt.IsZero() && now.After(expiresAt) {
		return GitHubConnectorCompleteResponse{}, ErrGitHubConnectStateNotFound
	}
	scope := db.Scope{TenantID: pending.Connector.TenantID, WorkspaceID: pending.Connector.WorkspaceID}
	repositories := metadataStringSlice(pending.State.Metadata, "selected_repositories")
	if s.GitHubRepositoryLister == nil {
		return GitHubConnectorCompleteResponse{}, ErrGitHubRepositoryListUnavailable
	}
	listed, listErr := s.GitHubRepositoryLister.ListInstallationRepositories(ctx, request.InstallationID)
	if listErr != nil {
		return GitHubConnectorCompleteResponse{}, ErrGitHubRepositoryListUnavailable
	}
	repositories = repositories[:0]
	for _, repository := range listed {
		if normalized := normalizeGitHubRepository(repository.FullName); normalized != "" {
			repositories = append(repositories, normalized)
		}
	}
	sort.Strings(repositories)
	webhookEnvelope, err := s.encryptGitHubWebhookSecret(scope, pending.Connector.ProjectID, s.GitHubAppWebhookSecret)
	if err != nil {
		return GitHubConnectorCompleteResponse{}, ErrGitHubConnectorSecretUnavailable
	}
	createdAt := pending.Connector.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	connection := githubProjectConnection{
		TenantID:               pending.Connector.TenantID,
		WorkspaceID:            pending.Connector.WorkspaceID,
		ProjectID:              pending.Connector.ProjectID,
		ConnectorID:            firstNonEmptyString(pending.Connector.ConnectorID, githubConnectorID),
		DisplayName:            firstNonEmptyString(pending.Connector.DisplayName, githubConnectorDisplayName),
		Status:                 domain.ConnectorStatusActive,
		HealthStatus:           "healthy",
		Provider:               "github_app",
		AccountLogin:           strings.TrimSpace(request.AccountLogin),
		InstallationID:         request.InstallationID,
		TokenReference:         fmt.Sprintf("github-app-installation:%d", request.InstallationID),
		WebhookSecretReference: "github-app:webhook",
		WebhookSecretEnvelope:  webhookEnvelope,
		WebhookSecretRotatedAt: now,
		SelectedRepositories:   repositories,
		CreatedAt:              createdAt,
		UpdatedAt:              now,
	}
	if err := s.persistGitHubConnection(ctx, connection); err != nil {
		return GitHubConnectorCompleteResponse{}, err
	}
	s.githubConnectMu.Lock()
	s.ensureGitHubConnectionsState()
	s.githubConnections[githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)] = connection
	delete(s.githubConnectStates, normalizedState)
	s.githubConnectMu.Unlock()
	status := s.toGitHubConnectionStatus(connection)
	redirectPath := "/app/" + url.PathEscape(connection.TenantID) + "/" + url.PathEscape(connection.WorkspaceID) + "/projects/" + url.PathEscape(connection.ProjectID)
	return GitHubConnectorCompleteResponse{
		Connection:   status,
		TenantID:     connection.TenantID,
		WorkspaceID:  connection.WorkspaceID,
		ProjectID:    connection.ProjectID,
		RedirectPath: redirectPath,
	}, nil
}

func (s *Service) UpsertGitHubPATConnector(ctx context.Context, request GitHubPATConnectorRequest) (GitHubConnectionStatus, error) {
	if strings.TrimSpace(request.ProjectID) == "" {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}
	project, scope, err := s.requireScopedProject(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}
	if s.GitHubPATValidator == nil {
		return GitHubConnectionStatus{}, ErrGitHubPATValidatorUnavailable
	}
	baseURL, err := githubconnector.NormalizeBaseURL(request.BaseURL)
	if err != nil {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}
	repositories, err := normalizeGitHubRepositories(request.SelectedRepositories)
	if err != nil {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}
	token := strings.TrimSpace(request.Token)
	if token == "" {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}
	validation, err := s.GitHubPATValidator.ValidateGitHubPAT(ctx, baseURL, token)
	if err != nil {
		return GitHubConnectionStatus{}, ErrInvalidGitHubConnectionRequest
	}
	now := s.Now().UTC()
	connectorID := strings.TrimSpace(request.ConnectorID)
	if connectorID == "" {
		connectorID = "github-pat"
	}
	displayName := firstNonEmptyString(strings.TrimSpace(request.DisplayName), githubPATConnectorDisplayName)
	envelope, err := s.encryptGitHubPAT(scope, project.ProjectID, connectorID, token)
	if err != nil {
		return GitHubConnectionStatus{}, ErrGitHubConnectorSecretUnavailable
	}
	metadata := map[string]any{
		"provider":              "github_pat",
		"base_url":              baseURL,
		"account_login":         strings.TrimSpace(validation.Login),
		"scopes":                append([]string(nil), validation.Scopes...),
		"selected_repositories": repositories,
		"last_validated_at":     now.Format(time.RFC3339Nano),
	}
	connector := db.TenancyConnector{
		TenantID:            scope.TenantID,
		WorkspaceID:         project.WorkspaceID,
		ProjectID:           project.ProjectID,
		ConnectorID:         connectorID,
		Type:                domain.ConnectorTypeGitHub,
		DisplayName:         displayName,
		Status:              domain.ConnectorStatusActive,
		SecretProvider:      "secret-envelope",
		SecretRefID:         githubPATSecretRef(connectorID),
		SecretRefVersion:    envelope.KeyVersion,
		SecretLastRotatedAt: &now,
		UpdatedAt:           now,
	}
	stateRecord := db.TenancyConnectorState{
		TenantID:     scope.TenantID,
		WorkspaceID:  project.WorkspaceID,
		ProjectID:    project.ProjectID,
		ConnectorID:  connectorID,
		HealthStatus: "healthy",
		Metadata:     metadata,
		ObservedAt:   now,
		UpdatedAt:    now,
	}
	if err := s.Store.UpsertTenancyConnector(ctx, connector, stateRecord); err != nil {
		return GitHubConnectionStatus{}, fmt.Errorf("persist github pat connector: %w", err)
	}
	secret := db.TenancyConnectorSecretEnvelope{
		TenantID:        scope.TenantID,
		WorkspaceID:     project.WorkspaceID,
		ProjectID:       project.ProjectID,
		ConnectorID:     connectorID,
		SecretName:      githubPATSecretName,
		EnvelopeVersion: envelope.Version,
		Envelope:        envelope,
		SecretRefID:     githubPATSecretRef(connectorID),
		RotatedAt:       now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.Store.UpsertTenancyConnectorSecretEnvelope(ctx, secret); err != nil {
		return GitHubConnectionStatus{}, fmt.Errorf("persist github pat envelope: %w", err)
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
	if err != nil {
		return GitHubConnectionStatus{}, fmt.Errorf("load github pat connector: %w", err)
	}
	return gitHubConnectionStatusFromStored(stored), nil
}

func (s *Service) GetGitHubConnectorStatus(ctx context.Context, workspaceID string, projectID string) (GitHubConnectionStatus, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubConnectionStatus{}, err
	}
	items, err := s.Store.ListTenancyConnectors(ctx, project.WorkspaceID, project.ProjectID, domain.ConnectorTypeGitHub, 10)
	if err != nil {
		return GitHubConnectionStatus{}, fmt.Errorf("list github connectors: %w", err)
	}
	if len(items) == 0 {
		return GitHubConnectionStatus{
			Provider:             "github_app",
			Connected:            false,
			Status:               domain.ConnectorStatusPending,
			HealthStatus:         "unknown",
			SelectedRepositories: []string{},
			Scopes:               []string{},
		}, nil
	}
	selected := items[0]
	for _, item := range items {
		if item.Connector.Status == domain.ConnectorStatusActive {
			selected = item
			break
		}
	}
	return gitHubConnectionStatusFromStored(selected), nil
}

func (s *Service) GetGitHubConnectorRepositories(ctx context.Context, connectorID string, workspaceID string, projectID string) (GitHubRepositoryListResponse, error) {
	project, _, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return GitHubRepositoryListResponse{}, err
	}
	connectorID = strings.TrimSpace(connectorID)
	if connectorID == "" {
		return GitHubRepositoryListResponse{}, ErrInvalidGitHubConnectionRequest
	}
	stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
	if err != nil {
		return GitHubRepositoryListResponse{}, err
	}
	provider := firstNonEmptyString(metadataString(stored.State.Metadata, "provider"), "github_app")
	repositories := []GitHubRepositoryStatus{}
	if provider == "github_app" && s.GitHubRepositoryLister != nil {
		installationID := metadataInt64(stored.State.Metadata, "installation_id")
		if installationID > 0 {
			listed, listErr := s.GitHubRepositoryLister.ListInstallationRepositories(ctx, installationID)
			if listErr == nil {
				for _, repository := range listed {
					repositories = append(repositories, GitHubRepositoryStatus{
						FullName: normalizeGitHubRepository(repository.FullName),
						Private:  repository.Private,
					})
				}
			}
		}
	}
	if len(repositories) == 0 {
		for _, repository := range metadataStringSlice(stored.State.Metadata, "selected_repositories") {
			repositories = append(repositories, GitHubRepositoryStatus{FullName: normalizeGitHubRepository(repository)})
		}
	}
	sort.Slice(repositories, func(i, j int) bool {
		return repositories[i].FullName < repositories[j].FullName
	})
	return GitHubRepositoryListResponse{
		ConnectorID:  stored.Connector.ConnectorID,
		Provider:     provider,
		Repositories: repositories,
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
		ConnectorID:            githubConnectorID,
		DisplayName:            githubConnectorDisplayName,
		Status:                 domain.ConnectorStatusActive,
		HealthStatus:           "healthy",
		Provider:               "github_app",
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
	persisted := s.githubConnections[key]
	status := s.toGitHubConnectionStatus(persisted)
	s.githubConnectMu.Unlock()
	if err := s.persistGitHubConnection(ctx, persisted); err != nil {
		return GitHubConnectionStatus{}, err
	}

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
		loaded, loadErr := s.loadGitHubConnection(ctx, scope, project.WorkspaceID, project.ProjectID)
		if loadErr != nil && !errors.Is(loadErr, db.ErrNotFound) {
			return GitHubConnectionStatus{}, loadErr
		}
		if !loaded {
			return s.GetGitHubConnectorStatus(ctx, project.WorkspaceID, project.ProjectID)
		}
		s.githubConnectMu.RLock()
		connection, exists = s.githubConnections[key]
		s.githubConnectMu.RUnlock()
		if !exists {
			return s.GetGitHubConnectorStatus(ctx, project.WorkspaceID, project.ProjectID)
		}
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
		loaded, loadErr := s.loadGitHubConnection(ctx, scope, project.WorkspaceID, project.ProjectID)
		if loadErr != nil {
			return GitHubConnectionStatus{}, loadErr
		}
		if !loaded {
			return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
		}
		s.githubConnectMu.Lock()
		connection, exists = s.githubConnections[key]
		if !exists {
			s.githubConnectMu.Unlock()
			return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
		}
	}
	updated := connection
	updated.SelectedRepositories = repositories
	updated.UpdatedAt = now
	s.githubConnectMu.Unlock()
	if err := s.persistGitHubConnection(ctx, updated); err != nil {
		return GitHubConnectionStatus{}, err
	}
	s.githubConnectMu.Lock()
	s.githubConnections[key] = updated
	status := s.toGitHubConnectionStatus(updated)
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
		loaded, loadErr := s.loadGitHubConnection(ctx, scope, project.WorkspaceID, project.ProjectID)
		if loadErr != nil {
			return GitHubConnectionStatus{}, loadErr
		}
		if !loaded {
			return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
		}
		s.githubConnectMu.Lock()
		connection, exists = s.githubConnections[key]
		if !exists {
			s.githubConnectMu.Unlock()
			return GitHubConnectionStatus{}, ErrGitHubConnectionNotFound
		}
	}
	updated := connection
	updated.WebhookSecretReference = normalizedSecretRef
	updated.WebhookSecretEnvelope = envelope
	updated.WebhookSecretRotatedAt = now
	updated.UpdatedAt = now
	s.githubConnectMu.Unlock()
	if err := s.persistGitHubConnection(ctx, updated); err != nil {
		return GitHubConnectionStatus{}, err
	}
	s.githubConnectMu.Lock()
	s.githubConnections[key] = updated
	status := s.toGitHubConnectionStatus(updated)
	s.githubConnectMu.Unlock()

	auditGitHubConnectorAction(ctx, "connector.github.webhook_secret.rotate", scope, project.ProjectID, "success")
	return status, nil
}

func (s *Service) HandleGitHubWebhook(ctx context.Context, eventType string, deliveryID string, signature string, payload []byte) (GitHubWebhookResult, error) {
	ctx, span := otel.Tracer("identrail/automation").Start(ctx, "automation.github_webhook")
	defer span.End()

	normalizedEventType := strings.ToLower(strings.TrimSpace(eventType))
	if normalizedEventType == "" || len(payload) == 0 {
		span.SetStatus(codes.Error, "invalid github webhook payload")
		return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
	}
	span.SetAttributes(attribute.String("github.event_type", normalizedEventType))

	var envelope githubWebhookEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid github webhook payload")
		return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
	}
	installationID := envelope.Installation.ID
	normalizedSignature := strings.TrimSpace(signature)

	if !s.verifyGitHubWebhookSignatureForInstallation(installationID, payload, normalizedSignature) {
		span.SetStatus(codes.Error, "github webhook signature invalid")
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
		span.SetStatus(codes.Error, "github webhook signature invalid")
		return GitHubWebhookResult{}, ErrGitHubWebhookSignatureInvalid
	}

	result, err := s.processGitHubWebhookConnections(ctx, span, normalizedEventType, deliveryID, repository, validConnections)
	if err != nil {
		return GitHubWebhookResult{}, err
	}
	return result, nil
}

func (s *Service) HandleGitHubAppWebhook(ctx context.Context, eventType string, deliveryID string, signature string, payload []byte) (GitHubWebhookResult, error) {
	normalizedEventType := strings.ToLower(strings.TrimSpace(eventType))
	if normalizedEventType == "" || len(payload) == 0 {
		return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
	}
	if !githubconnector.VerifyWebhookSignature(s.GitHubAppWebhookSecret, payload, signature) {
		return GitHubWebhookResult{}, ErrGitHubWebhookSignatureInvalid
	}
	if normalizedEventType == "installation" {
		event, err := githubconnector.ParseInstallationEvent(payload)
		if err != nil {
			return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
		}
		return GitHubWebhookResult{
			EventType:       event.Action,
			MatchedProjects: s.markGitHubInstallationDisconnected(ctx, event),
		}, nil
	}
	if normalizedEventType == "installation_repositories" {
		event, err := githubconnector.ParseInstallationRepositoriesEvent(payload)
		if err != nil {
			return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
		}
		return GitHubWebhookResult{
			EventType:       event.Action,
			MatchedProjects: s.reconcileGitHubInstallationRepositories(ctx, event),
		}, nil
	}
	var envelope githubWebhookEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return GitHubWebhookResult{}, ErrInvalidGitHubWebhookPayload
	}
	repository := normalizeGitHubRepository(envelope.Repository.FullName)
	if repository == "" {
		return GitHubWebhookResult{EventType: normalizedEventType}, nil
	}
	candidates := s.lookupGitHubConnectionsByRepository(repository, envelope.Installation.ID)
	if len(candidates) == 0 {
		return GitHubWebhookResult{EventType: normalizedEventType, Repository: repository}, nil
	}
	ctx, span := otel.Tracer("identrail/automation").Start(ctx, "automation.github_app_webhook")
	defer span.End()
	return s.processGitHubWebhookConnections(ctx, span, normalizedEventType, deliveryID, repository, candidates)
}

func (s *Service) processGitHubWebhookConnections(ctx context.Context, span trace.Span, eventType string, deliveryID string, repository string, connections []githubProjectConnection) (GitHubWebhookResult, error) {
	result := GitHubWebhookResult{
		EventType:       eventType,
		Repository:      repository,
		MatchedProjects: len(connections),
	}

	now := s.Now().UTC()
	normalizedDeliveryID := strings.TrimSpace(deliveryID)
	scanTriggerEvent := githubWebhookTriggersScan(eventType)

	for _, connection := range connections {
		replayed := s.isGitHubWebhookReplay(connection, normalizedDeliveryID, now)
		if replayed && scanTriggerEvent {
			result.SkippedScans++
			s.recordAutomationRun("event", "github", "skipped")
			continue
		}
		if !scanTriggerEvent {
			s.recordGitHubWebhookDelivery(ctx, connection, eventType, normalizedDeliveryID, now)
			continue
		}
		if s.shouldThrottleGitHubWebhookScan(connection, repository, now) {
			result.SkippedScans++
			s.recordAutomationRun("event", "github", "skipped")
			s.recordGitHubWebhookDelivery(ctx, connection, eventType, normalizedDeliveryID, now)
			continue
		}

		scopedCtx := db.WithScope(ctx, db.Scope{TenantID: connection.TenantID, WorkspaceID: connection.WorkspaceID})
		_, err := s.EnqueueRepoScan(scopedCtx, RepoScanRequest{Repository: repository})
		if err != nil {
			if errors.Is(err, ErrRepoScanQueueFull) {
				result.SkippedScans++
				s.recordAutomationRun("event", "github", "skipped")
				continue
			}
			if errors.Is(err, ErrRepoScanInProgress) ||
				errors.Is(err, ErrRepoScanDisabled) ||
				errors.Is(err, ErrRepoTargetNotAllowed) ||
				errors.Is(err, ErrInvalidRepoScanRequest) {
				result.SkippedScans++
				s.recordAutomationRun("event", "github", "skipped")
				s.recordGitHubWebhookDelivery(ctx, connection, eventType, normalizedDeliveryID, now)
				continue
			}
			s.recordAutomationRun("event", "github", "failed")
			span.RecordError(err)
			span.SetStatus(codes.Error, "enqueue webhook repo scan failed")
			return GitHubWebhookResult{}, err
		}
		result.QueuedScans++
		s.recordAutomationRun("event", "github", "queued")
		s.recordGitHubWebhookDelivery(ctx, connection, eventType, normalizedDeliveryID, now)
		s.recordGitHubWebhookQueuedScan(ctx, connection, repository, now)
	}

	span.SetAttributes(
		attribute.Int("automation.matched_projects", result.MatchedProjects),
		attribute.Int("automation.queued_scans", result.QueuedScans),
		attribute.Int("automation.skipped_scans", result.SkippedScans),
	)
	return result, nil
}

func (s *Service) verifyGitHubWebhookSignatureForInstallation(installationID int64, payload []byte, signature string) bool {
	s.githubConnectMu.RLock()
	defer s.githubConnectMu.RUnlock()

	for _, connection := range s.githubConnections {
		if connection.Status == domain.ConnectorStatusDisconnected {
			continue
		}
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
		if connection.Status == domain.ConnectorStatusDisconnected {
			continue
		}
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

func (s *Service) markGitHubInstallationDisconnected(ctx context.Context, event githubconnector.InstallationEvent) int {
	switch event.Action {
	case "deleted", "suspend", "suspended":
	default:
		return 0
	}
	items, err := s.Store.ListTenancyConnectorsUnscoped(ctx, domain.ConnectorTypeGitHub, 0)
	if err != nil {
		return 0
	}
	now := s.Now().UTC()
	matched := 0
	disconnectedKeys := []string{}
	for _, item := range items {
		if metadataInt64(item.State.Metadata, "installation_id") != event.InstallationID {
			continue
		}
		if firstNonEmptyString(metadataString(item.State.Metadata, "provider"), "github_app") != "github_app" {
			continue
		}
		matched++
		metadata := copyMetadata(item.State.Metadata)
		metadata["installation_action"] = event.Action
		metadata["account_login"] = firstNonEmptyString(event.AccountLogin, metadataString(metadata, "account_login"))
		metadata["disconnected_at"] = now.Format(time.RFC3339Nano)
		connector := item.Connector
		connector.Status = domain.ConnectorStatusDisconnected
		connector.UpdatedAt = now
		state := item.State
		state.HealthStatus = "error"
		state.LastErrorCode = "github_installation_disconnected"
		state.LastErrorMessage = "GitHub App installation was disconnected."
		state.Metadata = metadata
		state.ObservedAt = now
		state.UpdatedAt = now
		scopedCtx := db.WithScope(ctx, db.Scope{TenantID: item.Connector.TenantID, WorkspaceID: item.Connector.WorkspaceID})
		_ = s.Store.UpsertTenancyConnector(scopedCtx, connector, state)
		disconnectedKeys = append(disconnectedKeys, githubConnectionKey(item.Connector.TenantID, item.Connector.WorkspaceID, item.Connector.ProjectID))
	}
	if matched > 0 {
		s.githubConnectMu.Lock()
		for _, key := range disconnectedKeys {
			delete(s.githubConnections, key)
		}
		s.githubConnectMu.Unlock()
		s.hydrateGitHubConnections(ctx)
	}
	return matched
}

func (s *Service) reconcileGitHubInstallationRepositories(ctx context.Context, event githubconnector.InstallationRepositoriesEvent) int {
	items, err := s.Store.ListTenancyConnectorsUnscoped(ctx, domain.ConnectorTypeGitHub, 0)
	if err != nil {
		return 0
	}
	now := s.Now().UTC()
	matched := 0
	added := normalizeGitHubRepositoriesLenient(event.AddedRepositories)
	removed := normalizeGitHubRepositoriesLenient(event.RemovedRepositories)
	for _, item := range items {
		if metadataInt64(item.State.Metadata, "installation_id") != event.InstallationID {
			continue
		}
		if firstNonEmptyString(metadataString(item.State.Metadata, "provider"), "github_app") != "github_app" {
			continue
		}
		matched++
		metadata := copyMetadata(item.State.Metadata)
		metadata["installation_repositories_action"] = event.Action
		metadata["last_repository_selection_event_at"] = now.Format(time.RFC3339Nano)
		metadata["selected_repositories"] = reconcileGitHubRepositorySelection(
			metadataStringSlice(metadata, "selected_repositories"),
			added,
			removed,
		)
		state := item.State
		state.Metadata = metadata
		state.ObservedAt = now
		state.UpdatedAt = now
		connector := item.Connector
		connector.UpdatedAt = now
		scopedCtx := db.WithScope(ctx, db.Scope{TenantID: item.Connector.TenantID, WorkspaceID: item.Connector.WorkspaceID})
		_ = s.Store.UpsertTenancyConnector(scopedCtx, connector, state)
	}
	if matched > 0 {
		s.hydrateGitHubConnections(ctx)
	}
	return matched
}

func (s *Service) isGitHubWebhookReplay(connection githubProjectConnection, deliveryID string, now time.Time) bool {
	replayWindow := s.githubWebhookReplayWindow()
	cutoff := now.Add(-replayWindow)
	connectionKey := githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)
	normalizedDeliveryID := strings.TrimSpace(deliveryID)

	s.githubConnectMu.Lock()
	if s.githubWebhookSeen == nil {
		s.githubWebhookSeen = map[string]time.Time{}
	}
	for key, seenAt := range s.githubWebhookSeen {
		if seenAt.Before(cutoff) {
			delete(s.githubWebhookSeen, key)
		}
	}

	current, exists := s.githubConnections[connectionKey]
	if !exists {
		current = connection
	}

	replayed := false
	if normalizedDeliveryID != "" {
		if strings.EqualFold(strings.TrimSpace(current.LastWebhookDeliveryID), normalizedDeliveryID) {
			if current.LastWebhookEventAt != nil && !current.LastWebhookEventAt.UTC().Before(cutoff) {
				replayed = true
			}
		}
		replayKey := connectionKey + "::" + normalizedDeliveryID
		if seenAt, seen := s.githubWebhookSeen[replayKey]; seen && !seenAt.Before(cutoff) {
			replayed = true
		}
	}
	s.githubConnectMu.Unlock()
	return replayed
}

func (s *Service) recordGitHubWebhookDelivery(ctx context.Context, connection githubProjectConnection, eventType string, deliveryID string, now time.Time) {
	replayWindow := s.githubWebhookReplayWindow()
	cutoff := now.Add(-replayWindow)
	connectionKey := githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)
	normalizedDeliveryID := strings.TrimSpace(deliveryID)

	s.githubConnectMu.Lock()
	if s.githubWebhookSeen == nil {
		s.githubWebhookSeen = map[string]time.Time{}
	}
	for key, seenAt := range s.githubWebhookSeen {
		if seenAt.Before(cutoff) {
			delete(s.githubWebhookSeen, key)
		}
	}

	if normalizedDeliveryID != "" {
		replayKey := connectionKey + "::" + normalizedDeliveryID
		s.githubWebhookSeen[replayKey] = now
	}

	current, exists := s.githubConnections[connectionKey]
	if !exists {
		current = connection
	}
	current.LastWebhookEventType = eventType
	current.LastWebhookDeliveryID = normalizedDeliveryID
	eventAt := now
	current.LastWebhookEventAt = &eventAt
	current.UpdatedAt = now
	s.githubConnections[connectionKey] = current
	s.githubConnectMu.Unlock()

	_ = s.persistGitHubConnection(ctx, current)
}

func (s *Service) shouldThrottleGitHubWebhookScan(connection githubProjectConnection, repository string, now time.Time) bool {
	burstWindow := s.githubWebhookBurstWindow()
	normalizedRepository := normalizeGitHubRepository(repository)
	if burstWindow <= 0 || normalizedRepository == "" {
		return false
	}
	connectionKey := githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)
	queueKey := connectionKey + "::" + normalizedRepository
	cutoff := now.Add(-burstWindow)

	s.githubConnectMu.Lock()
	defer s.githubConnectMu.Unlock()
	if s.githubWebhookLastQueued == nil {
		s.githubWebhookLastQueued = map[string]time.Time{}
	}
	for key, queuedAt := range s.githubWebhookLastQueued {
		if queuedAt.Before(cutoff) {
			delete(s.githubWebhookLastQueued, key)
		}
	}
	if queuedAt, exists := s.githubWebhookLastQueued[queueKey]; exists && now.Sub(queuedAt) < burstWindow {
		return true
	}
	current, exists := s.githubConnections[connectionKey]
	if !exists || current.LastWebhookScanQueuedAt == nil {
		return false
	}
	if normalizeGitHubRepository(current.LastWebhookScanRepository) != normalizedRepository {
		return false
	}
	return now.Sub(current.LastWebhookScanQueuedAt.UTC()) < burstWindow
}

func (s *Service) recordGitHubWebhookQueuedScan(ctx context.Context, connection githubProjectConnection, repository string, now time.Time) {
	normalizedRepository := normalizeGitHubRepository(repository)
	if normalizedRepository == "" {
		return
	}
	connectionKey := githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)
	queueKey := connectionKey + "::" + normalizedRepository

	s.githubConnectMu.Lock()
	if s.githubWebhookLastQueued == nil {
		s.githubWebhookLastQueued = map[string]time.Time{}
	}
	s.githubWebhookLastQueued[queueKey] = now
	current, exists := s.githubConnections[connectionKey]
	if !exists {
		current = connection
	}
	current.LastWebhookScanRepository = normalizedRepository
	queuedAt := now
	current.LastWebhookScanQueuedAt = &queuedAt
	current.UpdatedAt = now
	s.githubConnections[connectionKey] = current
	s.githubConnectMu.Unlock()

	_ = s.persistGitHubConnection(ctx, current)
}

func (s *Service) githubWebhookReplayWindow() time.Duration {
	if s != nil && s.GitHubWebhookReplayWindow > 0 {
		return s.GitHubWebhookReplayWindow
	}
	return defaultGitHubWebhookReplayWindow
}

func (s *Service) githubWebhookBurstWindow() time.Duration {
	if s != nil && s.GitHubWebhookBurstWindow > 0 {
		return s.GitHubWebhookBurstWindow
	}
	return defaultGitHubWebhookBurstWindow
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

func (s *Service) hydrateGitHubConnections(ctx context.Context) {
	if s == nil || s.Store == nil {
		return
	}
	items, err := s.Store.ListTenancyConnectorsUnscoped(ctx, domain.ConnectorTypeGitHub, 0)
	if err != nil {
		return
	}
	hydrated := make(map[string]githubProjectConnection, len(items))
	for _, item := range items {
		if item.Connector.Status != domain.ConnectorStatusActive {
			continue
		}
		if firstNonEmptyString(metadataString(item.State.Metadata, "provider"), "github_app") != "github_app" {
			continue
		}
		connection, convErr := s.githubConnectionFromStored(ctx, item)
		if convErr != nil {
			continue
		}
		hydrated[githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)] = connection
	}
	if len(hydrated) == 0 {
		return
	}
	s.githubConnectMu.Lock()
	s.ensureGitHubConnectionsState()
	for key, connection := range hydrated {
		s.githubConnections[key] = connection
	}
	s.githubConnectMu.Unlock()
}

func (s *Service) loadGitHubConnection(ctx context.Context, scope db.Scope, workspaceID string, projectID string) (bool, error) {
	scopedCtx := db.WithScope(ctx, db.Scope{
		TenantID:    scope.TenantID,
		WorkspaceID: workspaceID,
	})
	items, err := s.Store.ListTenancyConnectors(scopedCtx, workspaceID, projectID, domain.ConnectorTypeGitHub, 10)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("list github connectors: %w", err)
	}
	for _, item := range items {
		if item.Connector.Status != domain.ConnectorStatusActive {
			continue
		}
		if firstNonEmptyString(metadataString(item.State.Metadata, "provider"), "github_app") != "github_app" {
			continue
		}
		connection, err := s.githubConnectionFromStored(scopedCtx, item)
		if err != nil {
			return false, err
		}
		s.githubConnectMu.Lock()
		s.ensureGitHubConnectionsState()
		s.githubConnections[githubConnectionKey(connection.TenantID, connection.WorkspaceID, connection.ProjectID)] = connection
		s.githubConnectMu.Unlock()
		return true, nil
	}
	return false, nil
}

func (s *Service) persistGitHubConnection(ctx context.Context, connection githubProjectConnection) error {
	if s == nil || s.Store == nil {
		return nil
	}
	rotatedAt := connection.WebhookSecretRotatedAt.UTC()
	if rotatedAt.IsZero() {
		rotatedAt = connection.UpdatedAt.UTC()
	}
	if rotatedAt.IsZero() {
		rotatedAt = s.Now().UTC()
	}
	scopedCtx := db.WithScope(ctx, db.Scope{
		TenantID:    connection.TenantID,
		WorkspaceID: connection.WorkspaceID,
	})
	metadata := map[string]any{
		"provider":                     "github_app",
		"account_login":                connection.AccountLogin,
		"installation_id":              connection.InstallationID,
		"token_reference":              connection.TokenReference,
		"webhook_secret_reference":     connection.WebhookSecretReference,
		"selected_repositories":        append([]string(nil), connection.SelectedRepositories...),
		"last_webhook_event_type":      connection.LastWebhookEventType,
		"last_webhook_delivery_id":     connection.LastWebhookDeliveryID,
		"last_webhook_scan_repository": normalizeGitHubRepository(connection.LastWebhookScanRepository),
		"webhook_secret_rotated_at":    rotatedAt.Format(time.RFC3339Nano),
	}
	if connection.LastWebhookEventAt != nil {
		metadata["last_webhook_event_at"] = connection.LastWebhookEventAt.UTC().Format(time.RFC3339Nano)
	}
	if connection.LastWebhookScanQueuedAt != nil {
		metadata["last_webhook_scan_queued_at"] = connection.LastWebhookScanQueuedAt.UTC().Format(time.RFC3339Nano)
	}
	connector := db.TenancyConnector{
		TenantID:            connection.TenantID,
		WorkspaceID:         connection.WorkspaceID,
		ProjectID:           connection.ProjectID,
		ConnectorID:         firstNonEmptyString(connection.ConnectorID, githubConnectorID),
		Type:                domain.ConnectorTypeGitHub,
		DisplayName:         firstNonEmptyString(connection.DisplayName, githubConnectorDisplayName),
		Status:              domain.ConnectorStatusActive,
		SecretProvider:      "secret-envelope",
		SecretRefID:         connection.WebhookSecretReference,
		SecretRefVersion:    connection.WebhookSecretEnvelope.KeyVersion,
		SecretLastRotatedAt: timePtr(rotatedAt),
		CreatedAt:           connection.CreatedAt,
		UpdatedAt:           connection.UpdatedAt,
	}
	state := db.TenancyConnectorState{
		TenantID:     connection.TenantID,
		WorkspaceID:  connection.WorkspaceID,
		ProjectID:    connection.ProjectID,
		ConnectorID:  firstNonEmptyString(connection.ConnectorID, githubConnectorID),
		HealthStatus: "healthy",
		Metadata:     metadata,
		ObservedAt:   connection.UpdatedAt,
		UpdatedAt:    connection.UpdatedAt,
	}
	if err := s.Store.UpsertTenancyConnector(scopedCtx, connector, state); err != nil {
		return fmt.Errorf("persist github connector: %w", err)
	}
	rotationDueAt := rotatedAt.Add(githubWebhookSecretRotationWindow)
	envelope := db.TenancyConnectorSecretEnvelope{
		TenantID:        connection.TenantID,
		WorkspaceID:     connection.WorkspaceID,
		ProjectID:       connection.ProjectID,
		ConnectorID:     firstNonEmptyString(connection.ConnectorID, githubConnectorID),
		SecretName:      githubWebhookSecretName,
		EnvelopeVersion: connection.WebhookSecretEnvelope.Version,
		Envelope:        connection.WebhookSecretEnvelope,
		SecretRefID:     connection.WebhookSecretReference,
		RotatedAt:       rotatedAt,
		RotationDueAt:   &rotationDueAt,
		CreatedAt:       connection.CreatedAt,
		UpdatedAt:       connection.UpdatedAt,
	}
	if err := s.Store.UpsertTenancyConnectorSecretEnvelope(scopedCtx, envelope); err != nil {
		return fmt.Errorf("persist github connector secret envelope: %w", err)
	}
	return nil
}

func (s *Service) githubConnectionFromStored(ctx context.Context, item db.TenancyConnectorWithState) (githubProjectConnection, error) {
	scopedCtx := db.WithScope(ctx, db.Scope{
		TenantID:    item.Connector.TenantID,
		WorkspaceID: item.Connector.WorkspaceID,
	})
	secret, err := s.Store.GetTenancyConnectorSecretEnvelope(
		scopedCtx,
		item.Connector.WorkspaceID,
		item.Connector.ProjectID,
		item.Connector.ConnectorID,
		githubWebhookSecretName,
	)
	if err != nil {
		return githubProjectConnection{}, fmt.Errorf("load github connector secret envelope: %w", err)
	}
	metadata := item.State.Metadata
	installationID := metadataInt64(metadata, "installation_id")
	if installationID <= 0 {
		return githubProjectConnection{}, fmt.Errorf("github connector installation id is missing")
	}
	lastWebhookEventAt := metadataTime(metadata, "last_webhook_event_at")
	lastWebhookScanQueuedAt := metadataTime(metadata, "last_webhook_scan_queued_at")
	rotatedAt := secret.RotatedAt
	if rotatedAt.IsZero() {
		rotatedAt = metadataTime(metadata, "webhook_secret_rotated_at")
	}
	return githubProjectConnection{
		TenantID:                  item.Connector.TenantID,
		WorkspaceID:               item.Connector.WorkspaceID,
		ProjectID:                 item.Connector.ProjectID,
		ConnectorID:               item.Connector.ConnectorID,
		DisplayName:               item.Connector.DisplayName,
		Status:                    item.Connector.Status,
		HealthStatus:              firstNonEmptyString(item.State.HealthStatus, "unknown"),
		Provider:                  firstNonEmptyString(metadataString(metadata, "provider"), "github_app"),
		AccountLogin:              metadataString(metadata, "account_login"),
		InstallationID:            installationID,
		BaseURL:                   metadataString(metadata, "base_url"),
		Scopes:                    metadataStringSlice(metadata, "scopes"),
		TokenReference:            metadataString(metadata, "token_reference"),
		WebhookSecretReference:    firstNonEmptyString(metadataString(metadata, "webhook_secret_reference"), secret.SecretRefID),
		WebhookSecretEnvelope:     secret.Envelope,
		WebhookSecretRotatedAt:    rotatedAt,
		SelectedRepositories:      metadataStringSlice(metadata, "selected_repositories"),
		CreatedAt:                 item.Connector.CreatedAt,
		UpdatedAt:                 item.Connector.UpdatedAt,
		LastWebhookEventType:      metadataString(metadata, "last_webhook_event_type"),
		LastWebhookDeliveryID:     metadataString(metadata, "last_webhook_delivery_id"),
		LastWebhookEventAt:        timePtr(lastWebhookEventAt),
		LastWebhookScanRepository: normalizeGitHubRepository(metadataString(metadata, "last_webhook_scan_repository")),
		LastWebhookScanQueuedAt:   timePtr(lastWebhookScanQueuedAt),
	}, nil
}

func gitHubConnectionStatusFromStored(item db.TenancyConnectorWithState) GitHubConnectionStatus {
	metadata := item.State.Metadata
	createdAt := item.Connector.CreatedAt
	updatedAt := item.Connector.UpdatedAt
	status := GitHubConnectionStatus{
		Provider:              firstNonEmptyString(metadataString(metadata, "provider"), "github_app"),
		Connected:             item.Connector.Status == domain.ConnectorStatusActive && item.State.HealthStatus == "healthy",
		ConnectorID:           item.Connector.ConnectorID,
		DisplayName:           item.Connector.DisplayName,
		Status:                item.Connector.Status,
		HealthStatus:          firstNonEmptyString(item.State.HealthStatus, "unknown"),
		AccountLogin:          metadataString(metadata, "account_login"),
		InstallationID:        metadataInt64(metadata, "installation_id"),
		BaseURL:               metadataString(metadata, "base_url"),
		Scopes:                metadataStringSlice(metadata, "scopes"),
		TokenReference:        metadataString(metadata, "token_reference"),
		SelectedRepositories:  metadataStringSlice(metadata, "selected_repositories"),
		CreatedAt:             &createdAt,
		UpdatedAt:             &updatedAt,
		LastWebhookEventType:  metadataString(metadata, "last_webhook_event_type"),
		LastWebhookDeliveryID: metadataString(metadata, "last_webhook_delivery_id"),
		LastWebhookEventAt:    timePtr(metadataTime(metadata, "last_webhook_event_at")),
	}
	if status.SelectedRepositories == nil {
		status.SelectedRepositories = []string{}
	}
	if status.Scopes == nil {
		status.Scopes = []string{}
	}
	return status
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, exists := metadata[key]
	if !exists {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func copyMetadata(metadata map[string]any) map[string]any {
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		out[key] = value
	}
	return out
}

func metadataStringSlice(metadata map[string]any, key string) []string {
	if metadata == nil {
		return []string{}
	}
	value, exists := metadata[key]
	if !exists {
		return []string{}
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				normalized := strings.TrimSpace(text)
				if normalized != "" {
					out = append(out, normalized)
				}
			}
		}
		return out
	default:
		return []string{}
	}
}

func metadataInt64(metadata map[string]any, key string) int64 {
	if metadata == nil {
		return 0
	}
	value, exists := metadata[key]
	if !exists {
		return 0
	}
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	default:
		return 0
	}
}

func metadataTime(metadata map[string]any, key string) time.Time {
	value := metadataString(metadata, key)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized != "" {
			return normalized
		}
	}
	return ""
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
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

func normalizeGitHubRepositoriesLenient(repositories []string) []string {
	normalized := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		item := normalizeGitHubRepository(repository)
		if item == "" || !githubRepositoryPattern.MatchString(item) {
			continue
		}
		normalized = append(normalized, item)
	}
	return normalized
}

func reconcileGitHubRepositorySelection(existing []string, added []string, removed []string) []string {
	selected := make(map[string]struct{}, len(existing)+len(added))
	for _, repository := range existing {
		item := normalizeGitHubRepository(repository)
		if item == "" || !githubRepositoryPattern.MatchString(item) {
			continue
		}
		selected[item] = struct{}{}
	}
	for _, repository := range added {
		item := normalizeGitHubRepository(repository)
		if item == "" || !githubRepositoryPattern.MatchString(item) {
			continue
		}
		selected[item] = struct{}{}
	}
	for _, repository := range removed {
		delete(selected, normalizeGitHubRepository(repository))
	}
	reconciled := make([]string, 0, len(selected))
	for repository := range selected {
		reconciled = append(reconciled, repository)
	}
	sort.Strings(reconciled)
	return reconciled
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
		ConnectorID:                   firstNonEmptyString(connection.ConnectorID, githubConnectorID),
		DisplayName:                   firstNonEmptyString(connection.DisplayName, githubConnectorDisplayName),
		Status:                        firstNonEmptyConnectorStatus(connection.Status, domain.ConnectorStatusActive),
		HealthStatus:                  firstNonEmptyString(connection.HealthStatus, "healthy"),
		AccountLogin:                  connection.AccountLogin,
		InstallationID:                connection.InstallationID,
		BaseURL:                       connection.BaseURL,
		Scopes:                        append([]string(nil), connection.Scopes...),
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
	if status.Scopes == nil {
		status.Scopes = []string{}
	}
	return status
}

func firstNonEmptyConnectorStatus(values ...domain.ConnectorStatus) domain.ConnectorStatus {
	for _, value := range values {
		if strings.TrimSpace(string(value)) != "" {
			return value
		}
	}
	return ""
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

func (s *Service) encryptGitHubPAT(scope db.Scope, projectID string, connectorID string, token string) (secretstore.Envelope, error) {
	manager := s.connectorSecretManager()
	return manager.Encrypt([]byte(token), githubPATSecretAAD(scope, projectID, connectorID))
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

func githubPATSecretAAD(scope db.Scope, projectID string, connectorID string) []byte {
	parts := []string{
		"github",
		"pat_token",
		strings.ToLower(strings.TrimSpace(scope.TenantID)),
		strings.ToLower(strings.TrimSpace(scope.WorkspaceID)),
		strings.ToLower(strings.TrimSpace(projectID)),
		strings.ToLower(strings.TrimSpace(connectorID)),
	}
	return []byte(strings.Join(parts, "\x00"))
}

func githubPATSecretRef(connectorID string) string {
	return "secret-envelope://github/" + strings.TrimSpace(connectorID) + "/" + githubPATSecretName
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
