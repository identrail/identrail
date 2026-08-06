package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

const (
	defaultAWSBaselineSourceMode              = "sdk"
	defaultAWSBaselineConnectorProfileVersion = "aws-readonly-iam-v1"
	defaultAWSBaselineGraphContractVersion    = "relationship-contract-v1"
)

// ErrAWSPlatformBaselineNotReady indicates the AWS platform gate blocked a scan.
var ErrAWSPlatformBaselineNotReady = errors.New("aws platform baseline not ready")

// AWSPlatformBaselineRequest optionally pins the connector and revision to verify.
type AWSPlatformBaselineRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
	GitSHA      string `json:"git_sha,omitempty"`
}

// AWSPlatformBaselineNotReadyError carries the persisted readiness result that
// explains why a project-scoped AWS scan was refused.
type AWSPlatformBaselineNotReadyError struct {
	Result db.AWSPlatformBaselineResult
}

func (e AWSPlatformBaselineNotReadyError) Error() string {
	return ErrAWSPlatformBaselineNotReady.Error()
}

func (e AWSPlatformBaselineNotReadyError) Is(target error) bool {
	return target == ErrAWSPlatformBaselineNotReady
}

// VerifyAWSPlatformBaseline evaluates, persists, and returns the AWS readiness gate.
func (s *Service) VerifyAWSPlatformBaseline(ctx context.Context, workspaceID string, projectID string, request AWSPlatformBaselineRequest) (db.AWSPlatformBaselineResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return db.AWSPlatformBaselineResult{}, err
	}
	now := s.Now().UTC()
	sourceMode := s.awsBaselineSourceMode()
	fixtureOnly := sourceMode == "fixture"
	connection, hasConnection, err := s.awsBaselineConnection(ctx, project, request.ConnectorID)
	if err != nil {
		return db.AWSPlatformBaselineResult{}, err
	}
	scanSource := db.ScanSource{ProjectID: project.ProjectID, ConnectorID: strings.TrimSpace(request.ConnectorID)}

	checks := []db.AWSPlatformBaselineCheck{
		s.awsBaselineConnectorHealthCheck(sourceMode, connection, hasConnection, now),
		s.awsBaselineGraphContractCheck(now),
		s.awsBaselineWorkerQueueCheck(ctx, scanSource, now),
		s.awsBaselineFixtureCheck(sourceMode, now),
		s.awsBaselineAppValidationCheck(scope, project, now),
	}
	status, requiredPassed, confidence, failureReasons, evidenceLinks := summarizeAWSBaselineChecks(checks)
	result := db.AWSPlatformBaselineResult{
		TenantID:                scope.TenantID,
		WorkspaceID:             project.WorkspaceID,
		ProjectID:               project.ProjectID,
		GitSHA:                  firstNonEmptyAWSValue(strings.TrimSpace(request.GitSHA), strings.TrimSpace(s.AWSBaselineGitSHA)),
		SourceMode:              sourceMode,
		FixtureOnly:             fixtureOnly,
		ConnectorProfileVersion: s.awsBaselineConnectorProfileVersion(),
		GraphContractVersion:    s.awsBaselineGraphContractVersion(),
		Status:                  status,
		Confidence:              confidence,
		RequiredChecksPassed:    requiredPassed,
		FailureReasons:          failureReasons,
		EvidenceLinks:           evidenceLinks,
		Checks:                  checks,
		VerifiedAt:              now,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if hasConnection {
		result.ConnectorID = connection.ConnectorID
		result.AccountID = connection.AccountID
		result.Region = connection.Region
	}
	stored, err := s.Store.UpsertAWSPlatformBaselineResult(ctx, result)
	if err != nil {
		return db.AWSPlatformBaselineResult{}, fmt.Errorf("persist aws platform baseline: %w", err)
	}
	return stored, nil
}

// GetAWSPlatformBaseline returns the latest persisted result or a deterministic
// not-run payload when no verification has occurred yet.
func (s *Service) GetAWSPlatformBaseline(ctx context.Context, workspaceID string, projectID string, request AWSPlatformBaselineRequest) (db.AWSPlatformBaselineResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return db.AWSPlatformBaselineResult{}, err
	}
	connectorID := strings.TrimSpace(request.ConnectorID)
	if connectorID == "" {
		connection, hasConnection, connectionErr := s.awsBaselineConnection(ctx, project, "")
		if connectionErr != nil {
			return db.AWSPlatformBaselineResult{}, connectionErr
		}
		if hasConnection && strings.TrimSpace(connection.ConnectorID) != "" {
			result, err := s.Store.GetAWSPlatformBaselineResult(ctx, db.AWSPlatformBaselineFilter{
				WorkspaceID: project.WorkspaceID,
				ProjectID:   project.ProjectID,
				ConnectorID: connection.ConnectorID,
			})
			if err == nil {
				return result, nil
			}
			if !errors.Is(err, db.ErrNotFound) {
				return db.AWSPlatformBaselineResult{}, err
			}
		}
	}
	result, err := s.Store.GetAWSPlatformBaselineResult(ctx, db.AWSPlatformBaselineFilter{
		WorkspaceID: project.WorkspaceID,
		ProjectID:   project.ProjectID,
		ConnectorID: connectorID,
	})
	if err == nil {
		return result, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return db.AWSPlatformBaselineResult{}, err
	}
	now := s.Now().UTC()
	check := db.AWSPlatformBaselineCheck{
		Name:          "aws_platform_baseline",
		Category:      "readiness",
		Required:      true,
		Status:        db.AWSPlatformBaselineCheckUnknown,
		Message:       "AWS platform baseline has not been verified for this project.",
		FailureReason: "aws platform baseline has not run",
		Remediation:   "Run AWS baseline verification before starting AWS scans or remediation.",
		EvidenceURL:   awsBaselineProjectEvidenceURL(scope, project),
		Confidence:    0,
		Evidence: map[string]any{
			"project_id": project.ProjectID,
		},
		CheckedAt: now,
	}
	return db.AWSPlatformBaselineResult{
		TenantID:                scope.TenantID,
		WorkspaceID:             project.WorkspaceID,
		ProjectID:               project.ProjectID,
		ConnectorID:             connectorID,
		GitSHA:                  strings.TrimSpace(s.AWSBaselineGitSHA),
		SourceMode:              s.awsBaselineSourceMode(),
		FixtureOnly:             s.awsBaselineSourceMode() == "fixture",
		ConnectorProfileVersion: s.awsBaselineConnectorProfileVersion(),
		GraphContractVersion:    s.awsBaselineGraphContractVersion(),
		Status:                  db.AWSPlatformBaselineStatusNotRun,
		Confidence:              0,
		RequiredChecksPassed:    false,
		FailureReasons:          []string{check.FailureReason},
		EvidenceLinks:           []string{check.EvidenceURL},
		Checks:                  []db.AWSPlatformBaselineCheck{check},
		VerifiedAt:              now,
		CreatedAt:               now,
		UpdatedAt:               now,
	}, nil
}

func (s *Service) ensureAWSPlatformBaselineReadyForScan(ctx context.Context, provider string, source db.ScanSource) error {
	if strings.ToLower(strings.TrimSpace(provider)) != string(domain.ConnectorTypeAWS) {
		return nil
	}
	source = source.Normalize()
	if source.ProjectID == "" {
		return nil
	}
	result, err := s.VerifyAWSPlatformBaseline(ctx, "", source.ProjectID, AWSPlatformBaselineRequest{ConnectorID: source.ConnectorID})
	if err != nil {
		return err
	}
	if !result.RequiredChecksPassed {
		return AWSPlatformBaselineNotReadyError{Result: result}
	}
	return nil
}

func (s *Service) awsBaselineConnection(ctx context.Context, project db.TenancyProject, connectorID string) (AWSConnectionStatus, bool, error) {
	connectorID = strings.TrimSpace(connectorID)
	if connectorID != "" {
		stored, err := s.Store.GetTenancyConnector(ctx, project.WorkspaceID, project.ProjectID, connectorID)
		if err != nil {
			return AWSConnectionStatus{}, false, err
		}
		if stored.Connector.Type != domain.ConnectorTypeAWS {
			return AWSConnectionStatus{}, false, ErrInvalidAWSConnectionRequest
		}
		return s.awsConnectionStatusFromStored(ctx, stored), true, nil
	}
	items, err := s.listEligibleAWSConnectors(ctx, project.WorkspaceID, project.ProjectID, 25)
	if err != nil {
		return AWSConnectionStatus{}, false, fmt.Errorf("list aws baseline connectors: %w", err)
	}
	if len(items) == 0 {
		return AWSConnectionStatus{}, false, nil
	}
	for _, item := range items {
		status := s.awsConnectionStatusFromStored(ctx, item)
		if status.Connected {
			return status, true, nil
		}
	}
	return s.awsConnectionStatusFromStored(ctx, items[0]), true, nil
}

func (s *Service) awsBaselineConnectorHealthCheck(sourceMode string, connection AWSConnectionStatus, hasConnection bool, checkedAt time.Time) db.AWSPlatformBaselineCheck {
	fixtureMode := sourceMode == "fixture"
	check := awsPlatformBaselineCheck("aws_connector_health", "connector", !fixtureMode, checkedAt)
	check.EvidenceURL = "/docs/auth/aws-connector"
	check.Evidence["source_mode"] = sourceMode
	if fixtureMode {
		check.Status = db.AWSPlatformBaselineCheckSkipped
		check.Message = "Fixture AWS source mode does not require a live AWS connector."
		check.Confidence = 0.9
		if hasConnection {
			check.Evidence["connector_id"] = connection.ConnectorID
			check.Evidence["status"] = connection.Status
			check.Evidence["health_status"] = connection.HealthStatus
		}
		return check
	}
	if !hasConnection {
		check.Status = db.AWSPlatformBaselineCheckFailed
		check.Message = "No AWS connector is configured for this project."
		check.FailureReason = "aws connector is missing"
		check.Remediation = "Connect an AWS account before running AWS scans or remediation."
		check.Confidence = 0.2
		return check
	}
	check.Evidence = map[string]any{
		"source_mode":       sourceMode,
		"connector_id":      connection.ConnectorID,
		"status":            connection.Status,
		"health_status":     connection.HealthStatus,
		"account_id":        connection.AccountID,
		"region":            connection.Region,
		"permission_checks": len(connection.PermissionChecks),
		"diagnostics":       len(connection.Diagnostics),
	}
	if connection.Connected {
		check.Status = db.AWSPlatformBaselineCheckPassed
		check.Message = "AWS connector is active and healthy."
		check.Confidence = 0.96
		return check
	}
	check.Status = db.AWSPlatformBaselineCheckFailed
	if awsConnectionHasPermissionDenial(connection) {
		check.Status = db.AWSPlatformBaselineCheckPermissionDenied
	}
	check.Message = "AWS connector is not ready."
	check.FailureReason = firstAWSBaselineConnectionFailure(connection)
	check.Remediation = firstNonEmptyAWSValue(
		connection.RemediationMessage,
		firstAWSRemediation(connection.Diagnostics, connection.PermissionChecks),
		"Validate the AWS connector role and required read-only IAM permissions.",
	)
	check.Confidence = 0.35
	return check
}

func (s *Service) awsBaselineGraphContractCheck(checkedAt time.Time) db.AWSPlatformBaselineCheck {
	check := awsPlatformBaselineCheck("graph_contract_version", "graph", true, checkedAt)
	contracts := domain.RelationshipContracts()
	check.Evidence = map[string]any{
		"contract_version":   s.awsBaselineGraphContractVersion(),
		"relationship_count": len(contracts),
	}
	check.EvidenceURL = "/docs/aws-normalizer-graph"
	if len(contracts) == 0 {
		check.Status = db.AWSPlatformBaselineCheckFailed
		check.Message = "No graph relationship contracts are registered."
		check.FailureReason = "graph contract registry is empty"
		check.Remediation = "Restore the relationship contract registry before running AWS scans."
		check.Confidence = 0.2
		return check
	}
	check.Status = db.AWSPlatformBaselineCheckPassed
	check.Message = "Graph relationship contract registry is available."
	check.Confidence = 0.95
	return check
}

func (s *Service) awsBaselineWorkerQueueCheck(ctx context.Context, source db.ScanSource, checkedAt time.Time) db.AWSPlatformBaselineCheck {
	check := awsPlatformBaselineCheck("worker_queue_availability", "queue", true, checkedAt)
	maxPending := s.ScanQueueMaxPending
	if maxPending <= 0 {
		maxPending = 1
	}
	source = source.Normalize()
	countMode := "queued"
	var (
		count int
		err   error
	)
	if maxPending == 1 {
		countMode = "queued_running"
		count, err = s.Store.CountPendingScansWithSource(ctx, string(domain.ConnectorTypeAWS), source)
	} else {
		count, err = s.Store.CountQueuedScansWithSource(ctx, string(domain.ConnectorTypeAWS), source)
	}
	check.Evidence = map[string]any{
		"queue_limit":      maxPending,
		"queue_count_mode": countMode,
		"project_id":       source.ProjectID,
		"connector_id":     source.ConnectorID,
	}
	if err != nil {
		check.Status = db.AWSPlatformBaselineCheckFailed
		check.Message = "AWS scan queue depth could not be read."
		check.FailureReason = "worker queue depth check failed"
		check.Remediation = "Verify API and worker storage connectivity before starting AWS scans."
		check.Confidence = 0.25
		return check
	}
	check.Evidence["pending_queue_count"] = count
	if count >= maxPending {
		check.Status = db.AWSPlatformBaselineCheckFailed
		check.Message = "AWS scan queue is at capacity for this scan source."
		check.FailureReason = "worker queue is full"
		check.Remediation = "Wait for matching queued AWS scans to drain or increase IDENTRAIL_SCAN_QUEUE_MAX_PENDING."
		check.Confidence = 0.45
		return check
	}
	check.Status = db.AWSPlatformBaselineCheckPassed
	check.Message = "AWS scan queue can accept work for this scan source."
	check.Confidence = 0.94
	return check
}

func (s *Service) awsBaselineFixtureCheck(sourceMode string, checkedAt time.Time) db.AWSPlatformBaselineCheck {
	check := awsPlatformBaselineCheck("fixture_availability", "fixtures", sourceMode == "fixture", checkedAt)
	check.EvidenceURL = "/docs/configuration-reference"
	check.Evidence = map[string]any{
		"source_mode": sourceMode,
	}
	if sourceMode != "fixture" {
		check.Status = db.AWSPlatformBaselineCheckSkipped
		check.Message = "Live AWS source mode does not require fixture files."
		check.Confidence = 0.9
		return check
	}
	paths := append([]string(nil), s.AWSBaselineFixturePaths...)
	check.Evidence["fixture_paths"] = paths
	count, missing, scanErrors := countAWSFixtureFiles(paths)
	check.Evidence["fixture_count"] = count
	if len(missing) > 0 {
		check.Evidence["missing_paths"] = missing
	}
	if len(scanErrors) > 0 {
		check.Evidence["scan_errors"] = scanErrors
	}
	if len(paths) == 0 || count == 0 || len(missing) > 0 || len(scanErrors) > 0 {
		check.Status = db.AWSPlatformBaselineCheckFailed
		check.Message = "AWS fixture source mode cannot find usable fixture files."
		check.FailureReason = "aws fixtures are unavailable"
		check.Remediation = "Set IDENTRAIL_AWS_FIXTURES to one or more readable JSON fixture files or directories."
		check.Confidence = 0.3
		return check
	}
	check.Status = db.AWSPlatformBaselineCheckPassed
	check.Message = "AWS fixture files are available for fixture-only execution."
	check.Confidence = 0.92
	return check
}

func (s *Service) awsBaselineAppValidationCheck(scope db.Scope, project db.TenancyProject, checkedAt time.Time) db.AWSPlatformBaselineCheck {
	check := awsPlatformBaselineCheck("app_validation_prerequisites", "app", true, checkedAt)
	check.EvidenceURL = awsBaselineProjectEvidenceURL(scope, project)
	check.Evidence = map[string]any{
		"tenant_id":    scope.TenantID,
		"workspace_id": project.WorkspaceID,
		"project_id":   project.ProjectID,
		"aws_url":      check.EvidenceURL,
		"setup_url":    awsBaselineSetupEvidenceURL(scope, project),
	}
	if project.ArchivedAt != nil {
		check.Status = db.AWSPlatformBaselineCheckFailed
		check.Message = "AWS app validation is blocked because the project is archived."
		check.FailureReason = "project is archived"
		check.Remediation = "Restore the project before running AWS scans or remediation."
		check.Confidence = 0.5
		return check
	}
	check.Status = db.AWSPlatformBaselineCheckPassed
	check.Message = "AWS app routes and project scope are available."
	check.Confidence = 0.95
	return check
}

func awsPlatformBaselineCheck(name string, category string, required bool, checkedAt time.Time) db.AWSPlatformBaselineCheck {
	return db.AWSPlatformBaselineCheck{
		Name:       name,
		Category:   category,
		Required:   required,
		Status:     db.AWSPlatformBaselineCheckUnknown,
		Evidence:   map[string]any{},
		Confidence: 0,
		CheckedAt:  checkedAt.UTC(),
	}
}

func summarizeAWSBaselineChecks(checks []db.AWSPlatformBaselineCheck) (string, bool, float64, []string, []string) {
	requiredPassed := true
	degraded := false
	failureReasons := []string{}
	evidenceLinks := []string{}
	for _, check := range checks {
		if strings.TrimSpace(check.EvidenceURL) != "" {
			evidenceLinks = append(evidenceLinks, check.EvidenceURL)
		}
		passed := check.Status == db.AWSPlatformBaselineCheckPassed || (!check.Required && check.Status == db.AWSPlatformBaselineCheckSkipped)
		if check.Required && !passed {
			requiredPassed = false
			failureReasons = append(failureReasons, firstNonEmptyAWSValue(check.FailureReason, check.Message, check.Name))
		}
		if !check.Required && check.Status != db.AWSPlatformBaselineCheckPassed && check.Status != db.AWSPlatformBaselineCheckSkipped {
			degraded = true
		}
	}
	status := db.AWSPlatformBaselineStatusReady
	confidence := 0.95
	if !requiredPassed {
		status = db.AWSPlatformBaselineStatusBlocked
		confidence = 0.35
	} else if degraded {
		status = db.AWSPlatformBaselineStatusDegraded
		confidence = 0.72
	}
	return status, requiredPassed, confidence, failureReasons, dedupeStrings(evidenceLinks)
}

func awsConnectionHasPermissionDenial(connection AWSConnectionStatus) bool {
	for _, check := range connection.PermissionChecks {
		if !check.Passed {
			return true
		}
	}
	for _, diagnostic := range connection.Diagnostics {
		code := strings.ToLower(diagnostic.Code)
		message := strings.ToLower(diagnostic.Message)
		if strings.Contains(code, "permission") || strings.Contains(code, "denied") ||
			strings.Contains(message, "permission") || strings.Contains(message, "denied") {
			return true
		}
	}
	return false
}

func firstAWSBaselineConnectionFailure(connection AWSConnectionStatus) string {
	for _, diagnostic := range connection.Diagnostics {
		if strings.TrimSpace(diagnostic.Message) != "" {
			return strings.TrimSpace(diagnostic.Message)
		}
	}
	for _, check := range connection.PermissionChecks {
		if !check.Passed && strings.TrimSpace(check.Message) != "" {
			return strings.TrimSpace(check.Message)
		}
	}
	return "aws connector is not healthy"
}

func countAWSFixtureFiles(paths []string) (int, []string, []string) {
	count := 0
	missing := []string{}
	scanErrors := []string{}
	for _, rawPath := range paths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			missing = append(missing, path)
			continue
		}
		if !info.IsDir() {
			if strings.EqualFold(filepath.Ext(path), ".json") {
				count++
			}
			continue
		}
		err = filepath.WalkDir(path, func(entryPath string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", entryPath, walkErr))
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(entryPath), ".json") {
				count++
			}
			return nil
		})
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", path, err))
		}
	}
	return count, missing, scanErrors
}

func dedupeStrings(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	deduped := []string{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		deduped = append(deduped, item)
	}
	return deduped
}

func (s *Service) awsBaselineSourceMode() string {
	sourceMode := strings.ToLower(strings.TrimSpace(s.AWSBaselineSourceMode))
	if sourceMode == "" {
		return defaultAWSBaselineSourceMode
	}
	return sourceMode
}

func (s *Service) awsBaselineConnectorProfileVersion() string {
	return firstNonEmptyAWSValue(strings.TrimSpace(s.AWSBaselineConnectorProfileVersion), defaultAWSBaselineConnectorProfileVersion)
}

func (s *Service) awsBaselineGraphContractVersion() string {
	return firstNonEmptyAWSValue(strings.TrimSpace(s.AWSBaselineGraphContractVersion), defaultAWSBaselineGraphContractVersion)
}

func awsBaselineProjectEvidenceURL(scope db.Scope, project db.TenancyProject) string {
	return fmt.Sprintf(
		"/app/%s/%s/aws?environment=%s",
		url.PathEscape(scope.TenantID),
		url.PathEscape(project.WorkspaceID),
		url.QueryEscape(project.ProjectID),
	)
}

func awsBaselineSetupEvidenceURL(scope db.Scope, project db.TenancyProject) string {
	return fmt.Sprintf(
		"/app/%s/%s/aws/connect?environment=%s",
		url.PathEscape(scope.TenantID),
		url.PathEscape(project.WorkspaceID),
		url.QueryEscape(project.ProjectID),
	)
}
