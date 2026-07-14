package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/secretstore"
)

type testSQLStateError string

func (e testSQLStateError) Error() string {
	return string(e)
}

func (e testSQLStateError) SQLState() string {
	return string(e)
}

func TestPostgresStoreUpsertAndGetOrganizationScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_organizations (tenant_id, display_name, slug, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (tenant_id) DO UPDATE
		 SET display_name = EXCLUDED.display_name,
		     slug = EXCLUDED.slug,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "Tenant A", "tenant-a", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertOrganization(ctx, TenancyOrganization{
		DisplayName: "Tenant A",
		Slug:        "tenant-a",
	}); err != nil {
		t.Fatalf("upsert organization: %v", err)
	}

	rows := sqlmock.NewRows([]string{"tenant_id", "display_name", "slug", "created_at", "updated_at"}).
		AddRow("tenant-a", "Tenant A", "tenant-a", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, display_name, slug, created_at, updated_at
		 FROM tenancy_organizations
		 WHERE tenant_id = $1`)).
		WithArgs("tenant-a").
		WillReturnRows(rows)

	organization, err := store.GetOrganization(ctx)
	if err != nil {
		t.Fatalf("get organization: %v", err)
	}
	if organization.TenantID != "tenant-a" {
		t.Fatalf("unexpected organization: %+v", organization)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertAndGetTenancyConnector(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO tenancy_connectors").
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"aws-123456789012",
			"aws",
			"Production AWS",
			"active",
			"",
			"",
			"",
			sqlmock.AnyArg(),
			"",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO tenancy_connector_states").
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"aws-123456789012",
			"healthy",
			"",
			nil,
			"",
			"",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.UpsertTenancyConnector(ctx, TenancyConnector{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-123456789012",
		Type:        domain.ConnectorTypeAWS,
		DisplayName: "Production AWS",
		Status:      domain.ConnectorStatusActive,
	}, TenancyConnectorState{
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "aws-123456789012",
		HealthStatus: "healthy",
		Metadata: map[string]any{
			"role_arn": "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		},
	}); err != nil {
		t.Fatalf("upsert connector: %v", err)
	}

	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "type", "display_name", "status",
		"secret_provider", "secret_ref_id", "secret_ref_version", "secret_last_rotated_at",
		"config_checksum", "last_sync_at", "created_at", "updated_at", "health_status", "sync_cursor",
		"last_successful_sync_at", "last_error_code", "last_error_message", "metadata", "observed_at", "state_updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-123456789012", "aws", "Production AWS", "active",
		nil, nil, nil, nil, nil, nil, now, now, "healthy", nil, nil, nil, nil,
		[]byte(`{"role_arn":"arn:aws:iam::123456789012:role/IdentrailReadOnly"}`),
		now, now,
	)
	mock.ExpectQuery(`(?s)SELECT.*FROM tenancy_connectors.*c\.connector_id = \$4.*LIMIT \$5`).
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-123456789012", 1).
		WillReturnRows(rows)

	connector, err := store.GetTenancyConnector(ctx, "workspace-a", "project-1", "aws-123456789012")
	if err != nil {
		t.Fatalf("get connector: %v", err)
	}
	if connector.Connector.Type != domain.ConnectorTypeAWS || connector.State.HealthStatus != "healthy" {
		t.Fatalf("unexpected connector: %+v", connector)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateTenancyConnectorWithSecretEnvelopeIfAbsentCreatesAtomically(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	connector, state, envelope := postgresAWSConnectorCreateFixture()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO tenancy_connectors").
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-prod", "aws", "Production AWS", "pending", "secret-envelope", "secret-ref", "test-v1", sqlmock.AnyArg(), "", nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO tenancy_connector_states").
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-prod", "unknown", "", nil, "", "", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO tenancy_connector_secret_envelopes").
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-prod", "external_id", 1, secretstore.AlgorithmAES256GCM, "test-v1", []byte("123456789012"), []byte("ciphertext"), "secret-ref", sqlmock.AnyArg(), nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, created, err := store.CreateTenancyConnectorWithSecretEnvelopeIfAbsent(ctx, connector, state, envelope)
	if err != nil {
		t.Fatalf("create connector with envelope: %v", err)
	}
	if !created || got.Connector.ConnectorID != "aws-prod" || got.State.HealthStatus != "unknown" {
		t.Fatalf("expected created connector with state, created=%v got=%+v", created, got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateTenancyConnectorWithSecretEnvelopeIfAbsentReturnsExistingOnConflict(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	connector, state, envelope := postgresAWSConnectorCreateFixture()
	now := connector.CreatedAt

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO tenancy_connectors").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "type", "display_name", "status",
		"secret_provider", "secret_ref_id", "secret_ref_version", "secret_last_rotated_at",
		"config_checksum", "last_sync_at", "created_at", "updated_at", "health_status", "sync_cursor",
		"last_successful_sync_at", "last_error_code", "last_error_message", "metadata", "observed_at", "state_updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-prod", "aws", "Existing AWS", "pending",
		"secret-envelope", "existing-secret-ref", "test-v1", now, nil, nil, now, now, "unknown", nil, nil, nil, nil,
		[]byte(`{"launch_url":"https://console.aws.amazon.com/cloudformation/home"}`),
		now, now,
	)
	mock.ExpectQuery(`(?s)SELECT.*FROM tenancy_connectors.*c\.connector_id = \$4.*LIMIT \$5`).
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-prod", 1).
		WillReturnRows(rows)

	got, created, err := store.CreateTenancyConnectorWithSecretEnvelopeIfAbsent(ctx, connector, state, envelope)
	if err != nil {
		t.Fatalf("load existing connector after conflict: %v", err)
	}
	if created || got.Connector.DisplayName != "Existing AWS" || got.Connector.SecretRefID != "existing-secret-ref" {
		t.Fatalf("expected existing connector on conflict, created=%v got=%+v", created, got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateTenancyConnectorWithSecretEnvelopeIfAbsentRollsBackStateFailure(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	connector, state, envelope := postgresAWSConnectorCreateFixture()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO tenancy_connectors").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO tenancy_connector_states").
		WillReturnError(errors.New("state insert failed"))
	mock.ExpectRollback()

	if _, _, err := store.CreateTenancyConnectorWithSecretEnvelopeIfAbsent(ctx, connector, state, envelope); err == nil || !strings.Contains(err.Error(), "create tenancy connector state if absent") {
		t.Fatalf("expected state insert failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateTenancyConnectorWithSecretEnvelopeIfAbsentRollsBackEnvelopeFailure(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	connector, state, envelope := postgresAWSConnectorCreateFixture()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO tenancy_connectors").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO tenancy_connector_states").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO tenancy_connector_secret_envelopes").
		WillReturnError(errors.New("envelope insert failed"))
	mock.ExpectRollback()

	if _, _, err := store.CreateTenancyConnectorWithSecretEnvelopeIfAbsent(ctx, connector, state, envelope); err == nil || !strings.Contains(err.Error(), "create tenancy connector secret envelope if absent") {
		t.Fatalf("expected envelope insert failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func postgresAWSConnectorCreateFixture() (TenancyConnector, TenancyConnectorState, TenancyConnectorSecretEnvelope) {
	now := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	connector := TenancyConnector{
		TenantID:            "tenant-a",
		WorkspaceID:         "workspace-a",
		ProjectID:           "project-1",
		ConnectorID:         "aws-prod",
		Type:                domain.ConnectorTypeAWS,
		DisplayName:         "Production AWS",
		Status:              domain.ConnectorStatusPending,
		SecretProvider:      "secret-envelope",
		SecretRefID:         "secret-ref",
		SecretRefVersion:    "test-v1",
		SecretLastRotatedAt: &now,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	state := TenancyConnectorState{
		TenantID:     "tenant-a",
		WorkspaceID:  "workspace-a",
		ProjectID:    "project-1",
		ConnectorID:  "aws-prod",
		HealthStatus: "unknown",
		Metadata: map[string]any{
			"launch_url": "https://console.aws.amazon.com/cloudformation/home",
		},
		ObservedAt: now,
		UpdatedAt:  now,
	}
	envelope := TenancyConnectorSecretEnvelope{
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		ProjectID:       "project-1",
		ConnectorID:     "aws-prod",
		SecretName:      "external_id",
		EnvelopeVersion: 1,
		Envelope: secretstore.Envelope{
			Version:    1,
			Algorithm:  secretstore.AlgorithmAES256GCM,
			KeyVersion: "test-v1",
			Nonce:      []byte("123456789012"),
			Ciphertext: []byte("ciphertext"),
		},
		SecretRefID: "secret-ref",
		RotatedAt:   now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return connector, state, envelope
}

func TestPostgresStoreListTenancyConnectors(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "type", "display_name", "status",
		"secret_provider", "secret_ref_id", "secret_ref_version", "secret_last_rotated_at",
		"config_checksum", "last_sync_at", "created_at", "updated_at", "health_status", "sync_cursor",
		"last_successful_sync_at", "last_error_code", "last_error_message", "metadata", "observed_at", "state_updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-123456789012", "aws", "Production AWS", "active",
		nil, nil, nil, nil, nil, nil, now, now, "healthy", nil, nil, nil, nil,
		[]byte(`{"region":"us-west-2"}`), now, now,
	)
	mock.ExpectQuery(`(?s)SELECT.*FROM tenancy_connectors.*c\.type = \$3.*LIMIT \$4`).
		WithArgs("tenant-a", "workspace-a", "aws", 10).
		WillReturnRows(rows)

	connectors, err := store.ListTenancyConnectors(ctx, "workspace-a", "", domain.ConnectorTypeAWS, 10)
	if err != nil {
		t.Fatalf("list connectors: %v", err)
	}
	if len(connectors) != 1 || connectors[0].Connector.ConnectorID != "aws-123456789012" {
		t.Fatalf("unexpected connectors: %+v", connectors)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAWSAccountRegionCoverageRegistry(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

	upsertRows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "account_id", "account_alias",
		"organization_id", "ou_path", "partition", "region", "role_arn", "coverage_status",
		"last_successful_scan_at", "last_observed_error_code", "last_observed_error_message",
		"scan_cursor", "suspended", "disabled", "unreachable", "created_at", "updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-prod", "123456789012", "Production",
		"o-example", "/Root/Prod", "aws", "us-west-2", "arn:aws:iam::123456789012:role/IdentrailReadOnly", "covered",
		now, "", "", []byte(`{"next_token":"abc"}`), false, false, false, now, now,
	)
	mock.ExpectQuery(`(?s)INSERT INTO aws_account_region_coverages.*FROM tenancy_connectors c.*c\.type = \$22.*ON CONFLICT.*RETURNING`).
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"aws-prod",
			"123456789012",
			"Production",
			"o-example",
			"/Root/Prod",
			"aws",
			"us-west-2",
			"arn:aws:iam::123456789012:role/IdentrailReadOnly",
			"covered",
			sqlmock.AnyArg(),
			"",
			"",
			sqlmock.AnyArg(),
			false,
			false,
			false,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			string(domain.ConnectorTypeAWS),
		).
		WillReturnRows(upsertRows)

	coverage, err := store.UpsertAWSAccountRegionCoverage(ctx, AWSAccountRegionCoverage{
		WorkspaceID:          "workspace-a",
		ProjectID:            "project-1",
		ConnectorID:          "aws-prod",
		AccountID:            "123456789012",
		AccountAlias:         "Production",
		OrganizationID:       "o-example",
		OUPath:               "/Root/Prod",
		Region:               "us-west-2",
		RoleARN:              "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		CoverageStatus:       AWSAccountRegionCoverageCovered,
		LastSuccessfulScanAt: &now,
		ScanCursor:           map[string]any{"next_token": "abc"},
	})
	if err != nil {
		t.Fatalf("upsert aws coverage: %v", err)
	}
	if coverage.AccountID != "123456789012" || coverage.ScanCursor["next_token"] != "abc" {
		t.Fatalf("unexpected upserted coverage: %+v", coverage)
	}

	listRows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "account_id", "account_alias",
		"organization_id", "ou_path", "partition", "region", "role_arn", "coverage_status",
		"last_successful_scan_at", "last_observed_error_code", "last_observed_error_message",
		"scan_cursor", "suspended", "disabled", "unreachable", "created_at", "updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-prod", "123456789012", "Production",
		"o-example", "/Root/Prod", "aws", "us-west-2", "arn:aws:iam::123456789012:role/IdentrailReadOnly", "covered",
		now, "", "", []byte(`{"next_token":"abc"}`), false, false, false, now, now,
	)
	mock.ExpectQuery(`(?s)SELECT.*FROM aws_account_region_coverages.*connector_id = \$4.*ORDER BY connector_id ASC, account_id ASC, region ASC LIMIT \$5`).
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-prod", 10).
		WillReturnRows(listRows)

	records, err := store.ListAWSAccountRegionCoverages(ctx, AWSAccountRegionCoverageFilter{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("list aws coverage: %v", err)
	}
	if len(records) != 1 || records[0].AccountID != "123456789012" {
		t.Fatalf("unexpected coverage rows: %+v", records)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAWSPlatformBaselineResultRegistry(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	checks := []AWSPlatformBaselineCheck{{
		Name:        "aws_connector_health",
		Category:    "connector",
		Required:    true,
		Status:      AWSPlatformBaselineCheckPassed,
		Message:     "AWS connector is active and healthy.",
		EvidenceURL: "/docs/auth/aws-connector",
		Confidence:  0.96,
		Evidence:    map[string]any{"connector_id": "aws-prod"},
		CheckedAt:   now,
	}}
	failureReasonsPayload, err := json.Marshal([]string{})
	if err != nil {
		t.Fatalf("marshal failure reasons: %v", err)
	}
	evidenceLinksPayload, err := json.Marshal([]string{"/docs/auth/aws-connector"})
	if err != nil {
		t.Fatalf("marshal evidence links: %v", err)
	}
	checksPayload, err := json.Marshal(checks)
	if err != nil {
		t.Fatalf("marshal checks: %v", err)
	}
	baselineColumns := []string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "git_sha", "source_mode",
		"fixture_only", "connector_profile_version", "graph_contract_version", "account_id",
		"region", "status", "confidence", "required_checks_passed", "failure_reasons",
		"evidence_links", "checks", "verified_at", "created_at", "updated_at",
	}
	resultRows := sqlmock.NewRows(baselineColumns).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-prod", "6dd631b1", "sdk",
		false, "aws-readonly-iam-v1", "relationship-contract-v1", "123456789012",
		"us-east-1", AWSPlatformBaselineStatusReady, 0.95, true, failureReasonsPayload,
		evidenceLinksPayload, checksPayload, now, now, now,
	)
	mock.ExpectQuery(`(?s)INSERT INTO aws_platform_baseline_results.*FROM tenancy_projects p.*c\.type = \$21.*ON CONFLICT.*RETURNING`).
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"aws-prod",
			"6dd631b1",
			"sdk",
			false,
			"aws-readonly-iam-v1",
			"relationship-contract-v1",
			"123456789012",
			"us-east-1",
			AWSPlatformBaselineStatusReady,
			0.95,
			true,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			string(domain.ConnectorTypeAWS),
		).
		WillReturnRows(resultRows)

	upserted, err := store.UpsertAWSPlatformBaselineResult(ctx, AWSPlatformBaselineResult{
		WorkspaceID:             "workspace-a",
		ProjectID:               "project-1",
		ConnectorID:             "aws-prod",
		GitSHA:                  "6dd631b1",
		SourceMode:              "sdk",
		ConnectorProfileVersion: "aws-readonly-iam-v1",
		GraphContractVersion:    "relationship-contract-v1",
		AccountID:               "123456789012",
		Region:                  "us-east-1",
		Status:                  AWSPlatformBaselineStatusReady,
		Confidence:              0.95,
		RequiredChecksPassed:    true,
		EvidenceLinks:           []string{"/docs/auth/aws-connector"},
		Checks:                  checks,
		VerifiedAt:              now,
		CreatedAt:               now,
		UpdatedAt:               now,
	})
	if err != nil {
		t.Fatalf("upsert aws baseline: %v", err)
	}
	if upserted.Status != AWSPlatformBaselineStatusReady || len(upserted.Checks) != 1 {
		t.Fatalf("unexpected upserted baseline: %+v", upserted)
	}

	getRows := sqlmock.NewRows(baselineColumns).AddRow(
		"tenant-a", "workspace-a", "project-1", "aws-prod", "6dd631b1", "sdk",
		false, "aws-readonly-iam-v1", "relationship-contract-v1", "123456789012",
		"us-east-1", AWSPlatformBaselineStatusReady, 0.95, true, failureReasonsPayload,
		evidenceLinksPayload, checksPayload, now, now, now,
	)
	mock.ExpectQuery(`(?s)SELECT tenant_id, workspace_id, project_id, connector_id, git_sha, source_mode.*FROM aws_platform_baseline_results.*connector_id = \$4`).
		WithArgs("tenant-a", "workspace-a", "project-1", "aws-prod").
		WillReturnRows(getRows)

	loaded, err := store.GetAWSPlatformBaselineResult(ctx, AWSPlatformBaselineFilter{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "aws-prod",
	})
	if err != nil {
		t.Fatalf("get aws baseline: %v", err)
	}
	if loaded.ConnectorID != "aws-prod" || len(loaded.EvidenceLinks) != 1 || loaded.Checks[0].Name != "aws_connector_health" {
		t.Fatalf("unexpected loaded baseline: %+v", loaded)
	}

	emptyRows := sqlmock.NewRows(baselineColumns)
	mock.ExpectQuery(`(?s)SELECT tenant_id, workspace_id, project_id, connector_id, git_sha, source_mode.*FROM aws_platform_baseline_results.*connector_id = \$4`).
		WithArgs("tenant-a", "workspace-a", "project-1", "missing").
		WillReturnRows(emptyRows)

	_, err = store.GetAWSPlatformBaselineResult(ctx, AWSPlatformBaselineFilter{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		ConnectorID: "missing",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing baseline to return ErrNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreKubernetesEnrollmentTokenClaim(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()
	updatedMetadata := map[string]any{
		"enrollment_token_sha256":  "token-hash",
		"enrollment_token_used_at": now.Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(updatedMetadata)
	if err != nil {
		t.Fatalf("marshal updated metadata: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenancy_connector_states
		 SET metadata = $5::jsonb,
	     health_status = $6,
	     last_error_code = $7,
	     last_error_message = $8,
	     observed_at = $9,
	     updated_at = $10
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
		   AND connector_id = $4
		   AND metadata ->> 'enrollment_token_sha256' = $11
		   AND metadata ->> 'enrollment_token_used_at' IS NULL`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "kubernetes-agent", payload, "healthy", "", "", now, now, "token-hash").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenancy_connectors
	     SET status = $5,
	         updated_at = $6
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
		   AND connector_id = $4`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "kubernetes-agent", string(domain.ConnectorStatusActive), now).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	claimed, err := store.ClaimKubernetesEnrollmentToken(
		ctx,
		"workspace-a",
		"project-1",
		"kubernetes-agent",
		"token-hash",
		updatedMetadata,
		domain.ConnectorStatusActive,
		"healthy",
		"",
		"",
		now,
		now,
	)
	if err != nil {
		t.Fatalf("claim token first attempt: %v", err)
	}
	if !claimed {
		t.Fatalf("expected first claim to return true")
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenancy_connector_states
		 SET metadata = $5::jsonb,
	     health_status = $6,
	     last_error_code = $7,
	     last_error_message = $8,
	     observed_at = $9,
	     updated_at = $10
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
		   AND connector_id = $4
		   AND metadata ->> 'enrollment_token_sha256' = $11
		   AND metadata ->> 'enrollment_token_used_at' IS NULL`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "kubernetes-agent", payload, "healthy", "", "", now, now.Add(time.Minute), "token-hash").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	claimed, err = store.ClaimKubernetesEnrollmentToken(
		ctx,
		"workspace-a",
		"project-1",
		"kubernetes-agent",
		"token-hash",
		updatedMetadata,
		domain.ConnectorStatusActive,
		"healthy",
		"",
		"",
		now,
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("claim token second attempt: %v", err)
	}
	if claimed {
		t.Fatalf("expected second claim to return false")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListTenancyConnectorsUnscopedWithoutLimit(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "type", "display_name", "status",
		"secret_provider", "secret_ref_id", "secret_ref_version", "secret_last_rotated_at",
		"config_checksum", "last_sync_at", "created_at", "updated_at", "health_status", "sync_cursor",
		"last_successful_sync_at", "last_error_code", "last_error_message", "metadata", "observed_at", "state_updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "github-a", "github", "GitHub A", "active",
		nil, nil, nil, nil, nil, nil, now, now, "healthy", nil, nil, nil, nil,
		[]byte(`{"installation_id":101}`), now, now,
	).AddRow(
		"tenant-a", "workspace-b", "project-2", "github-b", "github", "GitHub B", "active",
		nil, nil, nil, nil, nil, nil, now, now, "healthy", nil, nil, nil, nil,
		[]byte(`{"installation_id":202}`), now, now,
	)
	mock.ExpectQuery(`(?s)SELECT.*FROM tenancy_connectors.*c\.type = \$1.*ORDER BY c\.updated_at DESC$`).
		WithArgs("github").
		WillReturnRows(rows)

	connectors, err := store.ListTenancyConnectorsUnscoped(context.Background(), domain.ConnectorTypeGitHub, 0)
	if err != nil {
		t.Fatalf("list unscoped connectors: %v", err)
	}
	if len(connectors) != 2 {
		t.Fatalf("expected both connectors without limit, got %+v", connectors)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreConnectorSecretEnvelopeCRUD(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()
	due := now.Add(24 * time.Hour)

	envelope := TenancyConnectorSecretEnvelope{
		WorkspaceID:     "workspace-a",
		ProjectID:       "project-1",
		ConnectorID:     "github",
		SecretName:      "webhook_secret",
		EnvelopeVersion: 1,
		Envelope: secretstore.Envelope{
			Version:    1,
			Algorithm:  secretstore.AlgorithmAES256GCM,
			KeyVersion: "v1",
			Nonce:      []byte("123456789012"),
			Ciphertext: []byte("ciphertext"),
		},
		SecretRefID:   "vault://secret/v1",
		RotatedAt:     now,
		RotationDueAt: &due,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_connector_secret_envelopes (
		     tenant_id, workspace_id, project_id, connector_id, secret_name, envelope_version,
		     algorithm, key_version, nonce, ciphertext, secret_ref_id, rotated_at, rotation_due_at, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''), $12, $13, $14, $15)
		 ON CONFLICT (tenant_id, workspace_id, project_id, connector_id, secret_name) DO UPDATE
		 SET envelope_version = EXCLUDED.envelope_version,
		     algorithm = EXCLUDED.algorithm,
		     key_version = EXCLUDED.key_version,
		     nonce = EXCLUDED.nonce,
		     ciphertext = EXCLUDED.ciphertext,
		     secret_ref_id = EXCLUDED.secret_ref_id,
		     rotated_at = EXCLUDED.rotated_at,
		     rotation_due_at = EXCLUDED.rotation_due_at,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "github", "webhook_secret", 1, secretstore.AlgorithmAES256GCM, "v1", []byte("123456789012"), []byte("ciphertext"), "vault://secret/v1", now, &due, now, now).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertTenancyConnectorSecretEnvelope(ctx, envelope); err != nil {
		t.Fatalf("upsert connector secret envelope: %v", err)
	}

	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "connector_id", "secret_name", "envelope_version",
		"algorithm", "key_version", "nonce", "ciphertext", "secret_ref_id", "rotated_at", "rotation_due_at", "created_at", "updated_at",
	}).AddRow(
		"tenant-a", "workspace-a", "project-1", "github", "webhook_secret", 1,
		secretstore.AlgorithmAES256GCM, "v1", []byte("123456789012"), []byte("ciphertext"), "vault://secret/v1", now, due, now, now,
	)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, connector_id, secret_name, envelope_version,
		        algorithm, key_version, nonce, ciphertext, secret_ref_id, rotated_at, rotation_due_at, created_at, updated_at
		 FROM tenancy_connector_secret_envelopes
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
		   AND connector_id = $4
		   AND secret_name = $5`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "github", "webhook_secret").
		WillReturnRows(rows)

	got, err := store.GetTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "github", "webhook_secret")
	if err != nil {
		t.Fatalf("get connector secret envelope: %v", err)
	}
	if got.SecretRefID != "vault://secret/v1" || got.Envelope.Version != 1 {
		t.Fatalf("unexpected connector secret envelope: %+v", got)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_connector_secret_envelopes
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
		   AND connector_id = $4
		   AND secret_name = $5`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "github", "webhook_secret").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.DeleteTenancyConnectorSecretEnvelope(ctx, "workspace-a", "project-1", "github", "webhook_secret"); err != nil {
		t.Fatalf("delete connector secret envelope: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreWorkspaceScopeIsolation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	_, err = store.GetWorkspace(ctx, "workspace-b")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scoped workspace lookup to fail with ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertProjectRejectsCrossWorkspaceScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	err = store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-b",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-workspace upsert, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreDeleteProjectScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "project-1").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.DeleteProject(ctx, "workspace-a", "project-1"); err != nil {
		t.Fatalf("delete project: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "project-missing").
		WillReturnResult(sqlmock.NewResult(1, 0))

	if err := store.DeleteProject(ctx, "workspace-a", "project-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing project delete, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertsMapForeignKeyViolationToNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	fkErr := errors.New(`pq: insert or update on table "tenancy_projects" violates foreign key constraint "tenancy_projects_tenant_id_workspace_id_fkey"`)

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_workspaces (tenant_id, workspace_id, display_name, slug, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (tenant_id, workspace_id) DO UPDATE
		 SET display_name = EXCLUDED.display_name,
		     slug = EXCLUDED.slug,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "workspace-a", "Workspace A", "workspace-a", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fkErr)
	if err := store.UpsertWorkspace(ctx, TenancyWorkspace{
		WorkspaceID: "workspace-a",
		DisplayName: "Workspace A",
		Slug:        "workspace-a",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected workspace FK violation to map to ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_workspace_members (
		     tenant_id, workspace_id, member_id, user_id, user_uuid, email, role, status, joined_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, NULLIF($5, '')::uuid, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id, workspace_id, member_id) DO UPDATE
		 SET user_id = EXCLUDED.user_id,
		     user_uuid = EXCLUDED.user_uuid,
		     email = EXCLUDED.email,
		     role = EXCLUDED.role,
		     status = EXCLUDED.status,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "workspace-a", "member-1", "user-1", "", "user@example.com", "admin", "active", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fkErr)
	if err := store.UpsertWorkspaceMember(ctx, TenancyWorkspaceMember{
		WorkspaceID: "workspace-a",
		MemberID:    "member-1",
		UserID:      "user-1",
		Email:       "user@example.com",
		Role:        "admin",
		Status:      "active",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected member FK violation to map to ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO tenancy_projects (
		     tenant_id, workspace_id, project_id, name, slug, description, archived_at, created_at, updated_at
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (tenant_id, workspace_id, project_id) DO UPDATE
		 SET name = EXCLUDED.name,
		     slug = EXCLUDED.slug,
		     description = EXCLUDED.description,
		     archived_at = EXCLUDED.archived_at,
		     updated_at = EXCLUDED.updated_at`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "", nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(fkErr)
	if err := store.UpsertProject(ctx, TenancyProject{
		WorkspaceID: "workspace-a",
		ProjectID:   "project-1",
		Name:        "Project 1",
		Slug:        "project-1",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected project FK violation to map to ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreDeleteOrganizationScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_organizations
		 WHERE tenant_id = $1`)).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.DeleteOrganization(ctx); err != nil {
		t.Fatalf("delete organization: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_organizations
		 WHERE tenant_id = $1`)).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(1, 0))
	if err := store.DeleteOrganization(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing organization delete, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListAndDeleteWorkspaceScoped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "active", nil, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`)).
		WithArgs("tenant-a", 20).
		WillReturnRows(rows)

	workspaces, err := store.ListWorkspaces(ctx, 20)
	if err != nil {
		t.Fatalf("list workspaces: %v", err)
	}
	if len(workspaces) != 1 || workspaces[0].WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected workspaces: %+v", workspaces)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.DeleteWorkspace(ctx, "workspace-a"); err != nil {
		t.Fatalf("delete workspace: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreWorkspaceMemberCRUD(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	row := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "user_uuid", "email", "role", "status", "joined_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "member-1", "user-1", "", "user@example.com", "admin", "active", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, member_id, user_id, COALESCE(user_uuid::text, ''), email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "member-1").
		WillReturnRows(row)

	member, err := store.GetWorkspaceMember(ctx, "workspace-a", "member-1")
	if err != nil {
		t.Fatalf("get workspace member: %v", err)
	}
	if member.MemberID != "member-1" {
		t.Fatalf("unexpected member: %+v", member)
	}

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "user_uuid", "email", "role", "status", "joined_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "member-1", "user-1", "", "user@example.com", "admin", "active", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, member_id, user_id, COALESCE(user_uuid::text, ''), email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		 ORDER BY joined_at ASC
		 LIMIT $3`)).
		WithArgs("tenant-a", "workspace-a", 100).
		WillReturnRows(rows)

	members, err := store.ListWorkspaceMembers(ctx, "workspace-a", 100)
	if err != nil {
		t.Fatalf("list workspace members: %v", err)
	}
	if len(members) != 1 || members[0].MemberID != "member-1" {
		t.Fatalf("unexpected members: %+v", members)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "member-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	if err := store.DeleteWorkspaceMember(ctx, "workspace-a", "member-1"); err != nil {
		t.Fatalf("delete workspace member: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreFindFirstWorkspaceMemberByUserUUIDBypassesScopeRLS(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	store.SetScopeRLSEnforcement(true)

	now := time.Now().UTC()
	userUUID := "11111111-1111-1111-1111-111111111111"
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "user_uuid", "email", "role", "status", "joined_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "member-1", "subject-1", userUUID, "user@example.com", "admin", "active", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, member_id, user_id, COALESCE(user_uuid::text, ''), email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE user_uuid = NULLIF($1, '')::uuid
		   AND status = 'active'
		 ORDER BY joined_at DESC
		 LIMIT 1`)).
		WithArgs(userUUID).
		WillReturnRows(rows)

	member, err := store.FindFirstWorkspaceMemberByUserUUID(context.Background(), userUUID)
	if err != nil {
		t.Fatalf("find first member without scope under rls: %v", err)
	}
	if member.TenantID != "tenant-a" || member.WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected member: %+v", member)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreFindFirstWorkspaceMemberByUserUUIDAndTenantIDBypassesScopeRLS(t *testing.T) {
	rawDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer rawDB.Close()

	store := NewPostgresStoreWithDB(rawDB)
	store.SetScopeRLSEnforcement(true)

	now := time.Now().UTC()
	userUUID := "11111111-1111-1111-1111-111111111111"
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "user_uuid", "email", "role", "status", "joined_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "member-1", "subject-1", userUUID, "user@example.com", "admin", "active", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, member_id, user_id, COALESCE(user_uuid::text, ''), email, role, status, joined_at, updated_at
		 FROM tenancy_workspace_members
		 WHERE user_uuid = NULLIF($1, '')::uuid
		   AND tenant_id = $2
		   AND status = 'active'
		 ORDER BY joined_at DESC
		 LIMIT 1`)).
		WithArgs(userUUID, "tenant-a").
		WillReturnRows(rows)

	member, err := store.FindFirstWorkspaceMemberByUserUUIDAndTenantID(context.Background(), userUUID, "tenant-a")
	if err != nil {
		t.Fatalf("find first member by tenant without scope under rls: %v", err)
	}
	if member.TenantID != "tenant-a" || member.WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected member: %+v", member)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreProjectReadPaths(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()
	archivedAt := now

	row := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "project_id", "name", "slug", "coalesce", "archived_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "desc", archivedAt, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "project-1").
		WillReturnRows(row)

	project, err := store.GetProject(ctx, "workspace-a", "project-1")
	if err != nil {
		t.Fatalf("get project: %v", err)
	}
	if project.ProjectID != "project-1" || project.ArchivedAt == nil {
		t.Fatalf("unexpected project: %+v", project)
	}

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "project_id", "name", "slug", "coalesce", "archived_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "desc", nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2 AND archived_at IS NULL ORDER BY created_at DESC LIMIT $3`)).
		WithArgs("tenant-a", "workspace-a", 100).
		WillReturnRows(rows)

	projects, err := store.ListProjects(ctx, "workspace-a", false, 100)
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	if len(projects) != 1 || projects[0].ProjectID != "project-1" {
		t.Fatalf("unexpected projects: %+v", projects)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreWorkspaceAndMemberNotFoundPaths(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnError(sql.ErrNoRows)
	if _, err := store.GetWorkspace(ctx, "workspace-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing workspace to return ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspace_members
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND member_id = $3`)).
		WithArgs("tenant-a", "workspace-a", "missing-member").
		WillReturnResult(sqlmock.NewResult(1, 0))
	if err := store.DeleteWorkspaceMember(ctx, "workspace-a", "missing-member"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing member delete to return ErrNotFound, got %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(1, 0))
	if err := store.DeleteWorkspace(ctx, "workspace-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing workspace delete to return ErrNotFound, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListProjectsIncludesArchivedBranch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "project_id", "name", "slug", "coalesce", "archived_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "project-1", "Project 1", "project-1", "desc", now, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, name, slug, COALESCE(description, ''), archived_at, created_at, updated_at
		 FROM tenancy_projects
		 WHERE tenant_id = $1
		   AND workspace_id = $2 ORDER BY created_at DESC LIMIT $3`)).
		WithArgs("tenant-a", "workspace-a", 10).
		WillReturnRows(rows)

	projects, err := store.ListProjects(ctx, "workspace-a", true, 10)
	if err != nil {
		t.Fatalf("list projects include archived: %v", err)
	}
	if len(projects) != 1 || projects[0].ArchivedAt == nil {
		t.Fatalf("expected archived project in result, got %+v", projects)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreScanPolicyCRUD(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	mock.ExpectExec("INSERT INTO tenancy_scan_policies").
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"default",
			"Default policy",
			true,
			"scheduled",
			"0 * * * *",
			2,
			300,
			120,
			nil,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		PolicyID:           "default",
		Name:               "Default policy",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeScheduled,
		Cron:               "0 * * * *",
		MaxConcurrentScans: 2,
		HistoryLimit:       300,
		MaxFindings:        120,
	}); err != nil {
		t.Fatalf("upsert scan policy: %v", err)
	}

	listRows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "policy_id", "name", "enabled", "trigger_mode", "cron",
		"max_concurrent_scans", "history_limit", "max_findings", "last_scheduled_at", "created_at", "updated_at",
	}).AddRow("tenant-a", "workspace-a", "project-1", "default", "Default policy", true, "scheduled", "0 * * * *", 2, 300, 120, nil, now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, project_id, policy_id, name, enabled, trigger_mode, COALESCE\\(cron, ''\\),").
		WithArgs("tenant-a", "workspace-a", "project-1", "scheduled", true, 20).
		WillReturnRows(listRows)

	enabled := true
	listed, err := store.ListTenancyScanPolicies(ctx, "workspace-a", "project-1", domain.ScanTriggerModeScheduled, &enabled, "created_at", false, 20)
	if err != nil {
		t.Fatalf("list scan policies: %v", err)
	}
	if len(listed) != 1 || listed[0].PolicyID != "default" {
		t.Fatalf("unexpected listed scan policies: %+v", listed)
	}

	getRows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "policy_id", "name", "enabled", "trigger_mode", "cron",
		"max_concurrent_scans", "history_limit", "max_findings", "last_scheduled_at", "created_at", "updated_at",
	}).AddRow("tenant-a", "workspace-a", "project-1", "default", "Default policy", true, "scheduled", "0 * * * *", 2, 300, 120, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, project_id, policy_id, name, enabled, trigger_mode, COALESCE(cron, ''),
		        max_concurrent_scans, history_limit, max_findings, last_scheduled_at, created_at, updated_at
		 FROM tenancy_scan_policies
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
		   AND policy_id = $4`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "default").
		WillReturnRows(getRows)

	policy, err := store.GetTenancyScanPolicy(ctx, "workspace-a", "project-1", "default")
	if err != nil {
		t.Fatalf("get scan policy: %v", err)
	}
	if policy.HistoryLimit != 300 || policy.MaxFindings != 120 {
		t.Fatalf("unexpected scan policy payload: %+v", policy)
	}

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_scan_policies
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
		   AND policy_id = $4`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "default").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.DeleteTenancyScanPolicy(ctx, "workspace-a", "project-1", "default"); err != nil {
		t.Fatalf("delete scan policy: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreScanPolicyDuplicateNameReturnsConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})

	mock.ExpectExec("INSERT INTO tenancy_scan_policies").
		WithArgs(
			"tenant-a",
			"workspace-a",
			"project-1",
			"secondary",
			"Default policy",
			true,
			"manual",
			"",
			1,
			500,
			200,
			nil,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnError(testSQLStateError("23505"))

	err = store.UpsertTenancyScanPolicy(ctx, TenancyScanPolicy{
		WorkspaceID:        "workspace-a",
		ProjectID:          "project-1",
		PolicyID:           "secondary",
		Name:               "Default policy",
		Enabled:            true,
		TriggerMode:        domain.ScanTriggerModeManual,
		MaxConcurrentScans: 1,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected duplicate scan policy name to return ErrConflict, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreScheduledScanPolicyListAndClaim(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	now := time.Now().UTC()

	rows := sqlmock.NewRows([]string{
		"tenant_id", "workspace_id", "project_id", "policy_id", "name", "enabled", "trigger_mode", "cron",
		"max_concurrent_scans", "history_limit", "max_findings", "last_scheduled_at", "created_at", "updated_at",
	}).AddRow("tenant-a", "workspace-a", "project-1", "default", "Default policy", true, "scheduled", "*/5 * * * *", 1, 500, 200, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT p.tenant_id, p.workspace_id, p.project_id, p.policy_id, p.name, p.enabled, p.trigger_mode, COALESCE(p.cron, ''),
			        p.max_concurrent_scans, p.history_limit, p.max_findings, p.last_scheduled_at, p.created_at, p.updated_at
			 FROM tenancy_scan_policies p
			 JOIN tenancy_workspaces w
			   ON w.tenant_id = p.tenant_id
			  AND w.workspace_id = p.workspace_id
			  AND w.status = 'active'
			  AND w.deleted_at IS NULL
			 WHERE p.enabled = TRUE
			   AND p.trigger_mode IN ($1, $2)
			 ORDER BY p.created_at ASC, p.tenant_id ASC, p.workspace_id ASC, p.project_id ASC, p.policy_id ASC
			 LIMIT $3 OFFSET $4`)).
		WithArgs("scheduled", "hybrid", 100, 25).
		WillReturnRows(rows)

	listed, err := store.ListScheduledTenancyScanPolicies(ctx, 100, 25)
	if err != nil {
		t.Fatalf("ListScheduledTenancyScanPolicies returned error: %v", err)
	}
	if len(listed) != 1 || listed[0].PolicyID != "default" {
		t.Fatalf("unexpected list payload: %+v", listed)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenancy_scan_policies
		 SET last_scheduled_at = $5,
		     updated_at = $6
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND project_id = $3
			   AND policy_id = $4
			   AND enabled = TRUE
			   AND trigger_mode IN ($7, $8)
			   AND (last_scheduled_at IS NULL OR last_scheduled_at < $5)
			   AND EXISTS (
			       SELECT 1
			       FROM tenancy_workspaces w
			       WHERE w.tenant_id = tenancy_scan_policies.tenant_id
			         AND w.workspace_id = tenancy_scan_policies.workspace_id
			         AND w.status = 'active'
			         AND w.deleted_at IS NULL
			   )`)).
		WithArgs("tenant-a", "workspace-a", "project-1", "default", sqlmock.AnyArg(), sqlmock.AnyArg(), "scheduled", "hybrid").
		WillReturnResult(sqlmock.NewResult(0, 1))

	claimed, err := store.ClaimTenancyScanPolicySchedule(ctx, "workspace-a", "project-1", "default", now, now.Add(time.Second))
	if err != nil {
		t.Fatalf("ClaimTenancyScanPolicySchedule returned error: %v", err)
	}
	if !claimed {
		t.Fatal("expected claim to return true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListSoleOwnerWorkspaces(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "ws-sole", "Sole-owned", "ws-sole", "active", nil, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT w.tenant_id, w.workspace_id, w.display_name, w.slug, w.status, w.suspended_at, w.deleted_at, w.created_at, w.updated_at
		 FROM tenancy_workspaces w
		 JOIN tenancy_workspace_members caller
		   ON caller.tenant_id = w.tenant_id
		  AND caller.workspace_id = w.workspace_id
			  AND caller.user_uuid = NULLIF($1, '')::uuid
			  AND caller.status = 'active'
			  AND caller.role = 'owner'
			 WHERE w.status <> 'deleted'
			   AND w.deleted_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1
			     FROM tenancy_workspace_members other
		     LEFT JOIN users other_u ON other_u.id = other.user_uuid
		     WHERE other.tenant_id = w.tenant_id
		       AND other.workspace_id = w.workspace_id
		       AND other.user_uuid <> NULLIF($1, '')::uuid
		       AND other.status = 'active'
		       AND other.role = 'owner'
		       AND (other_u.id IS NULL OR other_u.status <> 'deleted')
		 )
		 ORDER BY w.workspace_id ASC`)).
		WithArgs("11111111-1111-1111-1111-111111111111").
		WillReturnRows(rows)

	results, err := store.ListSoleOwnerWorkspaces(context.Background(), "11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("list sole owner: %v", err)
	}
	if len(results) != 1 || results[0].WorkspaceID != "ws-sole" {
		t.Fatalf("unexpected payload: %+v", results)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// workspaceLifecycleScope mirrors the tenant + workspace scope every
// postgres lifecycle test below uses.
func workspaceLifecycleScope() context.Context {
	return WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
}

func TestPostgresStoreSuspendWorkspace(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "suspended", now, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE tenancy_workspaces
			 SET status = 'suspended',
			     suspended_at = COALESCE(suspended_at, $3::timestamptz),
			     updated_at = $3::timestamptz
			 WHERE tenant_id = $1
			   AND workspace_id = $2
			   AND status <> 'deleted'
			   AND deleted_at IS NULL
			 RETURNING tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at`)).
		WithArgs("tenant-a", "workspace-a", now.UTC()).
		WillReturnRows(rows)

	saved, err := store.SuspendWorkspace(ctx, "workspace-a", now)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if saved.Status != WorkspaceStatusSuspended || saved.SuspendedAt == nil {
		t.Fatalf("expected suspended status with timestamp, got %+v", saved)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreSuspendWorkspaceNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE tenancy_workspaces
			 SET status = 'suspended',`)).
		WithArgs("tenant-a", "workspace-a", now.UTC()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
			 FROM tenancy_workspaces
			 WHERE tenant_id = $1
			   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnError(sql.ErrNoRows)

	if _, err := store.SuspendWorkspace(ctx, "workspace-a", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreSuspendWorkspaceDeletedConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE tenancy_workspaces
			 SET status = 'suspended',`)).
		WithArgs("tenant-a", "workspace-a", now.UTC()).
		WillReturnError(sql.ErrNoRows)
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "deleted", nil, deletedAt, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
			 FROM tenancy_workspaces
			 WHERE tenant_id = $1
			   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnRows(rows)

	if _, err := store.SuspendWorkspace(ctx, "workspace-a", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreReactivateWorkspace(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "active", nil, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE tenancy_workspaces
		 SET status = 'active',
		     suspended_at = NULL,
		     updated_at = $3::timestamptz
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'suspended'
		   AND deleted_at IS NULL`)).
		WithArgs("tenant-a", "workspace-a", now.UTC()).
		WillReturnRows(rows)

	saved, err := store.ReactivateWorkspace(ctx, "workspace-a", now)
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if saved.Status != WorkspaceStatusActive || saved.SuspendedAt != nil {
		t.Fatalf("expected reactivated workspace, got %+v", saved)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreReactivateWorkspaceDeletedConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE tenancy_workspaces
		 SET status = 'active',`)).
		WithArgs("tenant-a", "workspace-a", now.UTC()).
		WillReturnError(sql.ErrNoRows)
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "deleted", nil, deletedAt, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
			 FROM tenancy_workspaces
			 WHERE tenant_id = $1
			   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnRows(rows)

	if _, err := store.ReactivateWorkspace(ctx, "workspace-a", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreSoftDeleteWorkspace(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "deleted", nil, now, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE tenancy_workspaces
		 SET status = 'deleted',
		     deleted_at = COALESCE(deleted_at, $3::timestamptz),
		     updated_at = $3::timestamptz
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a", now.UTC()).
		WillReturnRows(rows)

	saved, err := store.SoftDeleteWorkspace(ctx, "workspace-a", now)
	if err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if saved.Status != WorkspaceStatusDeleted || saved.DeletedAt == nil {
		t.Fatalf("expected soft-deleted workspace, got %+v", saved)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCancelWorkspaceDeletionClearsBothTimestamps(t *testing.T) {
	// Verify the UPDATE clears both suspended_at AND deleted_at — the
	// fix for the round-2 cubic P2 review on PR #1445. Without this
	// assertion a regression that drops `suspended_at = NULL` from the
	// SQL would survive code review since the value is also unset on
	// most happy-path inputs.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "active", nil, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`UPDATE tenancy_workspaces
		 SET status = 'active',
		     deleted_at = NULL,
		     suspended_at = NULL,
		     updated_at = $3::timestamptz
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a", now.UTC()).
		WillReturnRows(rows)

	saved, err := store.CancelWorkspaceDeletion(ctx, "workspace-a", now)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if saved.Status != WorkspaceStatusActive || saved.DeletedAt != nil || saved.SuspendedAt != nil {
		t.Fatalf("expected fully active workspace with cleared timestamps, got %+v", saved)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListWorkspaceStrandedActiveMembersReturnsStranded(t *testing.T) {
	// Exercise the happy-path SQL: a sole owner with one other active
	// member, where the postgres query returns the stranded row. The
	// regex match also pins the IS DISTINCT FROM operator added in
	// round 1 of the codex review so a future edit that reverts to the
	// null-unsafe `<>` would fail this test instead of silently
	// dropping NULL user_uuid members.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)

	// GetWorkspace pre-check.
	wsRows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "active", nil, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnRows(wsRows)

	memberRows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "user_uuid", "email", "role", "status", "joined_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "m-other", "subj-other", "22222222-2222-2222-2222-222222222222", "other@example.com", "analyst", "active", now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`IS DISTINCT FROM NULLIF($3, '')::uuid`)).
		WithArgs("tenant-a", "workspace-a", "11111111-1111-1111-1111-111111111111").
		WillReturnRows(memberRows)

	stranded, err := store.ListWorkspaceStrandedActiveMembers(ctx, "workspace-a", "11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("strand: %v", err)
	}
	if len(stranded) != 1 || stranded[0].MemberID != "m-other" {
		t.Fatalf("expected one stranded member, got %+v", stranded)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListWorkspaceStrandedActiveMembersPinsDeletedOwnerExclusion(t *testing.T) {
	// Codex round-10 cross-store parity pin: the SQL must carry the
	// `NOT (m.role = 'owner' AND mu.id IS NOT NULL AND mu.status = 'deleted')`
	// predicate so a soft-deleted co-owner is excluded from the
	// stranded list, matching the memory store. Without this the
	// postgres path would return a phantom transfer target for the
	// 409 sole_owner_requires_transfer response. A regression that
	// drops the predicate fails this test instead of slipping into
	// production.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	ctx := workspaceLifecycleScope()
	now := time.Date(2026, 5, 12, 9, 0, 0, 0, time.UTC)

	wsRows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "active", nil, nil, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnRows(wsRows)

	// The stranded query is expected to contain the deleted-owner
	// exclusion predicate verbatim. sqlmock matches against this
	// substring; if the predicate goes missing, the regex does not
	// match and the call errors here.
	emptyMembers := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "member_id", "user_id", "user_uuid", "email", "role", "status", "joined_at", "updated_at"})
	mock.ExpectQuery(regexp.QuoteMeta(`NOT (m.role = 'owner' AND mu.id IS NOT NULL AND mu.status = 'deleted')`)).
		WithArgs("tenant-a", "workspace-a", "11111111-1111-1111-1111-111111111111").
		WillReturnRows(emptyMembers)

	stranded, err := store.ListWorkspaceStrandedActiveMembers(ctx, "workspace-a", "11111111-1111-1111-1111-111111111111")
	if err != nil {
		t.Fatalf("strand: %v", err)
	}
	if len(stranded) != 0 {
		t.Fatalf("expected empty stranded list, got %+v", stranded)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListWorkspaceStrandedActiveMembersEmptyUUID(t *testing.T) {
	// Empty caller UUID short-circuits before any SQL is run. Pins the
	// memory + postgres parity: both stores treat an empty UUID as
	// "no caller identity, skip the guard".
	store := NewPostgresStoreWithDB(nil)
	members, err := store.ListWorkspaceStrandedActiveMembers(workspaceLifecycleScope(), "workspace-a", "")
	if err != nil {
		t.Fatalf("empty UUID: %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected no members for empty UUID, got %d", len(members))
	}
}

func TestPostgresStoreListWorkspacesPendingHardDelete(t *testing.T) {
	// #1420 PR 2: the hard-delete worker queries soft-deleted
	// workspaces past the grace cutoff via this method. Pin the SQL
	// filter (status='deleted', deleted_at IS NOT NULL, deleted_at <
	// cutoff) and the deterministic ORDER BY so the worker drains
	// the oldest entries first.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-WorkspaceDeletionGracePeriod)
	pastGrace := cutoff.Add(-time.Hour)

	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "deleted", nil, pastGrace, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE status = 'deleted'
		   AND deleted_at IS NOT NULL
		   AND deleted_at < $1::timestamptz
		 ORDER BY deleted_at ASC, workspace_id ASC
		 LIMIT $2`)).
		WithArgs(cutoff.UTC(), 100).
		WillReturnRows(rows)

	result, err := store.ListWorkspacesPendingHardDelete(context.Background(), cutoff, 100)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(result) != 1 || result[0].WorkspaceID != "workspace-a" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreHardDeleteWorkspacePurgesChildTables(t *testing.T) {
	// Happy-path sqlmock: the worker is past grace and HardDeleteWorkspace
	// must run the full transactional purge — SELECT FOR UPDATE the
	// soft-deleted row, DELETE scan/repo_scan/coverage rows (those carry
	// tenant/workspace columns but no FK back), then DELETE the workspace
	// row itself with the same status+deleted_at guard so a concurrent
	// cancel-deletion landing mid-transaction cannot drop live data.
	// Pinning every DELETE here means a regression that drops one of
	// them (e.g. forgets to purge scans) fails this test instead of
	// silently leaving workspace data behind.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	mock.ExpectBegin()
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "deleted", nil, deletedAt, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'deleted'
		   AND deleted_at = $3::timestamptz
		 FOR UPDATE`)).
		WithArgs("tenant-a", "workspace-a", deletedAt.UTC()).
		WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE sessions
		 SET current_org_id = NULL,
		     current_workspace_id = NULL,
		     current_project_id = NULL
		 WHERE current_org_id = $1
		   AND current_workspace_id = $2
		   AND current_project_id IS NULL`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE onboarding_state
		 SET org_id = NULL,
		     workspace_id = NULL,
		     project_id = NULL
		 WHERE org_id = $1
		   AND workspace_id = $2
		   AND project_id IS NULL`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Every non-cascading workspace-scoped table is purged in
	// declaration order: scans, repo_scans, AWS coverage, then the
	// authz suite, then finding triage. Pin each so a regression
	// dropping one fails this test.
	// The purge iterates a static table list. Required tables (scans,
	// repo_scans) run without a savepoint wrapper. Optional tables run
	// inside a SAVEPOINT/RELEASE pair so a `relation does not exist`
	// error rolls back only that DELETE without poisoning the
	// transaction (codex round-2 P2 on #1450).
	purgeOrder := []struct {
		table    string
		optional bool
	}{
		{table: "scans"},
		{table: "repo_scans"},
		{table: "repo_scan_cursors", optional: true},
		{table: "aws_account_region_coverages", optional: true},
		{table: "authz_entity_attributes", optional: true},
		{table: "authz_relationships", optional: true},
		{table: "authz_policy_sets", optional: true},
		{table: "authz_policy_versions", optional: true},
		{table: "authz_policy_rollouts", optional: true},
		{table: "authz_policy_events", optional: true},
		{table: "finding_triage_states", optional: true},
		{table: "finding_triage_events", optional: true},
	}
	for i, entry := range purgeOrder {
		savepoint := fmt.Sprintf("workspace_purge_%d", i)
		if entry.optional {
			mock.ExpectExec(regexp.QuoteMeta("SAVEPOINT " + savepoint)).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}
		mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM `+entry.table+` WHERE tenant_id = $1 AND workspace_id = $2`)).
			WithArgs("tenant-a", "workspace-a").
			WillReturnResult(sqlmock.NewResult(0, 0))
		if entry.optional {
			mock.ExpectExec(regexp.QuoteMeta("RELEASE SAVEPOINT " + savepoint)).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}
	}
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'deleted'
		   AND deleted_at = $3::timestamptz`)).
		WithArgs("tenant-a", "workspace-a", deletedAt.UTC()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	workspace, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "workspace-a", deletedAt, now)
	if err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if workspace.WorkspaceID != "workspace-a" || workspace.TenantID != "tenant-a" {
		t.Fatalf("unexpected returned workspace: %+v", workspace)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreHardDeleteWorkspaceClearsWorkspaceOnlyContextRows(t *testing.T) {
	// Session and onboarding records can hold workspace-level context where
	// `project_id` is empty (`NULLIF` in Write code). Since the FK to
	// `tenancy_projects` does not match with a NULL project, hard deletes
	// need an explicit update to clear that context before removing the
	// workspace row.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	mock.ExpectBegin()
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "deleted", nil, deletedAt, now, now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'deleted'
		   AND deleted_at = $3::timestamptz
		 FOR UPDATE`)).
		WithArgs("tenant-a", "workspace-a", deletedAt.UTC()).
		WillReturnRows(rows)

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE sessions
		 SET current_org_id = NULL,
		     current_workspace_id = NULL,
		     current_project_id = NULL
		 WHERE current_org_id = $1
		   AND current_workspace_id = $2
		   AND current_project_id IS NULL`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE onboarding_state
		 SET org_id = NULL,
		     workspace_id = NULL,
		     project_id = NULL
		 WHERE org_id = $1
		   AND workspace_id = $2
		   AND project_id IS NULL`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 1))

	purgeOrder := []struct {
		table    string
		optional bool
	}{
		{table: "scans"},
		{table: "repo_scans"},
		{table: "repo_scan_cursors", optional: true},
		{table: "aws_account_region_coverages", optional: true},
		{table: "authz_entity_attributes", optional: true},
		{table: "authz_relationships", optional: true},
		{table: "authz_policy_sets", optional: true},
		{table: "authz_policy_versions", optional: true},
		{table: "authz_policy_rollouts", optional: true},
		{table: "authz_policy_events", optional: true},
		{table: "finding_triage_states", optional: true},
		{table: "finding_triage_events", optional: true},
	}
	for i, entry := range purgeOrder {
		savepoint := fmt.Sprintf("workspace_purge_%d", i)
		if entry.optional {
			mock.ExpectExec(regexp.QuoteMeta("SAVEPOINT " + savepoint)).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}
		mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM `+entry.table+` WHERE tenant_id = $1 AND workspace_id = $2`)).
			WithArgs("tenant-a", "workspace-a").
			WillReturnResult(sqlmock.NewResult(0, 0))
		if entry.optional {
			mock.ExpectExec(regexp.QuoteMeta("RELEASE SAVEPOINT " + savepoint)).
				WillReturnResult(sqlmock.NewResult(0, 0))
		}
	}
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'deleted'
		   AND deleted_at = $3::timestamptz`)).
		WithArgs("tenant-a", "workspace-a", deletedAt.UTC()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	workspace, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "workspace-a", deletedAt, now)
	if err != nil {
		t.Fatalf("hard delete: %v", err)
	}
	if workspace.WorkspaceID != "workspace-a" || workspace.TenantID != "tenant-a" {
		t.Fatalf("unexpected returned workspace: %+v", workspace)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreHardDeleteWorkspaceRollsBackMissingOptionalTable(t *testing.T) {
	// Codex round-2 P2 on #1450: when an optional table is genuinely
	// absent, `DELETE FROM <missing_table>` returns
	// `relation does not exist` AND poisons the surrounding
	// transaction. The savepoint wrapper must ROLLBACK TO SAVEPOINT so
	// the next DELETE (and the final workspace DELETE) can still run.
	// Without the savepoint, the next statement would fail with
	// "current transaction is aborted".
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	deletedAt := now.Add(-(WorkspaceDeletionGracePeriod + time.Hour))

	mock.ExpectBegin()
	rows := sqlmock.NewRows([]string{"tenant_id", "workspace_id", "display_name", "slug", "status", "suspended_at", "deleted_at", "created_at", "updated_at"}).
		AddRow("tenant-a", "workspace-a", "Workspace A", "workspace-a", "deleted", nil, deletedAt, now, now)
	mock.ExpectQuery(regexp.QuoteMeta("FOR UPDATE")).
		WithArgs("tenant-a", "workspace-a", deletedAt.UTC()).
		WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE sessions
		 SET current_org_id = NULL,
		     current_workspace_id = NULL,
		     current_project_id = NULL
		 WHERE current_org_id = $1
		   AND current_workspace_id = $2
		   AND current_project_id IS NULL`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE onboarding_state
		 SET org_id = NULL,
		     workspace_id = NULL,
		     project_id = NULL
		 WHERE org_id = $1
		   AND workspace_id = $2
		   AND project_id IS NULL`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// scans + repo_scans (required) — no savepoint wrapper.
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM scans WHERE tenant_id = $1 AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM repo_scans WHERE tenant_id = $1 AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// repo_scan_cursors (optional) is the absent table here. The
	// savepoint is created, the DELETE fails with "relation does not
	// exist", and the code rolls back to the savepoint instead of
	// aborting the transaction.
	mock.ExpectExec(regexp.QuoteMeta("SAVEPOINT workspace_purge_2")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM repo_scan_cursors WHERE tenant_id = $1 AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnError(fmt.Errorf("pq: relation \"repo_scan_cursors\" does not exist"))
	mock.ExpectExec(regexp.QuoteMeta("ROLLBACK TO SAVEPOINT workspace_purge_2")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// All remaining optional tables succeed (treat them as installed
	// for simplicity). The next iterations issue SAVEPOINT + DELETE +
	// RELEASE.
	remaining := []string{"aws_account_region_coverages", "authz_entity_attributes", "authz_relationships", "authz_policy_sets", "authz_policy_versions", "authz_policy_rollouts", "authz_policy_events", "finding_triage_states", "finding_triage_events"}
	for i, table := range remaining {
		savepoint := fmt.Sprintf("workspace_purge_%d", i+3)
		mock.ExpectExec(regexp.QuoteMeta("SAVEPOINT " + savepoint)).
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM `+table+` WHERE tenant_id = $1 AND workspace_id = $2`)).
			WithArgs("tenant-a", "workspace-a").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(regexp.QuoteMeta("RELEASE SAVEPOINT " + savepoint)).
			WillReturnResult(sqlmock.NewResult(0, 0))
	}
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM tenancy_workspaces`)).
		WithArgs("tenant-a", "workspace-a", deletedAt.UTC()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "workspace-a", deletedAt, now); err != nil {
		t.Fatalf("hard delete with missing optional table: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreHardDeleteWorkspaceMissingReturnsNotFound(t *testing.T) {
	// If both the FOR UPDATE scan AND the fallback existence check
	// return no rows, the workspace genuinely does not exist and the
	// store surfaces ErrNotFound. Distinct from the not-pending-deletion
	// case above so the worker can tell "row gone" from "row still
	// active" — a regression collapsing the two would let the runner
	// silently skip records that should error.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	deletedAt := now.Add(-time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`FOR UPDATE`)).
		WithArgs("tenant-a", "workspace-missing", deletedAt.UTC()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT status, deleted_at FROM tenancy_workspaces WHERE tenant_id = $1 AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-missing").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "workspace-missing", deletedAt, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreHardDeleteWorkspaceRefusesActive(t *testing.T) {
	// The SELECT FOR UPDATE inside HardDeleteWorkspace carries a
	// `status='deleted' AND deleted_at IS NOT NULL` guard, so an
	// active workspace surfaces as ErrNotFound from the first scan.
	// The fallback SELECT then reports the actual status so the
	// returned error explains what happened — a regression that drops
	// the predicate would silently destroy live data.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	deletedAt := now.Add(-time.Hour)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id, workspace_id, display_name, slug, status, suspended_at, deleted_at, created_at, updated_at
		 FROM tenancy_workspaces
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'deleted'
		   AND deleted_at = $3::timestamptz
		 FOR UPDATE`)).
		WithArgs("tenant-a", "workspace-a", deletedAt.UTC()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT status, deleted_at FROM tenancy_workspaces WHERE tenant_id = $1 AND workspace_id = $2`)).
		WithArgs("tenant-a", "workspace-a").
		WillReturnRows(sqlmock.NewRows([]string{"status", "deleted_at"}).AddRow("active", nil))
	mock.ExpectRollback()

	if _, err := store.HardDeleteWorkspace(context.Background(), "tenant-a", "workspace-a", deletedAt, now); err == nil {
		t.Fatal("expected hard delete to refuse active workspace")
	} else if !strings.Contains(err.Error(), "lifecycle drifted") {
		t.Fatalf("expected lifecycle-drifted message, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
