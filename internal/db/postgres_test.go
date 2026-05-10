package db

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

func TestPostgresStoreCreateAndCompleteScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, $5, $6, 0, 0)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "aws", "running", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	scan, err := store.CreateScan(defaultScopeContext(), "aws", time.Now())
	if err != nil {
		t.Fatalf("create scan failed: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE scans
		 SET status=$2, finished_at=$3, asset_count=$4, finding_count=$5, error_message=$6
		 WHERE id=$1
		   AND tenant_id=$7
		   AND workspace_id=$8`)).
		WithArgs(scan.ID, "completed", sqlmock.AnyArg(), 2, 1, nil, "default", "default").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.CompleteScan(defaultScopeContext(), scan.ID, "completed", time.Now(), 2, 1, ""); err != nil {
		t.Fatalf("complete scan failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertFindings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO findings").
		WithArgs("scan-1", "f1", "risky_trust_policy", "high", "Risky trust", "summary", sqlmock.AnyArg(), sqlmock.AnyArg(), "fix", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	findings := []domain.Finding{{
		ID:           "f1",
		Type:         domain.FindingRiskyTrustPolicy,
		Severity:     domain.SeverityHigh,
		Title:        "Risky trust",
		HumanSummary: "summary",
		Path:         []string{"a", "b"},
		Evidence:     map[string]any{"k": "v"},
		Remediation:  "fix",
		CreatedAt:    time.Now(),
	}}

	if err := store.UpsertFindings(defaultScopeContext(), "scan-1", findings); err != nil {
		t.Fatalf("upsert findings failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertArtifacts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO raw_assets").WithArgs("scan-1", "arn:aws:iam::1:role/test", "iam_role", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO identities").WithArgs("scan-1", "aws:identity:arn:aws:iam::1:role/test", "aws", "role", "test", nil, nil, nil, nil, sqlmock.AnyArg(), "raw").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO policies").WithArgs("scan-1", "p1", "aws", "policy", "{}", sqlmock.AnyArg(), "raw").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO relationships").WithArgs("scan-1", "rel-1", "can_access", "a", "b", nil, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO permissions").WithArgs("scan-1", "a", "s3:GetObject", "*", "Allow").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = store.UpsertArtifacts(defaultScopeContext(), "scan-1", ScanArtifacts{
		RawAssets: []providers.RawAsset{{
			Kind:      "iam_role",
			SourceID:  "arn:aws:iam::1:role/test",
			Payload:   []byte(`{"arn":"arn:aws:iam::1:role/test"}`),
			Collected: now.Format(time.RFC3339Nano),
		}},
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "aws:identity:arn:aws:iam::1:role/test", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "test", RawRef: "raw"}},
			Policies:   []domain.Policy{{ID: "p1", Provider: domain.ProviderAWS, Name: "policy", Document: []byte("{}"), Normalized: map[string]any{"k": "v"}, RawRef: "raw"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-1", Type: domain.RelationshipCanAccess, FromNodeID: "a", ToNodeID: "b", DiscoveredAt: now}},
		Permissions:   []providers.PermissionTuple{{IdentityID: "a", Action: "s3:GetObject", Resource: "*", Effect: "Allow"}},
	})
	if err != nil {
		t.Fatalf("upsert artifacts failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestExecuteBulkInsert(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO test_table VALUES ($1, $2), ($3, $4)`)).
		WithArgs("scan-1", "asset-1", "scan-2", "asset-2").
		WillReturnResult(sqlmock.NewResult(0, 2))

	if err := executeBulkInsert(
		context.Background(),
		tx,
		`INSERT INTO test_table VALUES `,
		"",
		[][]any{{"scan-1", "asset-1"}, {"scan-2", "asset-2"}},
	); err != nil {
		t.Fatalf("execute bulk insert: %v", err)
	}

	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback tx: %v", err)
	}

	mock.ExpectBegin()
	tx, err = db.Begin()
	if err != nil {
		t.Fatalf("begin tx for empty-row validation: %v", err)
	}

	if err := executeBulkInsert(context.Background(), tx, `INSERT INTO test_table VALUES `, "", [][]any{{}}); err == nil {
		t.Fatal("expected empty bulk insert row to fail")
	}

	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback empty-row tx: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListScansAndFindings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	scanRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "error_message"}).
		AddRow("scan-1", "default", "default", "aws", "completed", now, now, 2, 1, "")
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, provider, status").WithArgs("default", "default", 20).WillReturnRows(scanRows)

	scans, err := store.ListScans(defaultScopeContext(), 20)
	if err != nil {
		t.Fatalf("list scans failed: %v", err)
	}
	if len(scans) != 1 || scans[0].ID != "scan-1" {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	findingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("default", "default", 100).WillReturnRows(findingsRows)

	findings, err := store.ListFindings(defaultScopeContext(), 100)
	if err != nil {
		t.Fatalf("list findings failed: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "f1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	allFindingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("default", "default").WillReturnRows(allFindingsRows)

	allFindings, err := store.ListFindingsAll(defaultScopeContext())
	if err != nil {
		t.Fatalf("list all findings failed: %v", err)
	}
	if len(allFindings) != 1 || allFindings[0].ID != "f1" {
		t.Fatalf("unexpected all findings: %+v", allFindings)
	}

	totalRows := sqlmock.NewRows([]string{"count"}).AddRow(3)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2`)).
		WithArgs("default", "default").
		WillReturnRows(totalRows)

	severityRows := sqlmock.NewRows([]string{"severity", "count"}).
		AddRow("critical", 1).
		AddRow("high", 2)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT f.severity, COUNT(*)
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		 GROUP BY f.severity`)).
		WithArgs("default", "default").
		WillReturnRows(severityRows)

	typeRows := sqlmock.NewRows([]string{"type", "count"}).
		AddRow("escalation_path", 1).
		AddRow("ownerless_identity", 2)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT f.type, COUNT(*)
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		 GROUP BY f.type`)).
		WithArgs("default", "default").
		WillReturnRows(typeRows)

	summary, err := store.SummarizeFindings(defaultScopeContext())
	if err != nil {
		t.Fatalf("summarize findings failed: %v", err)
	}
	if summary.Total != 3 || summary.BySeverity["high"] != 2 || summary.ByType["ownerless_identity"] != 2 {
		t.Fatalf("unexpected findings summary: %+v", summary)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListScansDefaultsNonPositiveLimitToOneHundred(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "error_message"}).
		AddRow("scan-1", "default", "default", "aws", "completed", now, now, 1, 1, "")
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, provider, status").WithArgs("default", "default", 100).WillReturnRows(rows)

	scans, err := store.ListScans(defaultScopeContext(), 0)
	if err != nil {
		t.Fatalf("list scans default limit: %v", err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected one scan, got %d", len(scans))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListFindingsFiltered(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at",
		"triage_status", "assignee", "suppression_expires_at", "updated_at", "updated_by",
	}).AddRow(
		"scan-1", "finding-1", "ownerless_identity", "critical", "Ownerless", "summary", []byte("[\"a\"]"), []byte("{\"x\":1}"), "fix", now,
		"ack", "secops", nil, now, "subject:user-1",
	)
	mock.ExpectQuery("SELECT\\s+f\\.scan_id,").
		WithArgs("default", "default", "critical", sqlmock.AnyArg(), 0, 11).
		WillReturnRows(rows)

	items, err := store.ListFindingsFiltered(defaultScopeContext(), FindingListFilter{
		Severity: "critical",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("list filtered findings failed: %v", err)
	}
	if len(items) != 1 || items[0].ID != "finding-1" {
		t.Fatalf("unexpected filtered findings: %+v", items)
	}
	if items[0].Triage.Status != domain.FindingLifecycleAck || items[0].Triage.Assignee != "secops" {
		t.Fatalf("unexpected triage payload: %+v", items[0].Triage)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListFindingsFilteredByScanAndLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	rows := sqlmock.NewRows([]string{
		"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at",
		"triage_status", "assignee", "suppression_expires_at", "updated_at", "updated_by",
	}).AddRow(
		"scan-1", "finding-2", "secret_exposure", "high", "Secret", "summary", []byte("null"), []byte("null"), "", now,
		"suppressed", "secops", now.Add(-time.Minute), now, "subject:user-2",
	)
	mock.ExpectQuery("SELECT\\s+f\\.scan_id,").
		WithArgs("default", "default", "scan-1", sqlmock.AnyArg(), "open", "secops", 0, 2).
		WillReturnRows(rows)

	items, err := store.ListFindingsFiltered(defaultScopeContext(), FindingListFilter{
		ScanID:          "scan-1",
		LifecycleStatus: "open",
		Assignee:        "secops",
		Limit:           1,
		Now:             now,
	})
	if err != nil {
		t.Fatalf("list filtered findings by scan failed: %v", err)
	}
	if len(items) != 1 || items[0].ID != "finding-2" {
		t.Fatalf("unexpected filtered findings: %+v", items)
	}
	if items[0].Triage.Status != domain.FindingLifecycleOpen {
		t.Fatalf("expected expired suppression to normalize to open, got %+v", items[0].Triage)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestFindingOrderClause(t *testing.T) {
	tests := []struct {
		sortBy string
		desc   bool
		want   string
	}{
		{sortBy: "created_at", desc: false, want: "f.created_at ASC, f.scan_id ASC, f.finding_id ASC"},
		{sortBy: "severity", desc: true, want: "END DESC, f.scan_id DESC, f.finding_id DESC"},
		{sortBy: "type", desc: false, want: "LOWER(f.type) ASC, f.scan_id ASC, f.finding_id ASC"},
		{sortBy: "title", desc: true, want: "LOWER(f.title) DESC, f.scan_id DESC, f.finding_id DESC"},
	}
	for _, tc := range tests {
		if got := findingOrderClause(tc.sortBy, tc.desc); !strings.Contains(got, tc.want) {
			t.Fatalf("findingOrderClause(%q, %t) = %q, want substring %q", tc.sortBy, tc.desc, got, tc.want)
		}
	}
}

func TestPostgresStoreGetScanAndFindingsByScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	scanRow := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "error_message"}).
		AddRow("scan-1", "default", "default", "aws", "completed", now, now, 2, 1, "")
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, provider, status").WithArgs("scan-1", "default", "default").WillReturnRows(scanRow)

	scan, err := store.GetScan(defaultScopeContext(), "scan-1")
	if err != nil {
		t.Fatalf("get scan failed: %v", err)
	}
	if scan.ID != "scan-1" {
		t.Fatalf("unexpected scan: %+v", scan)
	}

	findingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("scan-1", "default", "default", 100).WillReturnRows(findingsRows)

	findings, err := store.ListFindingsByScan(defaultScopeContext(), "scan-1", 100)
	if err != nil {
		t.Fatalf("list findings by scan failed: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "f1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreGetFinding(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	findingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("default", "default", "f1", "scan-1").WillReturnRows(findingsRows)

	item, err := store.GetFinding(defaultScopeContext(), "f1", "scan-1")
	if err != nil {
		t.Fatalf("get finding failed: %v", err)
	}
	if item.ID != "f1" || item.ScanID != "scan-1" {
		t.Fatalf("unexpected finding: %+v", item)
	}

	emptyRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"})
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("default", "default", "missing", "scan-1").WillReturnRows(emptyRows)
	if _, err := store.GetFinding(defaultScopeContext(), "missing", "scan-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing finding, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreScanEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO scan_events").
		WithArgs(sqlmock.AnyArg(), "scan-1", "info", "scan started", sqlmock.AnyArg(), "default", "default").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.AppendScanEvent(defaultScopeContext(), "scan-1", "info", "scan started", map[string]any{"provider": "aws"}); err != nil {
		t.Fatalf("append scan event failed: %v", err)
	}

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	rows := sqlmock.NewRows([]string{"id", "scan_id", "level", "message", "metadata", "created_at"}).
		AddRow("event-1", "scan-1", "info", "scan started", []byte(`{"provider":"aws"}`), now)
	mock.ExpectQuery("SELECT e.id, e.scan_id, e.level, e.message, e.metadata, e.created_at").WithArgs("scan-1", "default", "default", 10).WillReturnRows(rows)

	events, err := store.ListScanEvents(defaultScopeContext(), "scan-1", 10)
	if err != nil {
		t.Fatalf("list scan events failed: %v", err)
	}
	if len(events) != 1 || events[0].ID != "event-1" {
		t.Fatalf("unexpected events: %+v", events)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreRejectsInvalidScanEventLevel(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	if err := store.AppendScanEvent(defaultScopeContext(), "scan-1", "invalid", "bad", nil); err == nil {
		t.Fatal("expected invalid level error")
	}
}

func TestPostgresStoreListIdentitiesAndRelationships(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	identityRows := sqlmock.NewRows([]string{"id", "provider", "type", "name", "arn", "owner_hint", "created_at", "last_used_at", "tags", "raw_ref"}).
		AddRow("id-1", "aws", "role", "app-role", "arn:aws:iam::1:role/app-role", "", now, nil, []byte(`{"team":"platform"}`), "raw-1")
	mock.ExpectQuery("SELECT i.id, i.provider, i.type, i.name").WithArgs("", "aws", "role", "app", 20, "default", "default").WillReturnRows(identityRows)

	identities, err := store.ListIdentities(defaultScopeContext(), IdentityFilter{
		Provider:   "aws",
		Type:       "role",
		NamePrefix: "app",
	}, 20)
	if err != nil {
		t.Fatalf("list identities failed: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != "id-1" {
		t.Fatalf("unexpected identities: %+v", identities)
	}

	relationshipRows := sqlmock.NewRows([]string{"id", "type", "from_node_id", "to_node_id", "evidence_ref", "discovered_at"}).
		AddRow("rel-1", "can_assume", "id-1", "id-2", "", now)
	mock.ExpectQuery("SELECT r.id, r.type, r.from_node_id").WithArgs("", "can_assume", "", "", 30, "default", "default").WillReturnRows(relationshipRows)

	relationships, err := store.ListRelationships(defaultScopeContext(), RelationshipFilter{Type: "can_assume"}, 30)
	if err != nil {
		t.Fatalf("list relationships failed: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != "rel-1" {
		t.Fatalf("unexpected relationships: %+v", relationships)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNewPostgresStoreWithDB(t *testing.T) {
	store := NewPostgresStoreWithDB(&sql.DB{})
	if store == nil {
		t.Fatal("expected store")
	}
}

func TestPostgresStoreRepoScanLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "owner/repo", "running", sqlmock.AnyArg(), 0, 0).
		WillReturnResult(sqlmock.NewResult(1, 1))

	record, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", now)
	if err != nil {
		t.Fatalf("create repo scan failed: %v", err)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM repo_scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs(record.ID, "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO repo_findings").
		WithArgs(record.ID, "rf-1", "secret_exposure", "high", "secret", "summary", sqlmock.AnyArg(), sqlmock.AnyArg(), "fix", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.UpsertRepoFindings(defaultScopeContext(), record.ID, []domain.Finding{{
		ID:           "rf-1",
		Type:         domain.FindingSecretExposure,
		Severity:     domain.SeverityHigh,
		Title:        "secret",
		HumanSummary: "summary",
		Path:         []string{"app.env"},
		Evidence:     map[string]any{"k": "v"},
		Remediation:  "fix",
		CreatedAt:    now,
	}}); err != nil {
		t.Fatalf("upsert repo findings failed: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE repo_scans
		 SET status = $2,
		     finished_at = $3,
		     commits_scanned = $4,
		     files_scanned = $5,
		     finding_count = $6,
		     truncated = $7,
		     error_message = $8
		 WHERE id = $1
		   AND tenant_id = $9
		   AND workspace_id = $10`)).
		WithArgs(record.ID, "completed", sqlmock.AnyArg(), 12, 8, 1, false, nil, "default", "default").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.CompleteRepoScan(defaultScopeContext(), record.ID, "completed", now, 12, 8, 1, false, ""); err != nil {
		t.Fatalf("complete repo scan failed: %v", err)
	}

	repoScanRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "error_message", "history_limit", "max_findings_limit"}).
		AddRow(record.ID, "default", "default", "owner/repo", "completed", now, now, 12, 8, 1, false, "", 0, 0)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, repository, status").WithArgs("default", "default", 20).WillReturnRows(repoScanRows)
	repoScans, err := store.ListRepoScans(defaultScopeContext(), 20)
	if err != nil {
		t.Fatalf("list repo scans failed: %v", err)
	}
	if len(repoScans) != 1 || repoScans[0].ID != record.ID {
		t.Fatalf("unexpected repo scans: %+v", repoScans)
	}

	repoFindingsRows := sqlmock.NewRows([]string{"repo_scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow(record.ID, "rf-1", "secret_exposure", "high", "secret", "summary", []byte(`["app.env"]`), []byte(`{"k":"v"}`), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM repo_scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs(record.ID, "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("SELECT rf.repo_scan_id, rf.finding_id, rf.type").WithArgs(record.ID, "", "", 100, "default", "default").WillReturnRows(repoFindingsRows)
	repoFindings, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{RepoScanID: record.ID}, 100)
	if err != nil {
		t.Fatalf("list repo findings failed: %v", err)
	}
	if len(repoFindings) != 1 || repoFindings[0].ID != "rf-1" {
		t.Fatalf("unexpected repo findings: %+v", repoFindings)
	}

	repoScanRow := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "error_message", "history_limit", "max_findings_limit"}).
		AddRow(record.ID, "default", "default", "owner/repo", "completed", now, now, 12, 8, 1, false, "", 0, 0)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, repository, status").WithArgs(record.ID, "default", "default").WillReturnRows(repoScanRow)
	gotRepoScan, err := store.GetRepoScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get repo scan failed: %v", err)
	}
	if gotRepoScan.ID != record.ID {
		t.Fatalf("unexpected repo scan: %+v", gotRepoScan)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreFindingTriageStateAndHistory(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	expiry := now.Add(2 * time.Hour)

	mock.ExpectExec("INSERT INTO finding_triage_states").
		WithArgs("default", "default", "finding-1", "ack", "sec-oncall", sqlmock.AnyArg(), sqlmock.AnyArg(), "subject:alice").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertFindingTriageState(defaultScopeContext(), FindingTriageState{
		FindingID:            "finding-1",
		Status:               domain.FindingLifecycleAck,
		Assignee:             "sec-oncall",
		SuppressionExpiresAt: &expiry,
		UpdatedAt:            now,
		UpdatedBy:            "subject:alice",
	}); err != nil {
		t.Fatalf("upsert triage state failed: %v", err)
	}

	stateRows := sqlmock.NewRows([]string{"finding_id", "status", "assignee", "suppression_expires_at", "updated_at", "updated_by"}).
		AddRow("finding-1", "ack", "sec-oncall", expiry, now, "subject:alice")
	mock.ExpectQuery("SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by").
		WithArgs("finding-1", "default", "default").
		WillReturnRows(stateRows)

	state, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1")
	if err != nil {
		t.Fatalf("get triage state failed: %v", err)
	}
	if state.Status != domain.FindingLifecycleAck || state.Assignee != "sec-oncall" {
		t.Fatalf("unexpected triage state: %+v", state)
	}

	listRows := sqlmock.NewRows([]string{"finding_id", "status", "assignee", "suppression_expires_at", "updated_at", "updated_by"}).
		AddRow("finding-1", "ack", "sec-oncall", expiry, now, "subject:alice")
	mock.ExpectQuery("SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by").
		WithArgs("default", "default", "finding-1", "finding-2").
		WillReturnRows(listRows)

	states, err := store.ListFindingTriageStates(defaultScopeContext(), []string{"finding-1", "finding-2"})
	if err != nil {
		t.Fatalf("list triage states failed: %v", err)
	}
	if len(states) != 1 || states[0].FindingID != "finding-1" {
		t.Fatalf("unexpected triage states: %+v", states)
	}

	mock.ExpectExec("INSERT INTO finding_triage_events").
		WithArgs(sqlmock.AnyArg(), "default", "default", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", sqlmock.AnyArg(), "accepted risk", "subject:alice", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.AppendFindingTriageEvent(defaultScopeContext(), FindingTriageEvent{
		FindingID:            "finding-1",
		Action:               FindingTriageActionAcknowledged,
		FromStatus:           domain.FindingLifecycleOpen,
		ToStatus:             domain.FindingLifecycleAck,
		Assignee:             "sec-oncall",
		SuppressionExpiresAt: &expiry,
		Comment:              "accepted risk",
		Actor:                "subject:alice",
		CreatedAt:            now,
	}); err != nil {
		t.Fatalf("append triage event failed: %v", err)
	}

	eventRows := sqlmock.NewRows([]string{"id", "finding_id", "action", "from_status", "to_status", "assignee", "suppression_expires_at", "comment", "actor", "created_at"}).
		AddRow("evt-2", "finding-1", FindingTriageActionCommented, "ack", "ack", "sec-oncall", nil, "reviewed", "subject:bob", now.Add(2*time.Minute)).
		AddRow("evt-1", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", expiry, "accepted risk", "subject:alice", now)
	mock.ExpectQuery("SELECT id, finding_id, action, from_status, to_status, assignee, suppression_expires_at, comment, actor, created_at").
		WithArgs("finding-1", "default", "default", 10).
		WillReturnRows(eventRows)

	events, err := store.ListFindingTriageEvents(defaultScopeContext(), "finding-1", 10)
	if err != nil {
		t.Fatalf("list triage events failed: %v", err)
	}
	if len(events) != 2 || events[0].ID != "evt-2" {
		t.Fatalf("unexpected triage events: %+v", events)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreApplyFindingTriageTransition(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO finding_triage_states").
		WithArgs("default", "default", "finding-1", "ack", "sec-oncall", nil, sqlmock.AnyArg(), "subject:alice").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO finding_triage_events").
		WithArgs(sqlmock.AnyArg(), "default", "default", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", nil, "acknowledged", "subject:alice", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = store.ApplyFindingTriageTransition(defaultScopeContext(), FindingTriageState{
		FindingID: "finding-1",
		Status:    domain.FindingLifecycleAck,
		Assignee:  "sec-oncall",
		UpdatedAt: now,
		UpdatedBy: "subject:alice",
	}, FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionAcknowledged,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleAck,
		Assignee:   "sec-oncall",
		Comment:    "acknowledged",
		Actor:      "subject:alice",
		CreatedAt:  now,
	})
	if err != nil {
		t.Fatalf("apply triage transition failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreApplyFindingTriageTransitionRollsBackOnEventFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO finding_triage_states").
		WithArgs("default", "default", "finding-1", "ack", "sec-oncall", nil, sqlmock.AnyArg(), "subject:alice").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO finding_triage_events").
		WithArgs(sqlmock.AnyArg(), "default", "default", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", nil, "acknowledged", "subject:alice", sqlmock.AnyArg()).
		WillReturnError(sql.ErrTxDone)
	mock.ExpectRollback()

	err = store.ApplyFindingTriageTransition(defaultScopeContext(), FindingTriageState{
		FindingID: "finding-1",
		Status:    domain.FindingLifecycleAck,
		Assignee:  "sec-oncall",
		UpdatedAt: now,
		UpdatedBy: "subject:alice",
	}, FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionAcknowledged,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleAck,
		Assignee:   "sec-oncall",
		Comment:    "acknowledged",
		Actor:      "subject:alice",
		CreatedAt:  now,
	})
	if err == nil {
		t.Fatal("expected triage transition error")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreScanQueueLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, $5, $6, 0, 0)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "aws", "queued", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	queued, err := store.CreateQueuedScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create queued scan failed: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}

	countRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND ($3 = '' OR provider = $3)
		   AND status = 'queued'`)).
		WithArgs("default", "default", "aws").
		WillReturnRows(countRows)

	count, err := store.CountQueuedScans(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("count queued scans failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected queued count 1, got %d", count)
	}

	claimRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce", "trace_parent", "trace_state"}).
		AddRow(queued.ID, "default", "default", "aws", "running", now, nil, 0, 0, "", "", "")
	mock.ExpectQuery("WITH next_scan AS").WithArgs("default", "default", "aws").WillReturnRows(claimRows)

	claimed, err := store.ClaimNextQueuedScan(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("claim queued scan failed: %v", err)
	}
	if claimed.Status != "running" {
		t.Fatalf("expected running status after claim, got %q", claimed.Status)
	}

	mock.ExpectQuery("WITH next_scan AS").WithArgs("default", "default", "aws").WillReturnError(sql.ErrNoRows)
	if _, err := store.ClaimNextQueuedScan(defaultScopeContext(), "aws"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound when queue is empty, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateQueuedScanWithinLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("scan-queue:default:default:aws").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
		WithArgs("default", "default", "aws").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	successRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce", "trace_parent", "trace_state"}).
		AddRow("scan-1", "default", "default", "aws", "queued", now, nil, 0, 0, "", "", "")
	mock.ExpectQuery("INSERT INTO scans").
		WithArgs(sqlmock.AnyArg(), "default", "default", "aws", sqlmock.AnyArg(), "", "").
		WillReturnRows(successRows)
	mock.ExpectCommit()

	queued, err := store.CreateQueuedScanWithinLimit(defaultScopeContext(), "aws", now, 1)
	if err != nil {
		t.Fatalf("create queued scan with limit failed: %v", err)
	}
	if queued.ID != "scan-1" || queued.Status != "queued" {
		t.Fatalf("unexpected queued scan result %+v", queued)
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("scan-queue:default:default:aws").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\)").
		WithArgs("default", "default", "aws").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectRollback()

	if _, err := store.CreateQueuedScanWithinLimit(defaultScopeContext(), "aws", now.Add(time.Minute), 1); !errors.Is(err, ErrQueueLimitReached) {
		t.Fatalf("expected ErrQueueLimitReached, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateQueuedScanIfNoPending(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("scan-queue:default:default:aws").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND provider = $3
		   AND status IN ('queued', 'running')`)).
		WithArgs("default", "default", "aws").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, error_message, trace_parent, trace_state)
		 VALUES ($1, $2, $3, $4, $5, $6, NULL, 0, 0, NULL, NULLIF($7, ''), NULLIF($8, ''))`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "aws", "queued", now, "", "").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	queued, err := store.CreateQueuedScanIfNoPending(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create queued scan without pending duplicate failed: %v", err)
	}
	if queued.Status != "queued" || queued.Provider != "aws" {
		t.Fatalf("unexpected queued scan result %+v", queued)
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("scan-queue:default:default:aws").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND provider = $3
		   AND status IN ('queued', 'running')`)).
		WithArgs("default", "default", "aws").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectRollback()

	if _, err := store.CreateQueuedScanIfNoPending(defaultScopeContext(), "aws", now.Add(time.Minute)); !errors.Is(err, ErrPendingScanExists) {
		t.Fatalf("expected ErrPendingScanExists, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreRequiresScopeContext(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	if _, err := store.ListScans(context.Background(), 10); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}
}

func TestPostgresStoreCountQueuedScansBlankProviderIsWildcard(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	countRows := sqlmock.NewRows([]string{"count"}).AddRow(2)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND ($3 = '' OR provider = $3)
		   AND status = 'queued'`)).
		WithArgs("default", "default", "").
		WillReturnRows(countRows)

	count, err := store.CountQueuedScans(defaultScopeContext(), "")
	if err != nil {
		t.Fatalf("count queued scans wildcard: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected wildcard queued count 2, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCountQueuedScansAnyScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	countRows := sqlmock.NewRows([]string{"count"}).AddRow(3)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM scans
		 WHERE ($1 = '' OR provider = $1)
		   AND status = 'queued'`)).
		WithArgs("aws").
		WillReturnRows(countRows)

	count, err := store.CountQueuedScansAnyScope(context.Background(), "aws")
	if err != nil {
		t.Fatalf("count queued scans any scope: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected any-scope queued count 3, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreRepoQueueLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "owner/repo", "queued", sqlmock.AnyArg(), 50, 80).
		WillReturnResult(sqlmock.NewResult(1, 1))

	queued, err := store.CreateQueuedRepoScan(defaultScopeContext(), "owner/repo", 50, 80, now)
	if err != nil {
		t.Fatalf("create queued repo scan failed: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}
	if queued.HistoryLimit != 50 || queued.MaxFindings != 80 {
		t.Fatalf("expected queued limits retained, got %+v", queued)
	}

	queuedCountRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'queued'`)).
		WithArgs("default", "default").
		WillReturnRows(queuedCountRows)

	queuedCount, err := store.CountQueuedRepoScans(defaultScopeContext())
	if err != nil {
		t.Fatalf("count queued repo scans failed: %v", err)
	}
	if queuedCount != 1 {
		t.Fatalf("expected queued count 1, got %d", queuedCount)
	}

	pendingRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
			 FROM repo_scans
			 WHERE tenant_id = $1
			   AND workspace_id = $2
			   AND LOWER(repository) = LOWER($3)
			   AND status IN ('queued', 'running')`)).
		WithArgs("default", "default", "OWNER/REPO").
		WillReturnRows(pendingRows)

	pendingCount, err := store.CountPendingRepoScansByRepository(defaultScopeContext(), "OWNER/REPO")
	if err != nil {
		t.Fatalf("count pending repo scans failed: %v", err)
	}
	if pendingCount != 1 {
		t.Fatalf("expected pending count 1, got %d", pendingCount)
	}

	claimRows := sqlmock.NewRows([]string{
		"id",
		"tenant_id",
		"workspace_id",
		"repository",
		"status",
		"started_at",
		"finished_at",
		"commits_scanned",
		"files_scanned",
		"finding_count",
		"truncated",
		"coalesce",
		"history_limit",
		"max_findings_limit",
		"trace_parent",
		"trace_state",
	}).AddRow(queued.ID, "default", "default", "owner/repo", "running", now, nil, 0, 0, 0, false, "", 50, 80, "", "")
	mock.ExpectQuery("WITH next_repo_scan AS").WithArgs("default", "default").WillReturnRows(claimRows)

	claimed, err := store.ClaimNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("claim queued repo scan failed: %v", err)
	}
	if claimed.Status != "running" {
		t.Fatalf("expected running status, got %q", claimed.Status)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE repo_scans
		 SET status = 'queued',
		     started_at = NOW(),
		     finished_at = NULL,
		     error_message = NULL
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3
		   AND status = 'running'`)).
		WithArgs(claimed.ID, "default", "default").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.RequeueRepoScan(defaultScopeContext(), claimed.ID); err != nil {
		t.Fatalf("requeue repo scan failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCountQueuedRepoScansAnyScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	countRows := sqlmock.NewRows([]string{"count"}).AddRow(4)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE status = 'queued'`)).
		WillReturnRows(countRows)

	count, err := store.CountQueuedRepoScansAnyScope(context.Background())
	if err != nil {
		t.Fatalf("count queued repo scans any scope: %v", err)
	}
	if count != 4 {
		t.Fatalf("expected any-scope queued repo count 4, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateQueuedRepoScanWithinLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("repo-queue:default:default").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("repo-target:default:default:owner/repo").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND LOWER(repository) = LOWER($3)
		   AND status IN ('queued', 'running')`)).
		WithArgs("default", "default", "owner/repo").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'queued'`)).
		WithArgs("default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit, trace_parent, trace_state)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8, NULLIF($9, ''), NULLIF($10, ''))`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "owner/repo", "queued", now, 50, 80, "", "").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	record, err := store.CreateQueuedRepoScanWithinLimit(defaultScopeContext(), "owner/repo", 50, 80, now, 2)
	if err != nil {
		t.Fatalf("create queued repo scan within limit: %v", err)
	}
	if record.Repository != "owner/repo" || record.Status != "queued" {
		t.Fatalf("unexpected queued repo scan %+v", record)
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("repo-queue:default:default").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("repo-target:default:default:owner/repo").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND LOWER(repository) = LOWER($3)
		   AND status IN ('queued', 'running')`)).
		WithArgs("default", "default", "owner/repo").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectRollback()

	if _, err := store.CreateQueuedRepoScanWithinLimit(defaultScopeContext(), "owner/repo", 50, 80, now.Add(time.Minute), 2); !errors.Is(err, ErrPendingRepoScanExists) {
		t.Fatalf("expected ErrPendingRepoScanExists, got %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("repo-queue:default:default").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").
		WithArgs("repo-target:default:default:owner/other").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND LOWER(repository) = LOWER($3)
		   AND status IN ('queued', 'running')`)).
		WithArgs("default", "default", "owner/other").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'queued'`)).
		WithArgs("default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectRollback()

	if _, err := store.CreateQueuedRepoScanWithinLimit(defaultScopeContext(), "owner/other", 50, 80, now.Add(2*time.Minute), 2); !errors.Is(err, ErrQueueLimitReached) {
		t.Fatalf("expected ErrQueueLimitReached, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzEntityAttributesLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO authz_entity_attributes").
		WithArgs(
			"default",
			"default",
			AuthzEntityKindResource,
			"finding",
			"finding-1",
			"platform_sec",
			AuthzAttributeEnvProd,
			AuthzAttributeRiskTierHigh,
			AuthzAttributeClassificationConfidential,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzEntityAttributes(defaultScopeContext(), AuthzEntityAttributes{
		EntityKind:     AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "platform_sec",
		Environment:    AuthzAttributeEnvProd,
		RiskTier:       AuthzAttributeRiskTierHigh,
		Classification: AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert authz attributes: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"entity_kind",
		"entity_type",
		"entity_id",
		"owner_team",
		"env",
		"risk_tier",
		"classification",
		"updated_at",
	}).AddRow("default", "default", AuthzEntityKindResource, "finding", "finding-1", "platform_sec", AuthzAttributeEnvProd, AuthzAttributeRiskTierHigh, AuthzAttributeClassificationConfidential, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, entity_kind, entity_type, entity_id").
		WithArgs("default", "default", AuthzEntityKindResource, "finding", "finding-1").
		WillReturnRows(rows)

	record, err := store.GetAuthzEntityAttributes(defaultScopeContext(), AuthzEntityKindResource, "finding", "finding-1")
	if err != nil {
		t.Fatalf("get authz attributes: %v", err)
	}
	if record.OwnerTeam != "platform_sec" || record.Environment != AuthzAttributeEnvProd {
		t.Fatalf("unexpected authz attributes %+v", record)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzRelationshipLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO authz_relationships").
		WithArgs(
			"default",
			"default",
			"user",
			"alice",
			AuthzRelationshipManages,
			"workspace",
			"workspace-1",
			"sync",
			nil,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzRelationship(defaultScopeContext(), AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "alice",
		Relation:    AuthzRelationshipManages,
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
		Source:      "sync",
	}); err != nil {
		t.Fatalf("upsert authz relationship: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"subject_type",
		"subject_id",
		"relation",
		"object_type",
		"object_id",
		"source",
		"expires_at",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1", "sync", nil, now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at").
		WithArgs("default", "default", "user", "alice", sqlmock.AnyArg(), 10).
		WillReturnRows(rows)

	relationships, err := store.ListAuthzRelationships(defaultScopeContext(), AuthzRelationshipFilter{
		SubjectType: "user",
		SubjectID:   "alice",
	}, 10)
	if err != nil {
		t.Fatalf("list authz relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].Relation != AuthzRelationshipManages {
		t.Fatalf("unexpected authz relationships: %+v", relationships)
	}

	mock.ExpectExec("DELETE FROM authz_relationships").
		WithArgs("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.DeleteAuthzRelationship(defaultScopeContext(), AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "alice",
		Relation:    AuthzRelationshipManages,
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
	}); err != nil {
		t.Fatalf("delete authz relationship: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListAuthzRelationshipsWithFullFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"subject_type",
		"subject_id",
		"relation",
		"object_type",
		"object_id",
		"source",
		"expires_at",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1", "manual", now, now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at").
		WithArgs("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1").
		WillReturnRows(rows)

	relationships, err := store.ListAuthzRelationships(defaultScopeContext(), AuthzRelationshipFilter{
		SubjectType:    "user",
		SubjectID:      "alice",
		Relation:       AuthzRelationshipManages,
		ObjectType:     "workspace",
		ObjectID:       "workspace-1",
		IncludeExpired: true,
	}, 0)
	if err != nil {
		t.Fatalf("list authz relationships with full filters: %v", err)
	}
	if len(relationships) != 1 {
		t.Fatalf("expected one relationship, got %d", len(relationships))
	}
	if relationships[0].ExpiresAt == nil {
		t.Fatalf("expected expires_at to be populated")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListAuthzRelationshipsRejectsInvalidRelationFilter(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	if _, err := store.ListAuthzRelationships(defaultScopeContext(), AuthzRelationshipFilter{
		Relation: "viewer",
	}, 10); err == nil {
		t.Fatal("expected invalid relation filter error")
	}
}

func TestPostgresStoreAuthzPolicySetLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO authz_policy_sets").
		WithArgs(
			"default",
			"default",
			"core_policy",
			"Core Policy",
			"workspace baseline",
			"owner",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzPolicySet(defaultScopeContext(), AuthzPolicySet{
		PolicySetID: "core_policy",
		DisplayName: "Core Policy",
		Description: "workspace baseline",
		CreatedBy:   "owner",
	}); err != nil {
		t.Fatalf("upsert authz policy set: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"display_name",
		"description",
		"created_by",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "core_policy", "Core Policy", "workspace baseline", "owner", now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, display_name").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(rows)

	record, err := store.GetAuthzPolicySet(defaultScopeContext(), "core_policy")
	if err != nil {
		t.Fatalf("get authz policy set: %v", err)
	}
	if record.DisplayName != "Core Policy" || record.PolicySetID != "core_policy" {
		t.Fatalf("unexpected authz policy set %+v", record)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzPolicyVersionLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	setRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"display_name",
		"description",
		"created_by",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "core_policy", "Core Policy", "workspace baseline", "owner", now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, display_name").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(setRows)

	createdRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		1,
		`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		"7d506f99ea690c4297132763253db76fb6cc4eed6a7307b3dbd83eb9b1618240",
		"owner",
		now,
	)
	mock.ExpectQuery("INSERT INTO authz_policy_versions").
		WithArgs(
			"default",
			"default",
			"core_policy",
			1,
			`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
			"7d506f99ea690c4297132763253db76fb6cc4eed6a7307b3dbd83eb9b1618240",
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnRows(createdRows)

	created, err := store.CreateAuthzPolicyVersion(defaultScopeContext(), AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     1,
		Bundle:      `{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		CreatedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create authz policy version: %v", err)
	}
	if created.Version != 1 || created.PolicySetID != "core_policy" {
		t.Fatalf("unexpected created version %+v", created)
	}

	getRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		1,
		`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		created.Checksum,
		"owner",
		now,
	)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum").
		WithArgs("default", "default", "core_policy", 1).
		WillReturnRows(getRows)

	got, err := store.GetAuthzPolicyVersion(defaultScopeContext(), "core_policy", 1)
	if err != nil {
		t.Fatalf("get authz policy version: %v", err)
	}
	if got.Checksum != created.Checksum {
		t.Fatalf("unexpected checksum from get: %s", got.Checksum)
	}

	listRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		1,
		`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		created.Checksum,
		"owner",
		now,
	)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum").
		WithArgs("default", "default", "core_policy", 10).
		WillReturnRows(listRows)

	versions, err := store.ListAuthzPolicyVersions(defaultScopeContext(), "core_policy", 10)
	if err != nil {
		t.Fatalf("list authz policy versions: %v", err)
	}
	if len(versions) != 1 || versions[0].Version != 1 {
		t.Fatalf("unexpected listed versions %+v", versions)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateAuthzPolicyVersionAutoIncrementWithRetry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	setRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"display_name",
		"description",
		"created_by",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "core_policy", "Core Policy", "workspace baseline", "owner", now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, display_name").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(setRows)

	// First attempt returns no rows (simulates an ON CONFLICT DO NOTHING race).
	mock.ExpectQuery("INSERT INTO authz_policy_versions").
		WithArgs(
			"default",
			"default",
			"core_policy",
			`{"rules":[{"id":"allow-write","effect":"allow"}]}`,
			"a07bdecc388142a8c92166c6c3dc619deadedefb01305d6d528db73245eee201",
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id",
			"workspace_id",
			"policy_set_id",
			"version",
			"bundle",
			"checksum",
			"created_by",
			"created_at",
		}))

	createdRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		3,
		`{"rules":[{"id":"allow-write","effect":"allow"}]}`,
		"a07bdecc388142a8c92166c6c3dc619deadedefb01305d6d528db73245eee201",
		"owner",
		now,
	)
	mock.ExpectQuery("INSERT INTO authz_policy_versions").
		WithArgs(
			"default",
			"default",
			"core_policy",
			`{"rules":[{"id":"allow-write","effect":"allow"}]}`,
			"a07bdecc388142a8c92166c6c3dc619deadedefb01305d6d528db73245eee201",
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnRows(createdRows)

	created, err := store.CreateAuthzPolicyVersion(defaultScopeContext(), AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Bundle:      `{"rules":[{"id":"allow-write","effect":"allow"}]}`,
		CreatedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create authz policy version with auto-increment: %v", err)
	}
	if created.Version != 3 {
		t.Fatalf("expected auto-incremented version 3, got %d", created.Version)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzPolicyRolloutLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	active := 1
	candidate := 2
	mock.ExpectExec("INSERT INTO authz_policy_rollouts").
		WithArgs(
			"default",
			"default",
			"core_policy",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			AuthzPolicyRolloutModeShadow,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			35,
			sqlmock.AnyArg(),
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzPolicyRollout(defaultScopeContext(), AuthzPolicyRollout{
		PolicySetID:        "core_policy",
		ActiveVersion:      &active,
		CandidateVersion:   &candidate,
		Mode:               AuthzPolicyRolloutModeShadow,
		TenantAllowlist:    []string{"tenant-a"},
		WorkspaceAllowlist: []string{"workspace-a"},
		CanaryPercentage:   35,
		ValidatedVersions:  []int{1, 2},
		UpdatedBy:          "owner",
	}); err != nil {
		t.Fatalf("upsert authz policy rollout: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"active_version",
		"candidate_version",
		"mode",
		"tenant_allowlist",
		"workspace_allowlist",
		"canary_percentage",
		"validated_versions",
		"updated_by",
		"updated_at",
	}).AddRow("default", "default", "core_policy", int64(1), int64(2), AuthzPolicyRolloutModeShadow, `["tenant-a"]`, `["workspace-a"]`, 35, `[1,2]`, "owner", now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, active_version, candidate_version, mode,\\s+COALESCE\\(tenant_allowlist, '\\[\\]'::jsonb\\)::text,\\s+COALESCE\\(workspace_allowlist, '\\[\\]'::jsonb\\)::text,\\s+canary_percentage,\\s+COALESCE\\(validated_versions, '\\[\\]'::jsonb\\)::text,\\s+COALESCE\\(updated_by, ''\\), updated_at").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(rows)

	rollout, err := store.GetAuthzPolicyRollout(defaultScopeContext(), "core_policy")
	if err != nil {
		t.Fatalf("get authz policy rollout: %v", err)
	}
	if rollout.ActiveVersion == nil || rollout.CandidateVersion == nil {
		t.Fatalf("expected rollout versions to be present: %+v", rollout)
	}
	if *rollout.ActiveVersion != 1 || *rollout.CandidateVersion != 2 {
		t.Fatalf("unexpected rollout versions: %+v", rollout)
	}
	if rollout.CanaryPercentage != 35 {
		t.Fatalf("expected canary percentage 35, got %d", rollout.CanaryPercentage)
	}
	if len(rollout.TenantAllowlist) != 1 || rollout.TenantAllowlist[0] != "tenant-a" {
		t.Fatalf("unexpected tenant allowlist: %+v", rollout.TenantAllowlist)
	}
	if len(rollout.ValidatedVersions) != 2 || rollout.ValidatedVersions[0] != 1 || rollout.ValidatedVersions[1] != 2 {
		t.Fatalf("unexpected validated versions: %+v", rollout.ValidatedVersions)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzPolicyEventsLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	fromVersion := 1
	toVersion := 2
	mock.ExpectExec("INSERT INTO authz_policy_events").
		WithArgs(
			sqlmock.AnyArg(),
			"default",
			"default",
			"core_policy",
			"promote",
			&fromVersion,
			&toVersion,
			"owner",
			"promoted candidate",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.AppendAuthzPolicyEvent(defaultScopeContext(), AuthzPolicyEvent{
		PolicySetID: "core_policy",
		EventType:   "promote",
		FromVersion: &fromVersion,
		ToVersion:   &toVersion,
		Actor:       "owner",
		Message:     "promoted candidate",
		Metadata:    map[string]any{"source": "test"},
	}); err != nil {
		t.Fatalf("append authz policy event: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"event_type",
		"from_version",
		"to_version",
		"actor",
		"message",
		"metadata",
		"created_at",
	}).AddRow(
		"event-1",
		"default",
		"default",
		"core_policy",
		"promote",
		int64(1),
		int64(2),
		"owner",
		"promoted candidate",
		[]byte(`{"source":"test"}`),
		now,
	)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, policy_set_id, event_type, from_version, to_version").
		WithArgs("default", "default", "core_policy", 10).
		WillReturnRows(rows)

	events, err := store.ListAuthzPolicyEvents(defaultScopeContext(), "core_policy", 10)
	if err != nil {
		t.Fatalf("list authz policy events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Metadata["source"] != "test" {
		t.Fatalf("unexpected event metadata: %+v", events[0].Metadata)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreInjectScopeCTEBypassWhenDisabled(t *testing.T) {
	store := &PostgresStore{}
	query := "SELECT id FROM scans WHERE tenant_id = $1"
	args := []any{"tenant-a"}

	gotQuery, gotArgs, err := store.injectScopeCTE(defaultScopeContext(), query, args)
	if err != nil {
		t.Fatalf("inject scope cte: %v", err)
	}
	if gotQuery != query {
		t.Fatalf("expected query unchanged, got %q", gotQuery)
	}
	if !reflect.DeepEqual(gotArgs, args) {
		t.Fatalf("expected args unchanged, got %+v", gotArgs)
	}
}

func TestPostgresStoreInjectScopeCTERewritesQueryWhenEnabled(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	query := "SELECT id FROM scans WHERE tenant_id = $1 AND workspace_id = $2 LIMIT $3"
	args := []any{"tenant-a", "workspace-a", 10}

	gotQuery, gotArgs, err := store.injectScopeCTE(ctx, query, args)
	if err != nil {
		t.Fatalf("inject scope cte: %v", err)
	}

	expectedQuery := "WITH _identrail_scope AS (SELECT set_config('identrail.tenant_id', $4, true), set_config('identrail.workspace_id', $5, true), set_config('identrail.rls_enforce', $6, true)) " + query
	if gotQuery != expectedQuery {
		t.Fatalf("unexpected rewritten query:\nexpected: %s\ngot:      %s", expectedQuery, gotQuery)
	}

	expectedArgs := []any{"tenant-a", "workspace-a", 10, "tenant-a", "workspace-a", "on"}
	if !reflect.DeepEqual(gotArgs, expectedArgs) {
		t.Fatalf("unexpected rewritten args: %+v", gotArgs)
	}
}

func TestPostgresStoreInjectScopeCTEHandlesWithRecursive(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	query := "WITH RECURSIVE chain AS (SELECT 1 AS n) SELECT n FROM chain"

	gotQuery, gotArgs, err := store.injectScopeCTE(ctx, query, nil)
	if err != nil {
		t.Fatalf("inject scope cte: %v", err)
	}

	expectedQuery := "WITH RECURSIVE _identrail_scope AS (SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)), chain AS (SELECT 1 AS n) SELECT n FROM chain"
	if gotQuery != expectedQuery {
		t.Fatalf("unexpected recursive rewritten query:\nexpected: %s\ngot:      %s", expectedQuery, gotQuery)
	}

	expectedArgs := []any{"tenant-a", "workspace-a", "on"}
	if !reflect.DeepEqual(gotArgs, expectedArgs) {
		t.Fatalf("unexpected rewritten args: %+v", gotArgs)
	}
}

func TestPostgresStoreInjectScopeCTERequiresScopeWhenEnabled(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	if _, _, err := store.injectScopeCTE(context.Background(), "SELECT 1", nil); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}
}

func TestPostgresStoreQueryContextUsesScopedTransactionWithoutRewritingOrder(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	query := `SELECT id, started_at FROM scans WHERE tenant_id = $1 ORDER BY started_at DESC`
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows([]string{"id", "started_at"}).AddRow("scan-1", time.Now()))
	mock.ExpectCommit()

	rows, err := store.queryContext(defaultScopeContext(), query, "default")
	if err != nil {
		t.Fatalf("scoped query context: %v", err)
	}
	defer rows.Close()

	if !rows.Next() {
		t.Fatal("expected one scoped row")
	}
	var id string
	var startedAt time.Time
	if err := rows.Scan(&id, &startedAt); err != nil {
		t.Fatalf("scan scoped row: %v", err)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close scoped rows: %v", err)
	}
	if id != "scan-1" {
		t.Fatalf("expected scan-1, got %q", id)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreExecContextUsesScopedTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE scans SET status=$1 WHERE id=$2`)).
		WithArgs("completed", "scan-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	result, err := store.execContext(defaultScopeContext(), `UPDATE scans SET status=$1 WHERE id=$2`, "completed", "scan-1")
	if err != nil {
		t.Fatalf("exec scoped update: %v", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		t.Fatalf("rows affected: %v", err)
	}
	if rowsAffected != 1 {
		t.Fatalf("expected 1 row, got %d", rowsAffected)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreQueryRowContextUsesScopedTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id FROM scans WHERE tenant_id = $1`)).
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("default"))
	mock.ExpectCommit()

	scanner := store.queryRowContext(defaultScopeContext(), `SELECT tenant_id FROM scans WHERE tenant_id = $1`, "default")
	var tenantID string
	if err := scanner.Scan(&tenantID); err != nil {
		t.Fatalf("scoped query row scan: %v", err)
	}
	if tenantID != "default" {
		t.Fatalf("expected tenant id default, got %q", tenantID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreQueryRowContextRollsBackOnScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT tenant_id FROM scans WHERE tenant_id = $1`)).
		WithArgs("default").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}))
	mock.ExpectRollback()

	scanner := store.queryRowContext(defaultScopeContext(), `SELECT tenant_id FROM scans WHERE tenant_id = $1`, "default")
	var tenantID string
	err = scanner.Scan(&tenantID)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows from scan, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreBeginTxSetsRLSScopeContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	tx, err := store.beginTx(defaultScopeContext())
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback tx: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreBeginTxRequiresScopeWhenRLSEnabled(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	if _, err := store.beginTx(context.Background()); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertFindingTriageStateUsesScopedExecWhenRLSEnabled(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO finding_triage_states").
		WithArgs("default", "default", "finding-1", "ack", "sec-oncall", nil, sqlmock.AnyArg(), "subject:alice").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.UpsertFindingTriageState(defaultScopeContext(), FindingTriageState{
		FindingID: "finding-1",
		Status:    domain.FindingLifecycleAck,
		Assignee:  "sec-oncall",
		UpdatedAt: now,
		UpdatedBy: "subject:alice",
	}); err != nil {
		t.Fatalf("upsert triage state failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAppendFindingTriageEventUsesScopedExecWhenRLSEnabled(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO finding_triage_events").
		WithArgs(sqlmock.AnyArg(), "default", "default", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", nil, "acknowledged", "subject:alice", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.AppendFindingTriageEvent(defaultScopeContext(), FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionAcknowledged,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleAck,
		Assignee:   "sec-oncall",
		Comment:    "acknowledged",
		Actor:      "subject:alice",
		CreatedAt:  now,
	}); err != nil {
		t.Fatalf("append triage event failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCheckedSliceCapacity(t *testing.T) {
	got, err := checkedSliceCapacity(4, 3)
	if err != nil {
		t.Fatalf("checked slice capacity: %v", err)
	}
	if got != 7 {
		t.Fatalf("expected capacity 7, got %d", got)
	}

	maxInt := int(^uint(0) >> 1)
	if _, err := checkedSliceCapacity(maxInt, 1); !errors.Is(err, errQueryArgCapacityOverflow) {
		t.Fatalf("expected overflow error, got %v", err)
	}

	if _, err := checkedSliceCapacity(-1, 1); err == nil {
		t.Fatal("expected invalid input error")
	}
}

func TestPostgresStoreDBAndScopeFlagHelpers(t *testing.T) {
	var nilStore *PostgresStore
	if got := nilStore.DB(); got != nil {
		t.Fatalf("expected nil DB from nil store, got %v", got)
	}
	if nilStore.ScopeRLSEnforcementEnabled() {
		t.Fatal("expected nil store scope rls enforcement to be false")
	}

	sqlDB := &sql.DB{}
	store := NewPostgresStoreWithDB(sqlDB)
	if got := store.DB(); got != sqlDB {
		t.Fatalf("expected DB pointer to match")
	}
	if store.ScopeRLSEnforcementEnabled() {
		t.Fatal("expected scope rls enforcement disabled by default")
	}

	store.SetScopeRLSEnforcement(true)
	if !store.ScopeRLSEnforcementEnabled() {
		t.Fatal("expected scope rls enforcement enabled")
	}
}

func TestPostgresStoreWrapperScopeErrors(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	if _, err := store.execContext(context.Background(), "SELECT 1"); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired from execContext, got %v", err)
	}
	if _, err := store.queryContext(context.Background(), "SELECT 1"); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired from queryContext, got %v", err)
	}
	if err := store.queryRowContext(context.Background(), "SELECT 1").Scan(new(int)); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired from queryRowContext scan, got %v", err)
	}
}

func TestPostgresStoreClaimNextQueuedScanAnyScopeBypassesScopeInjection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce", "trace_parent", "trace_state"}).
		AddRow("scan-1", "tenant-a", "workspace-a", "aws", "running", now, nil, 0, 0, "", "", "")
	mock.ExpectQuery("WITH next_scan AS").
		WithArgs("aws").
		WillReturnRows(rows)

	record, err := store.ClaimNextQueuedScanAnyScope(context.Background(), "aws")
	if err != nil {
		t.Fatalf("claim any-scope scan: %v", err)
	}
	if record.ID != "scan-1" || record.Status != "running" {
		t.Fatalf("unexpected claimed scan: %+v", record)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreClaimNextQueuedRepoScanAnyScopeBypassesScopeInjection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id", "tenant_id", "workspace_id", "repository", "status", "started_at", "finished_at",
		"commits_scanned", "files_scanned", "finding_count", "truncated", "coalesce", "history_limit", "max_findings_limit", "trace_parent", "trace_state",
	}).AddRow("repo-scan-1", "tenant-a", "workspace-a", "owner/repo", "running", now, nil, 0, 0, 0, false, "", 500, 200, "", "")
	mock.ExpectQuery("WITH next_repo_scan AS").
		WillReturnRows(rows)

	record, err := store.ClaimNextQueuedRepoScanAnyScope(context.Background())
	if err != nil {
		t.Fatalf("claim any-scope repo scan: %v", err)
	}
	if record.ID != "repo-scan-1" || record.Status != "running" {
		t.Fatalf("unexpected claimed repo scan: %+v", record)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestErrorsIsNoRows(t *testing.T) {
	if !errorsIsNoRows(sql.ErrNoRows) {
		t.Fatal("expected true for sql.ErrNoRows")
	}
	if errorsIsNoRows(errors.New("different error")) {
		t.Fatal("expected false for non-no-rows error")
	}
}

func TestPostgresStoreListFindingMetasByScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	metaRows := sqlmock.NewRows([]string{"finding_id", "scan_id", "severity", "type", "created_at"}).
		AddRow("finding-2", "scan-1", "critical", "escalation_path", now.Add(2*time.Second)).
		AddRow("finding-1", "scan-1", "high", "ownerless_identity", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT finding_id, scan_id, severity, type, created_at
		 FROM findings
		 WHERE scan_id = $1
		 ORDER BY created_at DESC`)).
		WithArgs("scan-1").
		WillReturnRows(metaRows)

	metas, err := store.ListFindingMetasByScan(defaultScopeContext(), "scan-1")
	if err != nil {
		t.Fatalf("list finding metas: %v", err)
	}
	if len(metas) != 2 || metas[0].ID != "finding-2" {
		t.Fatalf("unexpected finding metas: %+v", metas)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListFindingsByScanAndIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	findingsByIDRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "finding-2", "escalation_path", "critical", "Alpha", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now.Add(2*time.Second)).
		AddRow("scan-1", "finding-1", "ownerless_identity", "high", "Zulu", "summary", []byte("[\"y\"]"), []byte("{\"b\":2}"), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
		 FROM findings f
		 WHERE f.scan_id = $1
		   AND f.finding_id IN ($2,$3)`)).
		WithArgs("scan-1", "finding-2", "finding-1").
		WillReturnRows(findingsByIDRows)

	items, err := store.ListFindingsByScanAndIDs(defaultScopeContext(), "scan-1", []string{"finding-2", " ", "finding-2", "finding-1"})
	if err != nil {
		t.Fatalf("list findings by ids: %v", err)
	}
	if len(items) != 2 || items[0].ID != "finding-2" || items[1].ID != "finding-1" {
		t.Fatalf("unexpected findings by ids: %+v", items)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListFindingTrendCounts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	trendRows := sqlmock.NewRows([]string{"id", "started_at", "severity", "count"}).
		AddRow("scan-1", now, "critical", 1).
		AddRow("scan-2", now.Add(time.Minute), nil, 0)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT s.id, s.started_at, f.severity, COUNT(f.finding_id)
		 FROM scans s
		 LEFT JOIN findings f
		   ON f.scan_id = s.id
		  AND ($3 = '' OR LOWER(f.severity) = $3)
		  AND ($4 = '' OR LOWER(f.type) = $4)
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		   AND s.id IN ($5,$6)
		 GROUP BY s.id, s.started_at, f.severity`)).
		WithArgs("default", "default", "critical", "escalation_path", "scan-1", "scan-2").
		WillReturnRows(trendRows)

	trend, err := store.ListFindingTrendCounts(defaultScopeContext(), []string{"scan-1", "scan-2", "scan-1"}, "critical", "escalation_path")
	if err != nil {
		t.Fatalf("list finding trend counts: %v", err)
	}
	if len(trend) != 2 || trend[0].ScanID != "scan-1" || trend[1].ScanID != "scan-2" {
		t.Fatalf("unexpected trend counts: %+v", trend)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
