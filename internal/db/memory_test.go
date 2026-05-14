package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

func TestMemoryStoreScanLifecycleAndFindings(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan failed: %v", err)
	}

	findings := []domain.Finding{{
		ID:           "finding-1",
		Type:         domain.FindingRiskyTrustPolicy,
		Severity:     domain.SeverityHigh,
		Title:        "Risky trust policy",
		HumanSummary: "Cross-account trust",
		CreatedAt:    now,
	}}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, findings); err != nil {
		t.Fatalf("upsert findings failed: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scan.ID, ScanArtifacts{
		RawAssets: []providers.RawAsset{{Kind: "iam_role", SourceID: "arn:aws:iam::1:role/test", Payload: []byte(`{"arn":"arn:aws:iam::1:role/test"}`), Collected: now.Format(time.RFC3339Nano)}},
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "aws:identity:arn:aws:iam::1:role/test", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "test", RawRef: "arn:aws:iam::1:role/test"}},
		},
		Permissions:   []providers.PermissionTuple{{IdentityID: "aws:identity:arn:aws:iam::1:role/test", Action: "s3:GetObject", Resource: "arn:aws:s3:::x/*", Effect: "Allow"}},
		Relationships: []domain.Relationship{{ID: "rel-1", Type: domain.RelationshipCanAccess, FromNodeID: "aws:identity:arn:aws:iam::1:role/test", ToNodeID: "aws:access:s3%3AGetObject:arn%3Aaws%3As3%3A%3A%3Ax%2F%2A", DiscoveredAt: now}},
	}); err != nil {
		t.Fatalf("upsert artifacts failed: %v", err)
	}
	// idempotent re-run must not fail
	if err := store.UpsertArtifacts(defaultScopeContext(), scan.ID, ScanArtifacts{}); err != nil {
		t.Fatalf("second upsert artifacts failed: %v", err)
	}

	if err := store.CompleteScan(defaultScopeContext(), scan.ID, "completed", now.Add(2*time.Second), 3, 1, ""); err != nil {
		t.Fatalf("complete scan failed: %v", err)
	}

	scans, err := store.ListScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list scans failed: %v", err)
	}
	if len(scans) != 1 || scans[0].Status != "completed" || scans[0].FindingCount != 1 {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	storedFindings, err := store.ListFindings(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list findings failed: %v", err)
	}
	if len(storedFindings) != 1 || storedFindings[0].ScanID != scan.ID {
		t.Fatalf("unexpected findings: %+v", storedFindings)
	}
	allFindings, err := store.ListFindingsAll(defaultScopeContext())
	if err != nil {
		t.Fatalf("list all findings failed: %v", err)
	}
	if len(allFindings) != 1 || allFindings[0].ScanID != scan.ID {
		t.Fatalf("unexpected all findings: %+v", allFindings)
	}
}

func TestMemoryStoreErrorsForUnknownScan(t *testing.T) {
	store := NewMemoryStore()
	err := store.CompleteScan(defaultScopeContext(), "missing", "failed", time.Now(), 0, 0, "boom")
	if err == nil {
		t.Fatal("expected error")
	}

	err = store.UpsertFindings(defaultScopeContext(), "missing", []domain.Finding{{ID: "f1"}})
	if err == nil {
		t.Fatal("expected error")
	}
	err = store.UpsertArtifacts(defaultScopeContext(), "missing", ScanArtifacts{})
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = store.GetScan(defaultScopeContext(), "missing")
	if err == nil {
		t.Fatal("expected get scan error")
	}
	_, err = store.ListFindingsByScan(defaultScopeContext(), "missing", 10)
	if err == nil {
		t.Fatal("expected findings-by-scan error")
	}
	err = store.AppendScanEvent(defaultScopeContext(), "missing", "info", "msg", nil)
	if err == nil {
		t.Fatal("expected append scan event error")
	}
	_, err = store.ListScanEvents(defaultScopeContext(), "missing", 10)
	if err == nil {
		t.Fatal("expected list scan events error")
	}
}

func TestMemoryStoreScanDetails(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}

	if err := store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f1", ScanID: scanA.ID, CreatedAt: now.Add(1 * time.Second)},
		{ID: "f2", ScanID: scanA.ID, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	gotScan, err := store.GetScan(defaultScopeContext(), scanA.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if gotScan.ID != scanA.ID {
		t.Fatalf("unexpected scan id: %q", gotScan.ID)
	}

	findings, err := store.ListFindingsByScan(defaultScopeContext(), scanA.ID, 10)
	if err != nil {
		t.Fatalf("list findings by scan: %v", err)
	}
	if len(findings) != 2 || findings[0].ID != "f2" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	if err := store.AppendScanEvent(defaultScopeContext(), scanB.ID, "info", "scan started", map[string]any{"provider": "aws"}); err != nil {
		t.Fatalf("append scan event 1: %v", err)
	}
	if err := store.AppendScanEvent(defaultScopeContext(), scanB.ID, "info", "scan completed", nil); err != nil {
		t.Fatalf("append scan event 2: %v", err)
	}
	events, err := store.ListScanEvents(defaultScopeContext(), scanB.ID, 10)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestMemoryStoreListFindingsFiltered(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f-a", ScanID: scanA.ID, Type: domain.FindingRiskyTrustPolicy, Severity: domain.SeverityHigh, Title: "Alpha", CreatedAt: now.Add(1 * time.Minute)},
		{ID: "f-b", ScanID: scanA.ID, Type: domain.FindingRiskyTrustPolicy, Severity: domain.SeverityHigh, Title: "Beta", CreatedAt: now.Add(2 * time.Minute)},
		{ID: "f-c", ScanID: scanA.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityLow, Title: "Gamma", CreatedAt: now.Add(3 * time.Minute)},
	}); err != nil {
		t.Fatalf("upsert scan A findings: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scanB.ID, []domain.Finding{
		{ID: "f-d", ScanID: scanB.ID, Type: domain.FindingRiskyTrustPolicy, Severity: domain.SeverityHigh, Title: "Delta", CreatedAt: now.Add(4 * time.Minute)},
	}); err != nil {
		t.Fatalf("upsert scan B findings: %v", err)
	}
	for _, findingID := range []string{"f-a", "f-b", "f-d"} {
		if err := store.UpsertFindingTriageState(defaultScopeContext(), FindingTriageState{
			FindingID: findingID,
			Status:    domain.FindingLifecycleAck,
			Assignee:  "platform",
			UpdatedAt: now.Add(5 * time.Minute),
			UpdatedBy: "subject:test",
		}); err != nil {
			t.Fatalf("upsert triage for %s: %v", findingID, err)
		}
	}
	expiredAt := now.Add(-time.Minute)
	if err := store.UpsertFindingTriageState(defaultScopeContext(), FindingTriageState{
		FindingID:            "f-c",
		Status:               domain.FindingLifecycleSuppressed,
		Assignee:             "platform",
		SuppressionExpiresAt: &expiredAt,
		UpdatedAt:            now.Add(6 * time.Minute),
		UpdatedBy:            "subject:test",
	}); err != nil {
		t.Fatalf("upsert triage for f-c: %v", err)
	}

	pageOne, err := store.ListFindingsFiltered(defaultScopeContext(), FindingListFilter{
		ScanID:          scanA.ID,
		Severity:        "HIGH",
		Type:            "RISKY_TRUST_POLICY",
		LifecycleStatus: "ACK",
		Assignee:        "PLATFORM",
		SortBy:          "title",
		Limit:           1,
		Offset:          0,
		Now:             now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("list filtered page one: %v", err)
	}
	if len(pageOne) != 2 || pageOne[0].ID != "f-a" || pageOne[1].ID != "f-b" {
		t.Fatalf("unexpected filtered page one: %+v", pageOne)
	}

	pageTwo, err := store.ListFindingsFiltered(defaultScopeContext(), FindingListFilter{
		ScanID:          scanA.ID,
		Severity:        "high",
		Type:            "risky_trust_policy",
		LifecycleStatus: "ack",
		Assignee:        "platform",
		SortBy:          "title",
		Limit:           1,
		Offset:          1,
		Now:             now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("list filtered page two: %v", err)
	}
	if len(pageTwo) != 1 || pageTwo[0].ID != "f-b" {
		t.Fatalf("unexpected filtered page two: %+v", pageTwo)
	}

	normalizedSuppression, err := store.ListFindingsFiltered(defaultScopeContext(), FindingListFilter{
		FindingID:       "f-c",
		LifecycleStatus: "open",
		Assignee:        "platform",
		Limit:           5,
		Now:             now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("list filtered normalized suppression: %v", err)
	}
	if len(normalizedSuppression) != 1 || normalizedSuppression[0].Triage.Status != domain.FindingLifecycleOpen {
		t.Fatalf("expected expired suppression to normalize to open, got %+v", normalizedSuppression)
	}

	_, err = store.ListFindingsFiltered(defaultScopeContext(), FindingListFilter{
		ScanID: "missing-scan",
		Limit:  1,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing scan to return ErrNotFound, got %v", err)
	}
}

func TestSortFilteredFindingsOrders(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	base := []domain.Finding{
		{ScanID: "scan-2", ID: "finding-b", Severity: domain.SeverityHigh, Type: domain.FindingRiskyTrustPolicy, Title: "zulu", CreatedAt: now},
		{ScanID: "scan-1", ID: "finding-a", Severity: domain.SeverityCritical, Type: domain.FindingOwnerless, Title: "alpha", CreatedAt: now.Add(-time.Minute)},
		{ScanID: "scan-1", ID: "finding-c", Severity: domain.SeverityCritical, Type: domain.FindingOwnerless, Title: "Beta", CreatedAt: now.Add(2 * time.Minute)},
	}

	bySeverity := append([]domain.Finding(nil), base...)
	sortFilteredFindings(bySeverity, "severity", true)
	if bySeverity[0].ID != "finding-c" || bySeverity[1].ID != "finding-a" {
		t.Fatalf("unexpected severity sort order: %+v", bySeverity)
	}

	byType := append([]domain.Finding(nil), base...)
	sortFilteredFindings(byType, "type", false)
	if byType[0].Type != domain.FindingOwnerless || byType[1].Type != domain.FindingOwnerless {
		t.Fatalf("unexpected type sort order: %+v", byType)
	}

	byTitle := append([]domain.Finding(nil), base...)
	sortFilteredFindings(byTitle, "title", false)
	if byTitle[0].Title != "alpha" || byTitle[1].Title != "Beta" {
		t.Fatalf("unexpected title sort order: %+v", byTitle)
	}

	byCreatedAt := append([]domain.Finding(nil), base...)
	sortFilteredFindings(byCreatedAt, "created_at", false)
	if byCreatedAt[0].ID != "finding-a" || byCreatedAt[len(byCreatedAt)-1].ID != "finding-c" {
		t.Fatalf("unexpected created_at sort order: %+v", byCreatedAt)
	}
}

func TestMemoryStoreSummarizeFindingsRespectsScope(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	defaultCtx := defaultScopeContext()
	otherCtx := WithScope(defaultCtx, Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	defaultScan, err := store.CreateScan(defaultCtx, "aws", now)
	if err != nil {
		t.Fatalf("create default scan: %v", err)
	}
	otherScan, err := store.CreateScan(otherCtx, "aws", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("create other scan: %v", err)
	}

	if err := store.UpsertFindings(defaultCtx, defaultScan.ID, []domain.Finding{
		{ID: "default-1", ScanID: defaultScan.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(time.Second)},
		{ID: "default-2", ScanID: defaultScan.ID, Type: domain.FindingEscalationPath, Severity: domain.SeverityMedium, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert default findings: %v", err)
	}
	if err := store.UpsertFindings(otherCtx, otherScan.ID, []domain.Finding{
		{ID: "other-1", ScanID: otherScan.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityCritical, CreatedAt: now.Add(3 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert other findings: %v", err)
	}

	summary, err := store.SummarizeFindings(defaultCtx)
	if err != nil {
		t.Fatalf("summarize default findings: %v", err)
	}
	if summary.Total != 2 {
		t.Fatalf("expected summary total 2, got %d", summary.Total)
	}
	if summary.BySeverity["high"] != 1 || summary.BySeverity["medium"] != 1 {
		t.Fatalf("unexpected severity counts: %+v", summary.BySeverity)
	}
	if summary.ByType["ownerless_identity"] != 1 || summary.ByType["escalation_path"] != 1 {
		t.Fatalf("unexpected type counts: %+v", summary.ByType)
	}
	if _, exists := summary.BySeverity["critical"]; exists {
		t.Fatalf("expected other-scope severity to be excluded, got %+v", summary.BySeverity)
	}
}

func TestMemoryStoreGetFinding(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}
	item, err := store.GetFinding(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if item.ID != "finding-1" || item.ScanID != scan.ID {
		t.Fatalf("unexpected finding %+v", item)
	}
	if _, err := store.GetFinding(defaultScopeContext(), "missing", scan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found for missing finding, got %v", err)
	}
}

func TestMemoryStoreGetFindingWithoutScanIDReturnsLatestMatch(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(1 * time.Minute)},
	}); err != nil {
		t.Fatalf("upsert scan A findings: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scanB.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityCritical, CreatedAt: now.Add(6 * time.Minute)},
	}); err != nil {
		t.Fatalf("upsert scan B findings: %v", err)
	}

	item, err := store.GetFinding(defaultScopeContext(), "finding-1", "")
	if err != nil {
		t.Fatalf("get finding without scan id: %v", err)
	}
	if item.ScanID != scanB.ID || item.Severity != domain.SeverityCritical {
		t.Fatalf("expected latest scan finding, got %+v", item)
	}
}

func TestMemoryStoreListFindingMetasByScan(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	ctx := defaultScopeContext()
	scanA, err := store.CreateScan(ctx, "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(ctx, "aws", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertFindings(ctx, scanA.ID, []domain.Finding{
		{ID: "f1", ScanID: scanA.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(time.Second)},
		{ID: "f2", ScanID: scanA.ID, Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings for scan A: %v", err)
	}
	if err := store.UpsertFindings(ctx, scanB.ID, []domain.Finding{
		{ID: "f3", ScanID: scanB.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now.Add(3 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings for scan B: %v", err)
	}
	metas, err := store.ListFindingMetasByScan(ctx, scanA.ID)
	if err != nil {
		t.Fatalf("list finding metas by scan: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("expected 2 finding metas, got %+v", metas)
	}
	if _, err := store.ListFindingMetasByScan(ctx, "missing-scan"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing scan, got %v", err)
	}
}

func TestMemoryStoreListFindingsByScanAndIDs(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	ctx := defaultScopeContext()
	scan, err := store.CreateScan(ctx, "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(ctx, scan.ID, []domain.Finding{
		{ID: "f1", ScanID: scan.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(time.Second)},
		{ID: "f2", ScanID: scan.ID, Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}
	selected, err := store.ListFindingsByScanAndIDs(ctx, scan.ID, []string{"f2", " ", "f2", "missing", "f1"})
	if err != nil {
		t.Fatalf("list findings by scan and ids: %v", err)
	}
	if len(selected) != 2 || selected[0].ID != "f2" || selected[1].ID != "f1" {
		t.Fatalf("unexpected selected findings: %+v", selected)
	}
}

func TestMemoryStoreListFindingTrendCounts(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	ctx := defaultScopeContext()
	scanA, err := store.CreateScan(ctx, "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(ctx, "aws", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertFindings(ctx, scanA.ID, []domain.Finding{
		{ID: "f1", ScanID: scanA.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(time.Second)},
		{ID: "f2", ScanID: scanA.ID, Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings for scan A: %v", err)
	}
	if err := store.UpsertFindings(ctx, scanB.ID, []domain.Finding{
		{ID: "f3", ScanID: scanB.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now.Add(3 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings for scan B: %v", err)
	}

	trend, err := store.ListFindingTrendCounts(ctx, []string{scanA.ID, scanB.ID}, "", "")
	if err != nil {
		t.Fatalf("list finding trend counts: %v", err)
	}
	if len(trend) != 3 {
		t.Fatalf("expected 3 trend rows (high+critical for A, low for B), got %+v", trend)
	}

	filteredTrend, err := store.ListFindingTrendCounts(ctx, []string{scanA.ID, scanB.ID}, "critical", "escalation_path")
	if err != nil {
		t.Fatalf("list filtered finding trend counts: %v", err)
	}
	if len(filteredTrend) != 2 {
		t.Fatalf("expected 2 filtered trend rows (one per scan), got %+v", filteredTrend)
	}
	if filteredTrend[0].ScanID != scanA.ID || filteredTrend[0].Severity != "critical" || filteredTrend[0].TotalCount != 1 {
		t.Fatalf("unexpected matching filtered trend row: %+v", filteredTrend[0])
	}
	if filteredTrend[1].ScanID != scanB.ID || filteredTrend[1].TotalCount != 0 {
		t.Fatalf("unexpected empty filtered trend row: %+v", filteredTrend[1])
	}
}

func TestMemoryStoreListRepoFindingTrendCounts(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	ctx := defaultScopeContext()
	scanA, err := store.CreateRepoScan(ctx, "owner/repo-a", now)
	if err != nil {
		t.Fatalf("create repo scan A: %v", err)
	}
	scanB, err := store.CreateRepoScan(ctx, "owner/repo-b", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("create repo scan B: %v", err)
	}
	if err := store.UpsertRepoFindings(ctx, scanA.ID, []domain.Finding{
		{ID: "f1", ScanID: scanA.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(time.Second)},
		{ID: "f2", ScanID: scanA.ID, Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert repo findings for scan A: %v", err)
	}
	if err := store.UpsertRepoFindings(ctx, scanB.ID, []domain.Finding{
		{ID: "f3", ScanID: scanB.ID, Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now.Add(3 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert repo findings for scan B: %v", err)
	}

	trend, err := store.ListRepoFindingTrendCounts(ctx, []string{scanA.ID, scanB.ID}, "", "")
	if err != nil {
		t.Fatalf("list repo finding trend counts: %v", err)
	}
	if len(trend) != 3 {
		t.Fatalf("expected 3 repo trend rows, got %+v", trend)
	}

	filteredTrend, err := store.ListRepoFindingTrendCounts(ctx, []string{scanA.ID, scanB.ID}, "critical", "escalation_path")
	if err != nil {
		t.Fatalf("list filtered repo finding trend counts: %v", err)
	}
	if len(filteredTrend) != 2 {
		t.Fatalf("expected 2 filtered repo trend rows (one per scan), got %+v", filteredTrend)
	}
	if filteredTrend[0].ScanID != scanA.ID || filteredTrend[0].Severity != "critical" || filteredTrend[0].TotalCount != 1 {
		t.Fatalf("unexpected filtered repo trend row for scan A: %+v", filteredTrend[0])
	}
	if filteredTrend[1].ScanID != scanB.ID || filteredTrend[1].TotalCount != 0 {
		t.Fatalf("unexpected filtered repo trend row for scan B: %+v", filteredTrend[1])
	}
}

func TestMemoryStoreIdentityAndRelationshipFilters(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanA.ID, ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{ID: "id-1", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-role", RawRef: "raw-1"},
				{ID: "id-2", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "db-role", RawRef: "raw-2"},
			},
		},
		Relationships: []domain.Relationship{
			{ID: "rel-1", Type: domain.RelationshipCanAssume, FromNodeID: "id-1", ToNodeID: "id-2", DiscoveredAt: now},
		},
	}); err != nil {
		t.Fatalf("upsert artifacts scan A: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanB.ID, ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{ID: "id-3", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-worker", RawRef: "raw-3"},
			},
		},
		Relationships: []domain.Relationship{
			{ID: "rel-2", Type: domain.RelationshipCanAccess, FromNodeID: "id-3", ToNodeID: "bucket-1", DiscoveredAt: now.Add(1 * time.Minute)},
		},
	}); err != nil {
		t.Fatalf("upsert artifacts scan B: %v", err)
	}

	identities, err := store.ListIdentities(defaultScopeContext(), IdentityFilter{ScanID: scanA.ID, NamePrefix: "app"}, 10)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != "id-1" {
		t.Fatalf("unexpected identities: %+v", identities)
	}

	relationships, err := store.ListRelationships(defaultScopeContext(), RelationshipFilter{Type: "can_access"}, 10)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != "rel-2" {
		t.Fatalf("unexpected relationships: %+v", relationships)
	}
}

func TestMemoryStoreRejectsInvalidScanEventLevel(t *testing.T) {
	store := NewMemoryStore()
	scan, err := store.CreateScan(defaultScopeContext(), "aws", time.Now().UTC())
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	err = store.AppendScanEvent(defaultScopeContext(), scan.ID, "invalid", "bad level", nil)
	if err == nil {
		t.Fatal("expected invalid event level error")
	}
}

func TestMemoryStoreRepoScanLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	if repoScan.Status != "running" {
		t.Fatalf("unexpected repo scan status %q", repoScan.Status)
	}

	findings := []domain.Finding{
		{ID: "rf-1", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, Title: "secret", HumanSummary: "summary", CreatedAt: now},
		{ID: "rf-2", Type: domain.FindingRepoMisconfig, Severity: domain.SeverityMedium, Title: "misconfig", HumanSummary: "summary", CreatedAt: now.Add(1 * time.Minute)},
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, findings); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}
	if err := store.CompleteRepoScan(defaultScopeContext(), repoScan.ID, "completed", now.Add(2*time.Minute), 10, 6, 2, false, ""); err != nil {
		t.Fatalf("complete repo scan: %v", err)
	}

	gotScan, err := store.GetRepoScan(defaultScopeContext(), repoScan.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if gotScan.Status != "completed" || gotScan.CommitsScanned != 10 || gotScan.FilesScanned != 6 || gotScan.FindingCount != 2 {
		t.Fatalf("unexpected repo scan record: %+v", gotScan)
	}

	storedFindings, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{RepoScanID: repoScan.ID}, 10)
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	if len(storedFindings) != 2 || storedFindings[0].ID != "rf-2" {
		t.Fatalf("unexpected repo findings: %+v", storedFindings)
	}

	highOnly, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{Severity: "high"}, 10)
	if err != nil {
		t.Fatalf("list repo findings high-only: %v", err)
	}
	if len(highOnly) != 1 || highOnly[0].ID != "rf-1" {
		t.Fatalf("unexpected high severity findings: %+v", highOnly)
	}

	repoScans, err := store.ListRepoScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(repoScans) != 1 || repoScans[0].ID != repoScan.ID {
		t.Fatalf("unexpected repo scans: %+v", repoScans)
	}
}

func TestMemoryStoreListRepoFindingsDoesNotMutateLegacyStoredEvidence(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}

	legacyFinding := domain.Finding{
		ScanID:       repoScan.ID,
		ID:           "rf-legacy",
		Type:         domain.FindingSecretExposure,
		Severity:     domain.SeverityHigh,
		Title:        "secret",
		HumanSummary: "summary",
		Evidence: map[string]any{
			"commit":             "abc123",
			"file_path":          "config/app.env",
			"line_number":        7,
			"detector":           "aws-access-key",
			"redacted_line_snip": "AWS_ACCESS_KEY_ID=AKIA****",
		},
		CreatedAt: now,
	}
	key := repoScan.ID + "|" + legacyFinding.ID
	store.repoFindings[key] = legacyFinding
	store.repoFindingIDs[repoScan.ID] = []string{key}

	listed, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{RepoScanID: repoScan.ID}, 10)
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected one listed finding, got %+v", listed)
	}
	if listed[0].Repository != "owner/repo" {
		t.Fatalf("expected repository backfill from repo scan, got %+v", listed[0])
	}
	if listed[0].LineSnippet != "AWS_ACCESS_KEY_ID=AKIA****" {
		t.Fatalf("expected normalized line snippet, got %+v", listed[0])
	}

	stored := store.repoFindings[key]
	if _, exists := stored.Evidence["line_snippet"]; exists {
		t.Fatalf("expected stored legacy evidence to stay unchanged, got %+v", stored.Evidence)
	}
	if _, exists := stored.Evidence["line_snippet_redacted"]; exists {
		t.Fatalf("expected stored legacy evidence redaction flag to stay unchanged, got %+v", stored.Evidence)
	}
}

func TestMemoryStoreListRepoFindingClustersPaginatesClusters(t *testing.T) {
	store := NewMemoryStore()

	firstScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo-a", time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create first repo scan: %v", err)
	}
	secondScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo-a", time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create second repo scan: %v", err)
	}
	thirdScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo-b", time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create third repo scan: %v", err)
	}

	for _, seed := range []struct {
		scanID     string
		findingID  string
		repository string
		createdAt  time.Time
	}{
		{scanID: firstScan.ID, findingID: "rf-1", repository: "owner/repo-a", createdAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)},
		{scanID: secondScan.ID, findingID: "rf-2", repository: "owner/repo-a", createdAt: time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)},
		{scanID: thirdScan.ID, findingID: "rf-3", repository: "owner/repo-b", createdAt: time.Date(2026, 5, 3, 12, 0, 0, 0, time.UTC)},
	} {
		if err := store.UpsertRepoFindings(defaultScopeContext(), seed.scanID, []domain.Finding{{
			ID:           seed.findingID,
			Type:         domain.FindingRepoMisconfig,
			Severity:     domain.SeverityMedium,
			Title:        "GitHub workflow uses pull_request_target trigger",
			HumanSummary: "pull_request_target can execute with elevated token context if not strictly controlled.",
			Repository:   seed.repository,
			Detector:     "workflow_pull_request_target",
			CreatedAt:    seed.createdAt,
		}}); err != nil {
			t.Fatalf("upsert repo finding %s: %v", seed.findingID, err)
		}
	}

	clusters, err := store.ListRepoFindingClusters(defaultScopeContext(), RepoFindingClusterListFilter{
		SortBy:   "count",
		SortDesc: true,
		Limit:    1,
		Offset:   0,
	})
	if err != nil {
		t.Fatalf("list repo finding clusters: %v", err)
	}
	if len(clusters) != 2 {
		t.Fatalf("expected one page plus sentinel cluster, got %+v", clusters)
	}
	if clusters[0].Repository != "owner/repo-a" || clusters[0].Count != 2 {
		t.Fatalf("expected highest-count cluster first, got %+v", clusters[0])
	}
	if clusters[1].Repository != "owner/repo-b" || clusters[1].Count != 1 {
		t.Fatalf("expected sentinel next cluster, got %+v", clusters[1])
	}
}

func TestMemoryStoreRepoScanErrors(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.GetRepoScan(defaultScopeContext(), "missing"); err == nil {
		t.Fatal("expected missing repo scan error")
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), "missing", []domain.Finding{{ID: "x"}}); err == nil {
		t.Fatal("expected missing repo scan error for findings upsert")
	}
	if err := store.CompleteRepoScan(defaultScopeContext(), "missing", "failed", time.Now(), 0, 0, 0, false, "boom"); err == nil {
		t.Fatal("expected missing repo scan error for completion")
	}
	if _, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{RepoScanID: "missing"}, 10); err == nil {
		t.Fatal("expected missing repo scan error for findings list")
	}
}

func TestMemoryStoreFindingTriageStateAndHistory(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 28, 9, 0, 0, 0, time.UTC)
	expiry := now.Add(24 * time.Hour)

	if _, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1"); err == nil {
		t.Fatal("expected missing triage state error")
	}

	state := FindingTriageState{
		FindingID:            "finding-1",
		Status:               domain.FindingLifecycleSuppressed,
		Assignee:             "sec-oncall",
		SuppressionExpiresAt: &expiry,
		UpdatedAt:            now,
		UpdatedBy:            "subject:alice",
	}
	if err := store.UpsertFindingTriageState(defaultScopeContext(), state); err != nil {
		t.Fatalf("upsert triage state: %v", err)
	}
	gotState, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1")
	if err != nil {
		t.Fatalf("get triage state: %v", err)
	}
	if gotState.Status != domain.FindingLifecycleSuppressed || gotState.Assignee != "sec-oncall" {
		t.Fatalf("unexpected triage state: %+v", gotState)
	}

	states, err := store.ListFindingTriageStates(defaultScopeContext(), []string{"finding-1", "missing"})
	if err != nil {
		t.Fatalf("list triage states: %v", err)
	}
	if len(states) != 1 || states[0].FindingID != "finding-1" {
		t.Fatalf("unexpected triage states: %+v", states)
	}

	firstEvent := FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionSuppressed,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleSuppressed,
		Assignee:   "sec-oncall",
		Comment:    "temporary exception",
		Actor:      "subject:alice",
		CreatedAt:  now,
	}
	secondEvent := FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionCommented,
		FromStatus: domain.FindingLifecycleSuppressed,
		ToStatus:   domain.FindingLifecycleSuppressed,
		Comment:    "reviewed",
		Actor:      "subject:bob",
		CreatedAt:  now.Add(1 * time.Minute),
	}
	if err := store.AppendFindingTriageEvent(defaultScopeContext(), firstEvent); err != nil {
		t.Fatalf("append first triage event: %v", err)
	}
	if err := store.AppendFindingTriageEvent(defaultScopeContext(), secondEvent); err != nil {
		t.Fatalf("append second triage event: %v", err)
	}
	events, err := store.ListFindingTriageEvents(defaultScopeContext(), "finding-1", 10)
	if err != nil {
		t.Fatalf("list triage events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 triage events, got %d", len(events))
	}
	if events[0].Action != FindingTriageActionCommented {
		t.Fatalf("expected latest event first, got %+v", events)
	}
}

func TestMemoryStoreApplyFindingTriageTransitionAtomic(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)

	err := store.ApplyFindingTriageTransition(defaultScopeContext(), FindingTriageState{
		FindingID: "finding-1",
		Status:    domain.FindingLifecycleAck,
		UpdatedAt: now,
		UpdatedBy: "subject:alice",
	}, FindingTriageEvent{
		FindingID:  "finding-2",
		Action:     FindingTriageActionAcknowledged,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleAck,
		CreatedAt:  now,
	})
	if err == nil {
		t.Fatal("expected mismatch error for triage transition")
	}
	if _, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1"); err == nil {
		t.Fatal("expected no state to be persisted after failed transition")
	}
	events, err := store.ListFindingTriageEvents(defaultScopeContext(), "finding-1", 10)
	if err != nil {
		t.Fatalf("list triage events after failed transition: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events to be persisted after failed transition, got %d", len(events))
	}
}

func TestMemoryStoreScanQueueLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)
	scopedCtx := WithQueueTraceContext(defaultScopeContext(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "congo=t61rcWkgMzE")
	queued, err := store.CreateQueuedScan(scopedCtx, "aws", now)
	if err != nil {
		t.Fatalf("create queued scan: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}
	if queued.TraceParent == "" {
		t.Fatal("expected queue traceparent to be persisted")
	}
	count, err := store.CountQueuedScans(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("count queued scans: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected queued count 1, got %d", count)
	}
	claimed, err := store.ClaimNextQueuedScan(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("claim queued scan: %v", err)
	}
	if claimed.ID != queued.ID || claimed.Status != "running" {
		t.Fatalf("unexpected claimed scan %+v", claimed)
	}
	if claimed.TraceParent == "" {
		t.Fatal("expected claimed scan to retain queue traceparent")
	}
	if _, err := store.ClaimNextQueuedScan(defaultScopeContext(), "aws"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound when queue is empty, got %v", err)
	}
}

func TestMemoryStoreCountQueuedScansBlankProviderIsWildcard(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)
	if _, err := store.CreateQueuedScan(defaultScopeContext(), "aws", now); err != nil {
		t.Fatalf("create aws queued scan: %v", err)
	}
	if _, err := store.CreateQueuedScan(defaultScopeContext(), "gcp", now.Add(time.Minute)); err != nil {
		t.Fatalf("create gcp queued scan: %v", err)
	}

	count, err := store.CountQueuedScans(defaultScopeContext(), "")
	if err != nil {
		t.Fatalf("count queued scans wildcard: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected wildcard queued count 2, got %d", count)
	}
}

func TestMemoryStoreCountQueuedScansAnyScope(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)
	otherScope := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	if _, err := store.CreateQueuedScan(defaultScopeContext(), "aws", now); err != nil {
		t.Fatalf("create default aws queued scan: %v", err)
	}
	if _, err := store.CreateQueuedScan(otherScope, "aws", now.Add(time.Minute)); err != nil {
		t.Fatalf("create scoped aws queued scan: %v", err)
	}
	if _, err := store.CreateQueuedScan(otherScope, "gcp", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("create scoped gcp queued scan: %v", err)
	}

	awsCount, err := store.CountQueuedScansAnyScope(context.Background(), "aws")
	if err != nil {
		t.Fatalf("count queued scans any scope for aws: %v", err)
	}
	if awsCount != 2 {
		t.Fatalf("expected queued aws count across scopes 2, got %d", awsCount)
	}

	totalCount, err := store.CountQueuedScansAnyScope(context.Background(), "")
	if err != nil {
		t.Fatalf("count queued scans any scope wildcard: %v", err)
	}
	if totalCount != 3 {
		t.Fatalf("expected wildcard queued count across scopes 3, got %d", totalCount)
	}
}

func TestMemoryStoreClaimNextQueuedScanAnyScope(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)
	otherScope := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	if _, err := store.CreateQueuedScan(defaultScopeContext(), "aws", now.Add(time.Minute)); err != nil {
		t.Fatalf("create default aws queued scan: %v", err)
	}
	first, err := store.CreateQueuedScan(otherScope, "aws", now)
	if err != nil {
		t.Fatalf("create earlier scoped aws queued scan: %v", err)
	}

	claimed, err := store.ClaimNextQueuedScanAnyScope(context.Background(), "aws")
	if err != nil {
		t.Fatalf("claim queued scan any scope: %v", err)
	}
	if claimed.ID != first.ID || claimed.TenantID != "tenant-b" || claimed.Status != "running" {
		t.Fatalf("unexpected claimed scan across scopes: %+v", claimed)
	}
	if _, err := store.ClaimNextQueuedScanAnyScope(context.Background(), "gcp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for empty provider queue, got %v", err)
	}
}

func TestMemoryStoreNonPositiveLimitsUseDefaultPageSize(t *testing.T) {
	store := NewMemoryStore()
	base := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 105; i++ {
		scan, err := store.CreateScan(defaultScopeContext(), "aws", base.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatalf("create scan %d: %v", i, err)
		}
		if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{{
			ID:        fmt.Sprintf("finding-%03d", i),
			Type:      domain.FindingOwnerless,
			Severity:  domain.SeverityHigh,
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}}); err != nil {
			t.Fatalf("upsert finding %d: %v", i, err)
		}
	}

	scans, err := store.ListScans(defaultScopeContext(), 0)
	if err != nil {
		t.Fatalf("list scans default page: %v", err)
	}
	if len(scans) != 100 {
		t.Fatalf("expected default scan page size 100, got %d", len(scans))
	}

	findings, err := store.ListFindings(defaultScopeContext(), 0)
	if err != nil {
		t.Fatalf("list findings default page: %v", err)
	}
	if len(findings) != 100 {
		t.Fatalf("expected default finding page size 100, got %d", len(findings))
	}
}

func TestMemoryStoreCreateQueuedScanWithinLimit(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)

	first, err := store.CreateQueuedScanWithinLimit(defaultScopeContext(), "aws", now, 1)
	if err != nil {
		t.Fatalf("create queued scan with limit: %v", err)
	}
	if first.Status != "queued" {
		t.Fatalf("expected queued status, got %q", first.Status)
	}
	if _, err := store.CreateQueuedScanWithinLimit(defaultScopeContext(), "aws", now.Add(time.Minute), 1); !errors.Is(err, ErrQueueLimitReached) {
		t.Fatalf("expected ErrQueueLimitReached, got %v", err)
	}
}

func TestMemoryStoreCreateQueuedScanIfNoPending(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)

	first, err := store.CreateQueuedScanIfNoPending(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create queued scan without pending duplicate: %v", err)
	}
	if first.Status != "queued" {
		t.Fatalf("expected queued status, got %q", first.Status)
	}

	if _, err := store.CreateQueuedScanIfNoPending(defaultScopeContext(), "aws", now.Add(time.Minute)); !errors.Is(err, ErrPendingScanExists) {
		t.Fatalf("expected ErrPendingScanExists, got %v", err)
	}

	if err := store.CompleteScan(defaultScopeContext(), first.ID, "completed", now.Add(2*time.Minute), 1, 1, ""); err != nil {
		t.Fatalf("complete first queued scan: %v", err)
	}

	second, err := store.CreateQueuedScanIfNoPending(defaultScopeContext(), "aws", now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("create queued scan after completion: %v", err)
	}
	if second.Status != "queued" {
		t.Fatalf("expected queued status for second scan, got %q", second.Status)
	}
}

func TestMemoryStoreRepoQueueLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 5, 0, 0, time.UTC)
	scopedCtx := WithQueueTraceContext(defaultScopeContext(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "congo=t61rcWkgMzE")
	queued, err := store.CreateQueuedRepoScan(scopedCtx, "owner/repo", 50, 80, now)
	if err != nil {
		t.Fatalf("create queued repo scan: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}
	if queued.TraceParent == "" {
		t.Fatal("expected queued repo scan traceparent to persist")
	}
	if queued.HistoryLimit != 50 || queued.MaxFindings != 80 {
		t.Fatalf("expected queued limits retained, got %+v", queued)
	}
	queuedCount, err := store.CountQueuedRepoScans(defaultScopeContext())
	if err != nil {
		t.Fatalf("count queued repo scans: %v", err)
	}
	if queuedCount != 1 {
		t.Fatalf("expected queued repo count 1, got %d", queuedCount)
	}
	pendingCount, err := store.CountPendingRepoScansByRepository(defaultScopeContext(), "owner/repo")
	if err != nil {
		t.Fatalf("count pending repo scans: %v", err)
	}
	if pendingCount != 1 {
		t.Fatalf("expected pending repo count 1, got %d", pendingCount)
	}
	if err := store.RequeueRepoScan(defaultScopeContext(), queued.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected requeue to reject non-running record, got %v", err)
	}
	claimed, err := store.ClaimNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("claim queued repo scan: %v", err)
	}
	if claimed.ID != queued.ID || claimed.Status != "running" {
		t.Fatalf("unexpected claimed repo scan %+v", claimed)
	}
	if claimed.TraceParent == "" {
		t.Fatal("expected claimed repo scan to retain queue traceparent")
	}
	if err := store.RequeueRepoScan(defaultScopeContext(), claimed.ID); err != nil {
		t.Fatalf("requeue repo scan: %v", err)
	}
	requeued, err := store.GetRepoScan(defaultScopeContext(), claimed.ID)
	if err != nil {
		t.Fatalf("get requeued repo scan: %v", err)
	}
	if requeued.Status != "queued" {
		t.Fatalf("expected requeued status, got %q", requeued.Status)
	}
	if !requeued.StartedAt.After(claimed.StartedAt) {
		t.Fatal("expected requeued repo scan to receive a fresh queue timestamp")
	}
}

func TestMemoryStoreCountQueuedRepoScansAnyScope(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 5, 0, 0, time.UTC)
	otherScope := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	if _, err := store.CreateQueuedRepoScan(defaultScopeContext(), "owner/repo-a", 10, 20, now); err != nil {
		t.Fatalf("create default queued repo scan: %v", err)
	}
	if _, err := store.CreateQueuedRepoScan(otherScope, "owner/repo-b", 10, 20, now.Add(time.Minute)); err != nil {
		t.Fatalf("create scoped queued repo scan: %v", err)
	}

	count, err := store.CountQueuedRepoScansAnyScope(context.Background())
	if err != nil {
		t.Fatalf("count queued repo scans any scope: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected queued repo count across scopes 2, got %d", count)
	}
}

func TestMemoryStoreCreateQueuedRepoScanWithinLimit(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 5, 0, 0, time.UTC)

	first, err := store.CreateQueuedRepoScanWithinLimit(defaultScopeContext(), "owner/repo-a", 10, 20, now, 1)
	if err != nil {
		t.Fatalf("create queued repo scan within limit: %v", err)
	}
	if first.Status != "queued" || first.HistoryLimit != 10 || first.MaxFindings != 20 {
		t.Fatalf("unexpected queued repo scan within limit: %+v", first)
	}
	if _, err := store.CreateQueuedRepoScanWithinLimit(defaultScopeContext(), "owner/repo-b", 10, 20, now.Add(time.Minute), 1); !errors.Is(err, ErrQueueLimitReached) {
		t.Fatalf("expected repo queue limit to be reached, got %v", err)
	}
	if _, err := store.CreateQueuedRepoScanWithinLimit(defaultScopeContext(), "owner/repo-a", 10, 20, now.Add(2*time.Minute), 2); !errors.Is(err, ErrPendingRepoScanExists) {
		t.Fatalf("expected duplicate pending repo scan to be rejected, got %v", err)
	}
}

func TestMemoryStoreClaimNextQueuedRepoScanAnyScope(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 5, 0, 0, time.UTC)
	otherScope := WithScope(context.Background(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	first, err := store.CreateQueuedRepoScan(otherScope, "owner/repo-b", 10, 20, now)
	if err != nil {
		t.Fatalf("create earlier scoped queued repo scan: %v", err)
	}
	if _, err := store.CreateQueuedRepoScan(defaultScopeContext(), "owner/repo-a", 10, 20, now.Add(time.Minute)); err != nil {
		t.Fatalf("create default queued repo scan: %v", err)
	}

	claimed, err := store.ClaimNextQueuedRepoScanAnyScope(context.Background())
	if err != nil {
		t.Fatalf("claim queued repo scan any scope: %v", err)
	}
	if claimed.ID != first.ID || claimed.TenantID != "tenant-b" || claimed.Status != "running" {
		t.Fatalf("unexpected claimed repo scan across scopes: %+v", claimed)
	}
}

func TestMemoryStorePendingRepoCountMatchingIsCaseInsensitive(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 25, 0, 0, time.UTC)
	if _, err := store.CreateQueuedRepoScan(defaultScopeContext(), "Owner/Repo", 10, 20, now); err != nil {
		t.Fatalf("create queued repo scan: %v", err)
	}

	count, err := store.CountPendingRepoScansByRepository(defaultScopeContext(), "owner/repo")
	if err != nil {
		t.Fatalf("count pending repo scans: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 pending repo scan for case-insensitive repository match, got %d", count)
	}
}

func TestMemoryStoreScopeIsolation(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC)

	defaultCtx := defaultScopeContext()
	otherCtx := WithScope(defaultScopeContext(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	defaultScan, err := store.CreateScan(defaultCtx, "aws", now)
	if err != nil {
		t.Fatalf("create default scan: %v", err)
	}
	otherScan, err := store.CreateScan(otherCtx, "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create other scan: %v", err)
	}

	if _, err := store.GetScan(defaultCtx, otherScan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get scan to fail with not found, got %v", err)
	}
	if _, err := store.GetScan(otherCtx, defaultScan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get scan to fail with not found, got %v", err)
	}

	defaultScans, err := store.ListScans(defaultCtx, 10)
	if err != nil {
		t.Fatalf("list default scans: %v", err)
	}
	if len(defaultScans) != 1 || defaultScans[0].ID != defaultScan.ID {
		t.Fatalf("unexpected default scope scans: %+v", defaultScans)
	}

	otherScans, err := store.ListScans(otherCtx, 10)
	if err != nil {
		t.Fatalf("list other scans: %v", err)
	}
	if len(otherScans) != 1 || otherScans[0].ID != otherScan.ID {
		t.Fatalf("unexpected other scope scans: %+v", otherScans)
	}

	defaultRepo, err := store.CreateQueuedRepoScan(defaultCtx, "owner/repo", 10, 10, now)
	if err != nil {
		t.Fatalf("create default repo scan: %v", err)
	}
	otherRepo, err := store.CreateQueuedRepoScan(otherCtx, "owner/repo", 10, 10, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create other repo scan: %v", err)
	}

	if _, err := store.GetRepoScan(defaultCtx, otherRepo.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get repo scan to fail with not found, got %v", err)
	}
	if _, err := store.GetRepoScan(otherCtx, defaultRepo.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get repo scan to fail with not found, got %v", err)
	}
}

func TestMemoryStoreRequiresScopeContext(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.ListScans(context.Background(), 10); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}
}

func TestMemoryStoreAuthzEntityAttributesLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := defaultScopeContext()

	err := store.UpsertAuthzEntityAttributes(ctx, AuthzEntityAttributes{
		EntityKind:     AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "platform_sec",
		Environment:    AuthzAttributeEnvProd,
		RiskTier:       AuthzAttributeRiskTierHigh,
		Classification: AuthzAttributeClassificationConfidential,
	})
	if err != nil {
		t.Fatalf("upsert authz attributes: %v", err)
	}

	attrs, err := store.GetAuthzEntityAttributes(ctx, AuthzEntityKindResource, "finding", "finding-1")
	if err != nil {
		t.Fatalf("get authz attributes: %v", err)
	}
	if attrs.OwnerTeam != "platform_sec" || attrs.Environment != AuthzAttributeEnvProd {
		t.Fatalf("unexpected authz attributes: %+v", attrs)
	}

	otherScope := WithScope(ctx, Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	if _, err := store.GetAuthzEntityAttributes(otherScope, AuthzEntityKindResource, "finding", "finding-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scoped authz attributes isolation, got %v", err)
	}

	if err := store.UpsertAuthzEntityAttributes(ctx, AuthzEntityAttributes{
		EntityKind:  AuthzEntityKindResource,
		EntityType:  "finding",
		EntityID:    "finding-2",
		Environment: "qa",
	}); err == nil {
		t.Fatal("expected invalid authz env error")
	}
}

func TestMemoryStoreAuthzRelationshipLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := defaultScopeContext()
	expiredAt := time.Now().UTC().Add(-1 * time.Minute)

	if err := store.UpsertAuthzRelationship(ctx, AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "alice",
		Relation:    AuthzRelationshipManages,
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
		Source:      "sync",
	}); err != nil {
		t.Fatalf("upsert active authz relationship: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "alice",
		Relation:    AuthzRelationshipDelegatedAdmin,
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
		ExpiresAt:   &expiredAt,
	}); err != nil {
		t.Fatalf("upsert expired authz relationship: %v", err)
	}

	relationships, err := store.ListAuthzRelationships(ctx, AuthzRelationshipFilter{
		SubjectType: "user",
		SubjectID:   "alice",
	}, 10)
	if err != nil {
		t.Fatalf("list active authz relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].Relation != AuthzRelationshipManages {
		t.Fatalf("unexpected active relationships: %+v", relationships)
	}

	withExpired, err := store.ListAuthzRelationships(ctx, AuthzRelationshipFilter{
		SubjectType:    "user",
		SubjectID:      "alice",
		IncludeExpired: true,
	}, 10)
	if err != nil {
		t.Fatalf("list relationships with expired: %v", err)
	}
	if len(withExpired) != 2 {
		t.Fatalf("expected 2 relationships including expired, got %d", len(withExpired))
	}

	if err := store.DeleteAuthzRelationship(ctx, AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "alice",
		Relation:    AuthzRelationshipManages,
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
	}); err != nil {
		t.Fatalf("delete authz relationship: %v", err)
	}

	remaining, err := store.ListAuthzRelationships(ctx, AuthzRelationshipFilter{
		SubjectType:    "user",
		SubjectID:      "alice",
		IncludeExpired: true,
	}, 10)
	if err != nil {
		t.Fatalf("list remaining authz relationships: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Relation != AuthzRelationshipDelegatedAdmin {
		t.Fatalf("unexpected remaining relationships: %+v", remaining)
	}
}

func TestMemoryStoreAuthzPolicyLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := defaultScopeContext()

	if err := store.UpsertAuthzPolicySet(ctx, AuthzPolicySet{
		PolicySetID: "core_policy",
		DisplayName: "Core Policy",
		Description: "workspace baseline",
		CreatedBy:   "owner",
	}); err != nil {
		t.Fatalf("upsert authz policy set: %v", err)
	}

	set, err := store.GetAuthzPolicySet(ctx, "core_policy")
	if err != nil {
		t.Fatalf("get authz policy set: %v", err)
	}
	if set.DisplayName != "Core Policy" {
		t.Fatalf("unexpected policy set: %+v", set)
	}

	firstVersion, err := store.CreateAuthzPolicyVersion(ctx, AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     1,
		Bundle:      `{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		CreatedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create first policy version: %v", err)
	}

	secondVersion, err := store.CreateAuthzPolicyVersion(ctx, AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Bundle:      `{"rules":[{"id":"allow-read","effect":"allow"},{"id":"allow-write","effect":"allow"}]}`,
		CreatedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create second policy version with auto-increment: %v", err)
	}
	if secondVersion.Version != firstVersion.Version+1 {
		t.Fatalf("expected auto-incremented version %d, got %d", firstVersion.Version+1, secondVersion.Version)
	}

	versions, err := store.ListAuthzPolicyVersions(ctx, "core_policy", 10)
	if err != nil {
		t.Fatalf("list policy versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
	if versions[0].Version != 2 || versions[1].Version != 1 {
		t.Fatalf("expected versions sorted newest-first, got %+v", versions)
	}

	activeVersion := 1
	candidateVersion := 2
	if err := store.UpsertAuthzPolicyRollout(ctx, AuthzPolicyRollout{
		PolicySetID:        "core_policy",
		ActiveVersion:      &activeVersion,
		CandidateVersion:   &candidateVersion,
		Mode:               AuthzPolicyRolloutModeShadow,
		TenantAllowlist:    []string{"tenant-a"},
		WorkspaceAllowlist: []string{"workspace-a"},
		CanaryPercentage:   40,
		ValidatedVersions:  []int{1, 2},
		UpdatedBy:          "owner",
	}); err != nil {
		t.Fatalf("upsert policy rollout: %v", err)
	}

	rollout, err := store.GetAuthzPolicyRollout(ctx, "core_policy")
	if err != nil {
		t.Fatalf("get policy rollout: %v", err)
	}
	if rollout.Mode != AuthzPolicyRolloutModeShadow || rollout.ActiveVersion == nil || *rollout.ActiveVersion != 1 {
		t.Fatalf("unexpected policy rollout: %+v", rollout)
	}
	if rollout.CanaryPercentage != 40 {
		t.Fatalf("expected canary percentage 40, got %d", rollout.CanaryPercentage)
	}
	if len(rollout.TenantAllowlist) != 1 || rollout.TenantAllowlist[0] != "tenant-a" {
		t.Fatalf("unexpected tenant allowlist: %+v", rollout.TenantAllowlist)
	}
	if len(rollout.ValidatedVersions) != 2 || rollout.ValidatedVersions[0] != 1 || rollout.ValidatedVersions[1] != 2 {
		t.Fatalf("unexpected validated versions: %+v", rollout.ValidatedVersions)
	}

	if err := store.AppendAuthzPolicyEvent(ctx, AuthzPolicyEvent{
		PolicySetID: "core_policy",
		EventType:   "publish",
		ToVersion:   &activeVersion,
		Actor:       "owner",
		Message:     "published baseline",
		Metadata:    map[string]any{"source": "test"},
	}); err != nil {
		t.Fatalf("append policy event publish: %v", err)
	}
	if err := store.AppendAuthzPolicyEvent(ctx, AuthzPolicyEvent{
		PolicySetID: "core_policy",
		EventType:   "promote",
		FromVersion: &activeVersion,
		ToVersion:   &candidateVersion,
		Actor:       "owner",
		Message:     "promoted candidate",
	}); err != nil {
		t.Fatalf("append policy event promote: %v", err)
	}

	events, err := store.ListAuthzPolicyEvents(ctx, "core_policy", 10)
	if err != nil {
		t.Fatalf("list policy events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 policy events, got %d", len(events))
	}
	if events[0].CreatedAt.Before(events[1].CreatedAt) {
		t.Fatalf("expected events sorted newest-first, got %+v", events)
	}

	otherScope := WithScope(ctx, Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	if _, err := store.GetAuthzPolicySet(otherScope, "core_policy"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scoped policy set isolation, got %v", err)
	}
	if _, err := store.GetAuthzPolicyRollout(otherScope, "core_policy"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scoped policy rollout isolation, got %v", err)
	}
}

func TestMemoryStoreAuthzPolicyLifecycleReadAndErrorPaths(t *testing.T) {
	store := NewMemoryStore()
	ctx := defaultScopeContext()

	if err := store.UpsertAuthzPolicySet(ctx, AuthzPolicySet{
		PolicySetID: "core_policy",
		DisplayName: "Core Policy",
		CreatedBy:   "owner",
	}); err != nil {
		t.Fatalf("upsert authz policy set: %v", err)
	}

	createdVersion, err := store.CreateAuthzPolicyVersion(ctx, AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     1,
		Bundle:      `{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		CreatedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create policy version: %v", err)
	}

	fetchedVersion, err := store.GetAuthzPolicyVersion(ctx, "core_policy", 1)
	if err != nil {
		t.Fatalf("get existing policy version: %v", err)
	}
	if fetchedVersion.Version != 1 || fetchedVersion.Checksum == "" {
		t.Fatalf("unexpected fetched policy version: %+v", fetchedVersion)
	}

	if _, err := store.GetAuthzPolicyVersion(ctx, "core_policy", 0); err == nil {
		t.Fatal("expected invalid policy version lookup to fail")
	}
	if _, err := store.GetAuthzPolicyVersion(ctx, "core_policy", 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing policy version to return ErrNotFound, got %v", err)
	}
	if _, err := store.GetAuthzPolicySet(ctx, "invalid policy set"); err == nil {
		t.Fatal("expected invalid policy set id lookup to fail")
	}

	if _, err := store.CreateAuthzPolicyVersion(ctx, AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     1,
		Bundle:      `{"rules":[{"id":"allow-write","effect":"allow"}]}`,
		CreatedBy:   "owner",
	}); err == nil {
		t.Fatal("expected duplicate policy version to fail")
	}

	missingVersion := createdVersion.Version + 1
	if err := store.UpsertAuthzPolicyRollout(ctx, AuthzPolicyRollout{
		PolicySetID:      "core_policy",
		ActiveVersion:    &createdVersion.Version,
		CandidateVersion: &missingVersion,
		Mode:             AuthzPolicyRolloutModeShadow,
		UpdatedBy:        "owner",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected rollout with missing candidate version to fail with ErrNotFound, got %v", err)
	}

	if err := store.UpsertAuthzPolicyRollout(ctx, AuthzPolicyRollout{
		PolicySetID:      "core_policy",
		ActiveVersion:    &createdVersion.Version,
		CandidateVersion: &createdVersion.Version,
		Mode:             AuthzPolicyRolloutModeEnforce,
		ValidatedVersions: []int{
			createdVersion.Version,
		},
		UpdatedBy: "owner",
	}); err != nil {
		t.Fatalf("expected enforce rollout with validated versions to succeed, got %v", err)
	}

	if err := store.AppendAuthzPolicyEvent(ctx, AuthzPolicyEvent{
		ID:          "event-1",
		PolicySetID: "core_policy",
		EventType:   "publish",
		ToVersion:   &createdVersion.Version,
		Actor:       "owner",
	}); err != nil {
		t.Fatalf("append first policy event: %v", err)
	}
	if err := store.AppendAuthzPolicyEvent(ctx, AuthzPolicyEvent{
		ID:          "event-1",
		PolicySetID: "core_policy",
		EventType:   "publish",
		ToVersion:   &createdVersion.Version,
		Actor:       "owner",
	}); err == nil {
		t.Fatal("expected duplicate policy event id to fail")
	}
	if err := store.AppendAuthzPolicyEvent(ctx, AuthzPolicyEvent{
		PolicySetID: "missing_policy_set",
		EventType:   "publish",
		ToVersion:   &createdVersion.Version,
		Actor:       "owner",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected event append for missing policy set to return ErrNotFound, got %v", err)
	}

	versions, err := store.ListAuthzPolicyVersions(ctx, "core_policy", 1)
	if err != nil {
		t.Fatalf("list policy versions with limit: %v", err)
	}
	if len(versions) != 1 || versions[0].Version != 1 {
		t.Fatalf("unexpected limited policy versions: %+v", versions)
	}

	events, err := store.ListAuthzPolicyEvents(ctx, "core_policy", 1)
	if err != nil {
		t.Fatalf("list policy events with limit: %v", err)
	}
	if len(events) != 1 || events[0].ID != "event-1" {
		t.Fatalf("unexpected limited policy events: %+v", events)
	}
}
