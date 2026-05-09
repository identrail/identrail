package aws

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureCollectorCollectFilesAndDirectories(t *testing.T) {
	dir := t.TempDir()

	roleA := `{"arn":"arn:aws:iam::123456789012:role/a","name":"a","assume_role_policy_document":"{}","permission_policies":[]}`
	roleB := `{"arn":"arn:aws:iam::123456789012:role/b","name":"b","assume_role_policy_document":"{}","permission_policies":[]}`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(roleA), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(roleB), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fixedNow := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	collector := NewFixtureCollector([]string{filepath.Join(dir, "a.json"), dir}, WithFixtureClock(func() time.Time { return fixedNow }))

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 deduplicated assets, got %d", len(assets))
	}
	for _, asset := range assets {
		if asset.Collected != "2026-03-16T12:00:00Z" {
			t.Fatalf("unexpected collected time: %q", asset.Collected)
		}
	}
}

func TestFixtureCollectorErrors(t *testing.T) {
	collector := NewFixtureCollector(nil)
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected error for empty fixture list")
	}

	dir := t.TempDir()
	collector = NewFixtureCollector([]string{dir})
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected error for empty directory")
	}

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	collector = NewFixtureCollector([]string{badFile})
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFixtureCollectorSkipsMalformedAndMissingARNFixturesWhenValidRecordsExist(t *testing.T) {
	dir := t.TempDir()

	validRole := `{"arn":"arn:aws:iam::123456789012:role/valid","name":"valid","assume_role_policy_document":"{}","permission_policies":[]}`
	missingARNRole := `{"name":"missing-arn","assume_role_policy_document":"{}","permission_policies":[]}`
	if err := os.WriteFile(filepath.Join(dir, "01-valid.json"), []byte(validRole), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "02-bad.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "03-missing-arn.json"), []byte(missingARNRole), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "04-duplicate.json"), []byte(validRole), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	collector := NewFixtureCollector([]string{dir})
	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect with partial malformed fixtures: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one deduplicated valid asset, got %d", len(assets))
	}
	if assets[0].SourceID != "arn:aws:iam::123456789012:role/valid" {
		t.Fatalf("unexpected source id for retained fixture: %q", assets[0].SourceID)
	}
}
