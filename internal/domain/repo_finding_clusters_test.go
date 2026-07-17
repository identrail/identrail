package domain

import (
	"testing"
	"time"
)

func TestBuildRepoFindingClustersGroupsMisconfigMembersByRepositoryAndDetector(t *testing.T) {
	redacted := false
	findings := []Finding{
		{
			ID:           "f-1",
			ScanID:       "scan-1",
			Type:         FindingRepoMisconfig,
			Severity:     SeverityMedium,
			Title:        "GitHub workflow uses pull_request_target trigger",
			HumanSummary: "pull_request_target can execute with elevated token context if not strictly controlled.",
			Repository:   "owner/repo",
			Commit:       "HEAD",
			FilePath:     ".github/workflows/build.yml",
			LineNumber:   7,
			Detector:     "workflow_pull_request_target",
			LineSnippet:  "pull_request_target:",
			CreatedAt:    time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
			SourceURL:    "https://github.com/owner/repo/blob/abc123/.github/workflows/build.yml#L7",
		},
		{
			ID:                  "f-2",
			ScanID:              "scan-2",
			Type:                FindingRepoMisconfig,
			Severity:            SeverityMedium,
			Title:               "GitHub workflow uses pull_request_target trigger",
			HumanSummary:        "pull_request_target can execute with elevated token context if not strictly controlled.",
			Repository:          "owner/repo",
			Commit:              "HEAD",
			FilePath:            ".github/workflows/release.yml",
			LineNumber:          11,
			Detector:            "workflow_pull_request_target",
			LineSnippet:         "pull_request_target:",
			LineSnippetRedacted: &redacted,
			CreatedAt:           time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
			SourceURL:           "https://github.com/owner/repo/blob/def456/.github/workflows/release.yml#L11",
		},
	}

	clusters := BuildRepoFindingClusters(findings)
	if len(clusters) != 1 {
		t.Fatalf("expected one cluster, got %+v", clusters)
	}

	cluster := clusters[0]
	if cluster.Count != 2 {
		t.Fatalf("expected cluster count 2, got %+v", cluster)
	}
	if cluster.Repository != "owner/repo" || cluster.Detector != "workflow_pull_request_target" {
		t.Fatalf("expected repo/detector rollup, got %+v", cluster)
	}
	if !cluster.FirstSeenAt.Equal(findings[0].CreatedAt) || !cluster.LastSeenAt.Equal(findings[1].CreatedAt) {
		t.Fatalf("expected first/last seen rollups, got %+v", cluster)
	}
	if cluster.Spread.Paths != 2 || cluster.Spread.RepoScans != 2 || cluster.Spread.Commits != 1 {
		t.Fatalf("expected spread metadata, got %+v", cluster.Spread)
	}
	if len(cluster.Members) != 2 || cluster.Members[0].FindingID != "f-2" || cluster.Members[1].FindingID != "f-1" {
		t.Fatalf("expected newest-first members, got %+v", cluster.Members)
	}
}

func TestBuildRepoFindingClustersSeparatesPostureScopesSharingOneDetector(t *testing.T) {
	// Repository-scoped `secret_scanning` and organization-scoped
	// `org_secret_scanning_policy` posture checks intentionally share the
	// `github_secret_scanning_disabled` detector, but they are distinct durable
	// findings with distinct lifecycle keys. Clustering must keep them apart so
	// an org policy gap never hides behind a repository setting.
	findings := []Finding{
		{
			ID:            "f-repo",
			ScanID:        "scan-1",
			Type:          FindingRepoMisconfig,
			Severity:      SeverityHigh,
			Title:         "GitHub posture gap: secret scanning",
			Repository:    "owner/repo",
			Detector:      "github_secret_scanning_disabled",
			AdapterSource: "github_posture",
			CreatedAt:     time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
		},
		{
			ID:            "f-org",
			ScanID:        "scan-1",
			Type:          FindingRepoMisconfig,
			Severity:      SeverityHigh,
			Title:         "GitHub posture gap: org secret scanning policy",
			Repository:    "owner/repo",
			Detector:      "github_secret_scanning_disabled",
			AdapterSource: "github_org_posture",
			CreatedAt:     time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
		},
	}

	clusters := BuildRepoFindingClusters(findings)
	if len(clusters) != 2 {
		t.Fatalf("expected posture scopes to cluster separately, got %+v", clusters)
	}
	bySource := map[string]RepoFindingCluster{}
	for _, cluster := range clusters {
		bySource[cluster.Source] = cluster
	}
	repoCluster, ok := bySource["github_posture"]
	if !ok || repoCluster.Count != 1 || repoCluster.Detector != "github_secret_scanning_disabled" {
		t.Fatalf("expected repository posture cluster, got %+v", clusters)
	}
	orgCluster, ok := bySource["github_org_posture"]
	if !ok || orgCluster.Count != 1 || orgCluster.Detector != "github_secret_scanning_disabled" {
		t.Fatalf("expected organization posture cluster, got %+v", clusters)
	}
	if repoCluster.ID == orgCluster.ID {
		t.Fatalf("expected distinct cluster ids per posture source, got %s", repoCluster.ID)
	}
}

func TestBuildRepoFindingClustersGroupsSecretsByFingerprint(t *testing.T) {
	findings := []Finding{
		{
			ID:         "secret-1",
			ScanID:     "scan-1",
			Type:       FindingSecretExposure,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			Detector:   "aws_access_key_id",
			FilePath:   "config/app.env",
			LineNumber: 3,
			Evidence:   map[string]any{"secret_fingerprint": "fp-a"},
			CreatedAt:  time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
		},
		{
			ID:         "secret-2",
			ScanID:     "scan-2",
			Type:       FindingSecretExposure,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			Detector:   "aws_access_key_id",
			FilePath:   "config/app.env",
			LineNumber: 3,
			Evidence:   map[string]any{"secret_fingerprint": "fp-a"},
			CreatedAt:  time.Date(2026, 4, 30, 9, 0, 0, 0, time.UTC),
		},
		{
			ID:         "secret-3",
			ScanID:     "scan-3",
			Type:       FindingSecretExposure,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			Detector:   "aws_access_key_id",
			FilePath:   "config/app.env",
			LineNumber: 3,
			Evidence:   map[string]any{"secret_fingerprint": "fp-b"},
			CreatedAt:  time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC),
		},
	}

	clusters := BuildRepoFindingClusters(findings)
	if len(clusters) != 2 {
		t.Fatalf("expected two secret clusters, got %+v", clusters)
	}
	if clusters[0].Count != 1 || clusters[1].Count != 2 {
		t.Fatalf("expected fingerprint-aware grouping, got %+v", clusters)
	}
}

func TestBuildRepoFindingClustersDoesNotMergeSecretsWithoutFingerprint(t *testing.T) {
	findings := []Finding{
		{
			ID:         "legacy-secret",
			ScanID:     "scan-1",
			Type:       FindingSecretExposure,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			Detector:   "aws_access_key_id",
			CreatedAt:  time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
		},
		{
			ID:         "legacy-secret",
			ScanID:     "scan-2",
			Type:       FindingSecretExposure,
			Severity:   SeverityHigh,
			Repository: "owner/repo",
			Detector:   "aws_access_key_id",
			CreatedAt:  time.Date(2026, 4, 30, 9, 0, 0, 0, time.UTC),
		},
	}

	clusters := BuildRepoFindingClusters(findings)
	if len(clusters) != 2 {
		t.Fatalf("expected separate fallback clusters for missing fingerprints, got %+v", clusters)
	}
}

func TestBuildRepoFindingClustersPromotesHighestSeverity(t *testing.T) {
	findings := []Finding{
		{
			ID:         "f-1",
			ScanID:     "scan-1",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityInfo,
			Repository: "owner/repo",
			Detector:   "workflow_pull_request_target",
			CreatedAt:  time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
		},
		{
			ID:         "f-2",
			ScanID:     "scan-2",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityLow,
			Repository: "owner/repo",
			Detector:   "workflow_pull_request_target",
			CreatedAt:  time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC),
		},
		{
			ID:         "f-3",
			ScanID:     "scan-3",
			Type:       FindingRepoMisconfig,
			Severity:   SeverityCritical,
			Repository: "owner/repo",
			Detector:   "workflow_pull_request_target",
			CreatedAt:  time.Date(2026, 4, 29, 11, 0, 0, 0, time.UTC),
		},
	}

	clusters := BuildRepoFindingClusters(findings)
	if len(clusters) != 1 {
		t.Fatalf("expected one cluster, got %+v", clusters)
	}
	if clusters[0].Severity != SeverityCritical {
		t.Fatalf("expected highest cluster severity to win, got %+v", clusters[0])
	}
}

func TestSortRepoFindingClusters(t *testing.T) {
	clusters := []RepoFindingCluster{
		{
			ID:          "cluster-b",
			Repository:  "owner/repo-b",
			Severity:    SeverityHigh,
			Detector:    "workflow_pull_request_target",
			Count:       2,
			FirstSeenAt: time.Date(2026, 4, 29, 9, 0, 0, 0, time.UTC),
			LastSeenAt:  time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			ID:          "cluster-a",
			Repository:  "owner/repo-a",
			Severity:    SeverityCritical,
			Detector:    "aws_access_key_id",
			Count:       5,
			FirstSeenAt: time.Date(2026, 4, 28, 9, 0, 0, 0, time.UTC),
			LastSeenAt:  time.Date(2026, 5, 1, 12, 5, 0, 0, time.UTC),
		},
		{
			ID:          "cluster-c",
			Repository:  "owner/repo-c",
			Severity:    SeverityLow,
			Detector:    "docker_latest_tag",
			Count:       1,
			FirstSeenAt: time.Date(2026, 4, 30, 9, 0, 0, 0, time.UTC),
			LastSeenAt:  time.Date(2026, 5, 1, 11, 0, 0, 0, time.UTC),
		},
	}

	SortRepoFindingClusters(clusters, "count", true)
	if clusters[0].ID != "cluster-a" {
		t.Fatalf("expected count-desc sort, got %+v", clusters)
	}

	SortRepoFindingClusters(clusters, "severity", true)
	if clusters[0].ID != "cluster-a" {
		t.Fatalf("expected severity-desc sort, got %+v", clusters)
	}

	SortRepoFindingClusters(clusters, "first_seen_at", false)
	if clusters[0].ID != "cluster-a" {
		t.Fatalf("expected first_seen_at-asc sort, got %+v", clusters)
	}

	SortRepoFindingClusters(clusters, "detector", false)
	if clusters[0].ID != "cluster-a" {
		t.Fatalf("expected detector-asc sort, got %+v", clusters)
	}

	SortRepoFindingClusters(clusters, "repository", false)
	if clusters[0].ID != "cluster-a" {
		t.Fatalf("expected repository-asc sort, got %+v", clusters)
	}

	SortRepoFindingClusters(clusters, "last_seen_at", true)
	if clusters[0].ID != "cluster-a" {
		t.Fatalf("expected last_seen_at-desc sort, got %+v", clusters)
	}
}
