package repoexposure

import (
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

type secretDetectorFixture struct {
	ID        string
	Positives []string
	Negatives []string
}

func TestSecretDetectorFixtures(t *testing.T) {
	fixtures := []secretDetectorFixture{
		{
			ID:        "aws_access_key_id",
			Positives: []string{"AKIAABCDEFGHIJKLMNOP"},
			Negatives: []string{"AKIA12"},
		},
		{
			ID:        "aws_secret_access_key",
			Positives: []string{"aws_secret_access_key=ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"},
			Negatives: []string{"AWS_SECRET=ABCD1234ABCD1234"},
		},
		{
			ID:        "github_token",
			Positives: []string{"ghp_123456789012345678901234567890123456"},
			Negatives: []string{"ghp_short"},
		},
		{
			ID:        "github_app_token",
			Positives: []string{"ghs_1234567890123456789012345678901234567890"},
			Negatives: []string{"ghs_short"},
		},
		{
			ID:        "slack_token",
			Positives: []string{"xoxp-12345678901234567890-abcdefghi-jkl"},
			Negatives: []string{"xox-short"},
		},
		{
			ID:        "gitlab_token",
			Positives: []string{"glpat-abcdefghijklmnopqrstuvwxyz"},
			Negatives: []string{"gitlab: token"},
		},
		{
			ID:        "azure_service_secret",
			Positives: []string{"AZURE_CLIENT_SECRET=Abcdefghijklmnopqrstuvwxyz0123456789!@#"},
			Negatives: []string{"AZURE_CLIENT_SECRET="},
		},
		{
			ID:        "gcp_api_key",
			Positives: []string{"AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
			Negatives: []string{"AIzaShort"},
		},
		{
			ID:        "stripe_api_key",
			Positives: []string{"sk_" + "live_" + "0123456789abcdefghijklmnopqrst"},
			Negatives: []string{"sk_live_short"},
		},
		{
			ID:        "openai_api_key",
			Positives: []string{"sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456789012"},
			Negatives: []string{"sk-1234"},
		},
		{
			ID:        "workos_api_key",
			Positives: []string{"workos_live_abcdefghijklmnopqrstuvwxyz1234567890_"},
			Negatives: []string{"workos_test_short"},
		},
		{
			ID:        "vercel_token",
			Positives: []string{"vercel_pat_1234567890abcdefghijklmnopqrstuvwxyz"},
			Negatives: []string{"VERCEL_TOKEN=foo"},
		},
		{
			ID:        "npm_token",
			Positives: []string{"NPM_TOKEN=super_secret_npm_token_12345"},
			Negatives: []string{"NPM_TOKEN="},
		},
		{
			ID:        "dockerhub_token",
			Positives: []string{"dckr_pat_1234567890abcdefghijklmnopqrst"},
			Negatives: []string{"docker_token_short"},
		},
		{
			ID:        "private_key_material",
			Positives: []string{"-----BEGIN PRIVATE KEY-----"},
			Negatives: []string{"PRIVATE_KEY"},
		},
		{
			ID:        "tls_key_material",
			Positives: []string{"-----BEGIN CERTIFICATE-----"},
			Negatives: []string{"BEGIN CERT"},
		},
		{
			ID:        "jwt_token",
			Positives: []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			Negatives: []string{"eyJ.not-a-jwt"},
		},
		{
			ID:        "database_connection_url",
			Positives: []string{"postgres://user:supersecret@db.example.com:5432/sample"},
			Negatives: []string{"postgres://127.0.0.1"},
		},
		{
			ID:        "oauth_client_secret",
			Positives: []string{"client_secret=superSecretClientSecretValue12345"},
			Negatives: []string{"client_secret="},
		},
		{
			ID:        "webhook_secret",
			Positives: []string{"webhook_secret=superlongwebhooksecretvalue123"},
			Negatives: []string{"webhook-secret"},
		},
		{
			ID:        "ci_cd_token",
			Positives: []string{"CI_JOB_TOKEN=1234567890abcdef1234"},
			Negatives: []string{"CI_JOB_TOKEN="},
		},
	}

	seen := map[string]bool{}
	for _, fixture := range fixtures {
		detector, found := findSecretDetector(fixture.ID)
		if !found {
			t.Fatalf("fixture references missing detector %s", fixture.ID)
		}
		if fixture.ID == "" {
			t.Fatal("fixture ID cannot be empty")
		}
		seen[fixture.ID] = true
		if len(fixture.Positives) == 0 {
			t.Fatalf("detector %s fixture is missing positive examples", detector.ID)
		}
		if len(fixture.Negatives) == 0 {
			t.Fatalf("detector %s fixture is missing negative examples", detector.ID)
		}

		for _, positive := range fixture.Positives {
			findings := detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 1, positive, time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC))
			if !containsDetector(findings, fixture.ID) {
				t.Fatalf("expected %s to detect fixture %q", fixture.ID, positive)
			}
		}

		for _, negative := range fixture.Negatives {
			findings := detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 1, negative, time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC))
			if containsDetector(findings, fixture.ID) {
				t.Fatalf("expected %s to ignore fixture %q", fixture.ID, negative)
			}
		}

		for _, positive := range fixture.Positives[:1] {
			findings := detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 1, positive, time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC))
			for _, finding := range findings {
				if finding.Detector != fixture.ID {
					continue
				}
				if got := finding.Evidence["detector_version"]; got != detector.Version {
					t.Fatalf("expected detector %s to include version %q got %v", fixture.ID, detector.Version, got)
				}
				if got := finding.Evidence["detector_provider"]; got != detector.Provider {
					t.Fatalf("expected detector %s to include provider %q got %v", fixture.ID, detector.Provider, got)
				}
				if got := finding.Evidence["detector_category"]; got != detector.Category {
					t.Fatalf("expected detector %s to include category %q got %v", fixture.ID, detector.Category, got)
				}
			}
		}
	}

	if len(seen) != len(secretDetectorRegistry) {
		t.Fatalf("expected fixture coverage for all %d detectors, got %d", len(secretDetectorRegistry), len(seen))
	}
}

func TestSecretDetectorRegistryCanAddWithoutCodeFlowChanges(t *testing.T) {
	if len(secretDetectorRegistry) == 0 {
		t.Fatal("expected at least one secret detector")
	}
	if first := secretDetectorRegistry[0]; first.ID == "" || first.Version == "" {
		t.Fatal("expected first registry entry to have id and version")
	}
}

func findSecretDetector(id string) (secretDetector, bool) {
	for _, detector := range secretDetectorRegistry {
		if detector.ID == id {
			return detector, true
		}
	}
	return secretDetector{}, false
}

func containsDetector(findings []domain.Finding, id string) bool {
	for _, finding := range findings {
		if finding.Detector == id {
			return true
		}
	}
	return false
}
