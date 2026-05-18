package repoexposure

import (
	"strings"
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
			Positives: []string{fixtureToken("AKIA", strings.Repeat("A", 16))},
			Negatives: []string{"AKIA12"},
		},
		{
			ID:        "aws_secret_access_key",
			Positives: []string{fixtureToken("aws_secret_access_key=", strings.Repeat("A", 40))},
			Negatives: []string{"AWS_SECRET=ABCD1234ABCD1234"},
		},
		{
			ID:        "github_token",
			Positives: []string{fixtureToken("ghp_", strings.Repeat("a", 36))},
			Negatives: []string{"ghp_short"},
		},
		{
			ID:        "github_app_token",
			Positives: []string{fixtureToken("ghs_", strings.Repeat("b", 40))},
			Negatives: []string{"ghs_short"},
		},
		{
			ID:        "slack_token",
			Positives: []string{fixtureToken("xoxp-", strings.Repeat("c", 20), "-", strings.Repeat("d", 13))},
			Negatives: []string{"xox-short"},
		},
		{
			ID:        "gitlab_token",
			Positives: []string{fixtureToken("glpat-", strings.Repeat("e", 24))},
			Negatives: []string{"gitlab: token"},
		},
		{
			ID:        "azure_service_secret",
			Positives: []string{fixtureToken("AZURE_CLIENT_SECRET=", "a1B2c3D4e5F6g7H8i9J0kLmN", "!pQrS$tUvWxYz", "12AB34CD56EF78")},
			Negatives: []string{"AZURE_CLIENT_SECRET="},
		},
		{
			ID:        "gcp_api_key",
			Positives: []string{fixtureToken("AIza", strings.Repeat("A", 35))},
			Negatives: []string{"AIzaShort"},
		},
		{
			ID:        "stripe_api_key",
			Positives: []string{fixtureToken("sk_", "live_", strings.Repeat("g", 24))},
			Negatives: []string{"sk_live_short"},
		},
		{
			ID:        "openai_api_key",
			Positives: []string{fixtureToken("sk-proj-", strings.Repeat("h", 40))},
			Negatives: []string{"sk-1234"},
		},
		{
			ID:        "workos_api_key",
			Positives: []string{fixtureToken("workos_live_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4", "p5Q6r7S8t9U0v")},
			Negatives: []string{"workos_test_short"},
		},
		{
			ID:        "vercel_token",
			Positives: []string{fixtureToken("vercel_pat_", strings.Repeat("j", 24))},
			Negatives: []string{"VERCEL_TOKEN=foo"},
		},
		{
			ID:        "npm_token",
			Positives: []string{fixtureToken("NPM_TOKEN=", strings.Repeat("k", 16))},
			Negatives: []string{"NPM_TOKEN="},
		},
		{
			ID:        "dockerhub_token",
			Positives: []string{fixtureToken("dckr_pat_", "A1b2C3d4E5f6G7h8I9j0kL", "m3N4p5Q6r7S8t9U0")},
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
			Positives: []string{fixtureToken("eyJ", strings.Repeat("m", 30), ".", strings.Repeat("n", 30), ".", strings.Repeat("o", 32))},
			Negatives: []string{"eyJ.not-a-jwt"},
		},
		{
			ID:        "database_connection_url",
			Positives: []string{"postgres://user:supersecret@db.example.com:5432/sample"},
			Negatives: []string{"postgres://127.0.0.1"},
		},
		{
			ID:        "oauth_client_secret",
			Positives: []string{fixtureToken("client_secret=", "A1b2C3d4E5f6G7h8I9j0K", "LmNoPqRsT")},
			Negatives: []string{"client_secret="},
		},
		{
			ID:        "webhook_secret",
			Positives: []string{fixtureToken("webhook_secret=", "A1b2C3d4E5f6G7h8I9j0k", "LmN")},
			Negatives: []string{"webhook-secret"},
		},
		{
			ID:        "ci_cd_token",
			Positives: []string{fixtureToken("CI_JOB_TOKEN=", strings.Repeat("r", 20))},
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

func TestSecretFingerprintUsesCapturedSecretValue(t *testing.T) {
	secretValue := fixtureToken("A1b2C3d4E5f6G7h8I9j0K", "LmNoPqRsT")
	detectedAt := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	first := firstFindingForDetector(t, detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 7, "client_secret="+secretValue, detectedAt), "oauth_client_secret")
	second := firstFindingForDetector(t, detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 7, "oauth_secret=\""+secretValue+"\"", detectedAt), "oauth_client_secret")

	expectedFingerprint := hashSHA256(secretValue)
	if got := first.Evidence["secret_fingerprint"]; got != expectedFingerprint {
		t.Fatalf("expected first fingerprint to hash captured value, got %v", got)
	}
	if got := second.Evidence["secret_fingerprint"]; got != expectedFingerprint {
		t.Fatalf("expected second fingerprint to hash captured value, got %v", got)
	}
	if first.ID != second.ID {
		t.Fatalf("expected matching IDs for identical captured value in same context, got %q and %q", first.ID, second.ID)
	}
}

func fixtureToken(parts ...string) string {
	return strings.Join(parts, "")
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

func firstFindingForDetector(t *testing.T, findings []domain.Finding, id string) domain.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Detector == id {
			return finding
		}
	}
	t.Fatalf("expected finding for detector %s, got %+v", id, findings)
	return domain.Finding{}
}
