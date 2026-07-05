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
			Positives: []string{fixtureToken("AKIA", entropicFixture(fixtureCharsetUpperAlnum, 16))},
			Negatives: []string{"AKIA12"},
		},
		{
			ID:        "aws_secret_access_key",
			Positives: []string{fixtureToken("aws_secret_access_key=", entropicFixture(fixtureCharsetAlnum, 40))},
			Negatives: []string{"AWS_SECRET=ABCD1234ABCD1234"},
		},
		{
			ID:        "github_token",
			Positives: []string{fixtureToken("ghp_", entropicFixture(fixtureCharsetAlnum, 36))},
			Negatives: []string{"ghp_short"},
		},
		{
			ID:        "github_app_token",
			Positives: []string{fixtureToken("ghs_", entropicFixture(fixtureCharsetAlnum, 40))},
			Negatives: []string{"ghs_short"},
		},
		{
			ID:        "slack_token",
			Positives: []string{fixtureToken("xoxp-", entropicFixture(fixtureCharsetAlnum, 20), "-", entropicFixture(fixtureCharsetAlnum, 13))},
			Negatives: []string{"xox-short"},
		},
		{
			ID:        "gitlab_token",
			Positives: []string{fixtureToken("glpat-", entropicFixture(fixtureCharsetAlnum, 24))},
			Negatives: []string{"gitlab: token"},
		},
		{
			ID:        "azure_service_secret",
			Positives: []string{fixtureToken("AZURE_CLIENT_SECRET=", "a1B2c3D4e5F6g7H8i9J0kLmN", "!pQrS$tUvWxYz", "12AB34CD56EF78")},
			Negatives: []string{"AZURE_CLIENT_SECRET="},
		},
		{
			ID:        "gcp_api_key",
			Positives: []string{fixtureToken("AIza", entropicFixture(fixtureCharsetAlnum, 35))},
			Negatives: []string{"AIzaShort"},
		},
		{
			ID:        "stripe_api_key",
			Positives: []string{fixtureToken("sk_", "live_", entropicFixture(fixtureCharsetAlnum, 24))},
			Negatives: []string{"sk_live_short"},
		},
		{
			ID:        "openai_api_key",
			Positives: []string{fixtureToken("sk-proj-", entropicFixture(fixtureCharsetAlnum, 40))},
			Negatives: []string{"sk-1234"},
		},
		{
			ID:        "workos_api_key",
			Positives: []string{fixtureToken("workos_live_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4", "p5Q6r7S8t9U0v")},
			Negatives: []string{"workos_test_short"},
		},
		{
			ID:        "vercel_token",
			Positives: []string{fixtureToken("vercel_pat_", entropicFixture(fixtureCharsetAlnum, 24))},
			Negatives: []string{"VERCEL_TOKEN=foo"},
		},
		{
			ID:        "npm_token",
			Positives: []string{fixtureToken("NPM_TOKEN=", entropicFixture(fixtureCharsetAlnum, 16))},
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
			Positives: []string{fixtureToken("eyJ", entropicFixture(fixtureCharsetAlnum, 30), ".", entropicFixture(fixtureCharsetAlnum, 30), ".", entropicFixture(fixtureCharsetAlnum, 32))},
			Negatives: []string{"eyJ.not-a-jwt"},
		},
		{
			ID: "database_connection_url",
			// Host "example.com" and database "sample" carry placeholder words,
			// but the credential is real. A composite detector must not treat
			// those context words as proof the value is fake.
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
			Positives: []string{fixtureToken("CI_JOB_TOKEN=", entropicFixture(fixtureCharsetAlnum, 20))},
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
		if detector.Confidence <= 0 || detector.Confidence > 1 {
			t.Fatalf("detector %s must define confidence between 0 and 1, got %.2f", detector.ID, detector.Confidence)
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
				if finding.ConfidenceScore <= 0 {
					t.Fatalf("expected detector %s to include top-level confidence score, got %+v", fixture.ID, finding)
				}
				if got := finding.Evidence["confidence_score"]; got != finding.ConfidenceScore {
					t.Fatalf("expected detector %s evidence confidence to match top-level score, got %v and %.2f", fixture.ID, got, finding.ConfidenceScore)
				}
				if got, ok := finding.Evidence["confidence_state"].(string); !ok || got == "" {
					t.Fatalf("expected detector %s to include confidence state", fixture.ID)
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

func TestSecretConfidenceClassifiesLikelyProductionSecret(t *testing.T) {
	secretValue := fixtureToken("aB3dE5fG7hJ9kLmN2pQrS4tUvW6xYz8", "AbCde")
	finding := firstFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "app.env", 7, fixtureToken("GITHUB_TOKEN=ghp_", secretValue), time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)),
		"github_token",
	)

	if got := finding.Evidence["confidence_state"]; got != secretClassificationHighConfidence {
		t.Fatalf("expected high-confidence classification, got %v in %+v", got, finding.Evidence)
	}
	if finding.ConfidenceScore < 0.95 {
		t.Fatalf("expected high confidence score, got %.2f", finding.ConfidenceScore)
	}
}

func TestSecretPlaceholderMarkerIsSuppressed(t *testing.T) {
	// A value containing a known placeholder marker ("example") is not a real
	// credential and must be dropped entirely rather than surfaced as a finding.
	assertNoFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "README.md", 7, "client_secret=exampleclientsecretvalue123", time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)),
		"oauth_client_secret",
	)
}

func TestSecretConfidenceUsesMatchedSecretContext(t *testing.T) {
	secretValue := fixtureToken("aB3dE5fG7hJ9kLmN2pQrS4tUvW6xYz8", "AbCde")
	finding := firstFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "app.env", 7, fixtureToken("GITHUB_TOKEN=ghp_", secretValue, " client_secret=exampleclientsecretvalue123"), time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)),
		"github_token",
	)

	if got := finding.Evidence["confidence_state"]; got != secretClassificationHighConfidence {
		t.Fatalf("expected real token confidence to ignore a separate placeholder match on the same line, got %v in %+v", got, finding.Evidence)
	}
	if finding.ConfidenceScore < 0.95 {
		t.Fatalf("expected high confidence score, got %.2f", finding.ConfidenceScore)
	}
}

func TestSecretConfidenceClassifiesRootSampleDirectory(t *testing.T) {
	secretValue := fixtureToken("aB3dE5fG7hJ9kLmN2pQrS4tUvW6xYz8", "AbCde")
	finding := firstFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "examples/secrets.env", 7, fixtureToken("GITHUB_TOKEN=ghp_", secretValue), time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)),
		"github_token",
	)

	if got := finding.Evidence["confidence_state"]; got != secretClassificationSamplePlaceholder {
		t.Fatalf("expected root sample directory classification, got %v in %+v", got, finding.Evidence)
	}
	if finding.ConfidenceScore > 0.40 {
		t.Fatalf("expected downgraded root sample score, got %.2f", finding.ConfidenceScore)
	}
}

func TestSecretTestModeTokenValueIsSuppressed(t *testing.T) {
	// A Stripe test-mode key (sk_test_) is a documented non-production value and
	// must be suppressed rather than reported as a critical leak.
	assertNoFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "app.env", 7, fixtureToken("STRIPE_SECRET_KEY=", "sk_test_", "aB3dE5fG7hJ9kLmN2pQrS4tUvW6x"), time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)),
		"stripe_api_key",
	)
}

func TestSecretConfidenceClassifiesTestFixturePath(t *testing.T) {
	secretValue := fixtureToken("aB3dE5fG7hJ9kLmN2pQrS4tUvW6xYz8", "AbCde")
	finding := firstFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "testdata/secrets.env", 7, fixtureToken("GITHUB_TOKEN=ghp_", secretValue), time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)),
		"github_token",
	)

	if got := finding.Evidence["confidence_state"]; got != secretClassificationTestFixture {
		t.Fatalf("expected test fixture classification, got %v in %+v", got, finding.Evidence)
	}
	if finding.ConfidenceScore > 0.35 {
		t.Fatalf("expected downgraded test fixture score, got %.2f", finding.ConfidenceScore)
	}
}

func TestSecretPrecisionGateDropsProvenFakeButKeepsReal(t *testing.T) {
	at := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)

	// The canonical AWS documentation example key must be suppressed.
	assertNoFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 1, "aws_access_key_id=AKIAIOSFODNN7EXAMPLE", at),
		"aws_access_key_id",
	)

	// A repeated / low-variety filler that merely satisfies the regex length is
	// not a real credential and must be suppressed.
	assertNoFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 2, fixtureToken("ghp_", strings.Repeat("a", 36)), at),
		"github_token",
	)

	// A real, high-entropy key in a production path must still surface —
	// precision must not cost a genuine true positive.
	firstFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 3, fixtureToken("ghp_", entropicFixture(fixtureCharsetAlnum, 36)), at),
		"github_token",
	)
}

func TestSecretSeverityCappedByConfidence(t *testing.T) {
	// A real-looking secret whose only weakness is a sample/example file path is
	// kept (no false negative) but must not present at the rule's full severity.
	at := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	finding := firstFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "examples/secrets.env", 7, fixtureToken("aws_secret_access_key=", entropicFixture(fixtureCharsetAlnum, 40)), at),
		"aws_secret_access_key",
	)
	if finding.Severity != domain.SeverityMedium {
		t.Fatalf("expected low-confidence match capped to medium severity, got %q", finding.Severity)
	}
}

func TestSecretPrecisionPolicyKnobs(t *testing.T) {
	at := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	realKey := fixtureToken("ghp_", entropicFixture(fixtureCharsetAlnum, 36))

	// DropTestAndSampleFindings suppresses real-looking secrets whose only
	// weakness is a test/sample path, for operators who want maximum precision.
	assertNoFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "examples/secrets.env", 1, realKey, at,
			withSecretFindingPolicy(secretFindingPolicy{DropTestAndSampleFindings: true})),
		"github_token",
	)

	// A MinConfidenceScore floor above the detector's confidence drops even an
	// otherwise high-confidence production match.
	assertNoFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 2, realKey, at,
			withSecretFindingPolicy(secretFindingPolicy{MinConfidenceScore: 0.999})),
		"github_token",
	)

	// The same production match with no floor still surfaces.
	firstFindingForDetector(t,
		detectSecretFindings("owner/repo", "HEAD", "config/secrets.env", 3, realKey, at),
		"github_token",
	)
}

func TestSecretContextMarkerDoesNotSuppressRealValue(t *testing.T) {
	// A placeholder marker inside the secret value proves it is fake and is
	// safe to suppress.
	valueReasons := secretPlaceholderReasons("client_secret=exampletoken", "exampletoken", false)
	if !classificationValueProvenFake(valueReasons) {
		t.Fatalf("expected an in-value marker to be proven fake, got %v", valueReasons)
	}

	// The same marker appearing only in the surrounding context (a variable
	// name or comment) next to a real, high-entropy secret must NOT trigger
	// suppression — that would be a false negative on a genuine exposure.
	realValue := entropicFixture(fixtureCharsetAlnum, 36)
	contextReasons := secretPlaceholderReasons("example_api_key = "+realValue, realValue, false)
	if classificationValueProvenFake(contextReasons) {
		t.Fatalf("expected a context-only marker NOT to be proven fake, got %v", contextReasons)
	}
	foundContextMarker := false
	for _, reason := range contextReasons {
		if strings.HasPrefix(reason, "context_marker:") {
			foundContextMarker = true
		}
	}
	if !foundContextMarker {
		t.Fatalf("expected a context_marker reason to still downrank confidence, got %v", contextReasons)
	}

	// A composite detector's value (e.g. a DSN) that carries a marker in its
	// host/database component must NOT be proven fake — the marker is not part
	// of the credential.
	dsn := "postgres://svc:" + realValue + "@sample-db.internal/appdb"
	compositeReasons := secretPlaceholderReasons(dsn, dsn, true)
	if classificationValueProvenFake(compositeReasons) {
		t.Fatalf("expected a composite value marker NOT to be proven fake, got %v", compositeReasons)
	}

	// The same protection must cover value-shape/entropy heuristics: a real
	// password behind a filler-looking host (a sequential run in the host name)
	// must not be suppressed as a composite value. The password is generated so
	// it is a real high-entropy credential without tripping literal scanners.
	shapeDSN := "postgres://svc:" + entropicFixture(fixtureCharsetAlnum, 18) + "@db-0123456789abcdef.internal/app"
	shapeReasons := secretPlaceholderReasons(shapeDSN, shapeDSN, true)
	if classificationValueProvenFake(shapeReasons) {
		t.Fatalf("expected a composite value with a filler-looking host NOT to be proven fake, got %v", shapeReasons)
	}
	// A non-composite value with the same sequential run IS proven fake. The
	// literal is an intentional sequential filler (gitleaks:allow), needed to
	// exercise the shape detector directly.
	nonComposite := secretPlaceholderReasons("token=0123456789abcdef0123", "0123456789abcdef0123", false) //gitleaks:allow
	if !classificationValueProvenFake(nonComposite) {
		t.Fatalf("expected a sequential non-composite value to be proven fake, got %v", nonComposite)
	}
}

func TestSecretDropTestAndSampleOnlyAffectsPathMatches(t *testing.T) {
	// A real, high-entropy secret in a PRODUCTION file that merely sits next to
	// a placeholder word (context_marker -> sample_or_placeholder state) must
	// survive even when the aggressive drop-test-and-sample knob is enabled: the
	// signal was a context word, not a test/sample path.
	realValue := entropicFixture(fixtureCharsetAlnum, 40)
	classification := classifySecretMatch(
		secretDetector{ID: "aws_secret_access_key", Severity: domain.SeverityCritical, Confidence: 0.96},
		"config/secrets.env",
		"example_secret = "+realValue,
		realValue,
		hashSHA256(realValue),
		secretFindingPolicy{},
	)
	if suppressed, reason := classification.suppressedBy(secretFindingPolicy{DropTestAndSampleFindings: true}); suppressed {
		t.Fatalf("expected production context-marker match to survive drop-test-and-sample, got suppressed (%s) with reasons %v", reason, classification.Reasons)
	}

	// The same knob still drops a match whose low confidence comes from a
	// genuine test/sample path.
	sampleClassification := classifySecretMatch(
		secretDetector{ID: "aws_secret_access_key", Severity: domain.SeverityCritical, Confidence: 0.96},
		"examples/secrets.env",
		realValue,
		realValue,
		hashSHA256(realValue),
		secretFindingPolicy{},
	)
	if suppressed, _ := sampleClassification.suppressedBy(secretFindingPolicy{DropTestAndSampleFindings: true}); !suppressed {
		t.Fatalf("expected sample-path match to be dropped when drop-test-and-sample is enabled, reasons %v", sampleClassification.Reasons)
	}
}

func TestSecretConfidencePathClassifiersIncludeRepositoryRootDirectories(t *testing.T) {
	for _, path := range []string{"examples/app.env", "example/app.env", "samples/app.env", "sample/app.env"} {
		if !isSecretSamplePath(path) {
			t.Fatalf("expected %s to be a sample path", path)
		}
	}
	if !isSecretTestFixturePath("__fixtures__/secrets.env") {
		t.Fatal("expected root __fixtures__ directory to be a test fixture path")
	}
	for _, path := range []string{"secrets/app.env", "credentials/app.env"} {
		if !isProductionSecretPath(path) {
			t.Fatalf("expected %s to be a production secret path", path)
		}
	}
}

func TestSecretAllowlistedFingerprintIsSuppressed(t *testing.T) {
	// An explicitly allowlisted fingerprint reflects the repository owner's
	// intent to opt the value out; it must be dropped, not merely tagged.
	secretValue := fixtureToken("A1b2C3d4E5f6G7h8I9j0K", "LmNoPqRsT")
	fingerprint := hashSHA256(secretValue)
	assertNoFindingForDetector(t,
		detectSecretFindings(
			"owner/repo",
			"HEAD",
			"config/secrets.env",
			7,
			"client_secret="+secretValue,
			time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
			withSecretFindingPolicy(secretFindingPolicy{AllowlistedFingerprints: map[string]struct{}{fingerprint: {}}}),
		),
		"oauth_client_secret",
	)
}

func TestParseSecretFindingPolicyAcceptsFingerprintForms(t *testing.T) {
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	policy := parseSecretFindingPolicy([]byte("\n# comments are ignored\nsecret-fingerprint: " + first + "\nsha256=" + second + " # inline comment\ninvalid\n"))

	if _, ok := policy.AllowlistedFingerprints[first]; !ok {
		t.Fatalf("expected first fingerprint to be allowlisted, got %+v", policy.AllowlistedFingerprints)
	}
	if _, ok := policy.AllowlistedFingerprints[second]; !ok {
		t.Fatalf("expected second fingerprint to be allowlisted, got %+v", policy.AllowlistedFingerprints)
	}
	if len(policy.AllowlistedFingerprints) != 2 {
		t.Fatalf("expected exactly two fingerprints, got %+v", policy.AllowlistedFingerprints)
	}
}

func TestParseSecretFindingPolicyAcceptsTuningDirectives(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	policy := parseSecretFindingPolicy([]byte(
		"drop-test-and-sample: true\n" +
			"min-confidence-score = 0.85\n" +
			"secret-fingerprint: " + fingerprint + "\n",
	))

	if !policy.DropTestAndSampleFindings {
		t.Fatalf("expected drop-test-and-sample directive to be applied, got %+v", policy)
	}
	if policy.MinConfidenceScore != 0.85 {
		t.Fatalf("expected min-confidence-score 0.85, got %.2f", policy.MinConfidenceScore)
	}
	if _, ok := policy.AllowlistedFingerprints[fingerprint]; !ok {
		t.Fatalf("expected fingerprints to still parse alongside directives, got %+v", policy.AllowlistedFingerprints)
	}

	// Out-of-range or malformed directive values are ignored rather than
	// silently disabling detection.
	ignored := parseSecretFindingPolicy([]byte("min-confidence-score: 5\ndrop-test-and-sample: maybe\n"))
	if ignored.MinConfidenceScore != 0 || ignored.DropTestAndSampleFindings {
		t.Fatalf("expected invalid directive values to be ignored, got %+v", ignored)
	}
}

func fixtureToken(parts ...string) string {
	return strings.Join(parts, "")
}

const (
	fixtureCharsetAlnum      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	fixtureCharsetUpperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// entropicFixture returns a deterministic, high-entropy token body of the given
// length drawn from charset. Unlike strings.Repeat, its output has enough
// character variety to pass the scanner's placeholder / low-variety / sequential
// heuristics, so fixtures model realistic credentials instead of obvious fillers
// that the precision gate (correctly) suppresses.
func entropicFixture(charset string, length int) string {
	if len(charset) == 0 || length <= 0 {
		return ""
	}
	out := make([]byte, length)
	state := uint64(1469598103934665603)
	for i := 0; i < length; i++ {
		state ^= uint64(i)*2654435761 + 40503
		state *= 1099511628211
		state ^= state >> 27
		out[i] = charset[state%uint64(len(charset))]
	}
	return string(out)
}

func assertNoFindingForDetector(t *testing.T, findings []domain.Finding, id string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Detector == id {
			t.Fatalf("expected detector %s to be suppressed, but it produced finding %+v", id, finding)
		}
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
