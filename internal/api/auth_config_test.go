package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

type authConfigBody struct {
	Auth struct {
		ManualMode         bool     `json:"manual_mode"`
		WorkOSLoginEnabled bool     `json:"workos_login_enabled"`
		NativeSAMLEnabled  bool     `json:"native_saml_enabled"`
		Providers          []string `json:"providers"`
	} `json:"auth"`
	Features struct {
		OnboardingWizard bool `json:"onboarding_wizard"`
		Connectors       struct {
			GitHub     bool `json:"github"`
			AWS        bool `json:"aws"`
			Kubernetes bool `json:"kubernetes"`
		} `json:"connectors"`
	} `json:"features"`
}

func fetchAuthConfig(t *testing.T, opts RouterOptions) authConfigBody {
	t.Helper()
	opts.FeatureNewAuth = true
	if opts.RateLimitRPM == 0 {
		opts.RateLimitRPM = 1000
	}
	if opts.RateLimitBurst == 0 {
		opts.RateLimitBurst = 1000
	}
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), NewService(db.NewMemoryStore(), fakeScanner{}, "aws"), opts)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body authConfigBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode auth config: %v body=%s", err, rec.Body.String())
	}
	return body
}

func TestAuthConfigFeaturesDefaultToDisabled(t *testing.T) {
	body := fetchAuthConfig(t, RouterOptions{})

	if body.Features.OnboardingWizard {
		t.Fatalf("expected onboarding_wizard false by default")
	}
	if body.Features.Connectors.GitHub || body.Features.Connectors.AWS || body.Features.Connectors.Kubernetes {
		t.Fatalf("expected all connectors false by default, got %+v", body.Features.Connectors)
	}
}

func TestAuthConfigFeaturesReflectEnabledFlags(t *testing.T) {
	body := fetchAuthConfig(t, RouterOptions{
		FeatureOnboardingWizard:  true,
		FeatureConnectorGitHubV2: true,
		FeatureConnectorAWS:      true,
		FeatureConnectorK8S:      false,
	})

	if !body.Features.OnboardingWizard {
		t.Fatalf("expected onboarding_wizard true")
	}
	if !body.Features.Connectors.GitHub || !body.Features.Connectors.AWS {
		t.Fatalf("expected github and aws connectors true, got %+v", body.Features.Connectors)
	}
	if body.Features.Connectors.Kubernetes {
		t.Fatalf("expected kubernetes connector false, got %+v", body.Features.Connectors)
	}
}

func TestAuthConfigPreservesExistingAuthContractAndLeaksNoSecrets(t *testing.T) {
	rec := httptest.NewRecorder()
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), NewService(db.NewMemoryStore(), fakeScanner{}, "aws"), RouterOptions{
		FeatureNewAuth:      true,
		FeatureWorkOSLogin:  true,
		RateLimitRPM:        1000,
		RateLimitBurst:      1000,
		WorkOSClientID:      "client_should_not_leak",
		WorkOSAPIKey:        "sk_should_not_leak",
		WorkOSWebhookSecret: "whsec_should_not_leak",
		SessionKey:          strings.Repeat("a", 64),
	})
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/config", nil))

	raw := rec.Body.String()
	if !strings.Contains(raw, `"workos_login_enabled":true`) {
		t.Fatalf("existing auth contract changed: %s", raw)
	}
	for _, secret := range []string{"client_should_not_leak", "sk_should_not_leak", "whsec_should_not_leak", strings.Repeat("a", 64)} {
		if strings.Contains(raw, secret) {
			t.Fatalf("auth config leaked sensitive value %q: %s", secret, raw)
		}
	}
}
