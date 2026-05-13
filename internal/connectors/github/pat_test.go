package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "default github", value: "", want: "https://github.com"},
		{name: "trims slash", value: "https://github.example.com/", want: "https://github.example.com"},
		{name: "allows localhost http", value: "http://localhost:3000/", want: "http://localhost:3000"},
		{name: "rejects plain http", value: "http://github.example.com", wantErr: true},
		{name: "rejects relative", value: "github.example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeBaseURL(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestValidatePATShape(t *testing.T) {
	if err := ValidatePATShape("ghp_abcdefghijklmnopqrstuvwxyz"); err != nil {
		t.Fatalf("expected classic pat shape: %v", err)
	}
	if err := ValidatePATShape("github_pat_abcdefghijklmnopqrstuvwxyz"); err != nil {
		t.Fatalf("expected fine-grained-ish pat shape: %v", err)
	}
	if err := ValidatePATShape("not-a-token"); err == nil {
		t.Fatal("expected invalid token shape")
	}
}

func TestPATValidatorValidate(t *testing.T) {
	var seenPath string
	var seenAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("X-OAuth-Scopes", "workflow, repo, repo")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"sec-eng"}`))
	}))
	defer server.Close()

	result, err := PATValidator{AllowedBaseURLs: []string{server.URL}}.Validate(context.Background(), server.URL, "ghp_abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		t.Fatalf("validate pat: %v", err)
	}
	if seenPath != "/api/v3/user" {
		t.Fatalf("unexpected user endpoint %q", seenPath)
	}
	if !strings.HasPrefix(seenAuth, "Bearer ghp_") {
		t.Fatalf("missing bearer token header %q", seenAuth)
	}
	if result.Login != "sec-eng" || len(result.Scopes) != 2 || result.Scopes[1] != "workflow" {
		t.Fatalf("unexpected validation result %+v", result)
	}
}

func TestPATValidatorRejectsMissingScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "read:user")
		_, _ = w.Write([]byte(`{"login":"sec-eng"}`))
	}))
	defer server.Close()

	_, err := PATValidator{AllowedBaseURLs: []string{server.URL}}.Validate(context.Background(), server.URL, "ghp_abcdefghijklmnopqrstuvwxyz")
	if err == nil || !strings.Contains(err.Error(), "repo or public_repo") {
		t.Fatalf("expected missing scope error, got %v", err)
	}
}

func TestPATValidatorRejectsProviderErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := PATValidator{AllowedBaseURLs: []string{server.URL}}.ValidateGitHubPAT(context.Background(), server.URL, "ghp_abcdefghijklmnopqrstuvwxyz")
	if err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("expected provider status error, got %v", err)
	}
}

func TestPATValidatorRejectsBadJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "public_repo")
		_, _ = w.Write([]byte(`{`))
	}))
	defer server.Close()

	_, err := PATValidator{AllowedBaseURLs: []string{server.URL}}.Validate(context.Background(), server.URL, "github_pat_abcdefghijklmnopqrstuvwxyz")
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestPATValidatorRejectsUnapprovedBaseURL(t *testing.T) {
	_, err := PATValidator{AllowedBaseURLs: []string{"https://github.com"}}.Validate(context.Background(), "https://ghe.example.com", "ghp_abcdefghijklmnopqrstuvwxyz")
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected unapproved base url error, got %v", err)
	}
}

func TestUserEndpoint(t *testing.T) {
	if got := userEndpoint("https://github.com/"); got != "https://api.github.com/user" {
		t.Fatalf("unexpected github.com endpoint %q", got)
	}
	if got := userEndpoint("https://github.example.com"); got != "https://github.example.com/api/v3/user" {
		t.Fatalf("unexpected ghes endpoint %q", got)
	}
}
