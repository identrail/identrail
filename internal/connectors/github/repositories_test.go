package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeInstallationTokenMinter struct {
	seenInstallationID int64
	token              InstallationToken
	err                error
}

func (f *fakeInstallationTokenMinter) Mint(ctx context.Context, installationID int64) (InstallationToken, error) {
	f.seenInstallationID = installationID
	if f.err != nil {
		return InstallationToken{}, f.err
	}
	return f.token, nil
}

func TestRepositoryClientListInstallationRepositories(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer inst-token" {
			t.Fatalf("missing installation token")
		}
		switch calls {
		case 1:
			if r.URL.Path != "/installation/repositories" || r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("unexpected first page url %s", r.URL.String())
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/installation/repositories?page=2>; rel="next"`, serverURLFromRequest(r)))
			_, _ = w.Write([]byte(`{"repositories":[{"full_name":"identrail/api","private":true},{"full_name":" ","private":false}]}`))
		case 2:
			_, _ = w.Write([]byte(`{"repositories":[{"full_name":"identrail/web","private":false}]}`))
		default:
			t.Fatalf("unexpected extra page")
		}
	}))
	defer server.Close()

	repositories, err := (RepositoryClient{
		TokenClient: minter,
		APIBaseURL:  server.URL,
	}).ListInstallationRepositories(context.Background(), 77)
	if err != nil {
		t.Fatalf("list repositories: %v", err)
	}
	if minter.seenInstallationID != 77 {
		t.Fatalf("unexpected installation id %d", minter.seenInstallationID)
	}
	if len(repositories) != 2 || repositories[0].FullName != "identrail/api" || repositories[1].FullName != "identrail/web" {
		t.Fatalf("unexpected repositories %+v", repositories)
	}
}

func TestRepositoryClientErrors(t *testing.T) {
	if _, err := (RepositoryClient{}).ListInstallationRepositories(context.Background(), 1); err == nil {
		t.Fatal("expected missing token client error")
	}
	minterErr := &fakeInstallationTokenMinter{err: fmt.Errorf("mint failed")}
	if _, err := (RepositoryClient{TokenClient: minterErr}).ListInstallationRepositories(context.Background(), 1); err == nil {
		t.Fatal("expected token mint error")
	}
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer server.Close()
	_, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).ListInstallationRepositories(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("expected status error, got %v", err)
	}
}

func TestRepositoryClientRejectsBadJSON(t *testing.T) {
	minter := &fakeInstallationTokenMinter{token: InstallationToken{Token: "inst-token", ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer server.Close()
	_, err := (RepositoryClient{TokenClient: minter, APIBaseURL: server.URL}).ListInstallationRepositories(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestNextLink(t *testing.T) {
	got := nextLink(`<https://api.github.com/page/2>; rel="next", <https://api.github.com/page/3>; rel="last"`)
	if got != "https://api.github.com/page/2" {
		t.Fatalf("unexpected next link %q", got)
	}
	if nextLink(`<not absolute>; rel="next"`) != "" {
		t.Fatal("expected relative next link to be ignored")
	}
}

func serverURLFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
