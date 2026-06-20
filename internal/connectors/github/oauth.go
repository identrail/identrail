package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGitHubOAuthBaseURL  = "https://github.com"
	defaultUserInstallPageSize = 100
	maxUserInstallPages        = 50
)

// ErrInstallationNotOwned indicates the GitHub user who authorized the connect
// flow does not have access to the supplied installation. This is the signal
// that a caller attempted to bind an installation they do not control.
var ErrInstallationNotOwned = errors.New("github installation not accessible to authorizing user")

// VerifiedInstallation describes an installation whose ownership has been
// confirmed against the authorizing GitHub user's accessible installations.
type VerifiedInstallation struct {
	InstallationID int64
	AccountLogin   string
	AccountType    string
}

// UserOAuthClient performs the GitHub App "request user authorization during
// installation" flow: it exchanges the post-install OAuth code for a
// user-to-server token, then confirms the supplied installation_id is one the
// authorizing user can actually access. This binds installation_id to a human
// who has rights on the target account, closing the cross-tenant IDOR where a
// caller could name any installation id.
type UserOAuthClient struct {
	ClientID     string
	ClientSecret string
	// OAuthBaseURL is the web origin that serves the OAuth token exchange
	// (https://github.com for github.com, the GHES host for Enterprise).
	OAuthBaseURL string
	// APIBaseURL is the REST API origin (https://api.github.com for github.com).
	APIBaseURL string
	HTTPClient *http.Client
	Now        func() time.Time
}

// Configured reports whether the client has the credentials required to run the
// OAuth verification. Completion paths fail closed when this is false.
func (c UserOAuthClient) Configured() bool {
	return strings.TrimSpace(c.ClientID) != "" && strings.TrimSpace(c.ClientSecret) != ""
}

// VerifyInstallationOwnership exchanges the post-install OAuth code for a user
// token and confirms the user can access installationID. On success it returns
// the GitHub-reported account for the installation, which callers should persist
// in place of any client-supplied account value.
func (c UserOAuthClient) VerifyInstallationOwnership(ctx context.Context, code string, installationID int64) (VerifiedInstallation, error) {
	if !c.Configured() {
		return VerifiedInstallation{}, fmt.Errorf("github oauth client is not configured")
	}
	if strings.TrimSpace(code) == "" {
		return VerifiedInstallation{}, fmt.Errorf("github oauth code is required")
	}
	if installationID <= 0 {
		return VerifiedInstallation{}, fmt.Errorf("installation id is required")
	}

	token, err := c.exchangeCode(ctx, code)
	if err != nil {
		return VerifiedInstallation{}, err
	}

	installations, err := c.listUserInstallations(ctx, token)
	if err != nil {
		return VerifiedInstallation{}, err
	}
	for _, installation := range installations {
		if installation.InstallationID == installationID {
			return installation, nil
		}
	}
	return VerifiedInstallation{}, ErrInstallationNotOwned
}

// exchangeCode trades the post-install OAuth code for a user-to-server token.
func (c UserOAuthClient) exchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(c.ClientID))
	form.Set("client_secret", strings.TrimSpace(c.ClientSecret))
	form.Set("code", strings.TrimSpace(code))

	endpoint := strings.TrimRight(c.oauthBaseURL(), "/") + "/login/oauth/access_token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange github oauth code: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("exchange github oauth code: status %d", res.StatusCode)
	}

	var payload struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode github oauth token: %w", err)
	}
	// GitHub returns HTTP 200 with an error field for bad/expired codes.
	if strings.TrimSpace(payload.Error) != "" {
		return "", fmt.Errorf("exchange github oauth code: %s", payload.Error)
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", errors.New("github oauth token response missing access_token")
	}
	return payload.AccessToken, nil
}

// listUserInstallations returns every installation the authorizing user can
// access, following pagination. The user-to-server token scopes this list to the
// authorizing human, which is what makes it an ownership proof.
func (c UserOAuthClient) listUserInstallations(ctx context.Context, userToken string) ([]VerifiedInstallation, error) {
	nextURL := strings.TrimRight(c.apiBaseURL(), "/") + "/user/installations?per_page=" + strconv.Itoa(defaultUserInstallPageSize)
	installations := []VerifiedInstallation{}
	for page := 0; nextURL != "" && page < maxUserInstallPages; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+userToken)

		res, err := c.httpClient().Do(req)
		if err != nil {
			return nil, fmt.Errorf("list github user installations: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, fmt.Errorf("list github user installations: status %d", res.StatusCode)
		}

		var payload struct {
			Installations []struct {
				ID      int64 `json:"id"`
				Account struct {
					Login string `json:"login"`
					Type  string `json:"type"`
				} `json:"account"`
			} `json:"installations"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("decode github user installations: %w", err)
		}
		for _, installation := range payload.Installations {
			installations = append(installations, VerifiedInstallation{
				InstallationID: installation.ID,
				AccountLogin:   strings.TrimSpace(installation.Account.Login),
				AccountType:    strings.TrimSpace(installation.Account.Type),
			})
		}
		nextURL = nextLink(res.Header.Get("Link"))
	}
	return installations, nil
}

func (c UserOAuthClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c UserOAuthClient) oauthBaseURL() string {
	if trimmed := strings.TrimSpace(c.OAuthBaseURL); trimmed != "" {
		return strings.TrimRight(trimmed, "/")
	}
	return defaultGitHubOAuthBaseURL
}

func (c UserOAuthClient) apiBaseURL() string {
	if trimmed := strings.TrimSpace(c.APIBaseURL); trimmed != "" {
		return strings.TrimRight(trimmed, "/")
	}
	return defaultGitHubAPIBaseURL
}
