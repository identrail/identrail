package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultGitHubAPIBaseURL = "https://api.github.com"
	defaultJWTTTL           = 9 * time.Minute
	tokenRefreshSkew        = 1 * time.Minute
)

var appSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$`)

// AppCredentials contains the non-tenant GitHub App credentials used by the
// hosted SaaS connector flow.
type AppCredentials struct {
	AppID         int64
	AppSlug       string
	PrivateKeyPEM string
}

// NormalizeAppSlug validates the GitHub App slug used in install URLs.
func NormalizeAppSlug(value string) (string, error) {
	slug := strings.ToLower(strings.TrimSpace(value))
	if !appSlugPattern.MatchString(slug) {
		return "", fmt.Errorf("invalid github app slug")
	}
	return slug, nil
}

// BuildInstallURL returns the GitHub App installation URL with an opaque state.
func BuildInstallURL(appSlug string, state string, redirectURI string) (string, error) {
	slug, err := NormalizeAppSlug(appSlug)
	if err != nil {
		return "", err
	}
	normalizedState := strings.TrimSpace(state)
	if normalizedState == "" {
		return "", fmt.Errorf("state is required")
	}
	values := url.Values{}
	values.Set("state", normalizedState)
	if redirect := strings.TrimSpace(redirectURI); redirect != "" {
		parsed, err := url.Parse(redirect)
		if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
			return "", fmt.Errorf("redirect uri must be absolute")
		}
		values.Set("redirect_uri", redirect)
	}
	return "https://github.com/apps/" + slug + "/installations/new?" + values.Encode(), nil
}

// SignAppJWT signs a short-lived RS256 JWT accepted by GitHub App APIs.
func SignAppJWT(creds AppCredentials, now time.Time) (string, error) {
	if creds.AppID <= 0 {
		return "", fmt.Errorf("github app id is required")
	}
	key, err := ParsePrivateKey(creds.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	issuedAt := now.UTC().Add(-30 * time.Second)
	expiresAt := now.UTC().Add(defaultJWTTTL)
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": issuedAt.Unix(),
		"exp": expiresAt.Unix(),
		"iss": strconv.FormatInt(creds.AppID, 10),
	}
	unsigned, err := encodeJWTSigningInput(header, claims)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign github app jwt: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func encodeJWTSigningInput(header map[string]string, claims map[string]any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON), nil
}

// ParsePrivateKey parses a PEM-encoded RSA private key in PKCS#1 or PKCS#8 form.
func ParsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(privateKeyPEM)))
	if block == nil {
		return nil, fmt.Errorf("github app private key must be PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse github app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("github app private key must be RSA")
	}
	return key, nil
}

// InstallationToken represents one GitHub App installation token response.
type InstallationToken struct {
	Token     string
	ExpiresAt time.Time
}

// InstallationTokenClient mints and caches installation tokens.
type InstallationTokenClient struct {
	Credentials AppCredentials
	HTTPClient  *http.Client
	APIBaseURL  string
	Now         func() time.Time

	mu    sync.Mutex
	cache map[int64]InstallationToken
}

// Mint returns a cached token unless it is close to expiry.
func (c *InstallationTokenClient) Mint(ctx context.Context, installationID int64) (InstallationToken, error) {
	if installationID <= 0 {
		return InstallationToken{}, fmt.Errorf("installation id is required")
	}
	now := c.now().UTC()
	c.mu.Lock()
	if c.cache != nil {
		if cached, ok := c.cache[installationID]; ok && cached.ExpiresAt.After(now.Add(tokenRefreshSkew)) {
			c.mu.Unlock()
			return cached, nil
		}
	}
	c.mu.Unlock()

	jwt, err := SignAppJWT(c.Credentials, now)
	if err != nil {
		return InstallationToken{}, err
	}
	endpoint := strings.TrimRight(c.apiBaseURL(), "/") + "/app/installations/" + strconv.FormatInt(installationID, 10) + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return InstallationToken{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.httpClient().Do(req)
	if err != nil {
		return InstallationToken{}, fmt.Errorf("mint github installation token: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return InstallationToken{}, fmt.Errorf("mint github installation token: status %d", res.StatusCode)
	}
	var payload struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return InstallationToken{}, fmt.Errorf("decode github installation token: %w", err)
	}
	if strings.TrimSpace(payload.Token) == "" || payload.ExpiresAt.IsZero() {
		return InstallationToken{}, errors.New("github installation token response missing token or expiry")
	}
	token := InstallationToken{Token: payload.Token, ExpiresAt: payload.ExpiresAt.UTC()}
	c.mu.Lock()
	if c.cache == nil {
		c.cache = map[int64]InstallationToken{}
	}
	c.cache[installationID] = token
	c.mu.Unlock()
	return token, nil
}

func (c *InstallationTokenClient) now() time.Time {
	if c != nil && c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *InstallationTokenClient) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *InstallationTokenClient) apiBaseURL() string {
	if c != nil && strings.TrimSpace(c.APIBaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(c.APIBaseURL), "/")
	}
	return defaultGitHubAPIBaseURL
}
