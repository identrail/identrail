package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// InstallationEvent is the subset of GitHub installation webhooks Identrail
// needs to bind and clean up GitHub App connectors.
type InstallationEvent struct {
	Action         string
	InstallationID int64
	AccountLogin   string
}

// InstallationRepositoriesEvent is the subset of GitHub repository-selection
// webhooks needed to keep connector repository allowlists current.
type InstallationRepositoriesEvent struct {
	Action              string
	InstallationID      int64
	AddedRepositories   []string
	RemovedRepositories []string
}

// VerifyWebhookSignature verifies GitHub's X-Hub-Signature-256 value.
func VerifyWebhookSignature(secret string, payload []byte, signature string) bool {
	normalizedSecret := strings.TrimSpace(secret)
	normalizedSignature := strings.TrimSpace(signature)
	if normalizedSecret == "" || len(payload) == 0 || !strings.HasPrefix(normalizedSignature, "sha256=") {
		return false
	}
	providedHex := strings.TrimPrefix(normalizedSignature, "sha256=")
	provided, err := hex.DecodeString(providedHex)
	if err != nil || len(provided) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(normalizedSecret))
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)
	return subtle.ConstantTimeCompare(provided, expected) == 1
}

// ParseInstallationEvent extracts the action, installation id, and account.
func ParseInstallationEvent(payload []byte) (InstallationEvent, error) {
	var body struct {
		Action       string `json:"action"`
		Installation struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		} `json:"installation"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return InstallationEvent{}, err
	}
	event := InstallationEvent{
		Action:         strings.ToLower(strings.TrimSpace(body.Action)),
		InstallationID: body.Installation.ID,
		AccountLogin:   strings.TrimSpace(body.Installation.Account.Login),
	}
	if event.InstallationID <= 0 {
		return InstallationEvent{}, fmt.Errorf("installation id is required")
	}
	return event, nil
}

// ParseInstallationRepositoriesEvent extracts added and removed repositories
// from an installation_repositories webhook.
func ParseInstallationRepositoriesEvent(payload []byte) (InstallationRepositoriesEvent, error) {
	var body struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		RepositoriesAdded []struct {
			FullName string `json:"full_name"`
		} `json:"repositories_added"`
		RepositoriesRemoved []struct {
			FullName string `json:"full_name"`
		} `json:"repositories_removed"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return InstallationRepositoriesEvent{}, err
	}
	event := InstallationRepositoriesEvent{
		Action:         strings.ToLower(strings.TrimSpace(body.Action)),
		InstallationID: body.Installation.ID,
	}
	if event.InstallationID <= 0 {
		return InstallationRepositoriesEvent{}, fmt.Errorf("installation id is required")
	}
	for _, repository := range body.RepositoriesAdded {
		fullName := strings.ToLower(strings.TrimSpace(repository.FullName))
		if fullName != "" {
			event.AddedRepositories = append(event.AddedRepositories, fullName)
		}
	}
	for _, repository := range body.RepositoriesRemoved {
		fullName := strings.ToLower(strings.TrimSpace(repository.FullName))
		if fullName != "" {
			event.RemovedRepositories = append(event.RemovedRepositories, fullName)
		}
	}
	return event, nil
}
