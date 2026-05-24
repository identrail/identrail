package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// DependabotAlert is the subset of GitHub's Dependabot alert API needed to
// normalize alerts into Identrail repo findings. None of these fields carry
// secret material.
type DependabotAlert struct {
	Number                int                        `json:"number"`
	State                 string                     `json:"state"`
	Dependency            DependabotDependency       `json:"dependency"`
	SecurityAdvisory      DependabotSecurityAdvisory `json:"security_advisory"`
	SecurityVulnerability DependabotVulnerability    `json:"security_vulnerability"`
	HTMLURL               string                     `json:"html_url"`
	URL                   string                     `json:"url"`
}

type DependabotDependency struct {
	Package      DependabotPackage `json:"package"`
	ManifestPath string            `json:"manifest_path"`
	Scope        string            `json:"scope"`
}

type DependabotPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type DependabotSecurityAdvisory struct {
	GHSAID      string                       `json:"ghsa_id"`
	CVEID       string                       `json:"cve_id"`
	Summary     string                       `json:"summary"`
	Severity    string                       `json:"severity"`
	Identifiers []DependabotAdvisoryIdentity `json:"identifiers"`
}

type DependabotAdvisoryIdentity struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type DependabotVulnerability struct {
	Package                DependabotPackage      `json:"package"`
	Severity               string                 `json:"severity"`
	VulnerableVersionRange string                 `json:"vulnerable_version_range"`
	FirstPatchedVersion    DependabotPatchVersion `json:"first_patched_version"`
}

type DependabotPatchVersion struct {
	Identifier string `json:"identifier"`
}

// ListDependabotAlerts returns all open GitHub Dependabot alerts for a
// repository. It follows GitHub pagination using the installation token.
func (c RepositoryClient) ListDependabotAlerts(ctx context.Context, installationID int64, repository string) ([]DependabotAlert, error) {
	if c.TokenClient == nil {
		return nil, fmt.Errorf("github installation token client is required")
	}
	normalizedRepository, err := normalizeRepositoryName(repository)
	if err != nil {
		return nil, err
	}
	token, err := c.TokenClient.Mint(ctx, installationID)
	if err != nil {
		return nil, err
	}
	alerts := []DependabotAlert{}
	endpoint := c.repositoryEndpoint(normalizedRepository, "/dependabot/alerts?state=open&per_page="+strconv.Itoa(defaultRepoPageLimit))
	_, err = c.getJSONPages(ctx, token.Token, endpoint, func(body []byte) error {
		var page []DependabotAlert
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		alerts = append(alerts, page...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list github dependabot alerts: %w", err)
	}
	return alerts, nil
}
