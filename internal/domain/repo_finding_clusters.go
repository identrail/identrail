package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// RepoFindingClusterSpread summarizes how widely one duplicated repo finding is spread.
type RepoFindingClusterSpread struct {
	Paths     int `json:"paths"`
	Commits   int `json:"commits"`
	RepoScans int `json:"repo_scans"`
}

// RepoFindingClusterMember captures one occurrence within a grouped repo-finding cluster.
type RepoFindingClusterMember struct {
	FindingID           string    `json:"finding_id"`
	RepoScanID          string    `json:"repo_scan_id,omitempty"`
	Repository          string    `json:"repository,omitempty"`
	Commit              string    `json:"commit,omitempty"`
	FilePath            string    `json:"file_path,omitempty"`
	LineNumber          int       `json:"line_number,omitempty"`
	LineSnippet         string    `json:"line_snippet,omitempty"`
	LineSnippetRedacted *bool     `json:"line_snippet_redacted,omitempty"`
	SourceURL           string    `json:"source_url,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

// RepoFindingCluster groups repeated repo findings into one analyst-facing rollup.
type RepoFindingCluster struct {
	ID           string                     `json:"id"`
	Repository   string                     `json:"repository,omitempty"`
	Type         FindingType                `json:"type"`
	Severity     FindingSeverity            `json:"severity"`
	Detector     string                     `json:"detector,omitempty"`
	Title        string                     `json:"title"`
	HumanSummary string                     `json:"human_summary"`
	Remediation  string                     `json:"remediation"`
	Count        int                        `json:"count"`
	FirstSeenAt  time.Time                  `json:"first_seen_at"`
	LastSeenAt   time.Time                  `json:"last_seen_at"`
	Spread       RepoFindingClusterSpread   `json:"spread"`
	Members      []RepoFindingClusterMember `json:"members"`
}

type repoFindingClusterAccumulator struct {
	cluster RepoFindingCluster
	paths   map[string]struct{}
	commits map[string]struct{}
	scans   map[string]struct{}
}

// BuildRepoFindingClusters groups repo findings into duplicate-aware clusters with member lists.
func BuildRepoFindingClusters(findings []Finding) []RepoFindingCluster {
	if len(findings) == 0 {
		return nil
	}
	clusters := map[string]*repoFindingClusterAccumulator{}
	for _, raw := range findings {
		finding := raw
		NormalizeRepoFindingMetadata(&finding)

		key := repoFindingClusterKey(finding)
		accumulator, exists := clusters[key]
		if !exists {
			accumulator = &repoFindingClusterAccumulator{
				cluster: RepoFindingCluster{
					ID:           RepoFindingClusterIDForKey(key),
					Repository:   strings.TrimSpace(finding.Repository),
					Type:         finding.Type,
					Severity:     finding.Severity,
					Detector:     strings.TrimSpace(finding.Detector),
					Title:        finding.Title,
					HumanSummary: finding.HumanSummary,
					Remediation:  finding.Remediation,
					FirstSeenAt:  finding.CreatedAt.UTC(),
					LastSeenAt:   finding.CreatedAt.UTC(),
				},
				paths:   map[string]struct{}{},
				commits: map[string]struct{}{},
				scans:   map[string]struct{}{},
			}
			if accumulator.cluster.FirstSeenAt.IsZero() {
				accumulator.cluster.FirstSeenAt = time.Time{}
			}
			clusters[key] = accumulator
		}

		accumulator.cluster.Count++
		if repository := strings.TrimSpace(finding.Repository); accumulator.cluster.Repository == "" && repository != "" {
			accumulator.cluster.Repository = repository
		}
		if detector := strings.TrimSpace(finding.Detector); accumulator.cluster.Detector == "" && detector != "" {
			accumulator.cluster.Detector = detector
		}
		if higherRepoFindingSeverity(finding.Severity, accumulator.cluster.Severity) {
			accumulator.cluster.Severity = finding.Severity
		}
		if accumulator.cluster.Title == "" && finding.Title != "" {
			accumulator.cluster.Title = finding.Title
		}
		if accumulator.cluster.HumanSummary == "" && finding.HumanSummary != "" {
			accumulator.cluster.HumanSummary = finding.HumanSummary
		}
		if accumulator.cluster.Remediation == "" && finding.Remediation != "" {
			accumulator.cluster.Remediation = finding.Remediation
		}
		if accumulator.cluster.FirstSeenAt.IsZero() || (!finding.CreatedAt.IsZero() && finding.CreatedAt.Before(accumulator.cluster.FirstSeenAt)) {
			accumulator.cluster.FirstSeenAt = finding.CreatedAt.UTC()
		}
		if !finding.CreatedAt.IsZero() && (accumulator.cluster.LastSeenAt.IsZero() || finding.CreatedAt.After(accumulator.cluster.LastSeenAt)) {
			accumulator.cluster.LastSeenAt = finding.CreatedAt.UTC()
		}

		if path := strings.TrimSpace(finding.FilePath); path != "" {
			accumulator.paths[path] = struct{}{}
		}
		if commit := strings.TrimSpace(finding.Commit); commit != "" {
			accumulator.commits[commit] = struct{}{}
		}
		if repoScanID := strings.TrimSpace(finding.ScanID); repoScanID != "" {
			accumulator.scans[repoScanID] = struct{}{}
		}

		accumulator.cluster.Members = append(accumulator.cluster.Members, RepoFindingClusterMember{
			FindingID:           finding.ID,
			RepoScanID:          strings.TrimSpace(finding.ScanID),
			Repository:          strings.TrimSpace(finding.Repository),
			Commit:              strings.TrimSpace(finding.Commit),
			FilePath:            strings.TrimSpace(finding.FilePath),
			LineNumber:          finding.LineNumber,
			LineSnippet:         finding.LineSnippet,
			LineSnippetRedacted: finding.LineSnippetRedacted,
			SourceURL:           strings.TrimSpace(finding.SourceURL),
			CreatedAt:           finding.CreatedAt.UTC(),
		})
	}

	result := make([]RepoFindingCluster, 0, len(clusters))
	for _, accumulator := range clusters {
		accumulator.cluster.Spread = RepoFindingClusterSpread{
			Paths:     len(accumulator.paths),
			Commits:   len(accumulator.commits),
			RepoScans: len(accumulator.scans),
		}
		sort.SliceStable(accumulator.cluster.Members, func(i, j int) bool {
			left := accumulator.cluster.Members[i]
			right := accumulator.cluster.Members[j]
			switch {
			case left.CreatedAt.After(right.CreatedAt):
				return true
			case left.CreatedAt.Before(right.CreatedAt):
				return false
			case left.FilePath != right.FilePath:
				return left.FilePath < right.FilePath
			case left.LineNumber != right.LineNumber:
				return left.LineNumber < right.LineNumber
			default:
				return left.FindingID < right.FindingID
			}
		})
		result = append(result, accumulator.cluster)
	}

	sort.SliceStable(result, func(i, j int) bool {
		left := result[i]
		right := result[j]
		switch {
		case left.LastSeenAt.After(right.LastSeenAt):
			return true
		case left.LastSeenAt.Before(right.LastSeenAt):
			return false
		case left.Count != right.Count:
			return left.Count > right.Count
		case higherRepoFindingSeverity(left.Severity, right.Severity):
			return true
		case higherRepoFindingSeverity(right.Severity, left.Severity):
			return false
		case left.Repository != right.Repository:
			return left.Repository < right.Repository
		case left.Detector != right.Detector:
			return left.Detector < right.Detector
		default:
			return left.ID < right.ID
		}
	})

	return result
}

func repoFindingClusterKey(finding Finding) string {
	repository := strings.TrimSpace(finding.Repository)
	detector := strings.TrimSpace(finding.Detector)
	fingerprint := repoFindingSecretFingerprint(finding)
	switch {
	case finding.Type == FindingSecretExposure && detector != "" && fingerprint != "":
		return strings.Join([]string{"secret", repository, string(finding.Type), detector, fingerprint}, "\x1f")
	case finding.Type == FindingSecretExposure:
		return strings.Join([]string{"finding", repository, string(finding.Type), strings.TrimSpace(finding.ScanID), strings.TrimSpace(finding.ID)}, "\x1f")
	case detector != "":
		return strings.Join([]string{"detector", repository, string(finding.Type), detector}, "\x1f")
	default:
		return strings.Join([]string{"finding", repository, string(finding.Type), strings.TrimSpace(finding.ID)}, "\x1f")
	}
}

func repoFindingSecretFingerprint(finding Finding) string {
	if len(finding.Evidence) == 0 {
		return ""
	}
	return strings.TrimSpace(stringFromAny(finding.Evidence["secret_fingerprint"]))
}

// RepoFindingClusterIDForKey returns the stable public cluster identifier for one grouping key.
func RepoFindingClusterIDForKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "repo-cluster:" + hex.EncodeToString(sum[:16])
}

// SortRepoFindingClusters applies the API ordering rules for repository finding clusters.
func SortRepoFindingClusters(items []RepoFindingCluster, sortBy string, desc bool) {
	sort.SliceStable(items, func(i, j int) bool {
		left := items[i]
		right := items[j]
		var cmp int
		switch sortBy {
		case "count":
			cmp = compareInt(left.Count, right.Count)
		case "severity":
			cmp = compareInt(repoFindingSeverityOrder(left.Severity), repoFindingSeverityOrder(right.Severity))
		case "repository":
			cmp = compareString(left.Repository, right.Repository)
		case "detector":
			cmp = compareString(left.Detector, right.Detector)
		case "first_seen_at":
			cmp = compareTime(left.FirstSeenAt, right.FirstSeenAt)
		default:
			cmp = compareTime(left.LastSeenAt, right.LastSeenAt)
		}
		if cmp == 0 {
			cmp = compareInt(left.Count, right.Count)
		}
		if cmp == 0 {
			cmp = compareString(left.ID, right.ID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareInt(left int, right int) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareString(left string, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareTime(left time.Time, right time.Time) int {
	switch {
	case left.Before(right):
		return -1
	case left.After(right):
		return 1
	default:
		return 0
	}
}

func higherRepoFindingSeverity(left FindingSeverity, right FindingSeverity) bool {
	return repoFindingSeverityOrder(left) > repoFindingSeverityOrder(right)
}

func repoFindingSeverityOrder(severity FindingSeverity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
