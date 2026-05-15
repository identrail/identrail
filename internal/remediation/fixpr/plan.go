// Package fixpr converts a finding and its remediation patch template into a
// deterministic source-control plan (branch, commit, PR title/body, files) and
// publishes that plan as a real GitHub pull request via the Git Data API.
//
// Direct commit to the default branch is intentionally out of scope; every plan
// targets a fresh branch off the configured base, leaving review and merge to
// the operator.
package fixpr

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/findings/standards"
)

// PlanOptions parameterizes plan generation with deployment-specific values.
type PlanOptions struct {
	// BaseBranch is the branch the fix PR targets (defaults to "main").
	BaseBranch string
	// BranchPrefix is prepended to the generated branch slug (defaults to
	// "identrail/fix"). The full branch name is "<prefix>/<finding-slug>".
	BranchPrefix string
	// FindingURL is a clickable link back to the finding in the UI; included
	// in the README and PR body for traceability. Optional.
	FindingURL string
}

// FixPRPlan is a deterministic, source-agnostic description of the branch,
// commit, files, and PR metadata required to publish a remediation PR.
type FixPRPlan struct {
	BaseBranch    string     `json:"base_branch"`
	BranchName    string     `json:"branch_name"`
	CommitMessage string     `json:"commit_message"`
	PRTitle       string     `json:"pr_title"`
	PRBody        string     `json:"pr_body"`
	Files         []PlanFile `json:"files"`
	FindingID     string     `json:"finding_id"`
	FindingType   string     `json:"finding_type"`
}

// PlanFile is a single file added or replaced by the plan's commit.
type PlanFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// BuildPlan composes the deterministic fix-PR plan for one finding and its
// remediation suggestion. Returns an error when the inputs cannot produce a
// minimally viable plan.
func BuildPlan(finding domain.Finding, template standards.PatchTemplate, opts PlanOptions) (FixPRPlan, error) {
	if strings.TrimSpace(finding.ID) == "" {
		return FixPRPlan{}, fmt.Errorf("finding id required")
	}
	if strings.TrimSpace(template.Summary) == "" {
		return FixPRPlan{}, fmt.Errorf("template summary required")
	}

	base := strings.TrimSpace(opts.BaseBranch)
	if base == "" {
		base = "main"
	}
	prefix := strings.TrimSpace(opts.BranchPrefix)
	if prefix == "" {
		prefix = "identrail/fix"
	}

	slug := slugifyFindingID(finding.ID)
	branch := prefix + "/" + slug
	dir := ".identrail/remediations/" + slug

	files := []PlanFile{
		{Path: dir + "/README.md", Content: buildReadme(finding, template, opts.FindingURL)},
	}
	if strings.TrimSpace(template.Template) != "" {
		files = append(files, PlanFile{
			Path:    dir + "/patch" + templateExtension(template),
			Content: ensureTrailingNewline(template.Template),
		})
	}

	return FixPRPlan{
		BaseBranch:    base,
		BranchName:    branch,
		CommitMessage: buildCommitMessage(finding, template),
		PRTitle:       buildPRTitle(finding),
		PRBody:        buildPRBody(finding, template, opts.FindingURL),
		Files:         files,
		FindingID:     finding.ID,
		FindingType:   string(finding.Type),
	}, nil
}

func buildReadme(finding domain.Finding, template standards.PatchTemplate, findingURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Remediation for finding %s\n\n", finding.ID)
	fmt.Fprintf(&b, "- **Finding type:** `%s`\n", finding.Type)
	fmt.Fprintf(&b, "- **Severity:** `%s`\n", finding.Severity)
	if finding.Title != "" {
		fmt.Fprintf(&b, "- **Title:** %s\n", finding.Title)
	}
	if findingURL != "" {
		fmt.Fprintf(&b, "- **Finding link:** %s\n", findingURL)
	}
	b.WriteString("\n## Summary\n\n")
	b.WriteString(template.Summary)
	if len(template.Steps) > 0 {
		b.WriteString("\n\n## Suggested steps\n\n")
		for i, step := range template.Steps {
			fmt.Fprintf(&b, "%d. %s\n", i+1, step)
		}
	}
	if len(template.SafetyNotes) > 0 {
		b.WriteString("\n## Safety notes\n\n")
		for _, note := range template.SafetyNotes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
	}
	if strings.TrimSpace(template.Template) != "" {
		fmt.Fprintf(&b, "\n## Patch template\n\nSee `patch%s` in this directory.\n", templateExtension(template))
	}
	b.WriteString("\n> This PR is generated from an Identrail finding and is preview-only.\n")
	b.WriteString("> Review the suggested patch, adapt placeholders, and validate before merging.\n")
	return b.String()
}

func buildPRTitle(finding domain.Finding) string {
	if finding.Title != "" {
		return "identrail: fix " + finding.Title
	}
	return fmt.Sprintf("identrail: remediation suggestion for %s", finding.Type)
}

func buildPRBody(finding domain.Finding, template standards.PatchTemplate, findingURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Summary\n\n%s\n\n", template.Summary)
	if finding.HumanSummary != "" {
		fmt.Fprintf(&b, "## Finding context\n\n%s\n\n", finding.HumanSummary)
	}
	b.WriteString("## Traceability\n\n")
	fmt.Fprintf(&b, "- Finding ID: `%s`\n", finding.ID)
	fmt.Fprintf(&b, "- Finding type: `%s`\n", finding.Type)
	fmt.Fprintf(&b, "- Severity: `%s`\n", finding.Severity)
	if finding.ScanID != "" {
		fmt.Fprintf(&b, "- Scan ID: `%s`\n", finding.ScanID)
	}
	if findingURL != "" {
		fmt.Fprintf(&b, "- Finding link: %s\n", findingURL)
	}
	if len(template.Steps) > 0 {
		b.WriteString("\n## Suggested steps\n\n")
		for _, step := range template.Steps {
			fmt.Fprintf(&b, "- %s\n", step)
		}
	}
	if len(template.SafetyNotes) > 0 {
		b.WriteString("\n## Safety notes\n\n")
		for _, note := range template.SafetyNotes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
	}
	b.WriteString("\n---\n*Generated by Identrail. Review before merging.*\n")
	return b.String()
}

func buildCommitMessage(finding domain.Finding, template standards.PatchTemplate) string {
	subject := truncate(template.Summary, 72)
	return fmt.Sprintf("identrail: %s\n\nFinding: %s (%s)\n", subject, finding.ID, finding.Type)
}

var (
	slugRe        = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	multiDotRe    = regexp.MustCompile(`\.{2,}`)
	leadingDotRe  = regexp.MustCompile(`(^|/)\.+`)
	trailingDotRe = regexp.MustCompile(`\.+(/|$)`)
)

// slugifyFindingID produces a string that is safe to use as a single git ref
// component. git-check-ref-format(1) rejects refs that begin with ".", contain
// "..", or end in ".lock", so those patterns are normalized to "-" rather than
// preserved.
func slugifyFindingID(id string) string {
	s := slugRe.ReplaceAllString(strings.TrimSpace(id), "-")
	s = multiDotRe.ReplaceAllString(s, "-")
	s = leadingDotRe.ReplaceAllString(s, "${1}")
	s = trailingDotRe.ReplaceAllString(s, "${1}")
	s = strings.Trim(s, "-.")
	s = strings.ToLower(s)
	if strings.HasSuffix(s, ".lock") {
		s = strings.TrimSuffix(s, ".lock") + "-lock"
	}
	if s == "" {
		return "finding"
	}
	if len(s) > 80 {
		s = strings.TrimRight(s[:80], "-.")
	}
	if s == "" {
		return "finding"
	}
	return s
}

func templateExtension(template standards.PatchTemplate) string {
	trimmed := strings.TrimSpace(template.Template)
	if trimmed == "" {
		return ".md"
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return ".json"
	}
	if strings.Contains(trimmed, "apiVersion:") || strings.Contains(trimmed, "\nkind:") {
		return ".yaml"
	}
	return ".txt"
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return strings.TrimSpace(s[:max-3]) + "..."
}
