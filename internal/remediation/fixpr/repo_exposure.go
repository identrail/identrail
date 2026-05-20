package fixpr

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/findings/standards"
)

var (
	ErrRepoExposureRemediationUnsupported = errors.New("repo exposure remediation unsupported")
	ErrRepoExposureRemediationUnsafe      = errors.New("repo exposure remediation is not safe to publish")
	ErrRepoExposureSourceRequired         = errors.New("repo exposure source content required")
	ErrRepoExposurePatchApplyFailed       = errors.New("repo exposure patch could not be applied")

	workflowPermissionsScalarWriteAllPattern = regexp.MustCompile(`^(\s*)permissions\s*:\s*write-all\s*(?:#.*)?$`)
	workflowPermissionValueWriteAllPattern   = regexp.MustCompile(`^(\s*[^:#]+:\s*)write-all(\s*(?:#.*)?)$`)
	workflowPermissionFlowWriteAllPattern    = regexp.MustCompile(`(:\s*)write-all(\s*(?:[,}#]|$))`)
	workflowPullRequestTargetTokenPattern    = regexp.MustCompile(`\bpull_request_target\b`)
	workflowOnKeyPattern                     = regexp.MustCompile(`^\s*on\s*:\s*(?:#.*)?$`)
	workflowPermissionsKeyPattern            = regexp.MustCompile(`^\s*permissions\s*:\s*(?:#.*)?$`)
)

// RepoExposureFixPRPlan composes a FixPRPlan for one repo exposure finding and
// its affected file content. It only writes the affected repository file; secret
// findings and placeholder-only remediations are rejected before publication.
func BuildRepoExposureFixPRPlan(finding domain.Finding, sourceContent string, opts PlanOptions) (FixPRPlan, standards.RepoExposureRemediation, error) {
	domain.NormalizeRepoFindingMetadata(&finding)
	remediation, ok := standards.SuggestRepoExposureRemediation(finding)
	if !ok {
		return FixPRPlan{}, standards.RepoExposureRemediation{}, ErrRepoExposureRemediationUnsupported
	}
	if remediation.Patch == nil || !remediation.Publishable || remediation.Patch.Placeholder {
		return FixPRPlan{}, remediation, fmt.Errorf("%w: %s", ErrRepoExposureRemediationUnsafe, remediation.PublishBlockedReason)
	}
	if strings.TrimSpace(sourceContent) == "" {
		return FixPRPlan{}, remediation, ErrRepoExposureSourceRequired
	}
	targetPath, err := repoExposureTargetPath(finding)
	if err != nil {
		return FixPRPlan{}, remediation, err
	}
	patched, err := applyRepoExposurePatch(sourceContent, finding, *remediation.Patch)
	if err != nil {
		return FixPRPlan{}, remediation, err
	}
	if patched == sourceContent {
		return FixPRPlan{}, remediation, fmt.Errorf("%w: no source changes produced", ErrRepoExposurePatchApplyFailed)
	}

	base := strings.TrimSpace(opts.BaseBranch)
	if base == "" {
		base = "main"
	}
	prefix := strings.TrimSpace(opts.BranchPrefix)
	if prefix == "" {
		prefix = "identrail/fix"
	}
	slug := slugifyFindingID(firstNonEmpty(finding.ID, remediation.Detector))
	branch := prefix + "/" + slug

	return FixPRPlan{
		BaseBranch:    base,
		BranchName:    branch,
		CommitMessage: buildRepoExposureCommitMessage(finding, remediation),
		PRTitle:       buildRepoExposurePRTitle(finding, remediation),
		PRBody:        buildRepoExposurePRBody(finding, remediation, opts.FindingURL),
		Files: []PlanFile{{
			Path:    targetPath,
			Content: patched,
		}},
		FindingID:   finding.ID,
		FindingType: string(finding.Type),
	}, remediation, nil
}

func repoExposureTargetPath(finding domain.Finding) (string, error) {
	rawTarget := strings.TrimSpace(finding.FilePath)
	if rawTarget == "" && len(finding.Path) == 1 {
		rawTarget = strings.TrimSpace(finding.Path[0])
	}
	if path.IsAbs(rawTarget) {
		return "", fmt.Errorf("%w: invalid repo file path", ErrRepoExposurePatchApplyFailed)
	}
	target := strings.Trim(rawTarget, "/")
	if target == "." || target == ".." || strings.Contains(target, `\`) || path.IsAbs(target) ||
		strings.HasPrefix(target, "../") ||
		strings.Contains(target, "/../") ||
		strings.HasSuffix(target, "/..") {
		return "", fmt.Errorf("%w: invalid repo file path", ErrRepoExposurePatchApplyFailed)
	}
	clean := path.Clean(target)
	if clean == "." || clean == "" || clean == ".." || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("%w: invalid repo file path", ErrRepoExposurePatchApplyFailed)
	}
	return clean, nil
}

func applyRepoExposurePatch(source string, finding domain.Finding, patch standards.RepoExposurePatchTemplate) (string, error) {
	lines, trailingNewline := splitLines(source)
	if len(lines) == 0 {
		return "", fmt.Errorf("%w: empty source", ErrRepoExposurePatchApplyFailed)
	}

	if finding.LineNumber <= 0 {
		return "", fmt.Errorf("%w: finding line number required", ErrRepoExposurePatchApplyFailed)
	}

	lineIndex := finding.LineNumber - 1
	if lineIndex < 0 || lineIndex >= len(lines) {
		return "", fmt.Errorf("%w: finding line %d is outside the supplied source", ErrRepoExposurePatchApplyFailed, finding.LineNumber)
	}
	switch patch.Strategy {
	case standards.RepoPatchStrategyWorkflowPermissionsReadDefault:
		return applyWorkflowPermissionsReadDefaultPatch(lines, trailingNewline, lineIndex, patch)
	case standards.RepoPatchStrategyWorkflowPullRequestTrigger:
		return applyWorkflowPullRequestTriggerPatch(lines, trailingNewline, lineIndex, patch)
	}
	if repoExposureLineMatches(lines[lineIndex], patch) {
		return replaceLine(lines, trailingNewline, lineIndex, patch), nil
	}
	return "", fmt.Errorf("%w: finding line %d did not match template", ErrRepoExposurePatchApplyFailed, finding.LineNumber)
}

func repoExposureLineMatches(line string, patch standards.RepoExposurePatchTemplate) bool {
	switch patch.Strategy {
	case standards.RepoPatchStrategyLineRegex:
		re, err := regexp.Compile(patch.MatchPattern)
		return err == nil && re.MatchString(line)
	case standards.RepoPatchStrategyLineLiteral, "":
		match := strings.TrimSpace(patch.Match)
		return match != "" && strings.TrimSpace(line) == match
	default:
		return false
	}
}

func replaceLine(lines []string, trailingNewline bool, index int, patch standards.RepoExposurePatchTemplate) string {
	indent := leadingWhitespace(lines[index])
	replacementLines := strings.Split(patch.Replacement, "\n")
	for i, line := range replacementLines {
		if strings.TrimSpace(line) == "" {
			replacementLines[i] = ""
			continue
		}
		replacementLines[i] = indent + line
	}
	updated := make([]string, 0, len(lines)+len(replacementLines)-1)
	updated = append(updated, lines[:index]...)
	updated = append(updated, replacementLines...)
	updated = append(updated, lines[index+1:]...)
	joined := strings.Join(updated, "\n")
	if trailingNewline {
		joined += "\n"
	}
	return joined
}

func applyWorkflowPermissionsReadDefaultPatch(lines []string, trailingNewline bool, lineIndex int, patch standards.RepoExposurePatchTemplate) (string, error) {
	line := lines[lineIndex]
	if workflowPermissionsScalarWriteAllPattern.MatchString(line) {
		return replaceLine(lines, trailingNewline, lineIndex, patch), nil
	}
	if strings.HasPrefix(strings.TrimSpace(line), "permissions:") {
		if patched, ok := replaceWorkflowPermissionWriteAllValue(line); ok {
			return replaceLineWithContent(lines, trailingNewline, lineIndex, patched), nil
		}
	}

	blockStart, ok := workflowParentKeyLine(lines, lineIndex, "permissions")
	if ok && blockStart != lineIndex {
		if patched, ok := replaceWorkflowPermissionWriteAllValue(line); ok {
			return replaceLineWithContent(lines, trailingNewline, lineIndex, patched), nil
		}
	}
	if !ok {
		return "", fmt.Errorf("%w: finding line %d is not in a permissions block", ErrRepoExposurePatchApplyFailed, lineIndex+1)
	}
	if blockStart != lineIndex && !workflowPermissionsKeyPattern.MatchString(lines[blockStart]) {
		return "", fmt.Errorf("%w: finding line %d is not in a permissions block", ErrRepoExposurePatchApplyFailed, lineIndex+1)
	}
	if patched, ok := replaceWorkflowPermissionWriteAllValue(lines[blockStart]); ok {
		return replaceLineWithContent(lines, trailingNewline, blockStart, patched), nil
	}
	updated := append([]string(nil), lines...)
	replaced := false
	for i := blockStart + 1; i < len(updated); i++ {
		if strings.TrimSpace(updated[i]) == "" {
			continue
		}
		if indentationWidth(updated[i]) <= indentationWidth(updated[blockStart]) {
			break
		}
		if patched, ok := replaceWorkflowPermissionWriteAllValue(updated[i]); ok {
			updated[i] = patched
			replaced = true
		}
	}
	if !replaced {
		return "", fmt.Errorf("%w: permissions block did not contain write-all values", ErrRepoExposurePatchApplyFailed)
	}
	return joinLines(updated, trailingNewline), nil
}

func replaceWorkflowPermissionWriteAllValue(line string) (string, bool) {
	if workflowPermissionValueWriteAllPattern.MatchString(line) {
		return workflowPermissionValueWriteAllPattern.ReplaceAllString(line, "${1}read${2}"), true
	}
	if workflowPermissionFlowWriteAllPattern.MatchString(line) {
		return workflowPermissionFlowWriteAllPattern.ReplaceAllString(line, "${1}read${2}"), true
	}
	return "", false
}

func applyWorkflowPullRequestTriggerPatch(lines []string, trailingNewline bool, lineIndex int, patch standards.RepoExposurePatchTemplate) (string, error) {
	targetIndex := lineIndex
	if !workflowPullRequestTargetTokenPattern.MatchString(lines[targetIndex]) {
		var ok bool
		targetIndex, ok = workflowPullRequestTargetLineInLocalBlock(lines, lineIndex)
		if !ok {
			return "", fmt.Errorf("%w: finding line %d is not in a pull_request_target trigger block", ErrRepoExposurePatchApplyFailed, lineIndex+1)
		}
	}
	patched := workflowPullRequestTargetTokenPattern.ReplaceAllString(lines[targetIndex], patch.Replacement)
	if patched == lines[targetIndex] {
		return "", fmt.Errorf("%w: pull_request_target trigger line did not change", ErrRepoExposurePatchApplyFailed)
	}
	return replaceLineWithContent(lines, trailingNewline, targetIndex, patched), nil
}

func workflowPullRequestTargetLineInLocalBlock(lines []string, lineIndex int) (int, bool) {
	blockStart := lineIndex
	if !workflowOnKeyPattern.MatchString(lines[blockStart]) {
		var ok bool
		blockStart, ok = workflowParentKeyLine(lines, lineIndex, "on")
		if !ok {
			return -1, false
		}
	}
	parentIndent := indentationWidth(lines[blockStart])
	for i := blockStart + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if indentationWidth(lines[i]) <= parentIndent {
			break
		}
		if workflowPullRequestTargetTokenPattern.MatchString(lines[i]) {
			return i, true
		}
	}
	return -1, false
}

func workflowParentKeyLine(lines []string, lineIndex int, key string) (int, bool) {
	keyPattern := workflowOnKeyPattern
	if key == "permissions" {
		keyPattern = workflowPermissionsKeyPattern
	}
	lineIndent := indentationWidth(lines[lineIndex])
	for i := lineIndex; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		indent := indentationWidth(lines[i])
		if i != lineIndex && indent >= lineIndent {
			continue
		}
		if keyPattern.MatchString(lines[i]) {
			return i, true
		}
		if i != lineIndex && indent <= lineIndent {
			lineIndent = indent
		}
	}
	return -1, false
}

func replaceLineWithContent(lines []string, trailingNewline bool, index int, content string) string {
	updated := append([]string(nil), lines...)
	updated[index] = content
	return joinLines(updated, trailingNewline)
}

func joinLines(lines []string, trailingNewline bool) string {
	joined := strings.Join(lines, "\n")
	if trailingNewline {
		joined += "\n"
	}
	return joined
}

func splitLines(source string) ([]string, bool) {
	trailingNewline := strings.HasSuffix(source, "\n")
	lines := strings.Split(source, "\n")
	if trailingNewline {
		lines = lines[:len(lines)-1]
	}
	return lines, trailingNewline
}

func leadingWhitespace(line string) string {
	for i, r := range line {
		if r != ' ' && r != '\t' {
			return line[:i]
		}
	}
	return line
}

func indentationWidth(line string) int {
	width := 0
	for _, r := range line {
		switch r {
		case ' ':
			width++
		case '\t':
			width += 2
		default:
			return width
		}
	}
	return width
}

func buildRepoExposureCommitMessage(finding domain.Finding, remediation standards.RepoExposureRemediation) string {
	subject := truncate("remediate "+remediation.Detector, 72)
	return fmt.Sprintf("identrail: %s\n\nFinding: %s (%s)\n", subject, finding.ID, finding.Type)
}

func buildRepoExposurePRTitle(finding domain.Finding, remediation standards.RepoExposureRemediation) string {
	location := strings.TrimSpace(finding.FilePath)
	if location == "" {
		return "identrail: remediate " + remediation.Detector
	}
	return "identrail: remediate " + remediation.Detector + " in " + location
}

func buildRepoExposurePRBody(finding domain.Finding, remediation standards.RepoExposureRemediation, findingURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Summary\n\n%s\n\n", remediation.Summary)
	fmt.Fprintf(&b, "## Risk summary\n\n%s\n\n", remediation.RiskSummary)
	b.WriteString("## Traceability\n\n")
	fmt.Fprintf(&b, "- Finding ID: `%s`\n", finding.ID)
	if finding.ScanID != "" {
		fmt.Fprintf(&b, "- Scan ID: `%s`\n", finding.ScanID)
	}
	fmt.Fprintf(&b, "- Detector: `%s`\n", remediation.Detector)
	fmt.Fprintf(&b, "- Finding type: `%s`\n", finding.Type)
	if finding.Repository != "" {
		fmt.Fprintf(&b, "- Repository: `%s`\n", finding.Repository)
	}
	if finding.FilePath != "" {
		if finding.LineNumber > 0 {
			fmt.Fprintf(&b, "- Location: `%s:%d`\n", finding.FilePath, finding.LineNumber)
		} else {
			fmt.Fprintf(&b, "- Location: `%s`\n", finding.FilePath)
		}
	}
	if finding.Commit != "" {
		fmt.Fprintf(&b, "- Commit: `%s`\n", finding.Commit)
	}
	if findingURL != "" {
		fmt.Fprintf(&b, "- Finding link: %s\n", findingURL)
	}
	if len(remediation.Steps) > 0 {
		b.WriteString("\n## Remediation steps\n\n")
		for _, step := range remediation.Steps {
			fmt.Fprintf(&b, "- %s\n", step)
		}
	}
	if len(remediation.Validation) > 0 {
		b.WriteString("\n## Validation notes\n\n")
		for _, note := range remediation.Validation {
			fmt.Fprintf(&b, "- %s\n", note)
		}
	}
	if len(remediation.SafetyNotes) > 0 {
		b.WriteString("\n## Safety notes\n\n")
		for _, note := range remediation.SafetyNotes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
	}
	b.WriteString("\n---\n*Generated by Identrail from a repository exposure finding. Review before merging.*\n")
	return b.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
