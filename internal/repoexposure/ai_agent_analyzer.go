package repoexposure

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/identrail/identrail/internal/domain"
)

const aiAgentAnalyzerVersion = "2026.05"

var envTokenPattern = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9_]{2,}\b`)
var aiKnownAIAgentConfigNamePattern = regexp.MustCompile(`(?i)^\.?mcp(?:[-.][^/.]+)?\.(?:json|ya?ml)$`)

type aiAgentCapability struct {
	Name     string
	Kind     string
	Severity domain.FindingSeverity
	Summary  string
}

func detectAIAgentConfigFindings(repo string, commit string, path string, content []byte, seen map[string]struct{}, detectedAt time.Time, options ...secretFindingOption) []domain.Finding {
	if !isAIAgentConfigPath(path) {
		return nil
	}

	findings := []domain.Finding{}
	lines := strings.Split(string(content), "\n")
	// Structured (JSON/YAML) configs are analyzed by structuredAIAgentSurfaces.
	// Running line-level capability/env heuristics on successfully parsed structured
	// configs can duplicate findings, so we skip those once parser-backed findings
	// are available.
	structuredPossible := isStructuredAgentConfig(path)
	resolver := newAgentLineResolver(lines)
	structuredSurfaces := []aiAgentStructuredFinding{}
	if structuredPossible {
		structuredSurfaces = structuredAIAgentSurfaces(path, content, resolver)
	}
	for index, line := range lines {
		lineNumber := index + 1
		secretFindings := detectSecretFindings(repo, commit, path, lineNumber, line, detectedAt, options...)
		for _, finding := range secretFindings {
			finding.Evidence["history_source"] = "head_snapshot"
			finding.Evidence["ai_agent_surface"] = true
			finding.Evidence["detector_category"] = firstNonEmptyString(anyString(finding.Evidence["detector_category"]), "ai_agent_secret")
			finding.Evidence["agent_config_path"] = path
			findings = append(findings, finding)
		}
		if len(secretFindings) > 0 {
			continue
		}

		// For structured surfaces, rely on structured parsing for capability capture,
		// but still scan plain text for env placeholders in command arguments.
		skipLineCapabilities := len(structuredSurfaces) > 0
		if !skipLineCapabilities && !structuredPossible {
			continue
		}

		variables := sensitiveEnvReferences(line)
		if len(variables) > 0 {
			appendAIAgentFinding(&findings, seen, repo, commit, path, lineNumber, "ai_agent_sensitive_env_reference", domain.SeverityMedium,
				"AI agent configuration references sensitive environment variables",
				"An MCP or AI-agent configuration references credential-like environment variables that may be reachable by tool execution.",
				"Keep sensitive values in a secret manager, scope agent runtime environment variables to the smallest needed set, and avoid committing local agent configs.",
				sanitizeAgentSnippet(line), detectedAt, map[string]any{
					"agent_config_path": path,
					"env_variables":     variables,
					"raw_secret_data":   false,
				})
		}
		if !skipLineCapabilities {
			for _, capability := range dangerousAgentCapabilities(line) {
				appendAIAgentFinding(&findings, seen, repo, commit, path, lineNumber, "ai_agent_dangerous_tool_capability", capability.Severity,
					"AI agent configuration exposes dangerous tool capability",
					capability.Summary,
					"Restrict the tool allowlist, isolate agent execution, remove broad shell/filesystem/network access, and gate deploy or cloud commands behind reviewed workflows.",
					sanitizeAgentSnippet(line), detectedAt, map[string]any{
						"agent_config_path": path,
						"capability":        capability.Kind,
						"tool_name":         capability.Name,
						"raw_secret_data":   false,
					})
			}
		}
	}

	for _, surface := range structuredSurfaces {
		appendAIAgentFinding(&findings, seen, repo, commit, path, surface.Line, surface.Detector, surface.Severity,
			surface.Title, surface.Summary, surface.Remediation, surface.Snippet, detectedAt, surface.Evidence)
	}

	if isCommittedLocalAIAgentConfig(path) {
		appendAIAgentFinding(&findings, seen, repo, commit, path, 1, "ai_agent_committed_local_config", domain.SeverityLow,
			"Local AI agent configuration is committed to the repository",
			"A local MCP or AI-agent configuration file is present in source control, which can expose tool definitions, environment expectations, internal endpoints, or developer-only automation behavior.",
			"Move local agent configuration to ignored developer files, commit only reviewed team-safe templates, and document required secrets through non-secret examples.",
			path, detectedAt, map[string]any{
				"agent_config_path": path,
				"raw_secret_data":   false,
			})
	}

	return findings
}

type aiAgentStructuredFinding struct {
	Detector    string
	Severity    domain.FindingSeverity
	Title       string
	Summary     string
	Remediation string
	Line        int
	Snippet     string
	Evidence    map[string]any
}

func structuredAIAgentSurfaces(path string, content []byte, resolver *agentLineResolver) []aiAgentStructuredFinding {
	lower := strings.ToLower(strings.TrimSpace(path))
	if !strings.HasSuffix(lower, ".json") && !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") {
		return nil
	}

	var root any
	if strings.HasSuffix(lower, ".json") {
		if err := json.Unmarshal(content, &root); err != nil {
			return nil
		}
	} else {
		if err := yaml.Unmarshal(content, &root); err != nil {
			return nil
		}
		root = normalizeYAMLValue(root)
	}

	findings := []aiAgentStructuredFinding{}
	walkAIAgentValue(root, nil, resolver, &findings)
	return findings
}

func walkAIAgentValue(value any, trail []string, resolver *agentLineResolver, findings *[]aiAgentStructuredFinding) {
	switch typed := value.(type) {
	case map[string]any:
		name := firstAIAgentName(typed, trail)
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := typed[key]
			lowerKey := strings.ToLower(strings.TrimSpace(key))
			childTrail := append(append([]string(nil), trail...), key)
			switch {
			case lowerKey == "command" || lowerKey == "args" || lowerKey == "arguments":
				for _, command := range agentStringValues(child) {
					appendAgentCapabilityFindings(resolver, findings, command, childTrail, name)
				}
			case isEnvContainerKey(lowerKey):
				envVars := sensitiveEnvValues(child)
				if len(envVars) > 0 {
					*findings = append(*findings, aiAgentStructuredFinding{
						Detector:    "ai_agent_sensitive_env_reference",
						Severity:    domain.SeverityMedium,
						Title:       "AI agent configuration references sensitive environment variables",
						Summary:     "An MCP or AI-agent configuration references credential-like environment variables that may be reachable by tool execution.",
						Remediation: "Keep sensitive values in a secret manager, scope agent runtime environment variables to the smallest needed set, and avoid committing local agent configs.",
						Line:        resolver.lineForContext(envVars[0], envVars[0]),
						Snippet:     "env: " + strings.Join(envVars, ", "),
						Evidence: map[string]any{
							"config_tree_path": strings.Join(childTrail, "."),
							"env_variables":    envVars,
							"tool_name":        name,
							"raw_secret_data":  false,
						},
					})
				}
			}
			walkAIAgentValue(child, childTrail, resolver, findings)
		}
	case []any:
		for _, child := range typed {
			walkAIAgentValue(child, trail, resolver, findings)
		}
	}
}

func appendAgentCapabilityFindings(resolver *agentLineResolver, findings *[]aiAgentStructuredFinding, value string, trail []string, name string) {
	for _, capability := range dangerousAgentCapabilities(value) {
		*findings = append(*findings, aiAgentStructuredFinding{
			Detector:    "ai_agent_dangerous_tool_capability",
			Severity:    capability.Severity,
			Title:       "AI agent configuration exposes dangerous tool capability",
			Summary:     capability.Summary,
			Remediation: "Restrict the tool allowlist, isolate agent execution, remove broad shell/filesystem/network access, and gate deploy or cloud commands behind reviewed workflows.",
			Line:        resolver.lineForContext(value, capability.Name),
			// The capability name is part of the snippet so multiple risky tools
			// in the same command (for example "aws ... && vercel ...") are not
			// collapsed by snippet-aware deduplication.
			Snippet: capability.Name + ": " + sanitizeAgentSnippet(value),
			Evidence: map[string]any{
				"config_tree_path": strings.Join(trail, "."),
				"capability":       capability.Kind,
				"tool_name":        firstNonEmptyString(name, capability.Name),
				"raw_secret_data":  false,
			},
		})
	}
}

func agentStringValues(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) != "" {
			return []string{typed}
		}
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if str, ok := item.(string); ok && strings.TrimSpace(str) != "" {
				values = append(values, str)
			}
		}
		return values
	}
	return nil
}

// agentLineResolver maps a structured finding back to a best-effort source line
// in the raw config. Repeated lookups of the same token advance a per-token
// cursor so distinct occurrences (for example identical commands in two servers)
// resolve to distinct lines instead of all collapsing onto line 1.
type agentLineResolver struct {
	lower  []string
	cursor map[string]int
}

func newAgentLineResolver(lines []string) *agentLineResolver {
	lower := make([]string, len(lines))
	for index, line := range lines {
		lower[index] = strings.ToLower(line)
	}
	return &agentLineResolver{lower: lower, cursor: map[string]int{}}
}

func (r *agentLineResolver) lineFor(needle string) int {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return -1
	}
	for index := r.cursor[needle]; index < len(r.lower); index++ {
		if strings.Contains(r.lower[index], needle) {
			r.cursor[needle] = index + 1
			return index + 1
		}
	}
	for index := 0; index < len(r.lower); index++ {
		if strings.Contains(r.lower[index], needle) {
			return index + 1
		}
	}
	return -1
}

func (r *agentLineResolver) lineForContext(needle string, fallback string) int {
	if line := r.lineFor(needle); line != -1 {
		return line
	}
	if fallback == "" {
		return 1
	}
	if line := r.lineFor(fallback); line != -1 {
		return line
	}
	return 1
}

func appendAIAgentFinding(
	findings *[]domain.Finding,
	seen map[string]struct{},
	repo string,
	revision string,
	path string,
	line int,
	ruleID string,
	severity domain.FindingSeverity,
	title string,
	summary string,
	remediation string,
	snippet string,
	detectedAt time.Time,
	extraEvidence map[string]any,
) {
	if line < 1 {
		line = 1
	}
	evidence := map[string]any{
		"ai_agent_surface":      true,
		"agent_config_path":     path,
		"detector_version":      aiAgentAnalyzerVersion,
		"detector_category":     "ai_agent_config",
		"line_snippet":          snippet,
		"line_snippet_redacted": false,
	}
	for key, value := range extraEvidence {
		evidence[key] = value
	}
	appendMisconfigFinding(findings, seen, repo, revision, path, line, ruleID, severity, title, summary, remediation, snippet, detectedAt, evidence)
}

func sensitiveEnvReferences(line string) []string {
	tokens := envTokenPattern.FindAllString(line, -1)
	return filterSensitiveEnvNames(tokens)
}

func sensitiveEnvValues(value any) []string {
	var tokens []string
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			tokens = append(tokens, strings.ToUpper(strings.TrimSpace(key)))
			tokens = append(tokens, sensitiveEnvValues(child)...)
		}
	case []any:
		for _, child := range typed {
			tokens = append(tokens, sensitiveEnvValues(child)...)
		}
	case string:
		tokens = append(tokens, sensitiveEnvReferences(typed)...)
	}
	return filterSensitiveEnvNames(tokens)
}

func filterSensitiveEnvNames(tokens []string) []string {
	seen := map[string]struct{}{}
	values := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(strings.ToUpper(token))
		if !isSensitiveEnvName(token) {
			continue
		}
		if _, exists := seen[token]; exists {
			continue
		}
		seen[token] = struct{}{}
		values = append(values, token)
	}
	sort.Strings(values)
	return values
}

func isSensitiveEnvName(name string) bool {
	if name == "" {
		return false
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	switch name {
	case "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "NPM_TOKEN", "NODE_AUTH_TOKEN",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
		"DATABASE_URL", "DB_URL", "PRIVATE_KEY", "WEBHOOK_SECRET", "SLACK_BOT_TOKEN", "VERCEL_TOKEN", "CLOUDFLARE_API_TOKEN":
		return true
	}
	if !strings.Contains(name, "_") {
		return false
	}
	lower := strings.ToLower(name)
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "private_key") ||
		strings.Contains(lower, "access_key") ||
		strings.Contains(lower, "credential")
}

func dangerousAgentCapabilities(line string) []aiAgentCapability {
	lower := strings.ToLower(line)
	capabilities := []aiAgentCapability{}
	for _, item := range []aiAgentCapability{
		{Name: "shell", Kind: "shell_execution", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke a shell or arbitrary command runner from repository-defined configuration."},
		{Name: "bash", Kind: "shell_execution", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke a shell or arbitrary command runner from repository-defined configuration."},
		{Name: "sh", Kind: "shell_execution", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke a shell or arbitrary command runner from repository-defined configuration."},
		{Name: "powershell", Kind: "shell_execution", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke a shell or arbitrary command runner from repository-defined configuration."},
		{Name: "cmd.exe", Kind: "shell_execution", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke a shell or arbitrary command runner from repository-defined configuration."},
		{Name: "aws", Kind: "cloud_cli", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke cloud or deployment CLIs that may mutate infrastructure or consume machine credentials."},
		{Name: "gcloud", Kind: "cloud_cli", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke cloud or deployment CLIs that may mutate infrastructure or consume machine credentials."},
		{Name: "az", Kind: "cloud_cli", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke cloud or deployment CLIs that may mutate infrastructure or consume machine credentials."},
		{Name: "kubectl", Kind: "cluster_cli", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke cluster administration commands from repository-defined configuration."},
		{Name: "vercel", Kind: "deployment_cli", Severity: domain.SeverityHigh, Summary: "An MCP or AI-agent tool can invoke deployment commands from repository-defined configuration."},
		{Name: "curl", Kind: "network_fetch", Severity: domain.SeverityMedium, Summary: "An MCP or AI-agent tool can fetch network resources, which increases exfiltration or tool-supply-chain risk when secrets are also reachable."},
		{Name: "wget", Kind: "network_fetch", Severity: domain.SeverityMedium, Summary: "An MCP or AI-agent tool can fetch network resources, which increases exfiltration or tool-supply-chain risk when secrets are also reachable."},
		{Name: "playwright", Kind: "browser_automation", Severity: domain.SeverityMedium, Summary: "An MCP or AI-agent tool can automate browsers from repository-defined configuration, which can reach authenticated sessions or internal services."},
		{Name: "filesystem", Kind: "filesystem_access", Severity: domain.SeverityMedium, Summary: "An MCP or AI-agent tool exposes broad filesystem access from repository-defined configuration."},
	} {
		if agentLineMentionsCommand(lower, item.Name) {
			capabilities = append(capabilities, item)
		}
	}
	return capabilities
}

func agentLineMentionsCommand(line string, command string) bool {
	if command == "" {
		return false
	}
	lowerCommand := regexp.QuoteMeta(strings.ToLower(command))
	pattern := regexp.MustCompile(`(?:^|[^a-z0-9_.-])` + lowerCommand + `(?:$|[^a-z0-9_.-])`)
	return pattern.MatchString(line)
}

func sanitizeAgentSnippet(line string) string {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) > 220 {
		trimmed = trimmed[:220] + "..."
	}
	return trimmed
}

func isEnvContainerKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "env", "environment", "envs", "secrets":
		return true
	default:
		return false
	}
}

func firstAIAgentName(values map[string]any, trail []string) string {
	for _, key := range []string{"name", "id", "server", "tool"} {
		if value, ok := values[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if len(trail) > 0 {
		return trail[len(trail)-1]
	}
	return ""
}

func normalizeYAMLValue(value any) any {
	switch typed := value.(type) {
	case map[any]any:
		normalized := map[string]any{}
		for key, child := range typed {
			normalized[strings.TrimSpace(toString(key))] = normalizeYAMLValue(child)
		}
		return normalized
	case map[string]any:
		normalized := map[string]any{}
		for key, child := range typed {
			normalized[key] = normalizeYAMLValue(child)
		}
		return normalized
	case []any:
		normalized := make([]any, 0, len(typed))
		for _, child := range typed {
			normalized = append(normalized, normalizeYAMLValue(child))
		}
		return normalized
	default:
		return value
	}
}

func toString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func isAIAgentConfigPath(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	switch {
	case lower == ".mcp.json",
		lower == "mcp.json",
		lower == ".cursor/mcp.json",
		strings.HasPrefix(lower, ".cursor/rules/"),
		strings.HasPrefix(lower, ".continue/"),
		strings.HasPrefix(lower, ".codex/"),
		strings.HasPrefix(lower, ".claude/"),
		lower == ".github/copilot-instructions.md":
		return true
	case isKnownAIAgentStructuredConfig(lower):
		return true
	default:
		return false
	}
}

func isStructuredAgentConfig(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	return strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

func isKnownAIAgentStructuredConfig(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	if isAIAgentGitHubWorkflowPath(lower) {
		return false
	}
	base := strings.ToLower(filepathBase(path))
	return aiKnownAIAgentConfigNamePattern.MatchString(base)
}

func isAIAgentGitHubWorkflowPath(path string) bool {
	return strings.HasPrefix(path, ".github/workflows/") || strings.Contains(path, "/.github/workflows/")
}

func isCommittedLocalAIAgentConfig(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	return lower == ".mcp.json" ||
		lower == ".cursor/mcp.json" ||
		strings.HasPrefix(lower, ".continue/") ||
		strings.HasPrefix(lower, ".codex/") ||
		strings.HasPrefix(lower, ".claude/")
}

func filepathBase(path string) string {
	path = strings.TrimRight(path, "/")
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func anyString(value any) string {
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed)
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
