package repoexposure

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestDetectAIAgentConfigFindingsDetectsSecretsEnvAndDangerousTools(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}",
        "OPENAI_API_KEY": "sk-proj-` + strings.Repeat("a", 40) + `"
      }
    },
    "deploy": {
      "command": "bash",
      "args": ["-lc", "aws s3 ls && vercel deploy"]
    }
  }
}`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC))

	seen := map[string]domain.Finding{}
	for _, finding := range findings {
		seen[finding.Detector] = finding
	}
	if secret := seen["openai_api_key"]; secret.ID == "" || secret.Type != domain.FindingSecretExposure {
		t.Fatalf("expected redacted OpenAI secret finding, got %+v", findings)
	} else if strings.Contains(secret.LineSnippet, "sk-proj-") || secret.LineSnippetRedacted == nil || !*secret.LineSnippetRedacted {
		t.Fatalf("expected secret line to be redacted, got %+v", secret)
	} else if rawStored, _ := secret.Evidence["raw_secret_stored"].(bool); rawStored {
		t.Fatalf("raw secret data must not be stored: %+v", secret.Evidence)
	} else if aiSurface, _ := secret.Evidence["ai_agent_surface"].(bool); !aiSurface {
		t.Fatalf("expected AI-agent secret evidence marker, got %+v", secret.Evidence)
	}

	if env := seen["ai_agent_sensitive_env_reference"]; env.ID == "" || env.Type != domain.FindingRepoMisconfig {
		t.Fatalf("expected sensitive environment reference finding, got %+v", findings)
	} else if vars, _ := env.Evidence["env_variables"].([]string); len(vars) == 0 || vars[0] != "GITHUB_TOKEN" {
		t.Fatalf("expected env variable evidence, got %+v", env.Evidence)
	}

	if capability := seen["ai_agent_dangerous_tool_capability"]; capability.ID == "" || capability.Severity != domain.SeverityHigh {
		t.Fatalf("expected high-severity dangerous capability finding, got %+v", findings)
	}

	if local := seen["ai_agent_committed_local_config"]; local.ID == "" {
		t.Fatalf("expected committed local agent config finding, got %+v", findings)
	}
}

func TestDetectAIAgentConfigFindingsIgnoresBenignAgentTemplate(t *testing.T) {
	content := []byte(`name: local-helper
command: node
env:
  PATH: /usr/local/bin
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", "agent-template.yaml", content, time.Time{})
	if len(findings) != 0 {
		t.Fatalf("expected benign agent template to produce zero findings, got %+v", findings)
	}
}

func TestDetectMisconfigFindingsSkipsGenericRulesForAIAgentConfigSurfaces(t *testing.T) {
	findings := detectMisconfigFindings(
		"octo-org/octo-repo",
		"HEAD",
		".github/copilot-instructions.md",
		[]byte("permissions: write-all"),
		time.Time{},
	)

	if len(findings) != 0 {
		for _, finding := range findings {
			if finding.Detector == "workflow_write_all_permissions" {
				t.Fatalf("expected AI-agent-only surface to skip workflow-level generic misconfiguration rule, got %+v", finding)
			}
		}
		t.Fatalf("expected no findings for plain Copilot instructions content, got %+v", findings)
	}
}

func TestDetectAIAgentConfigFindingsSkipsLineHeuristicForCopilotSurfaces(t *testing.T) {
	findings := detectMisconfigFindings(
		"octo-org/octo-repo",
		"HEAD",
		".github/copilot-instructions.md",
		[]byte("Here is a suggestion: run bash and kubectl for diagnostics when debugging."),
		time.Time{},
	)

	for _, finding := range findings {
		switch finding.Detector {
		case "ai_agent_dangerous_tool_capability", "ai_agent_sensitive_env_reference":
			t.Fatalf("expected non-structured AI-agent surfaces to skip line heuristics, got %+v", finding)
		}
	}
}

func TestDetectMisconfigFindingsSkipsParserFindingsForAIAgentConfigSurfaces(t *testing.T) {
	findings := detectMisconfigFindings(
		"octo-org/octo-repo",
		"HEAD",
		".continue/config.yaml",
		[]byte(`permissions:
  contents: write-all
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: shell
      securityContext:
        privileged: true
`),
		time.Time{},
	)

	for _, finding := range findings {
		switch finding.Detector {
		case "workflow_write_all_permissions", "workflow_pull_request_target", "k8s_privileged_true":
			t.Fatalf("expected AI-agent parser surface to skip YAML parser findings, got %+v", finding)
		}
	}
}

func TestAIAgentConfigPathSelection(t *testing.T) {
	for _, path := range []string{
		".mcp.json",
		".cursor/mcp.json",
		".continue/config.yaml",
		".github/copilot-instructions.md",
		"mcp.config.yaml",
		"mcp-server.yml",
	} {
		if !isAIAgentConfigPath(path) {
			t.Fatalf("expected %s to be detected as AI-agent config surface", path)
		}
	}

	if isAIAgentConfigPath("ops/deploy-agent.yaml") {
		t.Fatal("expected non-agent filenames containing 'agent' to be skipped")
	}
	if isAIAgentConfigPath(".github/workflows/mcp.yml") {
		t.Fatal("expected workflows path to be skipped from AI-agent scanning")
	}
	if isAIAgentConfigPath("docs/agent-notes.md") {
		t.Fatal("expected non-agent markdown notes to be skipped")
	}
}

func TestSensitiveEnvReferencesIgnoresFreeText(t *testing.T) {
	found := sensitiveEnvReferences("The token is revoked and the secret is updated.")
	if len(found) != 0 {
		t.Fatalf("expected free text not to be treated as env variable references, got %#v", found)
	}

	found = sensitiveEnvReferences("Use ${github_token} and ${openai_api_key} in local config")
	if len(found) != 2 || found[0] != "GITHUB_TOKEN" || found[1] != "OPENAI_API_KEY" {
		t.Fatalf("expected lowercase env placeholders to still be recognized, got %#v", found)
	}
}

func TestDetectAIAgentConfigFindingsHonorsSecretAllowlistPolicy(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "env": {
        "OPENAI_API_KEY": "sk-proj-` + strings.Repeat("a", 40) + `"
      }
    }
  }
}`)
	detectedAt := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

	baseline := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, detectedAt)
	var fingerprint string
	for _, finding := range baseline {
		if finding.Type == domain.FindingSecretExposure {
			fingerprint, _ = finding.Evidence["secret_fingerprint"].(string)
			break
		}
	}
	if fingerprint == "" {
		t.Fatalf("expected a secret fingerprint in baseline findings, got %+v", baseline)
	}

	allowlisted := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, detectedAt,
		withSecretFindingPolicy(secretFindingPolicy{AllowlistedFingerprints: map[string]struct{}{fingerprint: {}}}))

	var secret domain.Finding
	for _, finding := range allowlisted {
		if finding.Type == domain.FindingSecretExposure {
			secret = finding
			break
		}
	}
	if secret.ID == "" {
		t.Fatalf("expected a secret finding when allowlist policy is applied, got %+v", allowlisted)
	}
	if got := secret.Evidence["confidence_state"]; got != secretClassificationAllowlisted {
		t.Fatalf("expected allowlisted classification on AI-agent secret path, got %v in %+v", got, secret.Evidence)
	}
	if got, _ := secret.Evidence["secret_allowlisted"].(bool); !got {
		t.Fatalf("expected allowlisted evidence flag on AI-agent secret path, got %+v", secret.Evidence)
	}
}

func TestAppendAIAgentFindingPreservesMultipleCommandFindingsFromConfigTree(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "shellServer": {
      "command": "bash"
    },
    "networkServer": {
      "command": "curl"
    }
  }
}`)
	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, time.Time{})
	seen := map[string]int{}
	for _, finding := range findings {
		seen[finding.Detector]++
	}

	if seen["ai_agent_dangerous_tool_capability"] < 2 {
		t.Fatalf("expected at least two AI dangerous capability findings, got %+v", seen)
	}
	if seen["ai_agent_committed_local_config"] != 1 {
		t.Fatalf("expected local-config finding once, got %+v", seen)
	}
}

func TestStructuredAIAgentFindingsUseSourceLineNumbers(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "shellServer": {
      "command": "bash"
    },
    "cloudServer": {
      "args": ["-lc", "aws s3 ls && vercel deploy"]
    },
    "browserServer": {
      "env": {
        "OPENAI_API_KEY": "${OPENAI_API_KEY}",
        "AZURE_CLIENT_SECRET": "${AZURE_CLIENT_SECRET}"
      }
    }
  }
}`)
	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, time.Time{})

	commandLines := map[string]int{}
	envLines := 0
	for _, finding := range findings {
		if finding.Detector == "ai_agent_dangerous_tool_capability" {
			tool, _ := finding.Evidence["tool_name"].(string)
			commandLines[tool] = finding.LineNumber
			if finding.LineNumber == 1 {
				t.Fatalf("expected structured command finding to avoid defaulting to line 1, got %+v", finding)
			}
		}
		if finding.Detector == "ai_agent_sensitive_env_reference" {
			envLines = finding.LineNumber
			if finding.LineNumber == 1 {
				t.Fatalf("expected structured env finding to avoid defaulting to line 1, got %+v", finding)
			}
		}
	}
	if len(commandLines) < 2 {
		t.Fatalf("expected multiple structured capability findings from one config file, got %+v", findings)
	}
	if envLines == 0 {
		t.Fatalf("expected structured env reference finding, got %+v", findings)
	}
}

func TestStructuredAIAgentFindingsUseDeterministicTraversalAndLineMapping(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "shellServer": {
      "command": "bash",
      "env": {
        "CACHE": "true"
      }
    },
    "deployServer": {
      "command": "vercel",
      "args": ["--token", "deploy"]
    },
    "networkServer": {
      "command": "curl",
      "args": ["https://example.com"]
    },
    "cloudServer": {
      "command": "aws",
      "args": ["s3", "ls"]
    }
  }
}`)
	pass1 := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, time.Time{})
	pass2 := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, time.Time{})

	sig1 := structuredCapabilitySignatures(pass1)
	sig2 := structuredCapabilitySignatures(pass2)
	sort.Strings(sig1)
	sort.Strings(sig2)
	if len(sig1) != len(sig2) {
		t.Fatalf("expected deterministic signatures, got %d vs %d. pass1=%v pass2=%v", len(sig1), len(sig2), sig1, sig2)
	}
	for i := range sig1 {
		if sig1[i] != sig2[i] {
			t.Fatalf("expected deterministic ordering and line mapping, got %v vs %v", sig1, sig2)
		}
	}
}

func TestStructuredAIAgentLineHeuristicStillCatchesEnvRefsInArgs(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "shellServer": {
      "command": "bash",
      "args": [
        "-lc",
        "echo ${OPENAI_API_KEY} && echo ${GH_TOKEN}"
      ]
    }
  }
}`)
	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".cursor/mcp.json", content, time.Time{})

	found := false
	foundVars := map[string]struct{}{}
	for _, finding := range findings {
		if finding.Detector == "ai_agent_sensitive_env_reference" {
			found = true
			vars, _ := finding.Evidence["env_variables"].([]string)
			if len(vars) < 2 {
				t.Fatalf("expected both env placeholders to be included, got %+v", finding)
			}
			for _, v := range vars {
				foundVars[v] = struct{}{}
			}
		}
	}
	if !found {
		t.Fatalf("expected env reference finding for args placeholders, got %+v", findings)
	}
	for _, expected := range []string{"OPENAI_API_KEY", "GH_TOKEN"} {
		if _, ok := foundVars[expected]; !ok {
			t.Fatalf("expected env placeholder %q to be detected in args, got %+v", expected, findings)
		}
	}
}

func structuredCapabilitySignatures(findings []domain.Finding) []string {
	signatures := make([]string, 0)
	for _, finding := range findings {
		if finding.Detector != "ai_agent_dangerous_tool_capability" {
			continue
		}
		tool, _ := finding.Evidence["tool_name"].(string)
		capability, _ := finding.Evidence["capability"].(string)
		signatures = append(signatures, fmt.Sprintf("%s|%s|%d|%s", capability, tool, finding.LineNumber, finding.LineSnippet))
	}
	return signatures
}
