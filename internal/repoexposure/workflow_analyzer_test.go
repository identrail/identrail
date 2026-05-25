package repoexposure

import (
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestGitHubWorkflowAnalyzerDetectsContextualAttackPaths(t *testing.T) {
	content := []byte(`name: dangerous-pr-target
on:
  pull_request_target:
    branches: [main]
jobs:
  publish:
    permissions:
      contents: write
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: evilcorp/build-action@v1
      - run: echo "${{ github.event.pull_request.title }}"
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
      - uses: actions/cache@v4
        with:
          path: node_modules
          key: deps-${{ github.head_ref }}-${{ hashFiles('package-lock.json') }}
          restore-keys: deps-${{ github.head_ref }}-
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: dist/
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/pr-target.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_pull_request_target",
		"workflow_broad_token_permissions",
		"workflow_pull_request_target_privileged_context",
		"workflow_pull_request_target_untrusted_checkout",
		"workflow_unpinned_third_party_action",
		"workflow_shell_injection_user_context",
		"workflow_oidc_broad_trust",
		"workflow_cache_poisoning",
		"workflow_artifact_poisoning",
	})

	checkout := firstDetectorFinding(t, findings, "workflow_pull_request_target_untrusted_checkout")
	if checkout.Severity != domain.SeverityCritical {
		t.Fatalf("expected untrusted checkout to be critical, got %+v", checkout)
	}
	if got := checkout.Evidence["workflow_job"]; got != "publish" {
		t.Fatalf("expected workflow job evidence, got %+v", checkout.Evidence)
	}
	if events, _ := checkout.Evidence["workflow_events"].([]string); len(events) != 1 || events[0] != "pull_request_target" {
		t.Fatalf("expected event evidence, got %+v", checkout.Evidence)
	}

	injection := firstDetectorFinding(t, findings, "workflow_shell_injection_user_context")
	if tokens, _ := injection.Evidence["untrusted_context"].([]string); len(tokens) == 0 || tokens[0] != "github.event.pull_request.title" {
		t.Fatalf("expected untrusted context evidence, got %+v", injection.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerDetectsWorkflowRunPrivilegeChain(t *testing.T) {
	content := []byte(`name: release-after-build
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]
jobs:
  release:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - run: gh release upload "$TAG" dist/app.tar.gz
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/release.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_broad_token_permissions",
		"workflow_run_privilege_chain",
		"workflow_artifact_poisoning",
	})
}

func TestGitHubWorkflowAnalyzerDetectsPullRequestTargetSecretInheritance(t *testing.T) {
	content := []byte(`name: inherited-secret-pr-target
on: pull_request_target
permissions:
  contents: read
jobs:
  reusable:
    uses: octo-org/reusable/.github/workflows/build.yml@main
    secrets: inherit
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/reusable.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_pull_request_target",
		"workflow_pull_request_target_privileged_context",
		"workflow_unpinned_third_party_action",
	})
}

func TestGitHubWorkflowAnalyzerDetectsReusableWorkflowAttackSurface(t *testing.T) {
	content := []byte(`name: release-reusable
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]
jobs:
  release:
    permissions:
      contents: write
    uses: evilcorp/reusable/.github/workflows/release.yml@main
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/release-reusable.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_broad_token_permissions",
		"workflow_run_privilege_chain",
		"workflow_unpinned_third_party_action",
	})

	reusable := firstDetectorFinding(t, findings, "workflow_unpinned_third_party_action")
	if got, _ := reusable.Evidence["reusable_workflow_call"].(bool); !got {
		t.Fatalf("expected reusable workflow evidence, got %+v", reusable.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotFlagSameRepoReusableWorkflowAsThirdParty(t *testing.T) {
	content := []byte(`name: same-repo-reusable
on: pull_request
permissions:
  contents: read
jobs:
  build:
    uses: octo-org/octo-repo/.github/workflows/build.yml@main
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/same-repo-reusable.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_unpinned_third_party_action") {
		t.Fatalf("expected same-repo reusable workflow not to be third-party, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerDetectsCompactSecretExpression(t *testing.T) {
	content := []byte(`name: compact-secret-pr-target
on: pull_request_target
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/publish.sh
        env:
          TOKEN: ${{secrets.RELEASE_TOKEN}}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/compact-secret.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_pull_request_target",
		"workflow_pull_request_target_privileged_context",
	})
}

func TestGitHubWorkflowAnalyzerDetectsBracketSecretExpression(t *testing.T) {
	content := []byte(`name: bracket-secret-pr-target
on: pull_request_target
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/publish.sh
        env:
          TOKEN: ${{ secrets['release-token'] }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/bracket-secret.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_pull_request_target",
		"workflow_pull_request_target_privileged_context",
	})
}

func TestGitHubWorkflowAnalyzerKeepsHardenedPullRequestTargetShallow(t *testing.T) {
	content := []byte(`name: safe-labeler
on:
  pull_request_target:
    types: [opened, synchronize]
permissions:
  contents: read
  pull-requests: read
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/github-script@v7
        with:
          script: core.info("metadata only")
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/labeler.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	if !containsDetector(findings, "workflow_pull_request_target") {
		t.Fatalf("expected compatibility pull_request_target finding, got %+v", findings)
	}
	for _, detector := range []string{
		"workflow_broad_token_permissions",
		"workflow_pull_request_target_privileged_context",
		"workflow_pull_request_target_untrusted_checkout",
		"workflow_unpinned_third_party_action",
		"workflow_shell_injection_user_context",
		"workflow_oidc_broad_trust",
		"workflow_cache_poisoning",
		"workflow_artifact_poisoning",
	} {
		if containsDetector(findings, detector) {
			t.Fatalf("expected hardened workflow not to emit %s, got %+v", detector, findings)
		}
	}
}

func TestGitHubWorkflowAnalyzerHonorsEmptyJobPermissionsOverride(t *testing.T) {
	content := []byte(`name: empty-job-permissions
on: pull_request_target
permissions: write-all
jobs:
  analyze:
    permissions: {}
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@f00dbabe1234567890abcdef1234567890abcdef
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/empty-job-permissions.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	if !containsDetector(findings, "workflow_broad_token_permissions") {
		t.Fatalf("expected workflow-level broad token compatibility finding, got %+v", findings)
	}
	for _, detector := range []string{
		"workflow_pull_request_target_privileged_context",
		"workflow_oidc_broad_trust",
	} {
		if containsDetector(findings, detector) {
			t.Fatalf("expected empty job permissions override not to emit %s, got %+v", detector, findings)
		}
	}
}

func TestGitHubWorkflowAnalyzerDetectsAIPromptInjectionWithWriteToken(t *testing.T) {
	content := []byte(`name: ai-review
on: pull_request
permissions:
  contents: write
  pull-requests: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-review.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_broad_token_permissions",
		"workflow_ai_agent_prompt_injection",
	})

	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if prompt.Severity != domain.SeverityHigh {
		t.Fatalf("expected high severity for write-capable agent prompt path, got %+v", prompt)
	}
	if tokens, _ := prompt.Evidence["untrusted_prompt_context"].([]string); len(tokens) == 0 || tokens[0] != "github.event.pull_request.body" {
		t.Fatalf("expected PR body prompt evidence, got %+v", prompt.Evidence)
	}
	if capabilities, _ := prompt.Evidence["privileged_capabilities"].([]string); len(capabilities) == 0 || capabilities[0] != "github_token_write" {
		t.Fatalf("expected write-token capability evidence, got %+v", prompt.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerDetectsAIPromptInjectionThroughIssueAndReviewText(t *testing.T) {
	cases := []struct {
		name  string
		event string
		token string
	}{
		{name: "issue", event: "issues", token: "github.event.issue.body"},
		{name: "comment", event: "issue_comment", token: "github.event.comment.body"},
		{name: "review", event: "pull_request_review", token: "github.event.review.body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(`name: ai-triage
on: ` + tc.event + `
permissions:
  issues: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/triage-action@v1
        with:
          prompt: ${{ ` + tc.token + ` }}
`)
			findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-"+tc.name+".yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
			assertWorkflowDetectors(t, findings, []string{"workflow_ai_agent_prompt_injection"})
			prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
			if tokens, _ := prompt.Evidence["untrusted_prompt_context"].([]string); len(tokens) == 0 || tokens[0] != tc.token {
				t.Fatalf("expected %s prompt evidence, got %+v", tc.token, prompt.Evidence)
			}
		})
	}
}

func TestGitHubWorkflowAnalyzerDetectsRepositoryPromptFileForAIAgent(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: prompts/autofix.md
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{"workflow_ai_agent_prompt_injection"})
	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if tokens, _ := prompt.Evidence["untrusted_prompt_context"].([]string); len(tokens) == 0 || tokens[0] != "repository_prompt_file" {
		t.Fatalf("expected repository prompt file evidence, got %+v", prompt.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotFlagRepositoryPromptFileBeforeCheckoutOnPullRequest(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: prompts/autofix.md
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_ai_agent_prompt_injection") {
		t.Fatalf("expected pull_request prompt file without checkout not to be treated as attacker-controlled, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerResolvesEnvRoutedRepositoryPromptFile(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request
permissions:
  contents: write
env:
  PROMPT_FILE: prompts/autofix.md
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: ${{ env.PROMPT_FILE }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{"workflow_ai_agent_prompt_injection"})
	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if tokens, _ := prompt.Evidence["untrusted_prompt_context"].([]string); len(tokens) == 0 || tokens[0] != "repository_prompt_file" {
		t.Fatalf("expected env-routed repository prompt file evidence, got %+v", prompt.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerClassifiesUnprivilegedAIPromptPathAsMedium(t *testing.T) {
	content := []byte(`name: ai-summary
on: pull_request
permissions:
  contents: read
jobs:
  summarize:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/summary-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-summary.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if prompt.Severity != domain.SeverityMedium {
		t.Fatalf("expected medium severity without privileged capabilities, got %+v", prompt)
	}
	if capabilities, _ := prompt.Evidence["privileged_capabilities"].([]string); len(capabilities) != 0 {
		t.Fatalf("expected no privileged capability evidence, got %+v", prompt.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotFlagTrustedLeastPrivilegeAIJob(t *testing.T) {
	content := []byte(`name: trusted-ai
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  docs:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/docs-action@f00dbabe1234567890abcdef1234567890abcdef
        with:
          prompt: Summarize the latest generated docs.
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/trusted-ai.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_ai_agent_prompt_injection") {
		t.Fatalf("expected trusted least-privilege AI job not to emit prompt injection finding, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerResolvesEnvRoutedUntrustedPromptInput(t *testing.T) {
	cases := []struct {
		name      string
		reference string
	}{
		{name: "dot", reference: "${{ env.PROMPT }}"},
		{name: "bracket-single", reference: "${{ env['PROMPT'] }}"},
		{name: "bracket-double", reference: `${{ env["PROMPT"] }}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(`name: ai-review
on: pull_request
permissions:
  contents: write
jobs:
  review:
    runs-on: ubuntu-latest
    env:
      PROMPT: ${{ github.event.pull_request.body }}
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: ` + tc.reference + `
`)

			findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-review.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
			if !containsDetector(findings, "workflow_ai_agent_prompt_injection") {
				t.Fatalf("expected env-routed untrusted prompt to be detected, got %+v", findings)
			}
			prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
			if tokens, _ := prompt.Evidence["untrusted_prompt_context"].([]string); len(tokens) == 0 || tokens[0] != "github.event.pull_request.body" {
				t.Fatalf("expected PR body prompt evidence resolved through inherited env, got %+v", prompt.Evidence)
			}
		})
	}
}

func TestGitHubWorkflowAnalyzerDoesNotFlagRepositoryPromptFileOnIssueOnlyTrigger(t *testing.T) {
	content := []byte(`name: ai-triage
on: issue_comment
permissions:
  contents: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: prompts/triage.md
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-triage.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_ai_agent_prompt_injection") {
		t.Fatalf("expected repository prompt file on issue-only trigger not to be treated as attacker-controlled, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotFlagRepositoryPromptFileOnTrustedPullRequestTarget(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request_target
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: prompts/autofix.md
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_ai_agent_prompt_injection") {
		t.Fatalf("expected trusted base-ref pull_request_target prompt file not to be treated as attacker-controlled, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotTaintEarlierPromptFileFromLaterUntrustedCheckoutPullRequestTarget(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request_target
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: prompts/autofix.md
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_ai_agent_prompt_injection") {
		t.Fatalf("expected later untrusted checkout not to taint earlier AI prompt file step, got %+v", findings)
	}
	if !containsDetector(findings, "workflow_pull_request_target_untrusted_checkout") {
		t.Fatalf("expected later untrusted checkout to still be reported, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotEscalatePullRequestOnlyPromptFilePathToTargetCritical(t *testing.T) {
	content := []byte(`name: ai-autofix
on:
  pull_request:
  pull_request_target:
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: prompts/autofix.md
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if prompt.Severity != domain.SeverityHigh {
		t.Fatalf("expected pull_request-only repository prompt file path to stay high severity, got %+v", prompt)
	}
}

func TestGitHubWorkflowAnalyzerEscalatesPullRequestTargetPromptBodyPathToCritical(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request_target
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if prompt.Severity != domain.SeverityCritical {
		t.Fatalf("expected pull_request_target prompt body path to stay critical severity, got %+v", prompt)
	}
}

func TestGitHubWorkflowAnalyzerTreatsImplicitTargetTokenAsPrivilegedForAIPromptPath(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request_target
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: ${{ github.event.pull_request.body }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if prompt.Severity != domain.SeverityCritical {
		t.Fatalf("expected implicit pull_request_target token write path to be critical severity, got %+v", prompt)
	}
	if capabilities, _ := prompt.Evidence["privileged_capabilities"].([]string); len(capabilities) == 0 || capabilities[0] != "github_token_write_default" {
		t.Fatalf("expected implicit token write capability evidence, got %+v", prompt.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerFlagsRepositoryPromptFileOnUntrustedCheckoutPullRequestTarget(t *testing.T) {
	content := []byte(`name: ai-autofix
on: pull_request_target
permissions:
  contents: write
jobs:
  autofix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: anthropics/claude-code-action@v1
        with:
          prompt_file: prompts/autofix.md
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/ai-autofix.yml", content, time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC))
	prompt := firstDetectorFinding(t, findings, "workflow_ai_agent_prompt_injection")
	if tokens, _ := prompt.Evidence["untrusted_prompt_context"].([]string); len(tokens) == 0 || tokens[0] != "repository_prompt_file" {
		t.Fatalf("expected repository prompt file evidence when PR head is checked out, got %+v", prompt.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotTreatHeadSHAAsShellInjection(t *testing.T) {
	content := []byte(`name: pr-info
on: pull_request
permissions:
  contents: read
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.head.sha }}"
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/pr-info.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_shell_injection_user_context") {
		t.Fatalf("expected PR head SHA not to be treated as shell injection evidence, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerDoesNotFlagTrustedEventShellContext(t *testing.T) {
	content := []byte(`name: trusted-push
on: push
permissions:
  contents: read
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/push.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_shell_injection_user_context") {
		t.Fatalf("expected trusted push event not to emit shell injection finding, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerDetectsCacheSavePoisoning(t *testing.T) {
	content := []byte(`name: save-cache
on: pull_request
permissions:
  contents: read
jobs:
  deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/save@v4
        with:
          path: node_modules
          key: deps-${{ github.head_ref }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/save-cache.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_cache_poisoning",
	})
}

func TestGitHubWorkflowAnalyzerTreatsIssuesEventBodyAsUntrusted(t *testing.T) {
	content := []byte(`name: issue-triage
on: issues
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.body }}"
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/issues.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_shell_injection_user_context",
	})

	injection := firstDetectorFinding(t, findings, "workflow_shell_injection_user_context")
	if tokens, _ := injection.Evidence["untrusted_context"].([]string); len(tokens) == 0 || tokens[0] != "github.event.issue.body" {
		t.Fatalf("expected issue body evidence, got %+v", injection.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerTreatsPullRequestReviewBodyAsUntrusted(t *testing.T) {
	content := []byte(`name: review-triage
on: pull_request_review
permissions:
  contents: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.review.body }}"
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/review.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_shell_injection_user_context",
	})

	injection := firstDetectorFinding(t, findings, "workflow_shell_injection_user_context")
	if tokens, _ := injection.Evidence["untrusted_context"].([]string); len(tokens) == 0 || tokens[0] != "github.event.review.body" {
		t.Fatalf("expected review body evidence, got %+v", injection.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerTreatsPullRequestReviewOIDCAsBroadTrust(t *testing.T) {
	content := []byte(`name: review-deploy
on: pull_request_review
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@f00dbabe1234567890abcdef1234567890abcdef
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/review-deploy.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_oidc_broad_trust",
	})
}

func TestGitHubWorkflowAnalyzerDoesNotFlagBranchScopedOIDCDeploy(t *testing.T) {
	content := []byte(`name: deploy
on:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@f00dbabe1234567890abcdef1234567890abcdef
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/deploy.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_oidc_broad_trust") {
		t.Fatalf("expected branch-scoped deploy OIDC not to be flagged as broad trust, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerFlagsBroadTagOIDCDeployWithNarrowBranches(t *testing.T) {
	content := []byte(`name: mixed-deploy
on:
  push:
    branches: [main]
    tags: ['*']
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@f00dbabe1234567890abcdef1234567890abcdef
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/mixed-deploy.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_oidc_broad_trust",
	})
}

func TestGitHubWorkflowAnalyzerFlagsBroadPushOIDCDeploy(t *testing.T) {
	content := []byte(`name: broad-deploy
on: push
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/broad-deploy.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_unpinned_third_party_action",
		"workflow_oidc_broad_trust",
	})
}

func TestGitHubWorkflowAnalyzerTreatsWriteAllAsOIDCWrite(t *testing.T) {
	content := []byte(`name: write-all-oidc
on: pull_request
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/write-all-oidc.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_broad_token_permissions",
		"workflow_oidc_broad_trust",
	})
}

func TestGitHubWorkflowAnalyzerFlagsPrivilegedSelfHostedRunner(t *testing.T) {
	content := []byte(`name: pr-target-self-hosted
on: pull_request_target
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: self-hosted
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@f00dbabe1234567890abcdef1234567890abcdef
      - run: ./deploy.sh
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/self-hosted.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_self_hosted_runner",
	})

	runner := firstDetectorFinding(t, findings, "workflow_self_hosted_runner")
	if runner.Severity != domain.SeverityCritical {
		t.Fatalf("expected privileged self-hosted runner to be critical, got %+v", runner)
	}
	if labels, _ := runner.Evidence["runner_labels"].([]string); len(labels) != 1 || labels[0] != "self-hosted" {
		t.Fatalf("expected self-hosted label evidence, got %+v", runner.Evidence)
	}
	if selfHosted, _ := runner.Evidence["self_hosted_runner"].(bool); !selfHosted {
		t.Fatalf("expected self_hosted_runner evidence true, got %+v", runner.Evidence)
	}
	if env, _ := runner.Evidence["deployment_environment"].(string); env != "production" {
		t.Fatalf("expected production environment evidence, got %+v", runner.Evidence)
	}
	for _, amplifier := range []string{"cloud_auth", "environment", "id_token", "secrets"} {
		if !workflowEvidenceHasString(runner.Evidence["risk_amplifiers"], amplifier) {
			t.Fatalf("expected risk amplifier %s, got %+v", amplifier, runner.Evidence["risk_amplifiers"])
		}
	}
	if capability, _ := runner.Evidence["runner_capability"].(string); capability != "untrusted_privileged" {
		t.Fatalf("expected untrusted_privileged capability, got %+v", runner.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerFlagsArraySelfHostedRunnerWithoutAmplifiers(t *testing.T) {
	content := []byte(`name: pr-self-hosted-array
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: [self-hosted, linux, x64, prod]
    steps:
      - run: make test
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/array.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	runner := firstDetectorFinding(t, findings, "workflow_self_hosted_runner")
	if runner.Severity != domain.SeverityHigh {
		t.Fatalf("expected unamplified self-hosted runner to be high, got %+v", runner)
	}
	if unresolved, _ := runner.Evidence["labels_unresolved"].(bool); unresolved {
		t.Fatalf("expected explicit self-hosted array labels to be resolved, got %+v", runner.Evidence)
	}
	labels, _ := runner.Evidence["runner_labels"].([]string)
	if len(labels) != 4 || labels[0] != "self-hosted" || labels[3] != "prod" {
		t.Fatalf("expected ordered array label evidence, got %+v", runner.Evidence)
	}
}

func TestGitHubWorkflowAnalyzerFlagsRunnerGroupAsSelfHosted(t *testing.T) {
	content := []byte(`name: group-runner
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on:
      group: gpu-runners
      labels: [self-hosted, gpu]
    steps:
      - run: make build
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/group.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	runner := firstDetectorFinding(t, findings, "workflow_self_hosted_runner")
	if runner.Severity != domain.SeverityCritical {
		t.Fatalf("expected write-token self-hosted runner to be critical, got %+v", runner)
	}
	if group, _ := runner.Evidence["runner_group"].(string); group != "gpu-runners" {
		t.Fatalf("expected runner group evidence, got %+v", runner.Evidence)
	}
	if !workflowEvidenceHasString(runner.Evidence["risk_amplifiers"], "write_token") {
		t.Fatalf("expected write_token amplifier, got %+v", runner.Evidence["risk_amplifiers"])
	}
}

func TestGitHubWorkflowAnalyzerTreatsRunnerGroupWithoutSelfHostedLabelAsUnresolved(t *testing.T) {
	content := []byte(`name: group-runner-unresolved
on:
  pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on:
      group: gpu-runners
      labels: [linux, x64]
    steps:
      - run: make build
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/group.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	if containsDetector(findings, "workflow_self_hosted_runner") {
		t.Fatalf("expected group runner without explicit self-hosted label to be unresolved, got %+v", findings)
	}
	unresolved := firstDetectorFinding(t, findings, "workflow_self_hosted_runner_unresolved")
	if unresolved.Severity != domain.SeverityMedium {
		t.Fatalf("expected unresolved group-runner finding to be medium, got %+v", unresolved)
	}
}

func TestGitHubWorkflowAnalyzerResolvesMatrixSelfHostedRunner(t *testing.T) {
	content := []byte(`name: matrix-self-hosted
on: pull_request
permissions:
  contents: read
jobs:
  test:
    strategy:
      matrix:
        runner: [ubuntu-latest, self-hosted]
    runs-on: ${{ matrix.runner }}
    steps:
      - run: make test
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/matrix-self-hosted.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_self_hosted_runner",
	})
	if containsDetector(findings, "workflow_self_hosted_runner_unresolved") {
		t.Fatalf("expected matrix self-hosted value to resolve to self-hosted, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerResolvesNestedMatrixSelfHostedRunner(t *testing.T) {
	content := []byte(`name: matrix-object-self-hosted
on: pull_request
permissions:
  contents: read
jobs:
  test:
    strategy:
      matrix:
        target:
          - runner: ubuntu-latest
          - runner: self-hosted
    runs-on: ${{ matrix.target.runner }}
    steps:
      - run: make test
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/matrix-object-self-hosted.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_self_hosted_runner",
	})
	if containsDetector(findings, "workflow_self_hosted_runner_unresolved") {
		t.Fatalf("expected nested matrix self-hosted value to resolve to self-hosted, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerRespectsReferencedMatrixKeyForSelfHostedResolution(t *testing.T) {
	content := []byte(`name: matrix-different-axis
on: pull_request
permissions:
  contents: read
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        runner: [self-hosted]
    runs-on: ${{ matrix.os }}
    steps:
      - run: make test
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/matrix-other-axis.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_self_hosted_runner_unresolved",
	})
	if containsDetector(findings, "workflow_self_hosted_runner") {
		t.Fatalf("expected referenced matrix key isolation to avoid false positive self-hosted, got %+v", findings)
	}
}

func TestGitHubWorkflowAnalyzerTreatsExpressionRunnerAsUnresolved(t *testing.T) {
	content := []byte(`name: matrix-runner
on: pull_request
permissions:
  contents: read
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - run: make test
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/matrix.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_self_hosted_runner_unresolved",
	})
	if containsDetector(findings, "workflow_self_hosted_runner") {
		t.Fatalf("expected unresolved matrix runner not to assert self-hosted, got %+v", findings)
	}
	unresolved := firstDetectorFinding(t, findings, "workflow_self_hosted_runner_unresolved")
	if unresolved.Severity != domain.SeverityMedium {
		t.Fatalf("expected unresolved runner finding to be medium, got %+v", unresolved)
	}
}

func TestGitHubWorkflowAnalyzerRecognizesAdditionalGitHubHostedRunnerLabels(t *testing.T) {
	content := []byte(`name: hosted-arm
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04-arm
    steps:
      - run: make test
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/hosted-arm.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	for _, detector := range []string{"workflow_self_hosted_runner", "workflow_self_hosted_runner_unresolved"} {
		if containsDetector(findings, detector) {
			t.Fatalf("expected additional hosted runner labels not to emit %s, got %+v", detector, findings)
		}
	}
}

func TestGitHubWorkflowAnalyzerTreatsBroadCustomLabelAsUnresolved(t *testing.T) {
	content := []byte(`name: custom-runner
on: issue_comment
permissions:
  contents: read
jobs:
  triage:
    runs-on: my-fleet
    steps:
      - run: make triage
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/custom.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	assertWorkflowDetectors(t, findings, []string{
		"workflow_self_hosted_runner_unresolved",
	})
}

func TestGitHubWorkflowAnalyzerDoesNotFlagTrustedSelfHostedRunner(t *testing.T) {
	content := []byte(`name: push-self-hosted
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: make build
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/push-self-hosted.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	for _, detector := range []string{"workflow_self_hosted_runner", "workflow_self_hosted_runner_unresolved"} {
		if containsDetector(findings, detector) {
			t.Fatalf("expected trusted-only self-hosted runner not to emit %s, got %+v", detector, findings)
		}
	}
}

func TestGitHubWorkflowAnalyzerDoesNotFlagGitHubHostedRunner(t *testing.T) {
	content := []byte(`name: pr-hosted
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: make test
`)

	findings := detectMisconfigFindings("octo-org/octo-repo", "HEAD", ".github/workflows/hosted.yml", content, time.Date(2026, 5, 20, 9, 0, 0, 0, time.UTC))
	for _, detector := range []string{"workflow_self_hosted_runner", "workflow_self_hosted_runner_unresolved"} {
		if containsDetector(findings, detector) {
			t.Fatalf("expected GitHub-hosted runner not to emit %s, got %+v", detector, findings)
		}
	}
}

func workflowEvidenceHasString(value any, want string) bool {
	values, ok := value.([]string)
	if !ok {
		return false
	}
	for _, candidate := range values {
		if candidate == want {
			return true
		}
	}
	return false
}

func assertWorkflowDetectors(t *testing.T, findings []domain.Finding, detectors []string) {
	t.Helper()
	for _, detector := range detectors {
		if !containsDetector(findings, detector) {
			t.Fatalf("expected detector %s, got %+v", detector, findings)
		}
	}
}

func firstDetectorFinding(t *testing.T, findings []domain.Finding, detector string) domain.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.Detector == detector {
			return finding
		}
	}
	t.Fatalf("expected detector %s, got %+v", detector, findings)
	return domain.Finding{}
}
