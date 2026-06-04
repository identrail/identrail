package api

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/db"
)

const (
	awsPlatformDependencyIndexVersion = "aws-platform-dependency-index-v1"
	awsPlatformDependencyParentIssue  = 1472
	awsPlatformDependencyCurrentIssue = 1474
	awsPlatformDependencyIssueCount   = 85

	awsPlatformDependencyStatusReady    = "ready"
	awsPlatformDependencyStatusDegraded = "degraded"
	awsPlatformDependencyStatusBlocked  = "blocked"

	awsPlatformIssueStateCompleted = "completed"
	awsPlatformIssueStateReady     = "ready"
	awsPlatformIssueStateBlocked   = "blocked"
)

var (
	awsPlatformWaveLinePattern    = regexp.MustCompile(`^### Wave ([0-9]+):\s*(.+)$`)
	awsPlatformIssueLinePattern   = regexp.MustCompile(`^- #([0-9]+) - (.+) \(blocked by: (.+)\)$`)
	awsPlatformBlockerRefsPattern = regexp.MustCompile(`^#[0-9]+(, #[0-9]+)*$`)
	awsPlatformCompletedIssueRefs = map[string]struct{}{
		"#1473": {},
		"#1474": {},
		"#1475": {},
		"#1476": {},
		"#1477": {},
	}
)

const awsPlatformDependencyLedger = `
### Wave 0: Clean baseline and epic setup
- #1473 - AWS platform baseline verification gate (blocked by: none)
- #1474 - AWS platform issue dependency index (blocked by: #1473)
- #1475 - AWS live app validation harness (blocked by: #1473)

### Wave 1: AWS inventory collectors
- #1476 - AWS service collector contract and fixture pattern (blocked by: #1473, #1475)
- #1477 - EC2 instance profile machine identity collector (blocked by: #1476)
- #1478 - ECS task and execution role collector (blocked by: #1476)
- #1479 - Lambda execution role collector (blocked by: #1476)
- #1480 - EKS IRSA and Pod Identity collector (blocked by: #1476)
- #1481 - CodeBuild service role collector (blocked by: #1476)
- #1482 - CodePipeline deployment role collector (blocked by: #1476)
- #1483 - Step Functions state machine identity collector (blocked by: #1476)
- #1484 - EventBridge, Scheduler, and Pipes identity collector (blocked by: #1476)
- #1485 - Managed compute service role collector (blocked by: #1476)
- #1486 - SageMaker workload identity collector (blocked by: #1476)
- #1487 - IAM PassRole static relationship mapper (blocked by: #1476)

### Wave 2: Resource and credential mapping
- #1488 - S3 resource and bucket-policy reachability collector (blocked by: #1476)
- #1489 - KMS key policy and decrypt reachability collector (blocked by: #1476)
- #1490 - Secrets Manager metadata and reference collector (blocked by: #1476)
- #1491 - SSM Parameter metadata and reference collector (blocked by: #1476)
- #1492 - ECR repository metadata for workload identity context (blocked by: #1476)
- #1493 - SQS and SNS reachability collector (blocked by: #1476)
- #1494 - DynamoDB and RDS resource reachability collector (blocked by: #1476)
- #1495 - AWS resource sensitivity classification model (blocked by: #1476)
- #1496 - Credential and secret reference mapper across AWS workloads (blocked by: #1476)

### Wave 3: Account, region, and org scale
- #1497 - Account and region coverage planner (blocked by: #1496)
- #1498 - AWS Organizations account and OU discovery (blocked by: #1497)
- #1499 - AWS region availability discovery (blocked by: #1497)
- #1500 - Account/region fan-out scan worker (blocked by: #1498, #1499)
- #1501 - Per-account/region/service scan cursors (blocked by: #1500)
- #1502 - Per-service/account/region partial failure reporting (blocked by: #1500)
- #1503 - Public AWS account/region coverage API (blocked by: #1502, #1501)
- #1504 - AWS Organization StackSet onboarding app flow (blocked by: #1503)

### Wave 4: AI agent identity discovery
- #1505 - AWS AI agent normalized model adapter (blocked by: #1496, #1503)
- #1506 - Bedrock Agents identity collector (blocked by: #1505)
- #1507 - AgentCore Runtime identity collector (blocked by: #1505)
- #1508 - AgentCore Gateway and MCP tool mapping (blocked by: #1507)
- #1509 - AgentCore Memory, Browser, and Code Interpreter metadata mapping (blocked by: #1507)
- #1510 - External AI provider key metadata mapper in AWS (blocked by: #1505)
- #1511 - Custom agent detector across AWS workloads (blocked by: #1510, #1486)
- #1512 - AWS agent identity API and explorer data wiring (blocked by: #1506, #1508, #1509, #1511)

### Wave 5: Runtime evidence
- #1513 - AWS runtime event ingestion contract (blocked by: #1512, #1503)
- #1514 - CloudTrail LookupEvents runtime ingestion (blocked by: #1513)
- #1515 - CloudTrail S3 and EventBridge ingestion path (blocked by: #1513, #1501)
- #1516 - STS AssumeRole session and SourceIdentity resolver (blocked by: #1514)
- #1517 - IAM last-used and Access Analyzer signal ingestion (blocked by: #1513)
- #1518 - Secrets Manager read and KMS decrypt runtime mapping (blocked by: #1516, #1489, #1490)
- #1519 - S3 runtime data access mapping (blocked by: #1516, #1488)
- #1520 - Agent runtime and tool-call event ingestion (blocked by: #1513, #1512)

### Wave 6: Intelligence engines
- #1521 - AWS blast radius intelligence engine (blocked by: #1520, #1518, #1519, #1495)
- #1522 - AWS least-privilege recommendation engine (blocked by: #1521, #1517)
- #1523 - Unused access and dormant permission engine (blocked by: #1522)
- #1524 - Stale, ownerless, duplicate, and shared-role sprawl engine (blocked by: #1517, #1477, #1478, #1479)
- #1525 - AWS privilege escalation path engine (blocked by: #1521, #1487)
- #1526 - Cross-account trust and external access engine (blocked by: #1498, #1517)
- #1527 - Secret-to-permission equivalence engine (blocked by: #1496, #1518, #1521)
- #1528 - AWS AI agent risk engine (blocked by: #1512, #1520, #1527)

### Wave 7: Remediation planning
- #1529 - AWS remediation case model (blocked by: #1522, #1528)
- #1530 - IAM policy least-privilege diff generator (blocked by: #1529)
- #1531 - Trust policy hardening planner (blocked by: #1529, #1526)
- #1532 - Permission boundary and SCP recommendation planner (blocked by: #1529, #1498)
- #1533 - Secret and key rotation workflow planner (blocked by: #1529, #1527)
- #1534 - Access key disable and quarantine planner (blocked by: #1529, #1524)
- #1535 - IaC remediation PR and verification plan generator (blocked by: #1530, #1531)

### Wave 8: Approved remediation
- #1536 - AWS remediation approval workflow and RBAC gates (blocked by: #1535)
- #1537 - AWS remediation dry-run executor (blocked by: #1536)
- #1538 - Low-risk approved live remediation actions (blocked by: #1537)
- #1539 - Approved trust policy hardening executor (blocked by: #1537, #1531)
- #1540 - Approved permission boundary executor (blocked by: #1537, #1532)
- #1541 - Approved SCP guardrail executor (blocked by: #1537, #1532)
- #1542 - Post-remediation verification and rollback workflow (blocked by: #1538, #1539)

### Wave 9: Authorization and runtime governance
- #1543 - AWS advisory authorization decision API (blocked by: #1542, #1528)
- #1544 - Session policy recommendation path (blocked by: #1543)
- #1545 - AgentCore Gateway and policy advisory path (blocked by: #1543, #1528)
- #1546 - Limited enforcement framework with canaries and kill switch (blocked by: #1543, #1542)
- #1547 - High-confidence limited authorization enforcement pilot (blocked by: #1546)
- #1548 - AWS governance audit and decision reporting (blocked by: #1547, #1545)

### Wave 10: App experience and GA hardening
- #1549 - AWS machine identity detail page (blocked by: #1528, #1529)
- #1550 - AWS agent identity detail page (blocked by: #1512, #1528)
- #1551 - AWS graph explorer experience (blocked by: #1521)
- #1552 - AWS Remediation Center unified experience (blocked by: #1542)
- #1553 - AWS account and region coverage dashboard (blocked by: #1503)
- #1554 - AWS runtime timeline polish and correlation UX (blocked by: #1520, #1516)
- #1555 - AWS executive outcome view (blocked by: #1548, #1542)
- #1556 - AWS platform observability metrics and traces (blocked by: #1500, #1520, #1542)
- #1557 - AWS platform end-to-end demo, permission docs, and GA hardening (blocked by: #1549, #1550, #1551, #1552, #1555, #1556)
`

// AWSPlatformDependencyIndexRequest optionally pins connector context used for
// account and region evidence on the dependency index response.
type AWSPlatformDependencyIndexRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
}

// AWSPlatformDependencyIndexResult returns the deterministic AWS program ledger.
type AWSPlatformDependencyIndexResult struct {
	TenantID           string                       `json:"tenant_id"`
	WorkspaceID        string                       `json:"workspace_id"`
	ProjectID          string                       `json:"project_id"`
	ConnectorID        string                       `json:"connector_id,omitempty"`
	AccountID          string                       `json:"account_id,omitempty"`
	Region             string                       `json:"region,omitempty"`
	ParentIssueNumber  int                          `json:"parent_issue_number"`
	ParentIssueRef     string                       `json:"parent_issue_ref"`
	CurrentIssueNumber int                          `json:"current_issue_number"`
	CurrentIssueRef    string                       `json:"current_issue_ref"`
	Version            string                       `json:"version"`
	Status             string                       `json:"status"`
	Confidence         float64                      `json:"confidence"`
	IssueCount         int                          `json:"issue_count"`
	WaveCount          int                          `json:"wave_count"`
	ReadyIssueCount    int                          `json:"ready_issue_count"`
	BlockedIssueCount  int                          `json:"blocked_issue_count"`
	CompletedIssueRefs []string                     `json:"completed_issue_refs"`
	ReadyIssueRefs     []string                     `json:"ready_issue_refs"`
	BlockedIssueRefs   []string                     `json:"blocked_issue_refs"`
	FailureReasons     []string                     `json:"failure_reasons"`
	RemediationHints   []string                     `json:"remediation_hints"`
	EvidenceLinks      []string                     `json:"evidence_links"`
	Checks             []AWSPlatformDependencyCheck `json:"checks"`
	Issues             []AWSPlatformDependencyIssue `json:"issues"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
}

// AWSPlatformDependencyCheck records one validation check for the static issue
// dependency ledger.
type AWSPlatformDependencyCheck struct {
	Name          string         `json:"name"`
	Category      string         `json:"category"`
	Required      bool           `json:"required"`
	Status        string         `json:"status"`
	Message       string         `json:"message"`
	FailureReason string         `json:"failure_reason,omitempty"`
	Remediation   string         `json:"remediation,omitempty"`
	EvidenceURL   string         `json:"evidence_url,omitempty"`
	Confidence    float64        `json:"confidence"`
	Evidence      map[string]any `json:"evidence,omitempty"`
	CheckedAt     time.Time      `json:"checked_at"`
}

// AWSPlatformDependencyIssue is one child issue in the AWS machine identity
// platform dependency graph.
type AWSPlatformDependencyIssue struct {
	IssueNumber      int      `json:"issue_number"`
	IssueRef         string   `json:"issue_ref"`
	Title            string   `json:"title"`
	Wave             int      `json:"wave"`
	WaveName         string   `json:"wave_name"`
	Sequence         int      `json:"sequence"`
	BlockerRefs      []string `json:"blocker_refs"`
	DownstreamRefs   []string `json:"downstream_refs"`
	DependencyStatus string   `json:"dependency_status"`
	ReadyForPR       bool     `json:"ready_for_pr"`
	FailureReasons   []string `json:"failure_reasons"`
	Remediation      string   `json:"remediation"`
	NextAction       string   `json:"next_action"`
	EvidenceURL      string   `json:"evidence_url"`
}

type awsPlatformDependencyRow struct {
	IssueNumber        int
	IssueRef           string
	Title              string
	Wave               int
	WaveName           string
	Sequence           int
	BlockerRefs        []string
	ValidationFailures []string
}

// GetAWSPlatformDependencyIndex returns the deterministic AWS child-issue
// dependency ledger scoped to one workspace project.
func (s *Service) GetAWSPlatformDependencyIndex(ctx context.Context, workspaceID string, projectID string, request AWSPlatformDependencyIndexRequest) (AWSPlatformDependencyIndexResult, error) {
	project, scope, err := s.requireScopedProject(ctx, workspaceID, projectID)
	if err != nil {
		return AWSPlatformDependencyIndexResult{}, err
	}
	var connection AWSConnectionStatus
	hasConnection := false
	if strings.TrimSpace(request.ConnectorID) != "" {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, request.ConnectorID)
	} else {
		connection, hasConnection, err = s.awsBaselineConnection(ctx, project, "")
	}
	if err != nil {
		return AWSPlatformDependencyIndexResult{}, err
	}
	return buildAWSPlatformDependencyIndex(scope, project, connection, hasConnection, s.Now().UTC()), nil
}

func buildAWSPlatformDependencyIndex(scope db.Scope, project db.TenancyProject, connection AWSConnectionStatus, hasConnection bool, checkedAt time.Time) AWSPlatformDependencyIndexResult {
	rows, parseFailures := parseAWSPlatformDependencyLedger(awsPlatformDependencyLedger)
	issues, validationFailures := buildAWSPlatformDependencyIssues(rows)
	checks := awsPlatformDependencyChecks(rows, issues, append(parseFailures, validationFailures...), checkedAt)
	status, confidence, failureReasons, remediationHints := summarizeAWSPlatformDependencyChecks(checks)
	readyRefs, blockedRefs, completedRefs := awsPlatformDependencyBuckets(issues)
	result := AWSPlatformDependencyIndexResult{
		TenantID:           scope.TenantID,
		WorkspaceID:        project.WorkspaceID,
		ProjectID:          project.ProjectID,
		ParentIssueNumber:  awsPlatformDependencyParentIssue,
		ParentIssueRef:     awsIssueRef(awsPlatformDependencyParentIssue),
		CurrentIssueNumber: awsPlatformDependencyCurrentIssue,
		CurrentIssueRef:    awsIssueRef(awsPlatformDependencyCurrentIssue),
		Version:            awsPlatformDependencyIndexVersion,
		Status:             status,
		Confidence:         confidence,
		IssueCount:         len(issues),
		WaveCount:          awsPlatformWaveCount(rows),
		ReadyIssueCount:    len(readyRefs),
		BlockedIssueCount:  len(blockedRefs),
		CompletedIssueRefs: completedRefs,
		ReadyIssueRefs:     readyRefs,
		BlockedIssueRefs:   blockedRefs,
		FailureReasons:     failureReasons,
		RemediationHints:   remediationHints,
		EvidenceLinks: dedupeStrings([]string{
			awsIssueURL(awsPlatformDependencyParentIssue),
			awsIssueURL(awsPlatformDependencyCurrentIssue),
			"/docs/aws-platform-dependency-index",
			awsBaselineProjectEvidenceURL(scope, project),
		}),
		Checks:      checks,
		Issues:      issues,
		GeneratedAt: checkedAt,
		UpdatedAt:   checkedAt,
	}
	if hasConnection {
		result.ConnectorID = connection.ConnectorID
		result.AccountID = connection.AccountID
		result.Region = connection.Region
	}
	return result
}

func parseAWSPlatformDependencyLedger(raw string) ([]awsPlatformDependencyRow, []string) {
	rows := []awsPlatformDependencyRow{}
	failures := []string{}
	wave := -1
	waveName := ""
	sequence := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if match := awsPlatformWaveLinePattern.FindStringSubmatch(line); len(match) == 3 {
			parsedWave, err := strconv.Atoi(match[1])
			if err != nil {
				failures = append(failures, fmt.Sprintf("invalid wave number %q", match[1]))
				continue
			}
			wave = parsedWave
			waveName = strings.TrimSpace(match[2])
			continue
		}
		match := awsPlatformIssueLinePattern.FindStringSubmatch(line)
		if len(match) != 4 {
			failures = append(failures, fmt.Sprintf("ledger line does not match issue format: %s", line))
			continue
		}
		rowFailures := []string{}
		if wave < 0 {
			rowFailures = append(rowFailures, fmt.Sprintf("issue %s appears before a wave heading", match[1]))
		}
		issueNumber, err := strconv.Atoi(match[1])
		if err != nil {
			failures = append(failures, fmt.Sprintf("invalid issue number %q", match[1]))
			continue
		}
		blockerRefs, blockerFailures := parseAWSPlatformBlockerRefs(issueNumber, match[3])
		rowFailures = append(rowFailures, blockerFailures...)
		failures = append(failures, rowFailures...)
		sequence++
		rows = append(rows, awsPlatformDependencyRow{
			IssueNumber:        issueNumber,
			IssueRef:           awsIssueRef(issueNumber),
			Title:              strings.TrimSpace(match[2]),
			Wave:               wave,
			WaveName:           waveName,
			Sequence:           sequence,
			BlockerRefs:        append([]string(nil), blockerRefs...),
			ValidationFailures: append([]string(nil), rowFailures...),
		})
	}
	return rows, failures
}

func parseAWSPlatformBlockerRefs(issueNumber int, raw string) ([]string, []string) {
	raw = strings.TrimSpace(raw)
	if strings.EqualFold(raw, "none") {
		return []string{}, nil
	}
	if !awsPlatformBlockerRefsPattern.MatchString(raw) {
		return []string{}, []string{fmt.Sprintf("%s has malformed blocker refs %q", awsIssueRef(issueNumber), raw)}
	}
	parts := strings.Split(raw, ", ")
	refs := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	failures := []string{}
	for _, part := range parts {
		if _, ok := seen[part]; ok {
			failures = append(failures, fmt.Sprintf("%s repeats blocker %s", awsIssueRef(issueNumber), part))
			continue
		}
		seen[part] = struct{}{}
		refs = append(refs, part)
	}
	return refs, failures
}

func buildAWSPlatformDependencyIssues(rows []awsPlatformDependencyRow) ([]AWSPlatformDependencyIssue, []string) {
	failures := []string{}
	issueFailures := map[string][]string{}
	rowByRef := map[string]awsPlatformDependencyRow{}
	for _, row := range rows {
		if len(row.ValidationFailures) > 0 {
			issueFailures[row.IssueRef] = append(issueFailures[row.IssueRef], row.ValidationFailures...)
		}
		if existing, ok := rowByRef[row.IssueRef]; ok {
			failure := fmt.Sprintf("duplicate issue ref %s at sequences %d and %d", row.IssueRef, existing.Sequence, row.Sequence)
			failures = append(failures, failure)
			issueFailures[row.IssueRef] = append(issueFailures[row.IssueRef], failure)
		}
		rowByRef[row.IssueRef] = row
	}
	downstream := map[string][]string{}
	for _, row := range rows {
		for _, blockerRef := range row.BlockerRefs {
			blocker, ok := rowByRef[blockerRef]
			if !ok {
				failure := fmt.Sprintf("%s references missing blocker %s", row.IssueRef, blockerRef)
				failures = append(failures, failure)
				issueFailures[row.IssueRef] = append(issueFailures[row.IssueRef], failure)
				continue
			}
			if blocker.Sequence >= row.Sequence {
				failure := fmt.Sprintf("%s blocker %s is not earlier in the sequence", row.IssueRef, blockerRef)
				failures = append(failures, failure)
				issueFailures[row.IssueRef] = append(issueFailures[row.IssueRef], failure)
			}
			downstream[blockerRef] = append(downstream[blockerRef], row.IssueRef)
		}
	}
	issues := make([]AWSPlatformDependencyIssue, 0, len(rows))
	for _, row := range rows {
		downstreamRefs := append([]string(nil), downstream[row.IssueRef]...)
		sortIssueRefs(downstreamRefs)
		status, ready, reasons, remediation, nextAction := awsPlatformIssueReadiness(row, issueFailures[row.IssueRef])
		issues = append(issues, AWSPlatformDependencyIssue{
			IssueNumber:      row.IssueNumber,
			IssueRef:         row.IssueRef,
			Title:            row.Title,
			Wave:             row.Wave,
			WaveName:         row.WaveName,
			Sequence:         row.Sequence,
			BlockerRefs:      append([]string(nil), row.BlockerRefs...),
			DownstreamRefs:   downstreamRefs,
			DependencyStatus: status,
			ReadyForPR:       ready,
			FailureReasons:   reasons,
			Remediation:      remediation,
			NextAction:       nextAction,
			EvidenceURL:      awsIssueURL(row.IssueNumber),
		})
	}
	return issues, failures
}

func awsPlatformIssueReadiness(row awsPlatformDependencyRow, validationFailures []string) (string, bool, []string, string, string) {
	if len(validationFailures) > 0 {
		return awsPlatformIssueStateBlocked, false, dedupeStrings(validationFailures), "Fix dependency ledger validation errors before opening this issue.", "Correct the canonical dependency ledger before opening a PR."
	}
	if _, ok := awsPlatformCompletedIssueRefs[row.IssueRef]; ok {
		return awsPlatformIssueStateCompleted, false, []string{}, "No PR needed; this dependency is already closed.", "Use as evidence for downstream blockers."
	}
	openBlockers := []string{}
	for _, blockerRef := range row.BlockerRefs {
		if _, ok := awsPlatformCompletedIssueRefs[blockerRef]; !ok {
			openBlockers = append(openBlockers, blockerRef)
		}
	}
	if len(openBlockers) == 0 {
		return awsPlatformIssueStateReady, true, []string{}, "Open exactly one focused PR for this issue from current origin/dev.", "Ready for a focused implementation PR."
	}
	return awsPlatformIssueStateBlocked, false, []string{
		fmt.Sprintf("waiting on %s", strings.Join(openBlockers, ", ")),
	}, "Close every blocker before opening a PR for this issue.", fmt.Sprintf("Wait for %s to close.", strings.Join(openBlockers, ", "))
}

func awsPlatformDependencyChecks(rows []awsPlatformDependencyRow, issues []AWSPlatformDependencyIssue, failures []string, checkedAt time.Time) []AWSPlatformDependencyCheck {
	checks := []AWSPlatformDependencyCheck{
		awsPlatformDependencyCheck(
			"child_issue_count",
			"ledger",
			len(rows) == awsPlatformDependencyIssueCount,
			fmt.Sprintf("AWS platform ledger contains %d child issues.", len(rows)),
			fmt.Sprintf("expected %d child issues, found %d", awsPlatformDependencyIssueCount, len(rows)),
			"Restore the parent epic child issue list before using the index.",
			map[string]any{"expected_issue_count": awsPlatformDependencyIssueCount, "actual_issue_count": len(rows)},
			checkedAt,
		),
		awsPlatformDependencyCheck(
			"blocker_reference_format",
			"validation",
			!containsAWSPlatformFailure(failures, "malformed blocker refs") && !containsAWSPlatformFailure(failures, "repeats blocker"),
			"Every blocker reference uses #1234 formatting without duplicates.",
			"malformed or duplicate blocker references exist",
			"Use GitHub issue refs in #1234 format and remove duplicate blockers.",
			map[string]any{"format": "#1234"},
			checkedAt,
		),
		awsPlatformDependencyCheck(
			"blocker_reference_existence",
			"validation",
			!containsAWSPlatformFailure(failures, "missing blocker"),
			"Every blocker reference points to a child issue in this ledger.",
			"one or more blockers are missing from the ledger",
			"Add the missing child issue or correct the blocker reference before opening downstream PRs.",
			map[string]any{"parent_issue": awsIssueRef(awsPlatformDependencyParentIssue)},
			checkedAt,
		),
		awsPlatformDependencyCheck(
			"parent_sequence_ordering",
			"validation",
			!containsAWSPlatformFailure(failures, "not earlier in the sequence"),
			"Every blocker appears earlier than the issue it blocks.",
			"one or more blockers appear after their dependent issue",
			"Reorder the ledger so dependency blockers precede dependent implementation issues.",
			map[string]any{"wave_count": awsPlatformWaveCount(rows)},
			checkedAt,
		),
		awsPlatformDependencyCheck(
			"current_issue_readiness",
			"readiness",
			awsPlatformCurrentIssueReady(issues),
			fmt.Sprintf("%s is unblocked because all blockers are closed in the ledger.", awsIssueRef(awsPlatformDependencyCurrentIssue)),
			fmt.Sprintf("%s is still blocked", awsIssueRef(awsPlatformDependencyCurrentIssue)),
			fmt.Sprintf("Close blockers for %s before opening its PR.", awsIssueRef(awsPlatformDependencyCurrentIssue)),
			map[string]any{"current_issue": awsIssueRef(awsPlatformDependencyCurrentIssue)},
			checkedAt,
		),
	}
	if len(failures) > 0 {
		checks = append(checks, AWSPlatformDependencyCheck{
			Name:          "ledger_parse_errors",
			Category:      "validation",
			Required:      true,
			Status:        awsPlatformDependencyStatusBlocked,
			Message:       "The AWS dependency ledger has validation errors.",
			FailureReason: strings.Join(failures, "; "),
			Remediation:   "Fix the canonical ledger before using this dependency index.",
			EvidenceURL:   awsIssueURL(awsPlatformDependencyParentIssue),
			Confidence:    0.2,
			Evidence:      map[string]any{"failure_count": len(failures), "failures": append([]string(nil), failures...)},
			CheckedAt:     checkedAt,
		})
	}
	return checks
}

func awsPlatformDependencyCheck(name string, category string, passed bool, message string, failureReason string, remediation string, evidence map[string]any, checkedAt time.Time) AWSPlatformDependencyCheck {
	status := awsPlatformDependencyStatusReady
	confidence := 0.96
	if !passed {
		status = awsPlatformDependencyStatusBlocked
		confidence = 0.35
	}
	check := AWSPlatformDependencyCheck{
		Name:        name,
		Category:    category,
		Required:    true,
		Status:      status,
		Message:     message,
		EvidenceURL: awsIssueURL(awsPlatformDependencyParentIssue),
		Confidence:  confidence,
		Evidence:    evidence,
		CheckedAt:   checkedAt,
	}
	if !passed {
		check.FailureReason = failureReason
		check.Remediation = remediation
	}
	return check
}

func summarizeAWSPlatformDependencyChecks(checks []AWSPlatformDependencyCheck) (string, float64, []string, []string) {
	status := awsPlatformDependencyStatusReady
	confidence := 0.97
	failures := []string{}
	remediations := []string{}
	for _, check := range checks {
		if check.Required && check.Status != awsPlatformDependencyStatusReady {
			status = awsPlatformDependencyStatusBlocked
			confidence = 0.35
			failures = append(failures, firstNonEmptyAWSValue(check.FailureReason, check.Message, check.Name))
			if strings.TrimSpace(check.Remediation) != "" {
				remediations = append(remediations, check.Remediation)
			}
		}
	}
	if status == awsPlatformDependencyStatusReady && len(checks) == 0 {
		status = awsPlatformDependencyStatusDegraded
		confidence = 0.5
		failures = append(failures, "dependency checks did not run")
		remediations = append(remediations, "Restore dependency index checks before using this ledger.")
	}
	return status, confidence, dedupeStrings(failures), dedupeStrings(remediations)
}

func awsPlatformDependencyBuckets(issues []AWSPlatformDependencyIssue) ([]string, []string, []string) {
	ready := []string{}
	blocked := []string{}
	completed := []string{}
	for _, issue := range issues {
		switch issue.DependencyStatus {
		case awsPlatformIssueStateCompleted:
			completed = append(completed, issue.IssueRef)
		case awsPlatformIssueStateReady:
			ready = append(ready, issue.IssueRef)
		case awsPlatformIssueStateBlocked:
			blocked = append(blocked, issue.IssueRef)
		}
	}
	sortIssueRefs(ready)
	sortIssueRefs(blocked)
	sortIssueRefs(completed)
	return ready, blocked, completed
}

func awsPlatformCurrentIssueReady(issues []AWSPlatformDependencyIssue) bool {
	for _, issue := range issues {
		if issue.IssueNumber == awsPlatformDependencyCurrentIssue {
			return issue.ReadyForPR || issue.DependencyStatus == awsPlatformIssueStateCompleted
		}
	}
	return false
}

func awsPlatformWaveCount(rows []awsPlatformDependencyRow) int {
	seen := map[int]struct{}{}
	for _, row := range rows {
		seen[row.Wave] = struct{}{}
	}
	return len(seen)
}

func containsAWSPlatformFailure(failures []string, needle string) bool {
	for _, failure := range failures {
		if strings.Contains(failure, needle) {
			return true
		}
	}
	return false
}

func awsIssueRef(issueNumber int) string {
	return fmt.Sprintf("#%d", issueNumber)
}

func awsIssueURL(issueNumber int) string {
	return fmt.Sprintf("https://github.com/identrail/identrail/issues/%d", issueNumber)
}

func sortIssueRefs(refs []string) {
	sort.SliceStable(refs, func(i, j int) bool {
		return issueRefNumber(refs[i]) < issueRefNumber(refs[j])
	})
}

func issueRefNumber(ref string) int {
	ref = strings.TrimPrefix(strings.TrimSpace(ref), "#")
	n, err := strconv.Atoi(ref)
	if err != nil {
		return 0
	}
	return n
}
