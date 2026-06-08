package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

const (
	rawKindIAMPassRoleRelationship       = "iam_passrole_relationship"
	iamPassRoleRelationshipCollectorName = "iam_passrole_relationship"
	iamPassRoleServiceName               = "iam-passrole"
)

// IAMPassRoleRelationship is the normalized envelope describing one PassRole
// grant: a source identity (the role whose policy contains the grant) can pass
// a target role to a downstream AWS service. Wildcards, deny statements, and
// inverse (NotAction/NotResource) forms are surfaced explicitly so operators
// can reason about them rather than having them silently expand into vast
// fan-out edges.
type IAMPassRoleRelationship struct {
	awscontract.ServiceCollectorRecord
	SourceRoleARN      string            `json:"source_role_arn,omitempty"`
	SourceRoleName     string            `json:"source_role_name,omitempty"`
	SourceRolePath     string            `json:"source_role_path,omitempty"`
	TargetResource     string            `json:"target_resource,omitempty"`
	TargetWildcardKind string            `json:"target_wildcard_kind,omitempty"`
	PolicyName         string            `json:"policy_name,omitempty"`
	StatementSid       string            `json:"statement_sid,omitempty"`
	ActionExpression   string            `json:"action_expression,omitempty"`
	Effect             string            `json:"effect,omitempty"`
	PassedToService    string            `json:"passed_to_service,omitempty"`
	ConditionOperator  string            `json:"condition_operator,omitempty"`
	NotAction          bool              `json:"not_action,omitempty"`
	NotResource        bool              `json:"not_resource,omitempty"`
	OtherConditionKeys []string          `json:"other_condition_keys,omitempty"`
	UnresolvedTarget   bool              `json:"unresolved_target,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
}

// IAMPassRoleRelationshipCollector consumes IAM role assets via the shared
// IAMAPI and emits one normalized record per PassRole grant. It does not call
// AWS itself beyond ListRoles — every other input (policy documents, inline +
// managed) is already populated on the IAMRole record by the IAM SDK adapter.
type IAMPassRoleRelationshipCollector struct {
	client   IAMAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
}

// IAMPassRoleRelationshipOption tunes the collector.
type IAMPassRoleRelationshipOption func(*IAMPassRoleRelationshipCollector)

func WithIAMPassRoleRelationshipPageSize(pageSize int32) IAMPassRoleRelationshipOption {
	return func(c *IAMPassRoleRelationshipCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

func WithIAMPassRoleRelationshipMaxPages(maxPages int) IAMPassRoleRelationshipOption {
	return func(c *IAMPassRoleRelationshipCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

func WithIAMPassRoleRelationshipRetryPolicy(policy RetryPolicy) IAMPassRoleRelationshipOption {
	return func(c *IAMPassRoleRelationshipCollector) {
		if policy.MaxRetries >= 0 {
			c.retry.MaxRetries = policy.MaxRetries
		}
		if policy.BaseDelay > 0 {
			c.retry.BaseDelay = policy.BaseDelay
		}
		if policy.MaxDelay > 0 {
			c.retry.MaxDelay = policy.MaxDelay
		}
	}
}

func WithIAMPassRoleRelationshipSleeper(s Sleeper) IAMPassRoleRelationshipOption {
	return func(c *IAMPassRoleRelationshipCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

func WithIAMPassRoleRelationshipClock(now func() time.Time) IAMPassRoleRelationshipOption {
	return func(c *IAMPassRoleRelationshipCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewIAMPassRoleRelationshipCollector returns a collector configured with the
// same defaults as the other AWS service collectors.
func NewIAMPassRoleRelationshipCollector(client IAMAPI, opts ...IAMPassRoleRelationshipOption) *IAMPassRoleRelationshipCollector {
	c := &IAMPassRoleRelationshipCollector{
		client:   client,
		pageSize: defaultPageSize,
		maxPages: defaultMaxPages,
		retry: RetryPolicy{
			MaxRetries: defaultRetryCount,
			BaseDelay:  defaultBaseDelay,
			MaxDelay:   defaultMaxDelay,
		},
		jitter: defaultRetryJitterRatio,
		sleep:  defaultSleeper,
		randFn: rand.Float64,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ServiceName returns the canonical service name used by the composite
// collector when stamping diagnostics and scopes.
func (c *IAMPassRoleRelationshipCollector) ServiceName() string {
	return iamPassRoleServiceName
}

// Collect satisfies providers.Collector for callers without a scope.
func (c *IAMPassRoleRelationshipCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: iamPassRoleServiceName})
	return assets, err
}

// CollectWithDiagnostics walks every IAM role's permission policies and emits
// one normalized PassRole record per (source, target, condition, effect)
// tuple. Per-call state is held in local variables so concurrent invocations
// do not race on shared collector state.
func (c *IAMPassRoleRelationshipCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("iam passrole relationship collector requires client")
	}
	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}
	assets := []providers.RawAsset{}
	issues := []providers.SourceError{}
	addIssue := func(issue providers.SourceError) {
		if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
			return
		}
		issues = append(issues, issue)
	}
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()
	for page := 1; ; page++ {
		if page > c.maxPages {
			addIssue(providers.SourceError{
				Collector: iamPassRoleRelationshipCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "iam_passrole_page_limit_exceeded",
				Message:   fmt.Sprintf("iam passrole relationship collection exceeded max pages (%d)", c.maxPages),
				Retryable: false,
			})
			return assets, append([]providers.SourceError(nil), issues...), fmt.Errorf("iam passrole relationship collection exceeded max pages (%d)", c.maxPages)
		}
		page, err := retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, func(callCtx context.Context) (ListRolesPage, error) {
			return c.client.ListRoles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			wrapped := fmt.Errorf("list iam roles for passrole relationships: %w", err)
			addIssue(providers.SourceError{
				Collector: iamPassRoleRelationshipCollectorName,
				SourceID:  firstNonEmptyAWSValue(nextToken, "page"),
				Code:      "iam_passrole_page_failed",
				Message:   wrapped.Error(),
				Retryable: isRetryable(err),
			})
			snapshot := append([]providers.SourceError(nil), issues...)
			if len(assets) > 0 {
				return assets, snapshot, wrapped
			}
			return nil, snapshot, wrapped
		}
		for _, role := range page.Roles {
			for _, policy := range role.PermissionPolicies {
				doc, parseErr := parsePassRolePolicyDocument(policy.Document)
				if parseErr != nil {
					addIssue(providers.SourceError{
						Collector: iamPassRoleRelationshipCollectorName,
						SourceID:  iamPassRoleSourceID(role.ARN, policy.Name, "<unparseable>"),
						Code:      "iam_passrole_policy_parse_failed",
						Message:   fmt.Sprintf("policy %q on role %q could not be parsed: %v", policy.Name, role.ARN, parseErr),
						Retryable: false,
					})
					continue
				}
				for _, grant := range extractPassRoleGrants(doc) {
					record := normalizeIAMPassRoleRelationship(scope, role, policy.Name, grant, collectedAt)
					if strings.TrimSpace(record.SourceRoleARN) == "" || strings.TrimSpace(record.TargetResource) == "" {
						addIssue(providers.SourceError{
							Collector: iamPassRoleRelationshipCollectorName,
							Code:      "malformed_iam_passrole_record",
							Message:   "skipped iam passrole record without source or target",
							Retryable: false,
						})
						continue
					}
					sourceID := iamPassRoleRecordSourceID(record)
					if _, exists := seen[sourceID]; exists {
						continue
					}
					payload, err := json.Marshal(record)
					if err != nil {
						return nil, nil, fmt.Errorf("marshal iam passrole relationship %q: %w", sourceID, err)
					}
					assets = append(assets, providers.RawAsset{
						Kind:      rawKindIAMPassRoleRelationship,
						SourceID:  sourceID,
						Payload:   payload,
						Collected: collectedAt.Format(time.RFC3339Nano),
					})
					seen[sourceID] = struct{}{}
				}
			}
		}
		if strings.TrimSpace(page.NextToken) == "" {
			break
		}
		nextToken = strings.TrimSpace(page.NextToken)
	}
	return assets, append([]providers.SourceError(nil), issues...), nil
}

// normalizeIAMPassRoleRelationship folds a single extracted grant into the
// normalized record shape used by the API and graph layers.
func normalizeIAMPassRoleRelationship(scope AWSCollectorScope, role IAMRole, policyName string, grant passRoleGrant, collectedAt time.Time) IAMPassRoleRelationship {
	workloadID := iamPassRoleWorkloadID(role.ARN, policyName, grant)
	wildcardKind := passRoleGrantWildcardKind(grant.TargetResource)
	unresolved := wildcardKind != "specific"
	record := IAMPassRoleRelationship{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			TenantID:      firstNonEmptyAWSValue(scope.TenantID, "tenant"),
			WorkspaceID:   firstNonEmptyAWSValue(scope.WorkspaceID, "workspace"),
			ProjectID:     firstNonEmptyAWSValue(scope.ProjectID, "project"),
			ConnectorID:   firstNonEmptyAWSValue(scope.ConnectorID, "aws-connector"),
			AccountID:     firstNonEmptyAWSValue(scope.AccountID, accountIDFromARN(role.ARN)),
			Region:        strings.TrimSpace(scope.Region),
			Service:       iamPassRoleServiceName,
			WorkloadID:    workloadID,
			WorkloadType:  "iam_passrole_relationship",
			WorkloadName:  firstNonEmptyAWSValue(role.Name, roleNameFromARN(role.ARN)),
			RoleARN:       strings.TrimSpace(role.ARN),
			Source:        "iam_policy_document",
			EvidenceRef:   iamPassRoleEvidenceRef(role.ARN, policyName, grant.Sid),
			Confidence:    passRoleGrantConfidence(grant),
			ScanID:        firstNonEmptyAWSValue(scope.ScanID, "aws-iam-passrole-fixture"),
			CollectorName: iamPassRoleRelationshipCollectorName,
			CollectedAt:   collectedAt,
		},
		SourceRoleARN:      strings.TrimSpace(role.ARN),
		SourceRoleName:     firstNonEmptyAWSValue(role.Name, roleNameFromARN(role.ARN)),
		SourceRolePath:     strings.TrimSpace(role.Path),
		TargetResource:     strings.TrimSpace(grant.TargetResource),
		TargetWildcardKind: wildcardKind,
		PolicyName:         strings.TrimSpace(policyName),
		StatementSid:       grant.Sid,
		ActionExpression:   grant.ActionExpression,
		Effect:             grant.Effect,
		PassedToService:    strings.TrimSpace(grant.ServiceCondition),
		ConditionOperator:  strings.TrimSpace(grant.ConditionOp),
		NotAction:          grant.NotAction,
		NotResource:        grant.NotResource,
		OtherConditionKeys: append([]string(nil), grant.OtherConditions...),
		UnresolvedTarget:   unresolved,
		Tags:               copyTags(role.Tags),
	}
	return record
}

// iamPassRoleWorkloadID identifies the (source, policy, target, condition,
// effect) edge uniquely so the normalizer can dedupe across page boundaries.
func iamPassRoleWorkloadID(roleARN, policyName string, grant passRoleGrant) string {
	return strings.Join(normalizeStringList([]string{
		strings.TrimSpace(roleARN),
		strings.TrimSpace(policyName),
		strings.TrimSpace(grant.Sid),
		grant.ActionExpression,
		grant.Effect,
		grant.TargetResource,
		grant.ServiceCondition,
	}), "|")
}

func iamPassRoleSourceID(roleARN, policyName, suffix string) string {
	return strings.Join(normalizeStringList([]string{
		strings.TrimSpace(roleARN),
		strings.TrimSpace(policyName),
		strings.TrimSpace(suffix),
	}), "|")
}

func iamPassRoleRecordSourceID(record IAMPassRoleRelationship) string {
	return strings.Join(normalizeStringList([]string{
		record.SourceRoleARN,
		record.PolicyName,
		record.StatementSid,
		record.ActionExpression,
		record.Effect,
		record.TargetResource,
		record.PassedToService,
		record.ConditionOperator,
		fmt.Sprintf("not_action=%t", record.NotAction),
		fmt.Sprintf("not_resource=%t", record.NotResource),
	}), "|")
}

func iamPassRoleEvidenceRef(roleARN, policyName, sid string) string {
	parts := []string{strings.TrimSpace(roleARN)}
	if policy := strings.TrimSpace(policyName); policy != "" {
		parts = append(parts, "policy="+policy)
	}
	if s := strings.TrimSpace(sid); s != "" {
		parts = append(parts, "sid="+s)
	}
	return strings.Join(parts, "#")
}

var _ AWSServiceCollector = (*IAMPassRoleRelationshipCollector)(nil)
var _ providers.Collector = (*IAMPassRoleRelationshipCollector)(nil)
