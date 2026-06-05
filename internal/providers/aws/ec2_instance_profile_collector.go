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
	rawKindEC2InstanceProfile       = "ec2_instance_profile"
	ec2InstanceProfileCollectorName = "ec2_instance_profile"
	ec2ServiceName                  = "ec2"
)

// EC2InstanceProfile captures the EC2 workload-to-instance-profile evidence
// needed by the AWS machine identity graph. It intentionally stores metadata
// only: no user data, object contents, secrets, prompts, completions, or
// customer payloads are collected.
type EC2InstanceProfile struct {
	awscontract.ServiceCollectorRecord
	InstanceID            string            `json:"instance_id,omitempty"`
	InstanceARN           string            `json:"instance_arn,omitempty"`
	InstanceName          string            `json:"instance_name,omitempty"`
	InstanceState         string            `json:"instance_state,omitempty"`
	InstanceProfileARN    string            `json:"instance_profile_arn,omitempty"`
	InstanceProfileID     string            `json:"instance_profile_id,omitempty"`
	InstanceProfileName   string            `json:"instance_profile_name,omitempty"`
	RoleName              string            `json:"role_name,omitempty"`
	LaunchTemplateID      string            `json:"launch_template_id,omitempty"`
	LaunchTemplateName    string            `json:"launch_template_name,omitempty"`
	LaunchTemplateVersion string            `json:"launch_template_version,omitempty"`
	IMDSEndpoint          string            `json:"imds_endpoint,omitempty"`
	IMDSHTTPTokens        string            `json:"imds_http_tokens,omitempty"`
	IMDSHopLimit          int32             `json:"imds_hop_limit,omitempty"`
	Tags                  map[string]string `json:"tags,omitempty"`
}

// EC2InstanceProfilePage is one page of EC2 instance-profile inventory.
type EC2InstanceProfilePage struct {
	Records   []EC2InstanceProfile
	NextToken string
}

// EC2InstanceProfileAPI defines the read-only EC2/IAM metadata calls used by
// the collector. SDK adapters can compose EC2 Describe* and IAM GetInstanceProfile
// behind this contract without exposing SDK types to normalization tests.
type EC2InstanceProfileAPI interface {
	ListInstanceProfiles(ctx context.Context, nextToken string, pageSize int32) (EC2InstanceProfilePage, error)
}

// EC2InstanceProfileCollector collects EC2 instance-profile machine identities.
type EC2InstanceProfileCollector struct {
	client   EC2InstanceProfileAPI
	pageSize int32
	maxPages int
	retry    RetryPolicy
	jitter   float64
	sleep    Sleeper
	randFn   func() float64
	now      func() time.Time
	issues   []providers.SourceError
}

// EC2InstanceProfileOption customizes EC2InstanceProfileCollector behavior.
type EC2InstanceProfileOption func(*EC2InstanceProfileCollector)

// WithEC2InstanceProfilePageSize configures EC2 pagination size.
func WithEC2InstanceProfilePageSize(pageSize int32) EC2InstanceProfileOption {
	return func(c *EC2InstanceProfileCollector) {
		if pageSize > 0 {
			c.pageSize = pageSize
		}
	}
}

// WithEC2InstanceProfileMaxPages limits list pagination to guard against runaways.
func WithEC2InstanceProfileMaxPages(maxPages int) EC2InstanceProfileOption {
	return func(c *EC2InstanceProfileCollector) {
		if maxPages > 0 {
			c.maxPages = maxPages
		}
	}
}

// WithEC2InstanceProfileRetryPolicy customizes retry strategy for transient EC2/IAM errors.
func WithEC2InstanceProfileRetryPolicy(policy RetryPolicy) EC2InstanceProfileOption {
	return func(c *EC2InstanceProfileCollector) {
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

// WithEC2InstanceProfileRetryJitterRatio configures bounded random jitter around retry backoff.
func WithEC2InstanceProfileRetryJitterRatio(ratio float64) EC2InstanceProfileOption {
	return func(c *EC2InstanceProfileCollector) {
		if ratio < 0 {
			ratio = 0
		}
		c.jitter = ratio
	}
}

// WithEC2InstanceProfileRetryRandFunc injects deterministic randomness for retry jitter tests.
func WithEC2InstanceProfileRetryRandFunc(randFn func() float64) EC2InstanceProfileOption {
	return func(c *EC2InstanceProfileCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

// WithEC2InstanceProfileSleeper injects a testable sleep function.
func WithEC2InstanceProfileSleeper(s Sleeper) EC2InstanceProfileOption {
	return func(c *EC2InstanceProfileCollector) {
		if s != nil {
			c.sleep = s
		}
	}
}

// WithEC2InstanceProfileClock injects a deterministic clock.
func WithEC2InstanceProfileClock(now func() time.Time) EC2InstanceProfileOption {
	return func(c *EC2InstanceProfileCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewEC2InstanceProfileCollector creates a read-only EC2 instance-profile collector.
func NewEC2InstanceProfileCollector(client EC2InstanceProfileAPI, opts ...EC2InstanceProfileOption) *EC2InstanceProfileCollector {
	c := &EC2InstanceProfileCollector{
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

func (c *EC2InstanceProfileCollector) ServiceName() string {
	return ec2ServiceName
}

// Collect pulls EC2 instance-profile assets using an empty scope.
func (c *EC2InstanceProfileCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx, AWSCollectorScope{Service: ec2ServiceName})
	return assets, err
}

// CollectWithDiagnostics pulls EC2 instance-profile assets and includes non-fatal source errors.
func (c *EC2InstanceProfileCollector) CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if c.client == nil {
		return nil, nil, errors.New("ec2 instance profile collector requires client")
	}
	c.issues = c.issues[:0]

	if strings.TrimSpace(scope.Service) == "" {
		scope.Service = c.ServiceName()
	}

	assets := make([]providers.RawAsset, 0, c.pageSize)
	seen := map[string]struct{}{}
	nextToken := ""
	collectedAt := c.now().UTC()

	for page := 1; ; page++ {
		if page > c.maxPages {
			return nil, nil, fmt.Errorf("ec2 instance profile collection exceeded max pages (%d)", c.maxPages)
		}

		response, err := c.withRetry(ctx, func(callCtx context.Context) (EC2InstanceProfilePage, error) {
			return c.client.ListInstanceProfiles(callCtx, nextToken, c.pageSize)
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list ec2 instance profiles page %d: %w", page, err)
		}

		for _, record := range response.Records {
			normalized := normalizeEC2InstanceProfileScope(scope, record, collectedAt)
			if strings.TrimSpace(normalized.WorkloadID) == "" {
				c.addIssue(providers.SourceError{
					Collector: ec2InstanceProfileCollectorName,
					Code:      "malformed_source_record",
					Message:   "skipped EC2 instance profile record without workload id",
					Retryable: false,
				})
				continue
			}
			if strings.TrimSpace(normalized.InstanceProfileARN) == "" && strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: ec2InstanceProfileCollectorName,
					SourceID:  normalized.WorkloadID,
					Code:      "missing_instance_profile",
					Message:   "EC2 workload does not have an instance profile attached",
					Retryable: false,
				})
			}
			if strings.TrimSpace(normalized.InstanceProfileARN) != "" && strings.TrimSpace(normalized.RoleARN) == "" {
				c.addIssue(providers.SourceError{
					Collector: ec2InstanceProfileCollectorName,
					SourceID:  normalized.InstanceProfileARN,
					Code:      "missing_instance_profile_role",
					Message:   "EC2 instance profile did not resolve to an IAM role",
					Retryable: false,
				})
			}

			sourceID := ec2InstanceProfileSourceID(normalized)
			if _, exists := seen[sourceID]; exists {
				continue
			}
			payload, err := json.Marshal(normalized)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal ec2 instance profile %q: %w", sourceID, err)
			}

			assets = append(assets, providers.RawAsset{
				Kind:      rawKindEC2InstanceProfile,
				SourceID:  sourceID,
				Payload:   payload,
				Collected: collectedAt.Format(time.RFC3339Nano),
			})
			seen[sourceID] = struct{}{}
		}

		if response.NextToken == "" {
			break
		}
		nextToken = response.NextToken
	}

	issues := append([]providers.SourceError(nil), c.issues...)
	return assets, issues, nil
}

func (c *EC2InstanceProfileCollector) withRetry(ctx context.Context, fn func(context.Context) (EC2InstanceProfilePage, error)) (EC2InstanceProfilePage, error) {
	return retryAWSPage(ctx, c.retry, c.jitter, c.randFn, c.sleep, fn)
}

func (c *EC2InstanceProfileCollector) backoff(attempt int) time.Duration {
	return awsRetryBackoff(c.retry, c.jitter, c.randFn, attempt)
}

func (c *EC2InstanceProfileCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}

func normalizeEC2InstanceProfileScope(scope AWSCollectorScope, record EC2InstanceProfile, collectedAt time.Time) EC2InstanceProfile {
	normalized := record
	normalized.AccountID = firstNonEmptyAWSValue(record.AccountID, scope.AccountID)
	normalized.Region = firstNonEmptyAWSValue(record.Region, scope.Region)
	normalized.Service = firstNonEmptyAWSValue(record.Service, ec2ServiceName)
	normalized.WorkloadType = firstNonEmptyAWSValue(record.WorkloadType, "ec2_instance")
	normalized.WorkloadID = firstNonEmptyAWSValue(record.WorkloadID, record.InstanceARN, record.InstanceID, record.LaunchTemplateID)
	normalized.WorkloadName = firstNonEmptyAWSValue(record.WorkloadName, record.InstanceName, record.InstanceID, record.LaunchTemplateName, record.LaunchTemplateID)
	normalized.RoleARN = strings.TrimSpace(record.RoleARN)
	normalized.Source = firstNonEmptyAWSValue(record.Source, "describeinstances")
	normalized.EvidenceRef = firstNonEmptyAWSValue(record.EvidenceRef, record.InstanceARN, record.InstanceID, record.LaunchTemplateID, record.InstanceProfileARN)
	normalized.CollectorName = firstNonEmptyAWSValue(record.CollectorName, ec2InstanceProfileCollectorName)
	normalized.ScanID = firstNonEmptyAWSValue(record.ScanID, scope.ScanID, "aws-ec2-instance-profile-fixture")
	normalized.ConnectorID = firstNonEmptyAWSValue(record.ConnectorID, scope.ConnectorID, "aws-connector")
	normalized.TenantID = firstNonEmptyAWSValue(record.TenantID, scope.TenantID, "tenant")
	normalized.WorkspaceID = firstNonEmptyAWSValue(record.WorkspaceID, scope.WorkspaceID, "workspace")
	normalized.ProjectID = firstNonEmptyAWSValue(record.ProjectID, scope.ProjectID, "project")
	normalized.CollectedAt = collectedAt
	if normalized.Confidence <= 0 {
		normalized.Confidence = 0.95
	}
	normalized.InstanceID = strings.TrimSpace(record.InstanceID)
	normalized.InstanceARN = strings.TrimSpace(record.InstanceARN)
	normalized.InstanceName = strings.TrimSpace(record.InstanceName)
	normalized.InstanceState = strings.TrimSpace(record.InstanceState)
	normalized.InstanceProfileARN = strings.TrimSpace(record.InstanceProfileARN)
	normalized.InstanceProfileID = strings.TrimSpace(record.InstanceProfileID)
	normalized.InstanceProfileName = strings.TrimSpace(record.InstanceProfileName)
	normalized.RoleName = strings.TrimSpace(record.RoleName)
	normalized.LaunchTemplateID = strings.TrimSpace(record.LaunchTemplateID)
	normalized.LaunchTemplateName = strings.TrimSpace(record.LaunchTemplateName)
	normalized.LaunchTemplateVersion = strings.TrimSpace(record.LaunchTemplateVersion)
	normalized.IMDSEndpoint = strings.TrimSpace(record.IMDSEndpoint)
	normalized.IMDSHTTPTokens = strings.TrimSpace(record.IMDSHTTPTokens)
	normalized.Tags = copyTags(record.Tags)
	return normalized
}

func ec2InstanceProfileSourceID(record EC2InstanceProfile) string {
	return strings.Join([]string{
		firstNonEmptyAWSValue(record.AccountID, "account"),
		firstNonEmptyAWSValue(record.Region, "region"),
		firstNonEmptyAWSValue(record.WorkloadType, "ec2_instance"),
		firstNonEmptyAWSValue(record.WorkloadID, record.InstanceID, record.LaunchTemplateID, "workload"),
		firstNonEmptyAWSValue(record.InstanceProfileARN, "no-profile"),
		firstNonEmptyAWSValue(record.RoleARN, "no-role"),
	}, "|")
}

var _ AWSServiceCollector = (*EC2InstanceProfileCollector)(nil)
var _ providers.Collector = (*EC2InstanceProfileCollector)(nil)
