package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/providers"
)

// FixtureOption customizes fixture collector behavior.
type FixtureOption func(*FixtureCollector)

// FixtureCollector reads role payload fixtures and emits raw assets.
type FixtureCollector struct {
	paths []string
	now   func() time.Time
}

var _ providers.Collector = (*FixtureCollector)(nil)

// NewFixtureCollector constructs a fixture-based collector for local deterministic scans.
func NewFixtureCollector(paths []string, opts ...FixtureOption) *FixtureCollector {
	collector := &FixtureCollector{
		paths: append([]string(nil), paths...),
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(collector)
	}
	return collector
}

// WithFixtureClock injects deterministic time for tests.
func WithFixtureClock(now func() time.Time) FixtureOption {
	return func(c *FixtureCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// Collect loads role fixtures from files/directories and converts them to raw assets.
func (c *FixtureCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	if len(c.paths) == 0 {
		return nil, fmt.Errorf("fixture collector requires at least one fixture path")
	}

	expanded, err := expandFixturePaths(c.paths)
	if err != nil {
		return nil, err
	}

	assets := make([]providers.RawAsset, 0, len(expanded))
	seen := map[string]struct{}{}
	collectedAt := c.now().UTC().Format(time.RFC3339Nano)

	for _, path := range expanded {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		payload, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read fixture %s: %w", path, err)
		}

		assetKind, sourceID := fixtureAssetKindAndSourceID(payload)
		if assetKind == "" || sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}

		assets = append(assets, providers.RawAsset{
			Kind:      assetKind,
			SourceID:  sourceID,
			Payload:   payload,
			Collected: collectedAt,
		})
		seen[sourceID] = struct{}{}
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("no valid fixture assets found")
	}

	return assets, nil
}

func fixtureAssetKindAndSourceID(payload []byte) (string, string) {
	var role IAMRole
	if err := json.Unmarshal(payload, &role); err == nil {
		if sourceID := strings.TrimSpace(role.ARN); sourceID != "" {
			return "iam_role", sourceID
		}
	}

	var ecsRole ECSTaskRole
	if err := json.Unmarshal(payload, &ecsRole); err == nil {
		sourceID := ecsTaskRoleSourceID(ecsRole)
		if isECSTaskRoleFixture(ecsRole) {
			return rawKindECSTaskRole, sourceID
		}
	}

	var lambdaRole LambdaExecutionRole
	if err := json.Unmarshal(payload, &lambdaRole); err == nil {
		sourceID := lambdaExecutionRoleSourceID(lambdaRole)
		if isLambdaExecutionRoleFixture(lambdaRole) {
			return rawKindLambdaExecutionRole, sourceID
		}
	}

	var profile EC2InstanceProfile
	if err := json.Unmarshal(payload, &profile); err == nil {
		sourceID := ec2InstanceProfileSourceID(profile)
		if isEC2InstanceProfileFixture(profile) {
			return rawKindEC2InstanceProfile, sourceID
		}
	}

	return "", ""
}

func isECSTaskRoleFixture(record ECSTaskRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), ecsServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), ecsTaskRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "ecs_service", "service", "ecs_task_definition", "task_definition":
		return true
	}
	return strings.TrimSpace(record.RoleKind) != "" ||
		strings.TrimSpace(record.ClusterARN) != "" ||
		strings.TrimSpace(record.ServiceARN) != "" ||
		strings.TrimSpace(record.ServiceName) != "" ||
		strings.TrimSpace(record.TaskDefinitionARN) != "" ||
		strings.TrimSpace(record.TaskDefinitionFamily) != "" ||
		strings.TrimSpace(record.TaskRoleARN) != "" ||
		strings.TrimSpace(record.ExecutionRoleARN) != ""
}

func isLambdaExecutionRoleFixture(record LambdaExecutionRole) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), lambdaServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), lambdaExecutionRoleCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "lambda_function", "function":
		return true
	}
	return strings.TrimSpace(record.FunctionARN) != "" ||
		strings.TrimSpace(record.FunctionName) != "" ||
		strings.TrimSpace(record.FunctionVersion) != "" ||
		strings.TrimSpace(record.Runtime) != "" ||
		strings.TrimSpace(record.PackageType) != "" ||
		strings.TrimSpace(record.Handler) != "" ||
		strings.TrimSpace(record.KMSKeyARN) != "" ||
		len(record.EventSourceARNs) > 0 ||
		len(record.DisabledEventSourceARNs) > 0
}

func isEC2InstanceProfileFixture(record EC2InstanceProfile) bool {
	if strings.EqualFold(strings.TrimSpace(record.Service), ec2ServiceName) || strings.EqualFold(strings.TrimSpace(record.CollectorName), ec2InstanceProfileCollectorName) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(record.WorkloadType)) {
	case "ec2_instance", "instance", "ec2_launch_template", "launch_template":
		return true
	}
	return strings.TrimSpace(record.InstanceID) != "" ||
		strings.TrimSpace(record.InstanceARN) != "" ||
		strings.TrimSpace(record.InstanceName) != "" ||
		strings.TrimSpace(record.InstanceProfileARN) != "" ||
		strings.TrimSpace(record.InstanceProfileID) != "" ||
		strings.TrimSpace(record.InstanceProfileName) != "" ||
		strings.TrimSpace(record.LaunchTemplateID) != "" ||
		strings.TrimSpace(record.LaunchTemplateName) != ""
}

func expandFixturePaths(inputs []string) ([]string, error) {
	expanded := make([]string, 0, len(inputs))
	for _, input := range inputs {
		cleaned := strings.TrimSpace(input)
		if cleaned == "" {
			continue
		}

		info, err := os.Stat(cleaned)
		if err != nil {
			return nil, fmt.Errorf("stat fixture path %s: %w", cleaned, err)
		}
		if !info.IsDir() {
			expanded = append(expanded, cleaned)
			continue
		}

		entries, err := os.ReadDir(cleaned)
		if err != nil {
			return nil, fmt.Errorf("read fixture directory %s: %w", cleaned, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
				expanded = append(expanded, filepath.Join(cleaned, entry.Name()))
			}
		}
	}

	sort.Strings(expanded)
	if len(expanded) == 0 {
		return nil, fmt.Errorf("no fixture files found")
	}
	return expanded, nil
}
