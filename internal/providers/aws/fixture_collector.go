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

		var role IAMRole
		if err := json.Unmarshal(payload, &role); err != nil {
			return nil, fmt.Errorf("decode fixture %s: %w", path, err)
		}

		sourceID := strings.TrimSpace(role.ARN)
		if sourceID == "" {
			return nil, fmt.Errorf("fixture %s missing role arn", path)
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}

		assets = append(assets, providers.RawAsset{
			Kind:      "iam_role",
			SourceID:  sourceID,
			Payload:   payload,
			Collected: collectedAt,
		})
		seen[sourceID] = struct{}{}
	}

	return assets, nil
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
