package enterprise

import (
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

// ExecutiveReport is a deterministic rollup of finding state suitable for
// leadership consumption: open volume by severity, top finding types, mean
// time to resolve, and week-over-week trend.
type ExecutiveReport struct {
	OrganizationID    string                         `json:"organization_id"`
	GeneratedAt       time.Time                      `json:"generated_at"`
	WindowStart       time.Time                      `json:"window_start"`
	WindowEnd         time.Time                      `json:"window_end"`
	TotalOpenFindings int                            `json:"total_open_findings"`
	OpenBySeverity    map[domain.FindingSeverity]int `json:"open_by_severity"`
	OpenByType        map[domain.FindingType]int     `json:"open_by_type"`
	TopFindingTypes   []TopFindingType               `json:"top_finding_types"`
	MeanTimeToResolve time.Duration                  `json:"mean_time_to_resolve"`
	WeekOverWeek      WeekOverWeekTrend              `json:"week_over_week"`
}

// TopFindingType records the count of one finding type within the report
// window, used for the executive top-N callout.
type TopFindingType struct {
	Type  domain.FindingType `json:"type"`
	Count int                `json:"count"`
}

// WeekOverWeekTrend captures the delta in created-findings volume between the
// trailing 7-day window and the prior 7-day window.
type WeekOverWeekTrend struct {
	CurrentCount  int `json:"current_count"`
	PreviousCount int `json:"previous_count"`
	Delta         int `json:"delta"`
}

// ReportOptions parameterizes BuildExecutiveReport. Now defaults to time.Now()
// when nil so callers in tests can inject a deterministic clock.
type ReportOptions struct {
	OrganizationID string
	Now            func() time.Time
	TopN           int
}

// BuildExecutiveReport aggregates a finding slice into an ExecutiveReport.
// The function is pure (no I/O) and deterministic given fixed inputs, which
// keeps it cheap to call from the API layer and easy to unit-test.
func BuildExecutiveReport(findings []domain.Finding, opts ReportOptions) ExecutiveReport {
	now := opts.now()
	windowStart := now.Add(-7 * 24 * time.Hour)
	previousWindowStart := now.Add(-14 * 24 * time.Hour)
	topN := opts.TopN
	if topN <= 0 {
		topN = 5
	}

	report := ExecutiveReport{
		OrganizationID: strings.TrimSpace(opts.OrganizationID),
		GeneratedAt:    now,
		WindowStart:    windowStart,
		WindowEnd:      now,
		OpenBySeverity: map[domain.FindingSeverity]int{},
		OpenByType:     map[domain.FindingType]int{},
	}

	var totalResolveDuration time.Duration
	var resolvedCount int
	currentWeek := 0
	previousWeek := 0

	for _, finding := range findings {
		status := finding.Triage.Status
		if status == "" {
			status = domain.FindingLifecycleOpen
		}

		// Open rollups exclude suppressed/resolved findings.
		if status == domain.FindingLifecycleOpen || status == domain.FindingLifecycleAck {
			report.TotalOpenFindings++
			report.OpenBySeverity[finding.Severity]++
			report.OpenByType[finding.Type]++
		}

		if status == domain.FindingLifecycleResolved && !finding.CreatedAt.IsZero() {
			resolvedAt := triageResolutionTime(finding)
			if !resolvedAt.IsZero() && resolvedAt.After(finding.CreatedAt) {
				totalResolveDuration += resolvedAt.Sub(finding.CreatedAt)
				resolvedCount++
			}
		}

		created := finding.CreatedAt
		if created.IsZero() {
			continue
		}
		switch {
		case !created.Before(windowStart) && !created.After(now):
			currentWeek++
		case !created.Before(previousWindowStart) && created.Before(windowStart):
			previousWeek++
		}
	}

	if resolvedCount > 0 {
		report.MeanTimeToResolve = totalResolveDuration / time.Duration(resolvedCount)
	}
	report.WeekOverWeek = WeekOverWeekTrend{
		CurrentCount:  currentWeek,
		PreviousCount: previousWeek,
		Delta:         currentWeek - previousWeek,
	}
	report.TopFindingTypes = topFindingTypes(report.OpenByType, topN)
	return report
}

func topFindingTypes(counts map[domain.FindingType]int, topN int) []TopFindingType {
	if len(counts) == 0 {
		return nil
	}
	items := make([]TopFindingType, 0, len(counts))
	for typ, count := range counts {
		items = append(items, TopFindingType{Type: typ, Count: count})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Type < items[j].Type
	})
	if len(items) > topN {
		items = items[:topN]
	}
	return items
}

// triageResolutionTime returns the most reliable resolution timestamp we can
// derive from the finding's triage metadata. Triage.UpdatedAt is the moment of
// the most recent lifecycle transition; for findings whose terminal status is
// "resolved", that timestamp is a faithful proxy for resolution time.
func triageResolutionTime(finding domain.Finding) time.Time {
	if finding.Triage.UpdatedAt != nil && !finding.Triage.UpdatedAt.IsZero() {
		return *finding.Triage.UpdatedAt
	}
	return time.Time{}
}

func (o ReportOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}
