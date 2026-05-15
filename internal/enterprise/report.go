package enterprise

import (
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

// ExecutiveReport is a deterministic rollup of finding state suitable for
// leadership consumption: open volume by severity, top finding types, and
// week-over-week trend.
//
// MeanTimeToResolve is deliberately omitted from this first cut: the current
// FindingTriage schema only records a `last-updated` timestamp that mutates on
// every triage change (including comment-only and assignee edits), so deriving
// a faithful MTTR requires a dedicated resolved-at timestamp or a lifecycle
// history table. That work is tracked separately so the executive report
// cannot silently surface a materially incorrect figure.
type ExecutiveReport struct {
	OrganizationID    string                         `json:"organization_id"`
	GeneratedAt       time.Time                      `json:"generated_at"`
	WindowStart       time.Time                      `json:"window_start"`
	WindowEnd         time.Time                      `json:"window_end"`
	TotalOpenFindings int                            `json:"total_open_findings"`
	OpenBySeverity    map[domain.FindingSeverity]int `json:"open_by_severity"`
	OpenByType        map[domain.FindingType]int     `json:"open_by_type"`
	TopFindingTypes   []TopFindingType               `json:"top_finding_types"`
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

	currentWeek := 0
	previousWeek := 0

	for _, finding := range findings {
		status := effectiveStatus(finding, now)

		// Open rollups exclude suppressed/resolved findings.
		if status == domain.FindingLifecycleOpen || status == domain.FindingLifecycleAck {
			report.TotalOpenFindings++
			report.OpenBySeverity[finding.Severity]++
			report.OpenByType[finding.Type]++
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

// effectiveStatus normalizes a finding's triage status against the current
// clock so the executive rollup does not under-count open work. A finding
// marked suppressed whose SuppressionExpiresAt has already passed is treated
// as open again — the suppression has lapsed even if the persistence layer has
// not yet rewritten the row.
func effectiveStatus(finding domain.Finding, now time.Time) domain.FindingLifecycleStatus {
	status := finding.Triage.Status
	if status == "" {
		return domain.FindingLifecycleOpen
	}
	if status == domain.FindingLifecycleSuppressed {
		if expires := finding.Triage.SuppressionExpiresAt; expires != nil && !expires.IsZero() && !now.Before(*expires) {
			return domain.FindingLifecycleOpen
		}
	}
	return status
}

func (o ReportOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}
