package enterprise

import (
	"sort"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

// ExecutiveReport is a deterministic rollup of finding state suitable for
// leadership consumption: open volume by severity, top finding types,
// week-over-week trend, and mean time to resolve.
//
// MeanTimeToResolve is derived strictly from the FindingTriage.ResolvedAt
// timestamp, which is set only when a finding actually enters the resolved
// state. The mutable UpdatedAt timestamp is never used, so the figure cannot
// be skewed by comment-only or assignee edits. The field is omitted entirely
// when no resolved finding carries a reliable ResolvedAt, so leadership never
// sees a guessed number.
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
	MeanTimeToResolve *MTTRSummary                   `json:"mean_time_to_resolve,omitempty"`
}

// MTTRSummary reports mean time to resolve across findings that carry a
// trustworthy FindingTriage.ResolvedAt. Seconds is the mean of
// (ResolvedAt - CreatedAt) over ResolvedCount findings.
type MTTRSummary struct {
	ResolvedCount int     `json:"resolved_count"`
	Seconds       float64 `json:"seconds"`
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
	var mttrTotal time.Duration
	mttrCount := 0

	for _, finding := range findings {
		status := effectiveStatus(finding, now)

		// Open rollups exclude suppressed/resolved findings.
		if status == domain.FindingLifecycleOpen || status == domain.FindingLifecycleAck {
			report.TotalOpenFindings++
			report.OpenBySeverity[finding.Severity]++
			report.OpenByType[finding.Type]++
		}

		// MTTR uses only the trustworthy ResolvedAt timestamp; resolved
		// findings without a reliable ResolvedAt are excluded rather than
		// approximated from the mutable UpdatedAt.
		if status == domain.FindingLifecycleResolved {
			if resolvedAt := finding.Triage.ResolvedAt; resolvedAt != nil && !resolvedAt.IsZero() {
				if c := finding.CreatedAt; !c.IsZero() && !resolvedAt.Before(c) {
					mttrTotal += resolvedAt.Sub(c)
					mttrCount++
				}
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

	report.WeekOverWeek = WeekOverWeekTrend{
		CurrentCount:  currentWeek,
		PreviousCount: previousWeek,
		Delta:         currentWeek - previousWeek,
	}
	report.TopFindingTypes = topFindingTypes(report.OpenByType, topN)
	if mttrCount > 0 {
		report.MeanTimeToResolve = &MTTRSummary{
			ResolvedCount: mttrCount,
			Seconds:       mttrTotal.Seconds() / float64(mttrCount),
		}
	}
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
