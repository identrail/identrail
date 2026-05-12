package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const cronSearchLimit = 366 * 24 * 60

// CronSchedule is a small five-field cron matcher used by the scan-policy
// scheduler. It supports the common portable cron forms: *, */n, n, n-m,
// n-m/s, and comma-separated combinations.
type CronSchedule struct {
	minutes      map[int]bool
	hours        map[int]bool
	monthDays    map[int]bool
	monthDaysAny bool
	months       map[int]bool
	weekDays     map[int]bool
	weekDaysAny  bool
}

// ParseCronSchedule parses a standard five-field cron expression.
func ParseCronSchedule(expr string) (CronSchedule, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return CronSchedule{}, fmt.Errorf("cron expression must contain 5 fields")
	}

	minutes, err := parseCronField(fields[0], 0, 59)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("minute field: %w", err)
	}
	hours, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("hour field: %w", err)
	}
	monthDays, err := parseCronField(fields[2], 1, 31)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("day-of-month field: %w", err)
	}
	months, err := parseCronField(fields[3], 1, 12)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("month field: %w", err)
	}
	weekDays, err := parseCronField(fields[4], 0, 7)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("day-of-week field: %w", err)
	}
	if weekDays[7] {
		weekDays[0] = true
		delete(weekDays, 7)
	}

	return CronSchedule{
		minutes:      minutes,
		hours:        hours,
		monthDays:    monthDays,
		monthDaysAny: strings.TrimSpace(fields[2]) == "*",
		months:       months,
		weekDays:     weekDays,
		weekDaysAny:  strings.TrimSpace(fields[4]) == "*",
	}, nil
}

// LatestAfter returns the latest matching cron tick at or before now and after
// the provided exclusive boundary. This lets callers recover missed runs
// without backfilling duplicates for older ticks.
func (s CronSchedule) LatestAfter(after time.Time, now time.Time) (time.Time, bool) {
	cursor := now.UTC().Truncate(time.Minute)
	boundary := after.UTC()
	for i := 0; i < cronSearchLimit && cursor.After(boundary); i++ {
		if s.matches(cursor) {
			return cursor, true
		}
		cursor = cursor.Add(-time.Minute)
	}
	return time.Time{}, false
}

func (s CronSchedule) matches(t time.Time) bool {
	monthDayMatches := s.monthDays[t.Day()]
	weekDayMatches := s.weekDays[int(t.Weekday())]
	dayMatches := false
	switch {
	case s.monthDaysAny && s.weekDaysAny:
		dayMatches = true
	case s.monthDaysAny:
		dayMatches = weekDayMatches
	case s.weekDaysAny:
		dayMatches = monthDayMatches
	default:
		dayMatches = monthDayMatches || weekDayMatches
	}
	return s.minutes[t.Minute()] &&
		s.hours[t.Hour()] &&
		s.months[int(t.Month())] &&
		dayMatches
}

func parseCronField(raw string, min int, max int) (map[int]bool, error) {
	values := make(map[int]bool)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty cron field part")
		}
		start, end, step, err := parseCronPart(part, min, max)
		if err != nil {
			return nil, err
		}
		for value := start; value <= end; value += step {
			values[value] = true
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no cron values")
	}
	return values, nil
}

func parseCronPart(part string, min int, max int) (int, int, int, error) {
	step := 1
	base := part
	if strings.Contains(part, "/") {
		pieces := strings.Split(part, "/")
		if len(pieces) != 2 || pieces[0] == "" || pieces[1] == "" {
			return 0, 0, 0, fmt.Errorf("invalid step %q", part)
		}
		base = pieces[0]
		parsedStep, err := strconv.Atoi(pieces[1])
		if err != nil || parsedStep <= 0 {
			return 0, 0, 0, fmt.Errorf("invalid step %q", part)
		}
		step = parsedStep
	}

	if base == "*" {
		return min, max, step, nil
	}

	if strings.Contains(base, "-") {
		pieces := strings.Split(base, "-")
		if len(pieces) != 2 || pieces[0] == "" || pieces[1] == "" {
			return 0, 0, 0, fmt.Errorf("invalid range %q", part)
		}
		start, err := strconv.Atoi(pieces[0])
		if err != nil {
			return 0, 0, 0, fmt.Errorf("invalid range start %q", part)
		}
		end, err := strconv.Atoi(pieces[1])
		if err != nil {
			return 0, 0, 0, fmt.Errorf("invalid range end %q", part)
		}
		if start < min || end > max || start > end {
			return 0, 0, 0, fmt.Errorf("range %q outside %d-%d", part, min, max)
		}
		return start, end, step, nil
	}

	value, err := strconv.Atoi(base)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid value %q", part)
	}
	if value < min || value > max {
		return 0, 0, 0, fmt.Errorf("value %q outside %d-%d", part, min, max)
	}
	return value, value, step, nil
}
