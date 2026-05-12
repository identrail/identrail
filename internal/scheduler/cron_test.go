package scheduler

import (
	"testing"
	"time"
)

func TestCronScheduleLatestAfterRecoversLatestMissedTick(t *testing.T) {
	schedule, err := ParseCronSchedule("*/5 * * * *")
	if err != nil {
		t.Fatalf("ParseCronSchedule returned error: %v", err)
	}

	after := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 12, 12, 17, 30, 0, time.UTC)
	tick, ok := schedule.LatestAfter(after, now)
	if !ok {
		t.Fatal("expected a due tick")
	}

	want := time.Date(2026, 5, 12, 12, 15, 0, 0, time.UTC)
	if !tick.Equal(want) {
		t.Fatalf("tick = %s, want %s", tick, want)
	}
}

func TestCronScheduleLatestAfterRejectsDuplicateBoundary(t *testing.T) {
	schedule, err := ParseCronSchedule("*/5 * * * *")
	if err != nil {
		t.Fatalf("ParseCronSchedule returned error: %v", err)
	}

	boundary := time.Date(2026, 5, 12, 12, 15, 0, 0, time.UTC)
	if tick, ok := schedule.LatestAfter(boundary, boundary.Add(30*time.Second)); ok {
		t.Fatalf("expected no duplicate tick, got %s", tick)
	}
}

func TestParseCronScheduleValidatesFields(t *testing.T) {
	if _, err := ParseCronSchedule("*/0 * * * *"); err == nil {
		t.Fatal("expected invalid step to fail")
	}
	if _, err := ParseCronSchedule("* * *"); err == nil {
		t.Fatal("expected short expression to fail")
	}
	if _, err := ParseCronSchedule("60 * * * *"); err == nil {
		t.Fatal("expected out-of-range minute to fail")
	}
}

func TestParseCronScheduleSupportsCompositeSyntaxAndSundayAlias(t *testing.T) {
	schedule, err := ParseCronSchedule("1-10/3 4,8 * * 7")
	if err != nil {
		t.Fatalf("ParseCronSchedule returned error: %v", err)
	}

	now := time.Date(2026, 5, 17, 8, 10, 0, 0, time.UTC) // Sunday
	tick, ok := schedule.LatestAfter(now.Add(-20*time.Minute), now)
	if !ok {
		t.Fatal("expected a due tick")
	}
	want := time.Date(2026, 5, 17, 8, 10, 0, 0, time.UTC)
	if !tick.Equal(want) {
		t.Fatalf("tick = %s, want %s", tick, want)
	}
}

func TestCronScheduleLatestAfterReturnsFalseWhenWindowHasNoMatch(t *testing.T) {
	schedule, err := ParseCronSchedule("0 0 1 1 *")
	if err != nil {
		t.Fatalf("ParseCronSchedule returned error: %v", err)
	}

	after := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 12, 12, 20, 0, 0, time.UTC)
	if tick, ok := schedule.LatestAfter(after, now); ok {
		t.Fatalf("expected no tick, got %s", tick)
	}
}

func TestCronScheduleDayOfMonthAndDayOfWeekUseORSemantics(t *testing.T) {
	schedule, err := ParseCronSchedule("0 9 1 * 1")
	if err != nil {
		t.Fatalf("ParseCronSchedule returned error: %v", err)
	}

	// 2026-06-08 is Monday but not the 1st day of month.
	now := time.Date(2026, 6, 8, 9, 0, 0, 0, time.UTC)
	after := now.Add(-2 * time.Hour)
	tick, ok := schedule.LatestAfter(after, now)
	if !ok {
		t.Fatal("expected Monday tick to match")
	}
	if !tick.Equal(now) {
		t.Fatalf("tick = %s, want %s", tick, now)
	}
}
