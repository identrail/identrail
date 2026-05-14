package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNormalizeOnboardingStateForWriteDefaultsAndUTC(t *testing.T) {
	dismissedAt := time.Date(2026, 5, 14, 11, 30, 0, 0, time.FixedZone("WAT", 3600))
	completedAt := time.Date(2026, 5, 14, 12, 0, 0, 0, time.FixedZone("WAT", 3600))
	startedAt := time.Date(2026, 5, 14, 10, 0, 0, 0, time.FixedZone("WAT", 3600))
	updatedAt := time.Date(2026, 5, 14, 10, 15, 0, 0, time.FixedZone("WAT", 3600))

	state, err := NormalizeOnboardingStateForWrite(OnboardingState{
		UserID:                   " 11111111-1111-4111-8111-111111111111 ",
		CurrentStep:              " scan ",
		OrgID:                    " tenant-a ",
		WorkspaceID:              " production ",
		ProjectID:                " default ",
		ConnectorID:              " conn-1 ",
		ConnectorType:            " GitHub ",
		DashboardTourDismissedAt: &dismissedAt,
		CompletedAt:              &completedAt,
		StartedAt:                startedAt,
		UpdatedAt:                updatedAt,
	})
	if err != nil {
		t.Fatalf("normalize state: %v", err)
	}
	if state.UserID != "11111111-1111-4111-8111-111111111111" ||
		state.CurrentStep != "complete" ||
		state.OrgID != "tenant-a" ||
		state.WorkspaceID != "production" ||
		state.ProjectID != "default" ||
		state.ConnectorID != "conn-1" ||
		state.ConnectorType != "github" {
		t.Fatalf("unexpected normalized state: %+v", state)
	}
	if state.StartedAt.Location() != time.UTC ||
		state.UpdatedAt.Location() != time.UTC ||
		state.CompletedAt == nil || state.CompletedAt.Location() != time.UTC ||
		state.DashboardTourDismissedAt == nil || state.DashboardTourDismissedAt.Location() != time.UTC {
		t.Fatalf("expected UTC timestamps, got %+v", state)
	}
}

func TestNormalizeOnboardingStateForWriteRejectsInvalidState(t *testing.T) {
	cases := []struct {
		name  string
		state OnboardingState
	}{
		{name: "missing user", state: OnboardingState{CurrentStep: "org"}},
		{name: "invalid user", state: OnboardingState{UserID: "not-a-uuid", CurrentStep: "org"}},
		{name: "invalid step", state: OnboardingState{UserID: "11111111-1111-4111-8111-111111111111", CurrentStep: "billing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NormalizeOnboardingStateForWrite(tc.state); err == nil {
				t.Fatal("expected invalid onboarding state to fail")
			}
		})
	}
}

func TestMemoryStoreOnboardingStateLifecycle(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if _, err := store.GetOnboardingState(ctx, "11111111-1111-4111-8111-111111111111"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing onboarding state to return ErrNotFound, got %v", err)
	}
	if _, err := store.UpsertOnboardingState(ctx, OnboardingState{
		UserID:      "11111111-1111-4111-8111-111111111111",
		CurrentStep: "org",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected unknown user upsert to return ErrNotFound, got %v", err)
	}

	user, err := store.UpsertUser(ctx, User{
		ID:           "11111111-1111-4111-8111-111111111111",
		PrimaryEmail: "owner@example.com",
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("upsert user: %v", err)
	}
	startedAt := time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC)
	saved, err := store.UpsertOnboardingState(ctx, OnboardingState{
		UserID:      user.ID,
		CurrentStep: "workspace",
		StartedAt:   startedAt,
	})
	if err != nil {
		t.Fatalf("upsert onboarding state: %v", err)
	}
	if saved.CurrentStep != "workspace" || !saved.StartedAt.Equal(startedAt) {
		t.Fatalf("unexpected saved state: %+v", saved)
	}

	updated, err := store.UpsertOnboardingState(ctx, OnboardingState{
		UserID:      user.ID,
		CurrentStep: "connect",
	})
	if err != nil {
		t.Fatalf("update onboarding state: %v", err)
	}
	if updated.CurrentStep != "connect" || !updated.StartedAt.Equal(startedAt) {
		t.Fatalf("expected update to preserve started_at, got %+v", updated)
	}
	loaded, err := store.GetOnboardingState(ctx, " "+user.ID+" ")
	if err != nil {
		t.Fatalf("get onboarding state: %v", err)
	}
	if loaded.CurrentStep != "connect" {
		t.Fatalf("expected loaded connect step, got %+v", loaded)
	}
}
