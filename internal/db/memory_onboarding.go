package db

import (
	"context"
	"strings"

	"github.com/identrail/identrail/internal/audit"
)

// UpsertOnboardingState persists one user-scoped onboarding progress row.
func (m *MemoryStore) UpsertOnboardingState(ctx context.Context, state OnboardingState) (OnboardingState, error) {
	normalized, err := NormalizeOnboardingStateForWrite(state)
	if err != nil {
		return OnboardingState{}, err
	}
	m.mu.Lock()
	if _, exists := m.users[normalized.UserID]; !exists {
		m.mu.Unlock()
		return OnboardingState{}, ErrNotFound
	}
	if existing, exists := m.onboardingStates[normalized.UserID]; exists && !existing.StartedAt.IsZero() {
		normalized.StartedAt = existing.StartedAt
	}
	m.onboardingStates[normalized.UserID] = normalized
	m.mu.Unlock()
	audit.WriteAction(ctx, audit.AuditEvent{
		Action:       "onboarding.state.upsert",
		ResourceType: "onboarding_state",
		ResourceID:   normalized.UserID,
		Outcome:      "success",
	})
	return normalized, nil
}

// GetOnboardingState returns one user's onboarding progress row.
func (m *MemoryStore) GetOnboardingState(ctx context.Context, userID string) (OnboardingState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, exists := m.onboardingStates[strings.TrimSpace(userID)]
	if !exists {
		return OnboardingState{}, ErrNotFound
	}
	return state, nil
}
