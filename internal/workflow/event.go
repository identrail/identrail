// Package workflow routes finding lifecycle events to engineering and security
// workflow destinations (Slack, Jira, Linear) and emits an auditable record of
// every dispatch attempt for governance.
//
// The package is destination-agnostic: a Router fans an Event out to any
// Destination that opts in via its AlertPolicy. Every dispatch — success or
// failure — is captured as a DispatchRecord and forwarded to the AuditSink so
// the deployment can prove which lifecycle transitions reached which systems.
package workflow

import (
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

// EventKind enumerates the finding lifecycle transitions that can be routed.
type EventKind string

const (
	EventFindingCreated      EventKind = "finding.created"
	EventFindingAcknowledged EventKind = "finding.acknowledged"
	EventFindingSuppressed   EventKind = "finding.suppressed"
	EventFindingResolved     EventKind = "finding.resolved"
	EventFixPROpened         EventKind = "finding.fix_pr_opened"
)

// Event is one finding lifecycle event delivered to workflow destinations.
type Event struct {
	Kind       EventKind      `json:"kind"`
	Finding    domain.Finding `json:"finding"`
	Actor      string         `json:"actor,omitempty"`
	Note       string         `json:"note,omitempty"`
	EmittedAt  time.Time      `json:"emitted_at"`
	RelatedURL string         `json:"related_url,omitempty"`
}

// Validate enforces the minimum invariants every destination relies on.
func (e Event) Validate() error {
	if strings.TrimSpace(string(e.Kind)) == "" {
		return fmt.Errorf("event kind is required")
	}
	if strings.TrimSpace(e.Finding.ID) == "" {
		return fmt.Errorf("event finding.id is required")
	}
	return nil
}

// AlertPolicy filters events before they reach a destination. Zero-value
// fields are treated as "no constraint".
type AlertPolicy struct {
	MinSeverity domain.FindingSeverity
	AllowKinds  []EventKind
	AllowTypes  []domain.FindingType
}

// Allow reports whether the event passes the policy.
//
// A policy with an unrecognized MinSeverity fails closed (no events admitted)
// so a typo in configuration cannot accidentally fan low-severity events out
// to ticketing/chat destinations.
func (p AlertPolicy) Allow(event Event) bool {
	if p.MinSeverity != "" {
		ok, floorRank := severityRankOf(p.MinSeverity)
		if !ok {
			return false
		}
		eventOK, eventRank := severityRankOf(event.Finding.Severity)
		if !eventOK || eventRank < floorRank {
			return false
		}
	}
	if len(p.AllowKinds) > 0 && !containsKind(p.AllowKinds, event.Kind) {
		return false
	}
	if len(p.AllowTypes) > 0 && !containsType(p.AllowTypes, event.Finding.Type) {
		return false
	}
	return true
}

// Validate reports whether the policy is internally consistent. An unset
// MinSeverity is valid (no floor); a set MinSeverity must be a recognized
// severity value so the policy cannot silently fail open at runtime.
func (p AlertPolicy) Validate() error {
	if p.MinSeverity != "" {
		if ok, _ := severityRankOf(p.MinSeverity); !ok {
			return fmt.Errorf("unrecognized min severity %q", p.MinSeverity)
		}
	}
	return nil
}

var severityRank = map[domain.FindingSeverity]int{
	domain.SeverityInfo:     1,
	domain.SeverityLow:      2,
	domain.SeverityMedium:   3,
	domain.SeverityHigh:     4,
	domain.SeverityCritical: 5,
}

func severityRankOf(s domain.FindingSeverity) (bool, int) {
	rank, ok := severityRank[s]
	return ok, rank
}

func containsKind(allow []EventKind, candidate EventKind) bool {
	for _, k := range allow {
		if k == candidate {
			return true
		}
	}
	return false
}

func containsType(allow []domain.FindingType, candidate domain.FindingType) bool {
	for _, t := range allow {
		if t == candidate {
			return true
		}
	}
	return false
}

func valueOrFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
