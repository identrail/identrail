// Package userexport builds the self-serve "Download my data" ZIP bundle for
// #1421. It is split out from the API/worker so both can drive the same
// deterministic bundle layout and tests can exercise it without an HTTP server.
//
// Bundle layout (also documented in CHANGELOG and the OpenAPI spec):
//
//	manifest.json   — schema version, generated_at, user_id, file list.
//	user.json       — the requesting user's profile snapshot.
//	workspaces.json — workspaces the user is a member of, with role and joined-at.
//	audit.json      — durable, user-actor events derivable from store rows.
//	sessions.json   — historical session metadata (no token material).
//
// The package writes one ZIP stream; callers persist it wherever appropriate
// (local disk in dev, object storage in production).
package userexport

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/identrail/identrail/internal/db"
)

// Source narrows the store surface the bundle builder reads from. Keeping the
// interface tight matches the userpurge package convention and makes tests
// trivially mockable.
type Source interface {
	GetUser(ctx context.Context, userID string) (db.User, error)
	ListUserSessionHistory(ctx context.Context, userID string, limit int) ([]db.Session, error)
	ListWorkspaceMembershipsByUserUUID(ctx context.Context, userUUID string) ([]db.TenancyWorkspaceMember, error)
	GetOnboardingState(ctx context.Context, userID string) (db.OnboardingState, error)
}

// Result reports what the build produced so callers can persist the bundle
// (size + checksum end up on the user_data_exports row).
type Result struct {
	SizeBytes int64
	SHA256    string
}

// UserPayload is the JSON shape of user.json. Only fields the user already
// sees in /v1/me are included — the bundle is not a path for exfiltrating
// staff-only metadata.
type UserPayload struct {
	ID           string     `json:"id"`
	PrimaryEmail string     `json:"primary_email"`
	DisplayName  string     `json:"display_name,omitempty"`
	AvatarURL    string     `json:"avatar_url,omitempty"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

// WorkspacePayload is the JSON shape of one row in workspaces.json.
type WorkspacePayload struct {
	TenantID    string    `json:"tenant_id"`
	WorkspaceID string    `json:"workspace_id"`
	Role        string    `json:"role"`
	Status      string    `json:"status"`
	JoinedAt    time.Time `json:"joined_at"`
}

// SessionPayload is the JSON shape of one row in sessions.json. The opaque
// session ID hash is intentionally omitted — including it would expose a
// fingerprint usable to correlate sessions across the export.
type SessionPayload struct {
	AuthMethod        string     `json:"auth_method"`
	IP                string     `json:"ip,omitempty"`
	UserAgent         string     `json:"user_agent,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	IdleExpiresAt     time.Time  `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time  `json:"absolute_expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
}

// AuditPayload is the JSON shape of one row in audit.json. Audit sinks (file
// / HTTP) are external systems and are not readable from the API, so the
// events here are derived from durable rows the user is the actor of —
// account lifecycle timestamps, session activity, workspace joins,
// onboarding.
type AuditPayload struct {
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	Resource  string    `json:"resource,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
}

// Manifest is the top-level manifest.json. It records the schema version and
// the bundle contents so consumers can detect mismatches without unzipping.
type Manifest struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	UserID        string    `json:"user_id"`
	Files         []string  `json:"files"`
}

// BundleSchemaVersion is the version stamped into manifest.json. Bumped when
// the bundle layout changes in a way that breaks downstream parsers.
const BundleSchemaVersion = "1"

// Write streams a bundle for userID into w and returns the size + checksum.
// now is taken as a parameter so tests can pin time without relying on
// time.Now() inside the package.
func Write(ctx context.Context, src Source, userID string, now time.Time, w io.Writer) (Result, error) {
	if src == nil {
		return Result{}, errors.New("userexport: source is required")
	}
	if userID == "" {
		return Result{}, errors.New("userexport: user_id is required")
	}
	user, err := src.GetUser(ctx, userID)
	if err != nil {
		return Result{}, fmt.Errorf("load user: %w", err)
	}

	workspaces, err := loadWorkspaces(ctx, src, userID)
	if err != nil {
		return Result{}, err
	}
	sessions, err := loadSessions(ctx, src, userID)
	if err != nil {
		return Result{}, err
	}
	audits, err := loadAudit(ctx, src, user, sessions, workspaces)
	if err != nil {
		return Result{}, err
	}

	manifest := Manifest{
		SchemaVersion: BundleSchemaVersion,
		GeneratedAt:   now.UTC(),
		UserID:        user.ID,
		Files: []string{
			"manifest.json",
			"user.json",
			"workspaces.json",
			"audit.json",
			"sessions.json",
		},
	}

	hasher := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(w, hasher)}
	zw := zip.NewWriter(counter)

	if err := writeJSONFile(zw, "manifest.json", manifest, now); err != nil {
		return Result{}, err
	}
	if err := writeJSONFile(zw, "user.json", userPayload(user), now); err != nil {
		return Result{}, err
	}
	if err := writeJSONFile(zw, "workspaces.json", workspaces, now); err != nil {
		return Result{}, err
	}
	if err := writeJSONFile(zw, "audit.json", audits, now); err != nil {
		return Result{}, err
	}
	if err := writeJSONFile(zw, "sessions.json", sessions, now); err != nil {
		return Result{}, err
	}
	if err := zw.Close(); err != nil {
		return Result{}, fmt.Errorf("close zip: %w", err)
	}
	return Result{
		SizeBytes: counter.n,
		SHA256:    hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func userPayload(user db.User) UserPayload {
	payload := UserPayload{
		ID:           user.ID,
		PrimaryEmail: user.PrimaryEmail,
		DisplayName:  user.DisplayName,
		AvatarURL:    user.AvatarURL,
		Status:       user.Status,
		CreatedAt:    user.CreatedAt.UTC(),
		UpdatedAt:    user.UpdatedAt.UTC(),
	}
	if user.DeletedAt != nil {
		t := user.DeletedAt.UTC()
		payload.DeletedAt = &t
	}
	return payload
}

func loadWorkspaces(ctx context.Context, src Source, userID string) ([]WorkspacePayload, error) {
	memberships, err := src.ListWorkspaceMembershipsByUserUUID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list workspace memberships: %w", err)
	}
	payloads := make([]WorkspacePayload, 0, len(memberships))
	for _, m := range memberships {
		payloads = append(payloads, WorkspacePayload{
			TenantID:    m.TenantID,
			WorkspaceID: m.WorkspaceID,
			Role:        m.Role,
			Status:      m.Status,
			JoinedAt:    m.JoinedAt.UTC(),
		})
	}
	sort.Slice(payloads, func(i, j int) bool {
		if payloads[i].TenantID != payloads[j].TenantID {
			return payloads[i].TenantID < payloads[j].TenantID
		}
		return payloads[i].WorkspaceID < payloads[j].WorkspaceID
	})
	return payloads, nil
}

func loadSessions(ctx context.Context, src Source, userID string) ([]SessionPayload, error) {
	rows, err := src.ListUserSessionHistory(ctx, userID, 0)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	payloads := make([]SessionPayload, 0, len(rows))
	for _, s := range rows {
		payload := SessionPayload{
			AuthMethod:        s.AuthMethod,
			IP:                s.IP,
			UserAgent:         s.UserAgent,
			CreatedAt:         s.CreatedAt.UTC(),
			LastSeenAt:        s.LastSeenAt.UTC(),
			IdleExpiresAt:     s.IdleExpiresAt.UTC(),
			AbsoluteExpiresAt: s.AbsoluteExpiresAt.UTC(),
		}
		if s.RevokedAt != nil {
			t := s.RevokedAt.UTC()
			payload.RevokedAt = &t
		}
		payloads = append(payloads, payload)
	}
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].LastSeenAt.After(payloads[j].LastSeenAt)
	})
	return payloads, nil
}

func loadAudit(ctx context.Context, src Source, user db.User, sessions []SessionPayload, workspaces []WorkspacePayload) ([]AuditPayload, error) {
	events := make([]AuditPayload, 0, 4+len(sessions)+len(workspaces))
	events = append(events, AuditPayload{
		Action:    "auth.user.create",
		Timestamp: user.CreatedAt.UTC(),
		Resource:  "user:" + user.ID,
		Outcome:   "success",
	})
	if !user.UpdatedAt.Equal(user.CreatedAt) {
		events = append(events, AuditPayload{
			Action:    "auth.user.update",
			Timestamp: user.UpdatedAt.UTC(),
			Resource:  "user:" + user.ID,
			Outcome:   "success",
		})
	}
	if user.DeletedAt != nil {
		events = append(events, AuditPayload{
			Action:    "auth.user.delete",
			Timestamp: user.DeletedAt.UTC(),
			Resource:  "user:" + user.ID,
			Outcome:   "success",
		})
	}
	for _, s := range sessions {
		events = append(events, AuditPayload{
			Action:    "auth.session.create",
			Timestamp: s.CreatedAt,
			Resource:  "session:" + s.AuthMethod,
			Outcome:   "success",
		})
		if s.RevokedAt != nil {
			events = append(events, AuditPayload{
				Action:    "auth.session.revoke",
				Timestamp: *s.RevokedAt,
				Resource:  "session:" + s.AuthMethod,
				Outcome:   "success",
			})
		}
	}
	for _, w := range workspaces {
		events = append(events, AuditPayload{
			Action:    "tenancy.workspace.join",
			Timestamp: w.JoinedAt,
			Resource:  "workspace:" + w.WorkspaceID,
			Outcome:   "success",
		})
	}
	if state, err := src.GetOnboardingState(ctx, user.ID); err == nil {
		events = append(events, AuditPayload{
			Action:    "onboarding.start",
			Timestamp: state.StartedAt.UTC(),
			Resource:  "user:" + user.ID,
			Outcome:   "success",
		})
		if state.CompletedAt != nil {
			events = append(events, AuditPayload{
				Action:    "onboarding.complete",
				Timestamp: state.CompletedAt.UTC(),
				Resource:  "user:" + user.ID,
				Outcome:   "success",
			})
		}
	} else if !errors.Is(err, db.ErrNotFound) {
		return nil, fmt.Errorf("load onboarding state: %w", err)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	return events, nil
}

func writeJSONFile(zw *zip.Writer, name string, payload any, modified time.Time) error {
	header := &zip.FileHeader{
		Name:     name,
		Method:   zip.Deflate,
		Modified: modified.UTC(),
	}
	w, err := zw.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create zip entry %s: %w", name, err)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	return nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
