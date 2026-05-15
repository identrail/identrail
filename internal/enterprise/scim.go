// Package enterprise provides the foundational domain models for Identrail's
// enterprise-tier controls: SCIM provisioning, SAML federation, data-residency
// policy enforcement, and executive risk reporting.
//
// This package is intentionally I/O-free. It defines the types, validation,
// and aggregation logic that API and persistence layers later wire to HTTP
// endpoints and storage. Keeping the models pure makes them testable in
// isolation and reusable across CLI, API, and worker entry points.
package enterprise

import (
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// SCIMUserActiveStatus reflects whether a SCIM-provisioned principal is enabled.
type SCIMUserActiveStatus bool

// SCIMUser is the subset of the SCIM 2.0 core user schema Identrail consumes
// for enterprise provisioning. Fields map to the canonical schema URN
// "urn:ietf:params:scim:schemas:core:2.0:User"; only the attributes required
// for tenant onboarding and lifecycle are modeled here so a directory-sync
// provider can drive create / update / deactivate without leaking provider
// specifics into the rest of the system.
//
// JSON tags follow the SCIM 2.0 on-wire shape so the future /scim/v2/Users
// handler can decode standard provider payloads (Okta, Azure AD, OneLogin,
// etc.) directly into this struct without an intermediate wire DTO. In
// particular, email addresses are carried in the SCIM `emails` multi-valued
// attribute and resource timestamps live under the SCIM `meta` complex
// attribute (`meta.created`, `meta.lastModified`).
type SCIMUser struct {
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      bool        `json:"active"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Groups      []string    `json:"groups,omitempty"`
	Meta        SCIMMeta    `json:"meta"`
}

// SCIMEmail mirrors one entry of the SCIM `emails` multi-valued attribute.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMMeta carries the SCIM `meta` complex attribute. Only the fields
// Identrail relies on are modeled.
type SCIMMeta struct {
	ResourceType string    `json:"resourceType,omitempty"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// PrimaryEmail returns the canonical login identifier for the user: the
// primary entry in Emails when one is marked, otherwise the first non-empty
// value. Empty string when no usable email is present.
func (u SCIMUser) PrimaryEmail() string {
	firstNonEmpty := ""
	for _, e := range u.Emails {
		value := strings.TrimSpace(e.Value)
		if value == "" {
			continue
		}
		if e.Primary {
			return value
		}
		if firstNonEmpty == "" {
			firstNonEmpty = value
		}
	}
	return firstNonEmpty
}

// Validate enforces SCIM core schema invariants relevant to Identrail. The
// `id` attribute is intentionally NOT required here because SCIM 2.0 servers
// assign it on a successful POST /Users create — the resource arrives without
// one. Operations that semantically require an existing identifier
// (update/deactivate/delete) are enforced in SCIMProvisioningEvent.Validate.
//
// At most one email entry may be marked primary. Standard SCIM clients honor
// the multi-valued `primary` sub-attribute and assume it is unique; accepting
// duplicates silently would let a provider quirk reorder the login-identity
// selection on every payload.
//
// The selected primary email must be a plain addr-spec (e.g.
// "alice@example.com") rather than the mailbox display syntax accepted by
// net/mail ("Alice <alice@example.com>"). The downstream provisioning path
// upserts this string into the users/identities tables as a login identifier,
// so accepting display syntax would persist a non-canonical email.
func (u SCIMUser) Validate() error {
	if strings.TrimSpace(u.UserName) == "" {
		return fmt.Errorf("scim user userName is required")
	}
	primaryCount := 0
	for _, e := range u.Emails {
		if e.Primary {
			primaryCount++
		}
	}
	if primaryCount > 1 {
		return fmt.Errorf("scim user must declare at most one primary email, got %d", primaryCount)
	}
	email := u.PrimaryEmail()
	if email == "" {
		return fmt.Errorf("scim user must include at least one email value")
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("scim user email %q is invalid: %w", email, err)
	}
	if !strings.EqualFold(parsed.Address, email) {
		return fmt.Errorf("scim user email %q must be a plain address without display name", email)
	}
	return nil
}

// SCIMProvisioningOp enumerates the lifecycle operations a SCIM source can
// apply to a user. These mirror SCIM 2.0 protocol verbs (POST/PUT/PATCH/DELETE)
// reduced to the semantic transitions Identrail persists.
type SCIMProvisioningOp string

const (
	SCIMProvisioningCreate     SCIMProvisioningOp = "create"
	SCIMProvisioningUpdate     SCIMProvisioningOp = "update"
	SCIMProvisioningDeactivate SCIMProvisioningOp = "deactivate"
	SCIMProvisioningDelete     SCIMProvisioningOp = "delete"
)

// SCIMProvisioningEvent records one provisioning operation for audit and
// downstream workflow routing. It is emitted by the SCIM endpoint handler and
// can be persisted, dispatched to the workflow router for governance, or
// replayed against secondary stores.
type SCIMProvisioningEvent struct {
	Op            SCIMProvisioningOp `json:"op"`
	User          SCIMUser           `json:"user"`
	SourceTenant  string             `json:"source_tenant"`
	OccurredAt    time.Time          `json:"occurred_at"`
	CorrelationID string             `json:"correlation_id,omitempty"`
}

// Validate enforces the invariants every provisioning consumer relies on.
//
// Per RFC 7644, SCIM `id` is server-assigned on POST /Users (create), so it
// is intentionally optional on create events; update/deactivate/delete events
// must carry the resource id since they reference an existing user. The SCIM
// DELETE protocol does not carry a user body at all — only the id in the path
// — so this method skips the full SCIMUser.Validate for that op.
func (e SCIMProvisioningEvent) Validate() error {
	if !validSCIMProvisioningOp(e.Op) {
		return fmt.Errorf("scim provisioning op %q is not recognized", e.Op)
	}
	if strings.TrimSpace(e.SourceTenant) == "" {
		return fmt.Errorf("scim provisioning event source_tenant is required")
	}
	if e.OccurredAt.IsZero() {
		return fmt.Errorf("scim provisioning event occurred_at is required")
	}
	if e.Op == SCIMProvisioningDelete {
		if strings.TrimSpace(e.User.ID) == "" {
			return fmt.Errorf("scim provisioning delete event requires user.id")
		}
		return nil
	}
	if e.Op != SCIMProvisioningCreate && strings.TrimSpace(e.User.ID) == "" {
		return fmt.Errorf("scim provisioning %s event requires user.id", e.Op)
	}
	if err := e.User.Validate(); err != nil {
		return fmt.Errorf("scim provisioning event user invalid: %w", err)
	}
	if e.Op == SCIMProvisioningDeactivate && e.User.Active {
		return fmt.Errorf("deactivate event must carry user.active=false")
	}
	return nil
}

func validSCIMProvisioningOp(op SCIMProvisioningOp) bool {
	switch op {
	case SCIMProvisioningCreate, SCIMProvisioningUpdate, SCIMProvisioningDeactivate, SCIMProvisioningDelete:
		return true
	}
	return false
}
