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
type SCIMUser struct {
	ID          string    `json:"id"`
	ExternalID  string    `json:"external_id,omitempty"`
	UserName    string    `json:"user_name"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name,omitempty"`
	Active      bool      `json:"active"`
	Groups      []string  `json:"groups,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Validate enforces SCIM core schema invariants relevant to Identrail.
func (u SCIMUser) Validate() error {
	if strings.TrimSpace(u.ID) == "" {
		return fmt.Errorf("scim user id is required")
	}
	if strings.TrimSpace(u.UserName) == "" {
		return fmt.Errorf("scim user userName is required")
	}
	if _, err := mail.ParseAddress(u.Email); err != nil {
		return fmt.Errorf("scim user email %q is invalid: %w", u.Email, err)
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
