package auth

import (
	"strings"

	"github.com/identrail/identrail/internal/audit"
)

const (
	AuditActionInvitationCreate         = "auth.invitation.create"
	AuditActionInvitationRevoke         = "auth.invitation.revoke"
	AuditActionDomainCreate             = "auth.domain.create"
	AuditActionDomainVerify             = "auth.domain.verify"
	AuditActionIdentityConnectionCreate = "auth.identity_connection.create"
)

// EnterpriseAuditEvent builds the action audit envelope used by future enterprise auth flows.
func EnterpriseAuditEvent(action string, orgID string, resourceType string, resourceID string, outcome string) audit.AuditEvent {
	return audit.AuditEvent{
		Action:       strings.TrimSpace(action),
		TenantID:     strings.TrimSpace(orgID),
		ResourceType: strings.TrimSpace(resourceType),
		ResourceID:   strings.TrimSpace(resourceID),
		Outcome:      strings.TrimSpace(outcome),
	}
}
