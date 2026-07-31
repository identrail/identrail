package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/identrail/identrail/internal/db"
)

// processAWSOrganizationRolloutMemberRegistration accepts one authenticated
// StackSet member-account registration event. It routes off the presence of a
// RolloutId in the CloudFormation custom-resource properties so the extended
// path shares the single-account SNS/SQS delivery envelope, deduplication,
// authentication topic-ARN pinning, and CloudFormation acknowledgement
// contract; only the target write and scope binding are new here.
//
// Deep STS role validation is deliberately deferred. This slice persists an
// authenticated per-target registration in the `validating` state so the app
// stops calling the target "connected" until a follow-up worker actually
// proves the role. The rollout is never marked complete on the strength of
// this handler alone.
func (s *Service) processAWSOrganizationRolloutMemberRegistration(
	ctx context.Context,
	topicARN string,
	request awsCloudFormationCustomResourceRequest,
	phase string,
) error {
	if phase != "Register" {
		// Member-account rollout registration does not use a Bootstrap phase.
		// Bootstrap is per-account server-side External ID delivery; rollout
		// events reuse the rollout's one-time secret, which is delivered as
		// a StackSet parameter, not a challenged custom-resource attribute.
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail rollout registration phase is invalid.", fmt.Errorf("rollout registration phase must be Register"))
	}
	rolloutID := awsRegistrationProperty(request.ResourceProperties, "RolloutId")
	secret := awsRegistrationProperty(request.ResourceProperties, "RegistrationSecret")
	roleARN := awsRegistrationProperty(request.ResourceProperties, "RoleArn")
	organizationID := awsRegistrationProperty(request.ResourceProperties, "OrganizationId")
	stackSetName := awsRegistrationProperty(request.ResourceProperties, "StackSetName")
	templateVersion := awsRegistrationProperty(request.ResourceProperties, "TemplateVersion")

	store, err := s.awsOrganizationRolloutStore()
	if err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "Identrail rollout registration is unavailable.", err)
	}
	rollout, err := store.GetAWSOrganizationRolloutAnyScope(ctx, rolloutID)
	if err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail rollout is unknown or has been closed.", err)
	}
	if !s.isAWSRegistrationTopicARN(topicARN) {
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail rollout registration provider is unknown.", fmt.Errorf("rollout topic arn not allowlisted"))
	}
	if err := s.validateAWSOrganizationRolloutRegistration(rollout, request, organizationID, stackSetName, templateVersion, secret, roleARN); err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail rollout registration could not be verified.", err)
	}
	partition, region, accountID, ok := parseAWSStackARN(request.StackID)
	if !ok || !awsOrganizationRolloutRegionAllowed(rollout, region) {
		return s.failAWSCloudFormationRequest(ctx, request, "This member account/region is not part of the approved rollout.", fmt.Errorf("rollout stack region not allowed"))
	}
	if rollout.Partition != partition {
		return s.failAWSCloudFormationRequest(ctx, request, "This member account partition does not match the rollout.", fmt.Errorf("rollout partition mismatch"))
	}
	if !awsOrganizationRolloutAccountAllowed(rollout, accountID) {
		return s.failAWSCloudFormationRequest(ctx, request, "This member account is not part of the approved rollout scope.", fmt.Errorf("rollout account not in scope"))
	}
	if accountIDFromRoleARN(roleARN) != accountID {
		return s.failAWSCloudFormationRequest(ctx, request, "The AWS role does not belong to the reporting account.", fmt.Errorf("rollout role account mismatch"))
	}

	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: rollout.TenantID, WorkspaceID: rollout.WorkspaceID})

	target := db.AWSOrganizationRolloutTarget{
		RolloutID:       rollout.RolloutID,
		AccountID:       accountID,
		Region:          region,
		TenantID:        rollout.TenantID,
		WorkspaceID:     rollout.WorkspaceID,
		ProjectID:       rollout.ProjectID,
		IsManagement:    accountID == rollout.ManagementAccountID,
		State:           db.AWSOrganizationRolloutTargetValidating,
		StackID:         request.StackID,
		StackInstanceID: request.RequestID,
		RoleARN:         roleARN,
		Retryable:       true,
		EvidenceRef:     "aws-stackset:" + rollout.StackSetName + ":" + accountID + "/" + region,
	}
	if _, err := store.UpsertAWSOrganizationRolloutTarget(scopedCtx, target); err != nil {
		// The AWS-facing callback is intentionally not sent on persistence
		// failure so SQS redelivery can retry idempotently. Sending FAILED
		// here would begin a member-account stack rollback before the retry
		// could complete the same event.
		return err
	}
	if err := s.respondToAWSCloudFormation(ctx, request, "SUCCESS", "", false, map[string]any{"Registration": "accepted"}); err != nil {
		return err
	}
	return s.progressAWSOrganizationRolloutStatusFromTarget(scopedCtx, store, rollout)
}

// progressAWSOrganizationRolloutStatusFromTarget advances the rollout envelope
// out of `created` once any authenticated member event has landed. Terminal
// aggregation into `completed`/`partial`/`failed` is left to reconciliation
// so this handler cannot claim rollout-wide success from a single event.
func (s *Service) progressAWSOrganizationRolloutStatusFromTarget(ctx context.Context, store db.AWSOrganizationRolloutStore, rollout db.AWSOrganizationRollout) error {
	if rollout.Status != db.AWSOrganizationRolloutStatusCreated && rollout.Status != db.AWSOrganizationRolloutStatusLaunching {
		return nil
	}
	rollout.Status = db.AWSOrganizationRolloutStatusInProgress
	rollout.UpdatedAt = s.Now().UTC()
	if _, err := store.UpdateAWSOrganizationRollout(ctx, rollout, rollout.Version); err != nil && !errors.Is(err, db.ErrConflict) {
		return err
	}
	return nil
}

func (s *Service) validateAWSOrganizationRolloutRegistration(
	rollout db.AWSOrganizationRollout,
	request awsCloudFormationCustomResourceRequest,
	organizationID string,
	stackSetName string,
	templateVersion string,
	secret string,
	roleARN string,
) error {
	if request.ResourceType != "Custom::IdentrailAWSConnectorRegistration" {
		return fmt.Errorf("rollout registration resource type mismatch")
	}
	if !awsRoleARNPattern.MatchString(roleARN) {
		return fmt.Errorf("rollout role arn invalid")
	}
	if templateVersion != rollout.TemplateVersion {
		return fmt.Errorf("rollout template version mismatch")
	}
	if strings.TrimSpace(organizationID) != rollout.OrganizationID {
		return fmt.Errorf("rollout organization mismatch")
	}
	if strings.TrimSpace(stackSetName) != rollout.StackSetName {
		return fmt.Errorf("rollout stack set name mismatch")
	}
	if !s.Now().UTC().Before(rollout.ExpiresAt) {
		return fmt.Errorf("rollout expired")
	}
	if rollout.Status == db.AWSOrganizationRolloutStatusCanceled ||
		rollout.Status == db.AWSOrganizationRolloutStatusExpired ||
		rollout.Status == db.AWSOrganizationRolloutStatusFailed {
		return fmt.Errorf("rollout is not active")
	}
	hash := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(hash[:], rollout.RegistrationSecretHash) != 1 {
		return fmt.Errorf("rollout registration secret mismatch")
	}
	return nil
}

func awsOrganizationRolloutRegionAllowed(rollout db.AWSOrganizationRollout, region string) bool {
	region = strings.ToLower(strings.TrimSpace(region))
	for _, allowed := range rollout.TargetRegions {
		if allowed == region {
			return true
		}
	}
	return false
}

func awsOrganizationRolloutAccountAllowed(rollout db.AWSOrganizationRollout, accountID string) bool {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return false
	}
	for _, excluded := range rollout.ExcludedAccountIDs {
		if excluded == accountID {
			return false
		}
	}
	if accountID == rollout.ManagementAccountID {
		return true
	}
	// A selected-accounts rollout must list the account explicitly. An
	// OU-based rollout with no explicit selected accounts admits any
	// non-excluded account; OU-membership verification is a reconciliation
	// concern and lands in the next slice.
	if len(rollout.SelectedAccountIDs) == 0 {
		return true
	}
	for _, selected := range rollout.SelectedAccountIDs {
		if selected == accountID {
			return true
		}
	}
	return false
}
