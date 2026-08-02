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
	partition, region, accountID, stackName, ok := parseAWSStackARNWithName(request.StackID)
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
	// Bind the callback to a stack instance that actually belongs to the
	// rollout's StackSet. AWS StackSet-managed member-account stacks are
	// named `StackSet-<stackset-name>-<uuid>`. Without this check, a
	// selected-account principal that observed the rollout secret could
	// submit these properties from an unrelated stack in the same account
	// and move the target to `validating` under a different code path.
	if !awsOrganizationRolloutStackBelongsToStackSet(stackName, rollout.StackSetName) {
		return s.failAWSCloudFormationRequest(ctx, request, "The reporting stack does not belong to the approved StackSet instance.", fmt.Errorf("rollout stack name mismatch"))
	}
	// Bind RoleArn to the exact role name the rollout expects. Without this
	// check, a member-account operator (or an attacker with StackSet-instance
	// write in that account) could substitute another same-account role and
	// Identrail would validate that substituted trust policy on the next STS
	// pass, breaking the "same rollout secret authenticates the same read-only
	// role" invariant.
	if !awsOrganizationRolloutRoleARNMatchesExpectedName(roleARN, rollout.ExpectedRoleName) {
		return s.failAWSCloudFormationRequest(ctx, request, "The AWS role name does not match the rollout's expected role.", fmt.Errorf("rollout role name mismatch"))
	}

	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: rollout.TenantID, WorkspaceID: rollout.WorkspaceID})

	// SQS redelivery dedupe. Once a callback for this exact CloudFormation
	// request ID has been ACKed, a redelivery re-sends SUCCESS is a no-op
	// on the AWS side (the pre-signed callback URL is single-use) and
	// would race the CloudFormation response contract. Return nil so SQS
	// deletes the redelivered message without another network call.
	if existing, existsErr := store.GetAWSOrganizationRolloutTarget(scopedCtx, rollout.RolloutID, accountID, region); existsErr == nil &&
		existing.RegisterRequestID != "" && existing.RegisterRequestID == request.RequestID {
		return nil
	}

	target := db.AWSOrganizationRolloutTarget{
		RolloutID:         rollout.RolloutID,
		AccountID:         accountID,
		Region:            region,
		TenantID:          rollout.TenantID,
		WorkspaceID:       rollout.WorkspaceID,
		ProjectID:         rollout.ProjectID,
		IsManagement:      accountID == rollout.ManagementAccountID,
		State:             db.AWSOrganizationRolloutTargetValidating,
		StackID:           request.StackID,
		StackInstanceID:   request.RequestID,
		RoleARN:           roleARN,
		Retryable:         true,
		EvidenceRef:       "aws-stackset:" + rollout.StackSetName + ":" + accountID + "/" + region,
		RegisterRequestID: request.RequestID,
	}
	if _, err := store.UpsertAWSOrganizationRolloutTarget(scopedCtx, target); err != nil {
		// The AWS-facing callback is intentionally not sent on persistence
		// failure so SQS redelivery can retry idempotently. Sending FAILED
		// here would begin a member-account stack rollback before the retry
		// could complete the same event.
		return err
	}
	// Advance the envelope out of `created`/`launching` BEFORE the SUCCESS
	// callback so a status-write failure surfaces as a retryable error to SQS.
	// The previous order sent SUCCESS first and then attempted the envelope
	// update; if that update failed and its retries exhausted, the envelope
	// stayed at `created` forever even though a member had authenticated.
	if err := s.progressAWSOrganizationRolloutStatusFromTarget(scopedCtx, store, rollout); err != nil {
		return err
	}
	return s.respondToAWSCloudFormation(ctx, request, "SUCCESS", "", false, map[string]any{"Registration": "accepted"})
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
		rollout.Status == db.AWSOrganizationRolloutStatusFailed ||
		rollout.Status == db.AWSOrganizationRolloutStatusCompleted ||
		rollout.Status == db.AWSOrganizationRolloutStatusPartial {
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
	// Slice 1 does not resolve OU membership from AWS Organizations, so the
	// operator must always list target accounts explicitly. StartAWSOrganizationRollout
	// enforces that at request time; this check keeps the same invariant on
	// the ingestion path so a stray callback for an unlisted account cannot
	// be admitted just because the rollout also names OUs.
	for _, selected := range rollout.SelectedAccountIDs {
		if selected == accountID {
			return true
		}
	}
	return false
}

// awsOrganizationRolloutRoleARNMatchesExpectedName returns true only when the
// role ARN's role name equals the rollout's ExpectedRoleName. The role ARN
// format is arn:PARTITION:iam::ACCOUNT:role/ROLE_NAME (with optional path
// prefixes), so we compare the last segment after the final "/". The expected
// name is compared case-sensitive because IAM role names are case-sensitive.
func awsOrganizationRolloutRoleARNMatchesExpectedName(roleARN string, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	trimmed := strings.TrimSpace(roleARN)
	slash := strings.LastIndex(trimmed, "/")
	if slash < 0 || slash == len(trimmed)-1 {
		return false
	}
	return trimmed[slash+1:] == expected
}

// awsOrganizationRolloutStackBelongsToStackSet checks that stackName is a
// StackSet-managed member-account stack for the given StackSet name. AWS
// names such stacks `StackSet-<stackset-name>-<uuid>`, so we require the
// exact prefix plus a `-` before the trailing UUID.
func awsOrganizationRolloutStackBelongsToStackSet(stackName string, stackSetName string) bool {
	stackName = strings.TrimSpace(stackName)
	stackSetName = strings.TrimSpace(stackSetName)
	if stackName == "" || stackSetName == "" {
		return false
	}
	prefix := "StackSet-" + stackSetName + "-"
	return strings.HasPrefix(stackName, prefix) && len(stackName) > len(prefix)
}

// processAWSOrganizationRolloutMemberDelete handles a Delete callback from a
// member-account stack. The rollout target moves to `removed` so the panel
// no longer reports it as pending/validating. As with single-account delete,
// this callback must never fail the customer's stack teardown: the SUCCESS
// response is best-effort and any Identrail-side persistence failure leaves
// the eventual reconciliation loop responsible for the final state.
func (s *Service) processAWSOrganizationRolloutMemberDelete(
	ctx context.Context,
	topicARN string,
	request awsCloudFormationCustomResourceRequest,
	phase string,
) error {
	_ = phase
	rolloutID := awsRegistrationProperty(request.ResourceProperties, "RolloutId")
	if rolloutID == "" {
		return s.respondToAWSCloudFormation(ctx, request, "SUCCESS", "", false, nil)
	}
	store, err := s.awsOrganizationRolloutStore()
	if err != nil {
		return err
	}
	rollout, err := store.GetAWSOrganizationRolloutAnyScope(ctx, rolloutID)
	if err != nil {
		return err
	}
	if !s.isAWSRegistrationTopicARN(topicARN) {
		return fmt.Errorf("rollout topic arn not allowlisted")
	}
	if err := s.validateAWSOrganizationRolloutRegistration(rollout, request,
		awsRegistrationProperty(request.ResourceProperties, "OrganizationId"),
		awsRegistrationProperty(request.ResourceProperties, "StackSetName"),
		awsRegistrationProperty(request.ResourceProperties, "TemplateVersion"),
		awsRegistrationProperty(request.ResourceProperties, "RegistrationSecret"),
		awsRegistrationProperty(request.ResourceProperties, "RoleArn")); err != nil {
		return err
	}
	partition, region, accountID, stackName, ok := parseAWSStackARNWithName(request.StackID)
	if !ok || rollout.Partition != partition || !awsOrganizationRolloutRegionAllowed(rollout, region) ||
		!awsOrganizationRolloutStackBelongsToStackSet(stackName, rollout.StackSetName) {
		return fmt.Errorf("rollout delete stack is not approved")
	}
	scopedCtx := db.WithScope(ctx, db.Scope{TenantID: rollout.TenantID, WorkspaceID: rollout.WorkspaceID})
	existing, err := store.GetAWSOrganizationRolloutTarget(scopedCtx, rollout.RolloutID, accountID, region)
	if err != nil {
		return err
	}
	if existing.State == db.AWSOrganizationRolloutTargetRemoved && existing.RegisterRequestID == request.RequestID {
		return nil
	}
	target := existing
	target.State = db.AWSOrganizationRolloutTargetRemoved
	target.FailureCode = "rollout_member_stack_deleted"
	target.FailureMessage = "The AWS member-account stack was deleted."
	target.Retryable = false
	if _, upsertErr := store.UpsertAWSOrganizationRolloutTarget(scopedCtx, target); upsertErr != nil {
		return upsertErr
	}
	return s.respondToAWSCloudFormation(ctx, request, "SUCCESS", "", false, nil)
}
