package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/domain"
)

const (
	awsConnectorTemplateVersion    = "2.0.0"
	awsRegistrationTokenPurpose    = "aws-connector-registration-v1"
	awsRegistrationAttemptLifetime = 2 * time.Hour
)

var (
	awsStackARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):cloudformation:([a-z0-9-]+):([0-9]{12}):stack/[^/]+/[A-Za-z0-9-]+$`)
	awsTopicARNPattern = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):sns:([a-z0-9-]+):([0-9]{12}):[A-Za-z0-9_-]{1,256}$`)
)

// AWSCloudFormationResponder sends the bounded response required by a
// CloudFormation custom resource. Tests replace it to avoid outbound calls.
type AWSCloudFormationResponder interface {
	Respond(context.Context, string, awsCloudFormationCustomResourceResponse) error
}

type awsSNSEnvelope struct {
	Type             string `json:"Type"`
	TopicARN         string `json:"TopicArn"`
	Message          string `json:"Message"`
	SignatureVersion string `json:"SignatureVersion"`
}

type awsCloudFormationCustomResourceRequest struct {
	RequestType        string         `json:"RequestType"`
	ResponseURL        string         `json:"ResponseURL"`
	StackID            string         `json:"StackId"`
	RequestID          string         `json:"RequestId"`
	ResourceType       string         `json:"ResourceType"`
	LogicalResourceID  string         `json:"LogicalResourceId"`
	PhysicalResourceID string         `json:"PhysicalResourceId"`
	ResourceProperties map[string]any `json:"ResourceProperties"`
}

type awsCloudFormationCustomResourceResponse struct {
	Status             string         `json:"Status"`
	Reason             string         `json:"Reason,omitempty"`
	PhysicalResourceID string         `json:"PhysicalResourceId"`
	StackID            string         `json:"StackId"`
	RequestID          string         `json:"RequestId"`
	LogicalResourceID  string         `json:"LogicalResourceId"`
	NoEcho             bool           `json:"NoEcho,omitempty"`
	Data               map[string]any `json:"Data,omitempty"`
}

type httpAWSCloudFormationResponder struct {
	client *http.Client
}

func (r httpAWSCloudFormationResponder) Respond(ctx context.Context, responseURL string, response awsCloudFormationCustomResourceResponse) error {
	if err := validateAWSCloudFormationResponseURL(responseURL); err != nil {
		return err
	}
	body, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode cloudformation response: %w", err)
	}
	if len(body) > 4096 {
		return fmt.Errorf("cloudformation response exceeds 4096 bytes")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, responseURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build cloudformation response: %w", err)
	}
	request.Header.Set("content-type", "")
	client := r.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	result, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send cloudformation response: %w", err)
	}
	defer result.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(result.Body, 4096))
	if result.StatusCode < http.StatusOK || result.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("cloudformation response returned status %d", result.StatusCode)
	}
	return nil
}

func (s *Service) awsRegistrationTopicARN(region string) string {
	if s == nil || len(s.AWSRegistrationTopicARNs) == 0 {
		return ""
	}
	return strings.TrimSpace(s.AWSRegistrationTopicARNs[strings.ToLower(strings.TrimSpace(region))])
}

func (s *Service) awsOnboardingAttemptStore() (db.AWSConnectorOnboardingAttemptStore, error) {
	store, ok := s.Store.(db.AWSConnectorOnboardingAttemptStore)
	if !ok || store == nil {
		return nil, ErrAWSConnectorConfigUnavailable
	}
	return store, nil
}

func (s *Service) createAWSConnectorOnboardingAttempt(
	ctx context.Context,
	stored db.TenancyConnectorWithState,
	providerTopicARN string,
	templateChecksum string,
	region string,
	now time.Time,
) (db.AWSConnectorOnboardingAttempt, string, error) {
	store, err := s.awsOnboardingAttemptStore()
	if err != nil {
		return db.AWSConnectorOnboardingAttempt{}, "", err
	}
	attempt := db.AWSConnectorOnboardingAttempt{
		AttemptID:        uuid.NewString(),
		TenantID:         stored.Connector.TenantID,
		WorkspaceID:      stored.Connector.WorkspaceID,
		ProjectID:        stored.Connector.ProjectID,
		ConnectorID:      stored.Connector.ConnectorID,
		Status:           db.AWSConnectorOnboardingAttemptWaiting,
		TokenKeyVersion:  s.connectorSecretManager().ActiveKeyVersion(),
		ProviderTopicARN: strings.TrimSpace(providerTopicARN),
		TemplateVersion:  awsConnectorTemplateVersion,
		TemplateChecksum: normalizeAWSConnectorTemplateChecksum(templateChecksum),
		DeploymentRegion: strings.ToLower(strings.TrimSpace(region)),
		ExpiresAt:        now.UTC().Add(awsRegistrationAttemptLifetime),
		CreatedAt:        now.UTC(),
		UpdatedAt:        now.UTC(),
		Version:          1,
	}
	token, err := s.awsRegistrationToken(attempt)
	if err != nil {
		return db.AWSConnectorOnboardingAttempt{}, "", err
	}
	hash := sha256.Sum256([]byte(token))
	attempt.TokenHash = append([]byte(nil), hash[:]...)
	created, err := store.CreateAWSConnectorOnboardingAttempt(ctx, attempt)
	if err != nil {
		return db.AWSConnectorOnboardingAttempt{}, "", fmt.Errorf("create aws connector onboarding attempt: %w", err)
	}
	return created, token, nil
}

func (s *Service) activeOrNewAWSConnectorOnboardingAttempt(
	ctx context.Context,
	stored db.TenancyConnectorWithState,
	providerTopicARN string,
	templateChecksum string,
	region string,
) (db.AWSConnectorOnboardingAttempt, string, error) {
	store, err := s.awsOnboardingAttemptStore()
	if err != nil {
		return db.AWSConnectorOnboardingAttempt{}, "", err
	}
	now := s.Now().UTC()
	attempt, err := store.GetActiveAWSConnectorOnboardingAttempt(ctx, stored.Connector.WorkspaceID, stored.Connector.ProjectID, stored.Connector.ConnectorID)
	if err == nil {
		if now.Before(attempt.ExpiresAt) &&
			attempt.ProviderTopicARN == strings.TrimSpace(providerTopicARN) &&
			attempt.TemplateChecksum == normalizeAWSConnectorTemplateChecksum(templateChecksum) &&
			attempt.DeploymentRegion == strings.ToLower(strings.TrimSpace(region)) {
			token, tokenErr := s.awsRegistrationToken(attempt)
			if tokenErr != nil {
				return db.AWSConnectorOnboardingAttempt{}, "", tokenErr
			}
			return attempt, token, nil
		}
		attempt.Status = db.AWSConnectorOnboardingAttemptExpired
		attempt.FailureCode = "registration_expired"
		attempt.FailureMessage = "The AWS connection window expired. Start a new connection."
		attempt.UpdatedAt = now
		if _, updateErr := store.UpdateAWSConnectorOnboardingAttempt(ctx, attempt, attempt.Version); updateErr != nil && !errors.Is(updateErr, db.ErrConflict) {
			return db.AWSConnectorOnboardingAttempt{}, "", updateErr
		}
	} else if !errors.Is(err, db.ErrNotFound) {
		return db.AWSConnectorOnboardingAttempt{}, "", err
	}
	created, token, createErr := s.createAWSConnectorOnboardingAttempt(ctx, stored, providerTopicARN, templateChecksum, region, now)
	if createErr == nil || !errors.Is(createErr, db.ErrConflict) {
		return created, token, createErr
	}
	active, loadErr := store.GetActiveAWSConnectorOnboardingAttempt(ctx, stored.Connector.WorkspaceID, stored.Connector.ProjectID, stored.Connector.ConnectorID)
	if loadErr != nil {
		return db.AWSConnectorOnboardingAttempt{}, "", createErr
	}
	activeToken, tokenErr := s.awsRegistrationToken(active)
	if tokenErr != nil {
		return db.AWSConnectorOnboardingAttempt{}, "", tokenErr
	}
	return active, activeToken, nil
}

func (s *Service) awsRegistrationToken(attempt db.AWSConnectorOnboardingAttempt) (string, error) {
	identity := strings.Join([]string{
		strings.TrimSpace(attempt.AttemptID),
		strings.TrimSpace(attempt.TenantID),
		strings.TrimSpace(attempt.WorkspaceID),
		strings.TrimSpace(attempt.ProjectID),
		strings.TrimSpace(attempt.ConnectorID),
	}, "\x00")
	digest, err := s.connectorSecretManager().DeriveDigest(attempt.TokenKeyVersion, awsRegistrationTokenPurpose, []byte(identity))
	if err != nil {
		return "", fmt.Errorf("derive aws registration token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(digest), nil
}

// ProcessAWSConnectorRegistrationMessage consumes one SNS notification from the
// private registration queue. The queue policy authenticates delivery to the
// worker; the stored provider ARN and one-time token authenticate the attempt.
func (s *Service) ProcessAWSConnectorRegistrationMessage(ctx context.Context, body string) error {
	var envelope awsSNSEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return fmt.Errorf("decode aws registration envelope: %w", err)
	}
	if envelope.Type != "Notification" ||
		(envelope.SignatureVersion != "1" && envelope.SignatureVersion != "2") ||
		!awsTopicARNPattern.MatchString(strings.TrimSpace(envelope.TopicARN)) ||
		!s.isAWSRegistrationTopicARN(envelope.TopicARN) ||
		strings.TrimSpace(envelope.Message) == "" {
		return fmt.Errorf("invalid aws registration envelope")
	}
	var request awsCloudFormationCustomResourceRequest
	if err := json.Unmarshal([]byte(envelope.Message), &request); err != nil {
		return fmt.Errorf("decode aws registration request: %w", err)
	}
	if err := validateAWSCloudFormationRequestShape(request); err != nil {
		return err
	}
	if request.RequestType == "Delete" {
		// A partially created stack still owns the active onboarding attempt.
		// Terminalize it so a replacement launch can create a fresh grant
		// instead of being rejected as a replay for the rest of the lifetime.
		if store, storeErr := s.awsOnboardingAttemptStore(); storeErr == nil {
			s.cancelAWSOnboardingAttemptForDeletedStack(ctx, store, request)
		}
		return s.respondToAWSCloudFormation(ctx, request, "SUCCESS", "", false, nil)
	}

	attemptID := awsRegistrationProperty(request.ResourceProperties, "AttemptId")
	token := awsRegistrationProperty(request.ResourceProperties, "RegistrationToken")
	phase := awsRegistrationProperty(request.ResourceProperties, "Phase")
	store, err := s.awsOnboardingAttemptStore()
	if err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "Identrail registration is unavailable.", err)
	}
	attempt, err := store.GetAWSConnectorOnboardingAttemptAnyScope(ctx, attemptID)
	if err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail connection request is invalid or expired.", err)
	}
	scopedContext := db.WithScope(ctx, db.Scope{TenantID: attempt.TenantID, WorkspaceID: attempt.WorkspaceID})
	if err := s.validateAWSRegistrationRequest(attempt, envelope.TopicARN, request, phase, token); err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail connection request could not be verified.", err)
	}

	switch phase {
	case "Bootstrap":
		return s.processAWSRegistrationBootstrap(scopedContext, store, attempt, request)
	case "Register":
		return s.processAWSRegistrationRole(scopedContext, store, attempt, request)
	default:
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail connection phase is invalid.", fmt.Errorf("invalid registration phase"))
	}
}

func (s *Service) processAWSRegistrationBootstrap(ctx context.Context, store db.AWSConnectorOnboardingAttemptStore, attempt db.AWSConnectorOnboardingAttempt, request awsCloudFormationCustomResourceRequest) error {
	stackPartition, stackRegion, stackAccountID, _ := parseAWSStackARN(request.StackID)
	if request.RequestType == "Create" && attempt.BootstrapRequestID != "" && attempt.BootstrapRequestID != request.RequestID {
		return s.failAWSCloudFormationRequest(ctx, request, "This connection request has already been used.", fmt.Errorf("registration bootstrap replay"))
	}
	if request.RequestType == "Update" && attempt.BootstrapRequestID == "" {
		return s.failAWSCloudFormationRequest(ctx, request, "The original Identrail connection is incomplete.", fmt.Errorf("registration bootstrap update before create"))
	}
	stored, err := s.Store.GetTenancyConnector(ctx, attempt.WorkspaceID, attempt.ProjectID, attempt.ConnectorID)
	if err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail connector no longer exists.", err)
	}
	externalID, configured, err := s.awsExternalIDFromStoredStrict(ctx, stored)
	if err != nil || !configured || externalID == "" {
		if err == nil {
			err = fmt.Errorf("connector external id is unavailable")
		}
		return s.failAWSCloudFormationRequest(ctx, request, "Identrail could not prepare the connection trust guard.", err)
	}
	if attempt.BootstrapRequestID == "" {
		now := s.Now().UTC()
		attempt.Status = db.AWSConnectorOnboardingAttemptRegistering
		attempt.StackID = request.StackID
		attempt.AWSAccountID = stackAccountID
		attempt.AWSPartition = stackPartition
		attempt.BootstrapRequestID = request.RequestID
		attempt.UpdatedAt = now
		updated, updateErr := store.UpdateAWSConnectorOnboardingAttempt(ctx, attempt, attempt.Version)
		if updateErr != nil {
			return s.failAWSCloudFormationRequest(ctx, request, "Identrail could not reserve this connection request.", updateErr)
		}
		attempt = updated
		if err := s.persistAWSRegistrationProgress(ctx, stored, AWSConnectorOnboardingRegistering, "", stackAccountID, stackRegion); err != nil {
			return s.failAWSCloudFormationRequest(ctx, request, "Identrail could not save the AWS connection progress.", err)
		}
	}
	return s.respondToAWSCloudFormation(ctx, request, "SUCCESS", "", true, map[string]any{"ExternalId": externalID})
}

func (s *Service) processAWSRegistrationRole(ctx context.Context, store db.AWSConnectorOnboardingAttemptStore, attempt db.AWSConnectorOnboardingAttempt, request awsCloudFormationCustomResourceRequest) error {
	roleARN := awsRegistrationProperty(request.ResourceProperties, "RoleArn")
	externalID := awsRegistrationProperty(request.ResourceProperties, "ExternalId")
	templateVersion := awsRegistrationProperty(request.ResourceProperties, "TemplateVersion")
	if !awsRoleARNPattern.MatchString(roleARN) || templateVersion != attempt.TemplateVersion || accountIDFromRoleARN(roleARN) != attempt.AWSAccountID {
		return s.failAWSCloudFormationRequest(ctx, request, "The AWS role does not match this connection request.", fmt.Errorf("registration role mismatch"))
	}
	stored, err := s.Store.GetTenancyConnector(ctx, attempt.WorkspaceID, attempt.ProjectID, attempt.ConnectorID)
	if err != nil {
		return s.failAWSCloudFormationRequest(ctx, request, "The Identrail connector no longer exists.", err)
	}
	storedExternalID, configured, err := s.awsExternalIDFromStoredStrict(ctx, stored)
	if err != nil || !configured || subtle.ConstantTimeCompare([]byte(externalID), []byte(storedExternalID)) != 1 {
		if err == nil {
			err = fmt.Errorf("registration external id mismatch")
		}
		return s.failAWSCloudFormationRequest(ctx, request, "The AWS role trust guard does not match this connection request.", err)
	}
	if request.RequestType == "Create" && attempt.RegisterRequestID != "" && attempt.RegisterRequestID != request.RequestID {
		return s.failAWSCloudFormationRequest(ctx, request, "This connection request has already been used.", fmt.Errorf("registration replay"))
	}
	if request.RequestType == "Update" && attempt.RegisterRequestID == "" {
		return s.failAWSCloudFormationRequest(ctx, request, "The original Identrail connection is incomplete.", fmt.Errorf("registration update before create"))
	}
	// The persisted RegisterRequestID is the record that the CloudFormation
	// callback for this request already reached us and returned success — it
	// is only written below, after `respondToAWSCloudFormation` returns nil.
	// A same-request SQS redelivery whose callback failed the first time
	// therefore sees an empty RegisterRequestID and re-sends the response,
	// while a redelivery that follows a successful callback but crashed
	// validation sees it set and skips straight to validation. The S3
	// presigned response URL tolerates repeat PUTs, so a rare double-send
	// is safe.
	callbackAlreadyDelivered := request.RequestType == "Create" && attempt.RegisterRequestID != "" && attempt.RegisterRequestID == request.RequestID
	if !callbackAlreadyDelivered {
		if err := s.respondToAWSCloudFormation(ctx, request, "SUCCESS", "", false, map[string]any{"Registration": "accepted"}); err != nil {
			return err
		}
	}
	// Persist Validating state (and RegisterRequestID as the durable
	// "callback delivered" marker) only after the callback has been
	// acknowledged, so a redelivery of a failed-callback attempt retries.
	if attempt.RegisterRequestID == "" || request.RequestType == "Update" {
		now := s.Now().UTC()
		attempt.Status = db.AWSConnectorOnboardingAttemptValidating
		attempt.RoleARN = roleARN
		if attempt.RegisterRequestID == "" {
			attempt.RegisterRequestID = request.RequestID
			attempt.RegisteredAt = &now
		}
		attempt.UpdatedAt = now
		updated, updateErr := store.UpdateAWSConnectorOnboardingAttempt(ctx, attempt, attempt.Version)
		if updateErr != nil {
			return updateErr
		}
		attempt = updated
		if err := s.persistAWSRegistrationProgress(ctx, stored, AWSConnectorOnboardingValidating, roleARN, attempt.AWSAccountID, attempt.DeploymentRegion); err != nil {
			return err
		}
	}
	// If validation already reached a terminal outcome on a prior delivery,
	// return successfully so SQS deletes the redelivered message.
	if attempt.Status == db.AWSConnectorOnboardingAttemptConnected {
		return nil
	}
	status, validationErr := s.ValidateAWSConnector(ctx, attempt.ConnectorID, AWSConnectorValidateRequest{
		WorkspaceID: attempt.WorkspaceID,
		ProjectID:   attempt.ProjectID,
		RoleARN:     roleARN,
		Region:      attempt.DeploymentRegion,
	})
	now := s.Now().UTC()
	attempt.UpdatedAt = now
	if validationErr != nil {
		attempt.Status = db.AWSConnectorOnboardingAttemptNeedsFix
		attempt.FailureCode = "aws_validation_failed"
		attempt.FailureMessage = "Identrail could not verify read-only access. Open Troubleshooting to retry."
		if err := s.persistAWSRegistrationFailure(ctx, stored, roleARN, attempt.AWSAccountID, attempt.DeploymentRegion, attempt.FailureCode, attempt.FailureMessage); err != nil {
			return err
		}
	} else if status.Connected {
		attempt.Status = db.AWSConnectorOnboardingAttemptConnected
		attempt.ValidatedAt = &now
		attempt.FailureCode = ""
		attempt.FailureMessage = ""
	} else {
		attempt.Status = db.AWSConnectorOnboardingAttemptNeedsFix
		attempt.FailureCode = "aws_permissions_incomplete"
		attempt.FailureMessage = firstNonEmptyAWSValue(status.RemediationMessage, "The AWS role is missing required read-only access.")
	}
	_, updateErr := store.UpdateAWSConnectorOnboardingAttempt(ctx, attempt, attempt.Version)
	if updateErr != nil && !errors.Is(updateErr, db.ErrConflict) {
		return updateErr
	}
	return nil
}

func (s *Service) validateAWSRegistrationRequest(attempt db.AWSConnectorOnboardingAttempt, topicARN string, request awsCloudFormationCustomResourceRequest, phase string, token string) error {
	partition, region, accountID, ok := parseAWSStackARN(request.StackID)
	if !ok || region != attempt.DeploymentRegion {
		return fmt.Errorf("registration stack mismatch")
	}
	sameBoundStack := attempt.StackID != "" && attempt.StackID == request.StackID && attempt.AWSAccountID == accountID && attempt.AWSPartition == partition
	allowBoundUpdate := request.RequestType == "Update" && sameBoundStack
	if attempt.ProviderTopicARN != strings.TrimSpace(topicARN) || (!allowBoundUpdate && (attempt.Status == db.AWSConnectorOnboardingAttemptExpired || attempt.Status == db.AWSConnectorOnboardingAttemptFailed || !s.Now().UTC().Before(attempt.ExpiresAt))) {
		return fmt.Errorf("registration attempt is not active")
	}
	if phase == "Bootstrap" && !allowBoundUpdate {
		hash := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(hash[:], attempt.TokenHash) != 1 {
			return fmt.Errorf("registration token mismatch")
		}
	} else if phase == "Register" && attempt.BootstrapRequestID == "" {
		return fmt.Errorf("registration bootstrap is incomplete")
	}
	if attempt.StackID != "" && (attempt.StackID != request.StackID || attempt.AWSAccountID != accountID || attempt.AWSPartition != partition) {
		return fmt.Errorf("registration stack replay")
	}
	return nil
}

func (s *Service) persistAWSRegistrationProgress(ctx context.Context, stored db.TenancyConnectorWithState, status AWSConnectorOnboardingStatus, roleARN string, accountID string, region string) error {
	metadata := copyAWSMetadata(stored.State.Metadata)
	setup := awsMetadataSetupContract(metadata, AWSConnectorScopeSingleAccount, AWSConnectorDeploymentCloudFormation)
	applyAWSConnectorSetupMetadata(metadata, setup, status)
	if roleARN != "" {
		metadata["role_arn"] = roleARN
	}
	if accountID != "" {
		metadata["account_id"] = accountID
	}
	if region != "" {
		metadata["region"] = region
	}
	delete(metadata, "launch_url")
	now := s.Now().UTC()
	stored.State.Metadata = metadata
	stored.State.HealthStatus = "unknown"
	stored.State.LastErrorCode = ""
	stored.State.LastErrorMessage = ""
	stored.State.ObservedAt = now
	stored.State.UpdatedAt = now
	stored.Connector.Status = domain.ConnectorStatusPending
	stored.Connector.UpdatedAt = now
	return s.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State)
}

func (s *Service) persistAWSRegistrationFailure(ctx context.Context, stored db.TenancyConnectorWithState, roleARN string, accountID string, region string, code string, message string) error {
	metadata := copyAWSMetadata(stored.State.Metadata)
	setup := awsMetadataSetupContract(metadata, AWSConnectorScopeSingleAccount, AWSConnectorDeploymentCloudFormation)
	applyAWSConnectorSetupMetadata(metadata, setup, AWSConnectorOnboardingNeedsFix)
	metadata["role_arn"] = roleARN
	metadata["account_id"] = accountID
	metadata["region"] = region
	delete(metadata, "launch_url")
	now := s.Now().UTC()
	stored.State.Metadata = metadata
	stored.State.HealthStatus = "error"
	stored.State.LastErrorCode = code
	stored.State.LastErrorMessage = message
	stored.State.ObservedAt = now
	stored.State.UpdatedAt = now
	stored.Connector.Status = domain.ConnectorStatusDegraded
	stored.Connector.UpdatedAt = now
	return s.Store.UpsertTenancyConnector(ctx, stored.Connector, stored.State)
}

func (s *Service) isAWSRegistrationTopicARN(topicARN string) bool {
	topicARN = strings.TrimSpace(topicARN)
	for _, configured := range s.AWSRegistrationTopicARNs {
		if strings.TrimSpace(configured) == topicARN {
			return true
		}
	}
	return false
}

func (s *Service) failAWSCloudFormationRequest(ctx context.Context, request awsCloudFormationCustomResourceRequest, reason string, cause error) error {
	if responseErr := s.respondToAWSCloudFormation(ctx, request, "FAILED", reason, false, nil); responseErr != nil {
		return responseErr
	}
	return cause
}

func (s *Service) respondToAWSCloudFormation(ctx context.Context, request awsCloudFormationCustomResourceRequest, status string, reason string, noEcho bool, data map[string]any) error {
	physicalID := strings.TrimSpace(request.PhysicalResourceID)
	if physicalID == "" {
		physicalID = "identrail-aws-connector-" + strings.TrimSpace(request.LogicalResourceID)
	}
	responder := s.AWSCloudFormationResponder
	if responder == nil {
		responder = httpAWSCloudFormationResponder{}
	}
	return responder.Respond(ctx, request.ResponseURL, awsCloudFormationCustomResourceResponse{
		Status:             status,
		Reason:             reason,
		PhysicalResourceID: physicalID,
		StackID:            request.StackID,
		RequestID:          request.RequestID,
		LogicalResourceID:  request.LogicalResourceID,
		NoEcho:             noEcho,
		Data:               data,
	})
}

func validateAWSCloudFormationRequestShape(request awsCloudFormationCustomResourceRequest) error {
	switch request.RequestType {
	case "Create", "Update", "Delete":
	default:
		return fmt.Errorf("invalid cloudformation request type")
	}
	if strings.TrimSpace(request.StackID) == "" || strings.TrimSpace(request.RequestID) == "" || strings.TrimSpace(request.LogicalResourceID) == "" || (request.ResourceType != "Custom::IdentrailAWSConnectorRegistration" && request.ResourceType != "Custom::IdentrailAWSConnectorBootstrap") {
		return fmt.Errorf("invalid cloudformation registration request")
	}
	return validateAWSCloudFormationResponseURL(request.ResponseURL)
}

func validateAWSCloudFormationResponseURL(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
		return fmt.Errorf("invalid cloudformation response url")
	}
	host := strings.ToLower(parsed.Hostname())
	validHost := strings.HasSuffix(host, ".s3.amazonaws.com") ||
		strings.HasSuffix(host, ".s3.amazonaws.com.cn") ||
		(strings.Contains(host, ".s3.") || strings.Contains(host, ".s3-")) &&
			(strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn"))
	if !validHost || parsed.Fragment != "" {
		return fmt.Errorf("invalid cloudformation response host")
	}
	return nil
}

func parseAWSStackARN(stackID string) (partition string, region string, accountID string, ok bool) {
	matches := awsStackARNPattern.FindStringSubmatch(strings.TrimSpace(stackID))
	if len(matches) != 4 {
		return "", "", "", false
	}
	return matches[1], matches[2], matches[3], true
}

func awsRegistrationProperty(properties map[string]any, key string) string {
	value, _ := properties[key].(string)
	return strings.TrimSpace(value)
}

// cancelAWSOnboardingAttemptForDeletedStack marks the active attempt bound to
// a deleted stack as failed so a replacement stack for the same connector can
// create a fresh grant instead of being rejected as a replay. Only attempts
// whose StackID matches the deleted stack are cancelled — this keeps a
// spoofed Delete with an unbound attempt_id from wiping a legitimate
// in-flight bootstrap.
func (s *Service) cancelAWSOnboardingAttemptForDeletedStack(ctx context.Context, store db.AWSConnectorOnboardingAttemptStore, request awsCloudFormationCustomResourceRequest) {
	attemptID := awsRegistrationProperty(request.ResourceProperties, "AttemptId")
	if attemptID == "" {
		return
	}
	attempt, err := store.GetAWSConnectorOnboardingAttemptAnyScope(ctx, attemptID)
	if err != nil {
		return
	}
	if attempt.StackID == "" || attempt.StackID != request.StackID {
		return
	}
	if !awsOnboardingAttemptCancelable(attempt.Status) {
		return
	}
	scopedContext := db.WithScope(ctx, db.Scope{TenantID: attempt.TenantID, WorkspaceID: attempt.WorkspaceID})
	now := s.Now().UTC()
	attempt.Status = db.AWSConnectorOnboardingAttemptFailed
	attempt.FailureCode = "registration_stack_deleted"
	attempt.FailureMessage = "The AWS stack was deleted. Start a new connection."
	attempt.UpdatedAt = now
	_, _ = store.UpdateAWSConnectorOnboardingAttempt(scopedContext, attempt, attempt.Version)
}

func awsOnboardingAttemptCancelable(status string) bool {
	switch status {
	case db.AWSConnectorOnboardingAttemptWaiting,
		db.AWSConnectorOnboardingAttemptRegistering,
		db.AWSConnectorOnboardingAttemptValidating,
		db.AWSConnectorOnboardingAttemptNeedsFix:
		return true
	default:
		return false
	}
}
