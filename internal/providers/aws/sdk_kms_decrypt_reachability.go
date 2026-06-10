package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/textutil"
)

// KMSSDKClient is the narrow seam between the AWS SDK KMS client and the
// reachability collector. Only metadata-only and policy/grant inspection
// calls are exposed; encrypt/decrypt/sign/verify APIs are deliberately
// absent so the collector cannot accidentally invoke cryptographic
// operations.
type KMSSDKClient interface {
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyPolicy(ctx context.Context, params *kms.GetKeyPolicyInput, optFns ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	ListAliases(ctx context.Context, params *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	ListGrants(ctx context.Context, params *kms.ListGrantsInput, optFns ...func(*kms.Options)) (*kms.ListGrantsOutput, error)
	ListResourceTags(ctx context.Context, params *kms.ListResourceTagsInput, optFns ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
}

// SDKKMSDecryptReachabilityAPI implements the collector seam against the
// AWS SDK. Every read is metadata-only: ListKeys + per-key
// Describe/GetKeyPolicy/ListGrants/ListAliases/ListResourceTags.
type SDKKMSDecryptReachabilityAPI struct {
	client    KMSSDKClient
	accountID string
	region    string
}

var _ KMSDecryptReachabilityAPI = (*SDKKMSDecryptReachabilityAPI)(nil)

// NewSDKKMSDecryptReachabilityAPI constructs the SDK-backed API using
// ambient AWS credentials.
func NewSDKKMSDecryptReachabilityAPI(region string, profile string, accountID string) (KMSDecryptReachabilityAPI, error) {
	return NewSDKKMSDecryptReachabilityAPIWithContext(context.Background(), region, profile, accountID)
}

// NewSDKKMSDecryptReachabilityAPIWithContext constructs the SDK-backed API
// using the supplied context for config loading.
func NewSDKKMSDecryptReachabilityAPIWithContext(ctx context.Context, region string, profile string, accountID string) (KMSDecryptReachabilityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	resolved, err := kmsDecryptReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKKMSDecryptReachabilityAPIFromClient(kms.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

// NewSDKKMSDecryptReachabilityAPIFromAssumeRole constructs the SDK-backed
// API after assuming the supplied connector role.
func NewSDKKMSDecryptReachabilityAPIFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string, accountID string) (KMSDecryptReachabilityAPI, error) {
	cfg, err := loadSDKConfig(ctx, region, profile)
	if err != nil {
		return nil, err
	}
	trimmedRoleARN := strings.TrimSpace(roleARN)
	if trimmedRoleARN == "" {
		return nil, fmt.Errorf("aws connector role arn is required")
	}
	options := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = textutil.FirstNonEmpty(strings.TrimSpace(sessionName), "identrail-recurring-scan")
		},
	}
	if trimmedExternalID := strings.TrimSpace(externalID); trimmedExternalID != "" {
		options = append(options, func(options *stscreds.AssumeRoleOptions) {
			options.ExternalID = &trimmedExternalID
		})
	}
	cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), trimmedRoleARN, options...))
	resolved, err := kmsDecryptReachabilityAccountID(ctx, cfg, accountID)
	if err != nil {
		return nil, err
	}
	resolvedRegion := firstNonEmptyAWSValue(strings.TrimSpace(region), strings.TrimSpace(cfg.Region))
	return NewSDKKMSDecryptReachabilityAPIFromClient(kms.NewFromConfig(cfg), resolved, resolvedRegion), nil
}

// NewSDKKMSDecryptReachabilityAPIFromClient is the seam tests use to inject
// a fake KMS client.
func NewSDKKMSDecryptReachabilityAPIFromClient(client KMSSDKClient, accountID string, region string) KMSDecryptReachabilityAPI {
	return &SDKKMSDecryptReachabilityAPI{
		client:    client,
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
	}
}

// ListKMSKeyReachability enumerates one page of KMS keys (using the SDK's
// native pagination via Marker/NextMarker), describes each key, and folds
// in policy + grant + alias + tag metadata. Aliases are pre-fetched once
// per page-call to avoid an N+1 ListAliases-per-key.
func (a *SDKKMSDecryptReachabilityAPI) ListKMSKeyReachability(ctx context.Context, nextToken string, pageSize int32) (KMSDecryptReachabilityPage, error) {
	if a.client == nil {
		return KMSDecryptReachabilityPage{}, errors.New("kms SDK client is required")
	}
	limit := pageSize
	if limit <= 0 {
		limit = defaultPageSize
	}
	listOutput, err := a.client.ListKeys(ctx, &kms.ListKeysInput{
		Limit:  awsv2.Int32(limit),
		Marker: stringPtrOrNil(nextToken),
	})
	if err != nil {
		return KMSDecryptReachabilityPage{}, err
	}
	if listOutput == nil {
		return KMSDecryptReachabilityPage{}, nil
	}
	diagnostics := []providers.SourceError{}
	// Pre-fetch every alias in the account once per page. ListAliases is
	// paginated separately, but the cost is paid once instead of once per
	// key in the page.
	aliasesByKey, aliasDiagnostics := a.fetchAliasesByKey(ctx)
	diagnostics = append(diagnostics, aliasDiagnostics...)

	records := []KMSDecryptReachability{}
	for _, summary := range listOutput.Keys {
		keyID := strings.TrimSpace(awsv2.ToString(summary.KeyId))
		keyARN := strings.TrimSpace(awsv2.ToString(summary.KeyArn))
		if keyID == "" && keyARN == "" {
			diagnostics = append(diagnostics, kmsDecryptReachabilityDiagnostic("kms_key_id_missing", "listkeys", "KMS key summary did not include an id or arn", false))
			continue
		}
		record := KMSDecryptReachability{KeyID: keyID, KeyARN: keyARN}
		record.Region = a.region
		a.enrichDescribeKey(ctx, keyID, keyARN, &record, &diagnostics)
		// Use whichever id flavor DescribeKey produced for the rest of the
		// per-key calls.
		callID := firstNonEmptyAWSValue(record.KeyID, keyID, keyARN)
		a.enrichKeyPolicy(ctx, callID, &record, &diagnostics)
		a.enrichKeyRotation(ctx, callID, &record, &diagnostics)
		a.enrichGrants(ctx, callID, &record, &diagnostics)
		a.enrichTags(ctx, callID, &record, &diagnostics)
		if list, ok := aliasesByKey[strings.TrimSpace(record.KeyID)]; ok {
			record.Aliases = list
		}
		records = append(records, record)
	}
	return KMSDecryptReachabilityPage{
		Records:     records,
		NextToken:   strings.TrimSpace(awsv2.ToString(listOutput.NextMarker)),
		Diagnostics: diagnostics,
	}, nil
}

func (a *SDKKMSDecryptReachabilityAPI) enrichDescribeKey(ctx context.Context, keyID string, keyARN string, record *KMSDecryptReachability, diagnostics *[]providers.SourceError) {
	id := firstNonEmptyAWSValue(keyARN, keyID)
	output, err := a.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: awsv2.String(id)})
	if err != nil {
		*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_describe_key_failed", id, fmt.Sprintf("DescribeKey %q failed: %v", id, err), true))
		return
	}
	if output == nil || output.KeyMetadata == nil {
		return
	}
	meta := output.KeyMetadata
	record.KeyID = strings.TrimSpace(awsv2.ToString(meta.KeyId))
	record.KeyARN = strings.TrimSpace(awsv2.ToString(meta.Arn))
	record.AccountID = strings.TrimSpace(awsv2.ToString(meta.AWSAccountId))
	record.KeyManager = string(meta.KeyManager)
	record.KeyState = string(meta.KeyState)
	record.KeyUsage = string(meta.KeyUsage)
	record.KeySpec = string(meta.KeySpec)
	record.Origin = string(meta.Origin)
	record.Description = strings.TrimSpace(awsv2.ToString(meta.Description))
	record.Enabled = meta.Enabled
	if meta.CreationDate != nil {
		record.CreatedAt = meta.CreationDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	if meta.DeletionDate != nil {
		record.DeletionDate = meta.DeletionDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	if meta.MultiRegion != nil && *meta.MultiRegion {
		record.MultiRegion = true
		if meta.MultiRegionConfiguration != nil {
			record.MultiRegionPrimary = strings.EqualFold(string(meta.MultiRegionConfiguration.MultiRegionKeyType), "PRIMARY")
			if meta.MultiRegionConfiguration.PrimaryKey != nil {
				record.PrimaryKeyARN = strings.TrimSpace(awsv2.ToString(meta.MultiRegionConfiguration.PrimaryKey.Arn))
			}
			for _, replica := range meta.MultiRegionConfiguration.ReplicaKeys {
				if arn := strings.TrimSpace(awsv2.ToString(replica.Arn)); arn != "" {
					record.ReplicaKeyARNs = append(record.ReplicaKeyARNs, arn)
				}
			}
		}
	}
	// Symmetric customer-managed keys with AWS_KMS origin support automatic
	// rotation. Imported EXTERNAL-origin key material is not automatically
	// rotation-capable.
	if strings.EqualFold(string(meta.KeyManager), "CUSTOMER") &&
		strings.EqualFold(string(meta.KeySpec), "SYMMETRIC_DEFAULT") &&
		strings.EqualFold(string(meta.Origin), "AWS_KMS") {
		record.RotationSupported = true
	}
}

func (a *SDKKMSDecryptReachabilityAPI) enrichKeyPolicy(ctx context.Context, keyID string, record *KMSDecryptReachability, diagnostics *[]providers.SourceError) {
	if keyID == "" {
		return
	}
	output, err := a.client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: awsv2.String(keyID), PolicyName: awsv2.String("default")})
	if err != nil {
		*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_key_policy_failed", keyID, fmt.Sprintf("GetKeyPolicy %q failed: %v", keyID, err), true))
		return
	}
	if output == nil || output.Policy == nil {
		return
	}
	record.HasKeyPolicy = true
	grants, statementCount, iamDelegation, parseErr := parseKMSKeyPolicyGrants(awsv2.ToString(output.Policy), strings.TrimSpace(record.AccountID))
	if parseErr != nil {
		*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_key_policy_parse_failed", keyID, fmt.Sprintf("parse key policy %q: %v", keyID, parseErr), false))
		return
	}
	record.KeyPolicyStatementCount = statementCount
	record.IdentityGrants = grants
	record.IAMDelegationEnabled = iamDelegation
}

func (a *SDKKMSDecryptReachabilityAPI) enrichKeyRotation(ctx context.Context, keyID string, record *KMSDecryptReachability, diagnostics *[]providers.SourceError) {
	if keyID == "" {
		return
	}
	output, err := a.client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: awsv2.String(keyID)})
	if err != nil {
		if kmsIsRotationUnsupported(err) {
			return
		}
		*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_key_rotation_failed", keyID, fmt.Sprintf("GetKeyRotationStatus %q failed: %v", keyID, err), true))
		return
	}
	if output == nil {
		return
	}
	record.RotationEnabled = output.KeyRotationEnabled
}

func (a *SDKKMSDecryptReachabilityAPI) enrichGrants(ctx context.Context, keyID string, record *KMSDecryptReachability, diagnostics *[]providers.SourceError) {
	if keyID == "" {
		return
	}
	nextToken := ""
	for page := 1; ; page++ {
		if page > defaultMaxPages {
			*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_list_grants_page_limit_exceeded", keyID, fmt.Sprintf("ListGrants paginated beyond max pages for %q", keyID), false))
			return
		}
		output, err := a.client.ListGrants(ctx, &kms.ListGrantsInput{
			KeyId:  awsv2.String(keyID),
			Marker: stringPtrOrNil(nextToken),
		})
		if err != nil {
			*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_list_grants_failed", keyID, fmt.Sprintf("ListGrants %q failed: %v", keyID, err), true))
			return
		}
		if output == nil {
			return
		}
		for _, entry := range output.Grants {
			record.Grants = append(record.Grants, kmsGrantFromSDK(entry))
		}
		nextToken = strings.TrimSpace(awsv2.ToString(output.NextMarker))
		if nextToken == "" {
			return
		}
	}
}

func (a *SDKKMSDecryptReachabilityAPI) enrichTags(ctx context.Context, keyID string, record *KMSDecryptReachability, diagnostics *[]providers.SourceError) {
	if keyID == "" {
		return
	}
	nextToken := ""
	tags := map[string]string{}
	for page := 1; ; page++ {
		if page > defaultMaxPages {
			*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_list_tags_page_limit_exceeded", keyID, fmt.Sprintf("ListResourceTags paginated beyond max pages for %q", keyID), false))
			break
		}
		output, err := a.client.ListResourceTags(ctx, &kms.ListResourceTagsInput{
			KeyId:  awsv2.String(keyID),
			Marker: stringPtrOrNil(nextToken),
		})
		if err != nil {
			*diagnostics = append(*diagnostics, kmsDecryptReachabilityDiagnostic("kms_list_tags_failed", keyID, fmt.Sprintf("ListResourceTags %q failed: %v", keyID, err), true))
			break
		}
		if output == nil {
			break
		}
		for _, tag := range output.Tags {
			key := strings.TrimSpace(awsv2.ToString(tag.TagKey))
			if key == "" {
				continue
			}
			tags[key] = strings.TrimSpace(awsv2.ToString(tag.TagValue))
		}
		nextToken = strings.TrimSpace(awsv2.ToString(output.NextMarker))
		if nextToken == "" {
			break
		}
	}
	if len(tags) > 0 {
		record.Tags = tags
	}
}

// fetchAliasesByKey pulls every alias in the account once and indexes them
// by TargetKeyId. We only surface alias *names*, never alias ARNs, since
// the ARN is a deterministic projection of the name.
func (a *SDKKMSDecryptReachabilityAPI) fetchAliasesByKey(ctx context.Context) (map[string][]string, []providers.SourceError) {
	if a.client == nil {
		return map[string][]string{}, nil
	}
	out := map[string][]string{}
	diagnostics := []providers.SourceError{}
	nextToken := ""
	for page := 1; ; page++ {
		if page > defaultMaxPages {
			diagnostics = append(diagnostics, kmsDecryptReachabilityDiagnostic("kms_list_aliases_page_limit_exceeded", "listaliases", "ListAliases paginated beyond max pages", false))
			break
		}
		output, err := a.client.ListAliases(ctx, &kms.ListAliasesInput{Marker: stringPtrOrNil(nextToken)})
		if err != nil {
			diagnostics = append(diagnostics, kmsDecryptReachabilityDiagnostic("kms_list_aliases_failed", "listaliases", fmt.Sprintf("ListAliases failed: %v", err), true))
			break
		}
		if output == nil {
			break
		}
		for _, alias := range output.Aliases {
			name := strings.TrimSpace(awsv2.ToString(alias.AliasName))
			target := strings.TrimSpace(awsv2.ToString(alias.TargetKeyId))
			if name == "" || target == "" {
				continue
			}
			out[target] = append(out[target], name)
		}
		nextToken = strings.TrimSpace(awsv2.ToString(output.NextMarker))
		if nextToken == "" {
			break
		}
	}
	return out, diagnostics
}

func kmsGrantFromSDK(entry kmstypes.GrantListEntry) KMSGrant {
	g := KMSGrant{
		GrantID:           strings.TrimSpace(awsv2.ToString(entry.GrantId)),
		Name:              strings.TrimSpace(awsv2.ToString(entry.Name)),
		GranteePrincipal:  strings.TrimSpace(awsv2.ToString(entry.GranteePrincipal)),
		RetiringPrincipal: strings.TrimSpace(awsv2.ToString(entry.RetiringPrincipal)),
		IssuingAccount:    strings.TrimSpace(awsv2.ToString(entry.IssuingAccount)),
	}
	if entry.GranteeServicePrincipal != nil && strings.TrimSpace(*entry.GranteeServicePrincipal) != "" {
		g.GranteePrincipalType = "service"
		if g.GranteePrincipal == "" {
			g.GranteePrincipal = strings.TrimSpace(*entry.GranteeServicePrincipal)
		}
	} else if g.GranteePrincipal != "" {
		g.GranteePrincipalType = "aws"
	}
	for _, op := range entry.Operations {
		g.Operations = append(g.Operations, string(op))
	}
	if entry.Constraints != nil {
		for k := range entry.Constraints.EncryptionContextEquals {
			g.EncryptionContextKeys = append(g.EncryptionContextKeys, k)
		}
		for k := range entry.Constraints.EncryptionContextSubset {
			g.EncryptionContextSubsetKeys = append(g.EncryptionContextSubsetKeys, k)
		}
		sort.Strings(g.EncryptionContextKeys)
		sort.Strings(g.EncryptionContextSubsetKeys)
	}
	if entry.CreationDate != nil {
		g.CreatedAt = entry.CreationDate.UTC().Format("2006-01-02T15:04:05Z")
	}
	return g
}

func kmsDecryptReachabilityDiagnostic(code string, sourceID string, message string, retryable bool) providers.SourceError {
	return providers.SourceError{
		Collector: kmsDecryptReachabilityCollectorName,
		SourceID:  strings.TrimSpace(sourceID),
		Code:      strings.TrimSpace(code),
		Message:   strings.TrimSpace(message),
		Retryable: retryable,
	}
}

func kmsDecryptReachabilityAccountID(ctx context.Context, cfg awsv2.Config, accountID string) (string, error) {
	trimmed := strings.TrimSpace(accountID)
	if trimmed != "" {
		return trimmed, nil
	}
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("read AWS caller identity for kms account id: %w", err)
	}
	resolved := strings.TrimSpace(awsv2.ToString(identity.Account))
	if resolved == "" {
		return "", fmt.Errorf("read AWS caller identity for kms account id: empty account id")
	}
	return resolved, nil
}

// kmsIsRotationUnsupported recognises the AWS error returned when
// GetKeyRotationStatus is called on a key type that does not support
// rotation (asymmetric, HMAC, multi-region replica, etc.). It is not a
// diagnostic — the absence of rotation is expected for those key types.
func kmsIsRotationUnsupported(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unsupportedoperationexception") ||
		strings.Contains(msg, "kms key with arn") && strings.Contains(msg, "does not support") ||
		strings.Contains(msg, "is not supported for")
}
