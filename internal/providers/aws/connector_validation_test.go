package aws

import (
	"context"
	"errors"
	"testing"

	api "github.com/Oluwatobi-Mustapha/identrail/internal/api"
	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
)

type fakeSTSAssumeRoleClient struct {
	output *sts.AssumeRoleOutput
	err    error
	seen   *sts.AssumeRoleInput
}

func (f *fakeSTSAssumeRoleClient) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.seen = params
	return f.output, f.err
}

type fakeSTSIdentityClient struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (f fakeSTSIdentityClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.output, f.err
}

type fakeIAMListRolesClient struct {
	output *iam.ListRolesOutput
	err    error
}

func (f fakeIAMListRolesClient) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return f.output, f.err
}

func TestConnectionValidatorValidateAWSConnectionActive(t *testing.T) {
	assume := &fakeSTSAssumeRoleClient{
		output: &sts.AssumeRoleOutput{
			Credentials: &ststypes.Credentials{
				AccessKeyId:     awsv2.String("access"),
				SecretAccessKey: awsv2.String("secret"),
				SessionToken:    awsv2.String("token"),
			},
		},
	}
	validator := testConnectionValidator(assume, fakeSTSIdentityClient{
		output: &sts.GetCallerIdentityOutput{
			Account: awsv2.String("123456789012"),
			Arn:     awsv2.String("arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/session"),
			UserId:  awsv2.String("AROATEST:session"),
		},
	}, fakeIAMListRolesClient{output: &iam.ListRolesOutput{}})

	result, err := validator.ValidateAWSConnection(context.Background(), api.AWSConnectionValidationRequest{
		RoleARN:     "arn:aws:iam::123456789012:role/IdentrailReadOnly",
		ExternalID:  "external",
		Region:      "us-west-2",
		SessionName: "session",
	})
	if err != nil {
		t.Fatalf("validate connection: %v", err)
	}
	if result.AccountID != "123456789012" || result.PrincipalARN == "" {
		t.Fatalf("expected account metadata, got %+v", result)
	}
	if len(result.Diagnostics) != 0 || len(result.PermissionChecks) != 2 {
		t.Fatalf("expected clean diagnostics and two checks, got %+v", result)
	}
	for _, check := range result.PermissionChecks {
		if !check.Passed {
			t.Fatalf("expected check %s to pass: %+v", check.Name, result.PermissionChecks)
		}
	}
	if assume.seen == nil || awsv2.ToString(assume.seen.ExternalId) != "external" || awsv2.ToString(assume.seen.RoleSessionName) != "session" {
		t.Fatalf("assume role request was not populated correctly: %+v", assume.seen)
	}
}

func TestConnectionValidatorValidateAWSConnectionTrustFailure(t *testing.T) {
	validator := testConnectionValidator(&fakeSTSAssumeRoleClient{
		err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"},
	}, fakeSTSIdentityClient{}, fakeIAMListRolesClient{})

	result, err := validator.ValidateAWSConnection(context.Background(), api.AWSConnectionValidationRequest{
		RoleARN: "arn:aws:iam::123456789012:role/BadTrust",
	})
	if err != nil {
		t.Fatalf("validate connection: %v", err)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "aws_access_denied" {
		t.Fatalf("expected access denied diagnostic, got %+v", result.Diagnostics)
	}
	if len(result.PermissionChecks) != 1 || result.PermissionChecks[0].Passed {
		t.Fatalf("expected failed assume-role check, got %+v", result.PermissionChecks)
	}
}

func TestConnectionValidatorValidateAWSConnectionIAMPermissionFailure(t *testing.T) {
	validator := testConnectionValidator(&fakeSTSAssumeRoleClient{
		output: &sts.AssumeRoleOutput{
			Credentials: &ststypes.Credentials{
				AccessKeyId:     awsv2.String("access"),
				SecretAccessKey: awsv2.String("secret"),
				SessionToken:    awsv2.String("token"),
			},
		},
	}, fakeSTSIdentityClient{output: &sts.GetCallerIdentityOutput{
		Account: awsv2.String("123456789012"),
		Arn:     awsv2.String("arn:aws:sts::123456789012:assumed-role/IdentrailReadOnly/session"),
		UserId:  awsv2.String("AROATEST:session"),
	}}, fakeIAMListRolesClient{err: errors.New("iam denied")})

	result, err := validator.ValidateAWSConnection(context.Background(), api.AWSConnectionValidationRequest{
		RoleARN: "arn:aws:iam::123456789012:role/IdentrailReadOnly",
	})
	if err != nil {
		t.Fatalf("validate connection: %v", err)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "aws_iam_list_roles_failed" {
		t.Fatalf("expected iam diagnostic, got %+v", result.Diagnostics)
	}
	if len(result.PermissionChecks) != 2 || result.PermissionChecks[1].Passed {
		t.Fatalf("expected failed iam check, got %+v", result.PermissionChecks)
	}
}

func TestConnectionValidatorValidateAWSConnectionLoadConfigError(t *testing.T) {
	validator := NewConnectionValidator("", "")
	validator.loadConfig = func(context.Context, string, string) (awsv2.Config, error) {
		return awsv2.Config{}, errors.New("missing config")
	}
	_, err := validator.ValidateAWSConnection(context.Background(), api.AWSConnectionValidationRequest{
		RoleARN: "arn:aws:iam::123456789012:role/IdentrailReadOnly",
	})
	if err == nil {
		t.Fatal("expected load config error")
	}
}

func TestClassifyAWSError(t *testing.T) {
	tests := map[string]string{
		"AccessDeniedException": "aws_access_denied",
		"InvalidClientTokenId":  "aws_credentials_invalid",
		"ExpiredTokenException": "aws_credentials_expired",
		"ThrottlingException":   "aws_throttled",
		"ValidationError":       "aws_validationerror",
	}
	for code, want := range tests {
		if got := classifyAWSError(&smithy.GenericAPIError{Code: code}, "fallback"); got != want {
			t.Fatalf("classifyAWSError(%q) = %q, want %q", code, got, want)
		}
	}
	if got := classifyAWSError(errors.New("plain"), "fallback"); got != "fallback" {
		t.Fatalf("plain error classified as %q", got)
	}
}

func testConnectionValidator(assume stsAssumeRoleAPI, identity stsIdentityAPI, iamClient iamListRolesAPI) *ConnectionValidator {
	validator := NewConnectionValidator("", "")
	validator.loadConfig = func(context.Context, string, string) (awsv2.Config, error) {
		return awsv2.Config{}, nil
	}
	validator.newAssumeRoleClient = func(awsv2.Config) stsAssumeRoleAPI { return assume }
	validator.newIdentityClient = func(awsv2.Config) stsIdentityAPI { return identity }
	validator.newIAMClient = func(awsv2.Config) iamListRolesAPI { return iamClient }
	return validator
}
