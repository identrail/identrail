package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	api "github.com/identrail/identrail/internal/api"
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

type fakeIAMValidationClient struct {
	listRolesOutput                *iam.ListRolesOutput
	listRolesErr                   error
	listRolePoliciesOutput         *iam.ListRolePoliciesOutput
	listRolePoliciesErr            error
	getRolePolicyOutput            *iam.GetRolePolicyOutput
	getRolePolicyErr               error
	listAttachedRolePoliciesOutput *iam.ListAttachedRolePoliciesOutput
	listAttachedRolePoliciesErr    error
	getPolicyOutput                *iam.GetPolicyOutput
	getPolicyErr                   error
	getPolicyVersionOutput         *iam.GetPolicyVersionOutput
	getPolicyVersionErr            error
}

func (f fakeIAMValidationClient) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return f.listRolesOutput, f.listRolesErr
}

func (f fakeIAMValidationClient) ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return f.listRolePoliciesOutput, f.listRolePoliciesErr
}

func (f fakeIAMValidationClient) GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return f.getRolePolicyOutput, f.getRolePolicyErr
}

func (f fakeIAMValidationClient) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return f.listAttachedRolePoliciesOutput, f.listAttachedRolePoliciesErr
}

func (f fakeIAMValidationClient) GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return f.getPolicyOutput, f.getPolicyErr
}

func (f fakeIAMValidationClient) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return f.getPolicyVersionOutput, f.getPolicyVersionErr
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
	}, fakeIAMValidationClient{
		listRolesOutput: &iam.ListRolesOutput{Roles: []iamtypes.Role{{
			RoleName: awsv2.String("AppRole"),
		}}},
		listRolePoliciesOutput: &iam.ListRolePoliciesOutput{PolicyNames: []string{"inline"}},
		getRolePolicyOutput:    &iam.GetRolePolicyOutput{PolicyDocument: awsv2.String("{}")},
		listAttachedRolePoliciesOutput: &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{
			PolicyArn:  awsv2.String("arn:aws:iam::123456789012:policy/Managed"),
			PolicyName: awsv2.String("Managed"),
		}}},
		getPolicyOutput:        &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: awsv2.String("v1")}},
		getPolicyVersionOutput: &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awsv2.String("{}")}},
	})

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
	}, fakeSTSIdentityClient{}, fakeIAMValidationClient{})

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
	}}, fakeIAMValidationClient{listRolesErr: errors.New("iam denied")})

	result, err := validator.ValidateAWSConnection(context.Background(), api.AWSConnectionValidationRequest{
		RoleARN: "arn:aws:iam::123456789012:role/IdentrailReadOnly",
	})
	if err != nil {
		t.Fatalf("validate connection: %v", err)
	}
	if len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "aws_iam_read_failed" {
		t.Fatalf("expected iam diagnostic, got %+v", result.Diagnostics)
	}
	if len(result.PermissionChecks) != 2 || result.PermissionChecks[1].Passed {
		t.Fatalf("expected failed iam check, got %+v", result.PermissionChecks)
	}
}

func TestConnectionValidatorValidateAWSConnectionPolicyReadFailure(t *testing.T) {
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
	}}, fakeIAMValidationClient{
		listRolesOutput: &iam.ListRolesOutput{Roles: []iamtypes.Role{{RoleName: awsv2.String("AppRole")}}},
		listRolePoliciesErr: &smithy.GenericAPIError{
			Code:    "AccessDenied",
			Message: "denied",
		},
	})

	result, err := validator.ValidateAWSConnection(context.Background(), api.AWSConnectionValidationRequest{
		RoleARN: "arn:aws:iam::123456789012:role/IdentrailReadOnly",
	})
	if err != nil {
		t.Fatalf("validate connection: %v", err)
	}
	if len(result.PermissionChecks) != 2 || result.PermissionChecks[1].Passed {
		t.Fatalf("expected policy-read check to fail, got %+v", result.PermissionChecks)
	}
	if result.PermissionChecks[1].Name != "iam:ReadRolePolicies" {
		t.Fatalf("expected collector permission check, got %+v", result.PermissionChecks[1])
	}
}

func TestValidateIAMReadPermissionsEdges(t *testing.T) {
	tests := []struct {
		name       string
		client     fakeIAMValidationClient
		wantPassed bool
		wantMsg    string
	}{
		{
			name:       "no sample roles",
			client:     fakeIAMValidationClient{listRolesOutput: &iam.ListRolesOutput{}},
			wantPassed: true,
			wantMsg:    "no sample role",
		},
		{
			name: "inline policy document denied",
			client: fakeIAMValidationClient{
				listRolesOutput:        &iam.ListRolesOutput{Roles: []iamtypes.Role{{RoleName: awsv2.String("AppRole")}}},
				listRolePoliciesOutput: &iam.ListRolePoliciesOutput{PolicyNames: []string{"inline"}},
				getRolePolicyErr:       errors.New("inline denied"),
			},
			wantPassed: false,
			wantMsg:    "cannot read inline",
		},
		{
			name: "attached policy listing denied",
			client: fakeIAMValidationClient{
				listRolesOutput:             &iam.ListRolesOutput{Roles: []iamtypes.Role{{RoleName: awsv2.String("AppRole")}}},
				listRolePoliciesOutput:      &iam.ListRolePoliciesOutput{},
				listAttachedRolePoliciesErr: errors.New("attached denied"),
			},
			wantPassed: false,
			wantMsg:    "cannot list managed",
		},
		{
			name: "managed policy metadata denied",
			client: fakeIAMValidationClient{
				listRolesOutput:        &iam.ListRolesOutput{Roles: []iamtypes.Role{{RoleName: awsv2.String("AppRole")}}},
				listRolePoliciesOutput: &iam.ListRolePoliciesOutput{},
				listAttachedRolePoliciesOutput: &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{
					PolicyArn: awsv2.String("arn:aws:iam::123456789012:policy/Managed"),
				}}},
				getPolicyErr: errors.New("policy denied"),
			},
			wantPassed: false,
			wantMsg:    "cannot read managed IAM policy metadata",
		},
		{
			name: "managed policy version denied",
			client: fakeIAMValidationClient{
				listRolesOutput:        &iam.ListRolesOutput{Roles: []iamtypes.Role{{RoleName: awsv2.String("AppRole")}}},
				listRolePoliciesOutput: &iam.ListRolePoliciesOutput{},
				listAttachedRolePoliciesOutput: &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{
					PolicyArn: awsv2.String("arn:aws:iam::123456789012:policy/Managed"),
				}}},
				getPolicyOutput:     &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: awsv2.String("v1")}},
				getPolicyVersionErr: errors.New("version denied"),
			},
			wantPassed: false,
			wantMsg:    "cannot read managed IAM policy versions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := validateIAMReadPermissions(context.Background(), tt.client)
			if check.Passed != tt.wantPassed {
				t.Fatalf("Passed = %v, want %v (%+v)", check.Passed, tt.wantPassed, check)
			}
			if !strings.Contains(check.Message, tt.wantMsg) {
				t.Fatalf("Message = %q, want substring %q", check.Message, tt.wantMsg)
			}
		})
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

func testConnectionValidator(assume stsAssumeRoleAPI, identity stsIdentityAPI, iamClient iamValidationAPI) *ConnectionValidator {
	validator := NewConnectionValidator("", "")
	validator.loadConfig = func(context.Context, string, string) (awsv2.Config, error) {
		return awsv2.Config{}, nil
	}
	validator.newAssumeRoleClient = func(awsv2.Config) stsAssumeRoleAPI { return assume }
	validator.newIdentityClient = func(awsv2.Config) stsIdentityAPI { return identity }
	validator.newIAMClient = func(awsv2.Config) iamValidationAPI { return iamClient }
	return validator
}
