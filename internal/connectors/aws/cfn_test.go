package aws

import (
	"net/url"
	"strings"
	"testing"
)

func TestBuildCloudFormationLaunchURL(t *testing.T) {
	tests := []struct {
		name       string
		region     string
		wantHost   string
		wantRegion string
	}{
		{
			name:       "commercial region",
			region:     "eu-west-1",
			wantHost:   "console.aws.amazon.com",
			wantRegion: "eu-west-1",
		},
		{
			name:       "govcloud region",
			region:     "us-gov-west-1",
			wantHost:   "console.amazonaws-us-gov.com",
			wantRegion: "us-gov-west-1",
		},
		{
			name:       "china region",
			region:     "cn-north-1",
			wantHost:   "console.amazonaws.cn",
			wantRegion: "cn-north-1",
		},
		{
			name:       "invalid region defaults to commercial us east",
			region:     "not-a-region",
			wantHost:   "console.aws.amazon.com",
			wantRegion: "us-east-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			launchURL := BuildCloudFormationLaunchURL(CloudFormationLaunchInput{
				TemplateURL:        "https://cdn.example.com/identrail-readonly.yaml",
				Region:             tt.region,
				StackName:          "identrail-prod",
				IdentrailAccountID: "123456789012",
				ExternalID:         "external-id",
				RoleName:           "IdentrailReadOnlyProd",
			})

			parsed, err := url.Parse(launchURL)
			if err != nil {
				t.Fatalf("parse launch URL: %v", err)
			}
			if parsed.Scheme != "https" || parsed.Host != tt.wantHost {
				t.Fatalf("unexpected console URL: %s", launchURL)
			}
			if got := parsed.Query().Get("region"); got != tt.wantRegion {
				t.Fatalf("expected region %s, got %q", tt.wantRegion, got)
			}
			if !strings.Contains(parsed.Fragment, "templateURL=https://cdn.example.com/identrail-readonly.yaml") {
				t.Fatalf("expected encoded template URL in fragment, got %q", parsed.Fragment)
			}
			if !strings.Contains(parsed.Fragment, "param_IdentrailAccountId=123456789012") {
				t.Fatalf("expected Identrail account id in fragment, got %q", parsed.Fragment)
			}
			if !strings.Contains(parsed.Fragment, "param_ExternalId=external-id") {
				t.Fatalf("expected external id in fragment, got %q", parsed.Fragment)
			}
		})
	}
}

func TestNormalizeRegion(t *testing.T) {
	if got := NormalizeRegion("us-gov-west-1"); got != "us-gov-west-1" {
		t.Fatalf("expected gov region to be preserved, got %q", got)
	}
	if got := NormalizeRegion("not-a-region"); got != "us-east-1" {
		t.Fatalf("expected invalid region to default to us-east-1, got %q", got)
	}
}

func TestReadOnlyPolicyDocument(t *testing.T) {
	policy, err := ReadOnlyPolicyDocument()
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !strings.Contains(string(policy), "iam:SimulatePrincipalPolicy") {
		t.Fatalf("expected IAM simulation action in policy")
	}
	hash, err := ReadOnlyPolicyHash()
	if err != nil {
		t.Fatalf("hash policy: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("expected sha256 hex hash, got %q", hash)
	}
	if len(PermissionPreview()) == 0 {
		t.Fatalf("expected permission preview entries")
	}
}
