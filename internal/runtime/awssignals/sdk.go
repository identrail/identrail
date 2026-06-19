package awssignals

import (
	"context"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func NewSDKClientsFromAssumeRole(ctx context.Context, region string, profile string, roleARN string, externalID string, sessionName string) (IAMAPI, AccessAnalyzerAPI, error) {
	loadOptions := []func(*awsconfig.LoadOptions) error{}
	if strings.TrimSpace(region) != "" {
		loadOptions = append(loadOptions, awsconfig.WithRegion(strings.TrimSpace(region)))
	}
	if strings.TrimSpace(profile) != "" {
		loadOptions = append(loadOptions, awsconfig.WithSharedConfigProfile(strings.TrimSpace(profile)))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(roleARN) != "" {
		name := strings.TrimSpace(sessionName)
		if name == "" {
			name = "identrail-iam-access-signals"
		}
		options := []func(*stscreds.AssumeRoleOptions){
			func(options *stscreds.AssumeRoleOptions) { options.RoleSessionName = name },
		}
		if strings.TrimSpace(externalID) != "" {
			options = append(options, func(options *stscreds.AssumeRoleOptions) {
				options.ExternalID = awsv2.String(strings.TrimSpace(externalID))
			})
		}
		cfg.Credentials = awsv2.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), strings.TrimSpace(roleARN), options...))
	}
	return iam.NewFromConfig(cfg), accessanalyzer.NewFromConfig(cfg), nil
}

func NewSDKClientsFromStaticCredentials(region string, accessKeyID string, secretAccessKey string, sessionToken string) (IAMAPI, AccessAnalyzerAPI) {
	cfg := awsv2.Config{
		Region:      strings.TrimSpace(region),
		Credentials: credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken),
	}
	return iam.NewFromConfig(cfg), accessanalyzer.NewFromConfig(cfg)
}
