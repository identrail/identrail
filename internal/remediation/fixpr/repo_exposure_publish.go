package fixpr

import (
	"context"
	"errors"
	"strings"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/findings/standards"
)

var (
	ErrRepoExposurePublishApprovalRequired   = errors.New("repo exposure publish requires operator approval")
	ErrRepoExposurePublishCredentialsMissing = errors.New("repo exposure publish requires explicit write-capable credentials")
)

// RepoExposurePublishOptions controls the publish boundary for repository
// exposure remediation PRs. Callers must set both OperatorApproved and
// WritePermissionsConfigured before any GitHub write is attempted.
type RepoExposurePublishOptions struct {
	Owner                      string
	Repo                       string
	Token                      string
	SourceContent              string
	PlanOptions                PlanOptions
	OperatorApproved           bool
	WritePermissionsConfigured bool
}

// PublishRepoExposureRemediation builds and publishes a repository exposure
// remediation PR only after the caller confirms operator approval and explicit
// write-capable credentials. GitHub still validates token scope server-side;
// this gate prevents read-only scanner installs from entering the write path.
func (p GitHubPublisher) PublishRepoExposureRemediation(
	ctx context.Context,
	finding domain.Finding,
	opts RepoExposurePublishOptions,
) (PublishResult, standards.RepoExposureRemediation, error) {
	if !opts.OperatorApproved {
		return PublishResult{}, standards.RepoExposureRemediation{}, ErrRepoExposurePublishApprovalRequired
	}
	token := strings.TrimSpace(opts.Token)
	if !opts.WritePermissionsConfigured || token == "" {
		return PublishResult{}, standards.RepoExposureRemediation{}, ErrRepoExposurePublishCredentialsMissing
	}

	plan, remediation, err := BuildRepoExposureFixPRPlan(finding, opts.SourceContent, opts.PlanOptions)
	if err != nil {
		return PublishResult{}, remediation, err
	}
	result, err := p.Publish(ctx, opts.Owner, opts.Repo, token, plan)
	return result, remediation, err
}
