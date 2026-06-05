package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/providers"
)

var _ providers.DiagnosticCollector = (*AWSCompositeCollector)(nil)

// AWSCollectorScope carries service context used by each service-level collector.
type AWSCollectorScope struct {
	TenantID    string
	WorkspaceID string
	ProjectID   string
	ConnectorID string
	ScanID      string
	AccountID   string
	Region      string
	Service     string
}

// AWSServiceCollector defines the reusable contract for collectable AWS service
// modules. Future EC2, ECS, Lambda, EKS, Bedrock, and runtime collectors should
// implement this interface so the composite collector can preserve partial
// failure diagnostics across account, region, and service boundaries.
type AWSServiceCollector interface {
	ServiceName() string
	CollectWithDiagnostics(ctx context.Context, scope AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error)
}

// AWSCompositeCollector runs a sequence of AWS service collectors with partial-failure tolerance.
type AWSCompositeCollector struct {
	accountID string
	region    string
	services  []AWSServiceCollector
}

func (c *AWSCompositeCollector) AccountID() string {
	if c == nil {
		return ""
	}
	return c.accountID
}

func (c *AWSCompositeCollector) Region() string {
	if c == nil {
		return ""
	}
	return c.region
}

func (c *AWSCompositeCollector) ServiceNames() []string {
	if c == nil {
		return nil
	}
	names := make([]string, 0, len(c.services))
	for _, service := range c.services {
		if service == nil {
			continue
		}
		names = append(names, service.ServiceName())
	}
	return names
}

// NewAWSCompositeCollector creates a composite AWS collector that runs IAM first by default
// and accepts optional additional service collectors for future extension.
func NewAWSCompositeCollector(iamAPI IAMAPI, accountID string, region string, additionalServices ...AWSServiceCollector) *AWSCompositeCollector {
	services := make([]AWSServiceCollector, 0, 1+len(additionalServices))
	services = append(services, &iamCollectorAdapter{collector: NewCollector(iamAPI)})
	for _, service := range additionalServices {
		if service == nil {
			continue
		}
		services = append(services, service)
	}
	return &AWSCompositeCollector{
		accountID: strings.TrimSpace(accountID),
		region:    strings.TrimSpace(region),
		services:  services,
	}
}

// NewAWSScanner creates the canonical AWS app scanner wiring for shared runtime and CLI construction.
func NewAWSScanner(iamAPI IAMAPI, accountID string, region string, ruleSet ...providers.RiskRuleSet) app.Scanner {
	return NewAWSScannerWithServices(iamAPI, accountID, region, nil, ruleSet...)
}

// NewAWSScannerWithServices creates AWS scanner wiring with optional service collectors.
func NewAWSScannerWithServices(iamAPI IAMAPI, accountID string, region string, additionalServices []AWSServiceCollector, ruleSet ...providers.RiskRuleSet) app.Scanner {
	var resolvedRuleSet providers.RiskRuleSet = NewRuleSet()
	if len(ruleSet) > 0 && ruleSet[0] != nil {
		resolvedRuleSet = ruleSet[0]
	}

	return app.Scanner{
		Collector:            NewAWSCompositeCollector(iamAPI, accountID, region, additionalServices...),
		Normalizer:           NewRoleNormalizer(),
		PermissionResolver:   NewPolicyPermissionResolver(),
		RelationshipResolver: NewRelationshipBuilder(),
		RiskRuleSet:          resolvedRuleSet,
	}
}

// CollectWithDiagnostics executes all service collectors sequentially, de-duplicates assets,
// and returns service-level diagnostics while continuing on non-fatal service failures.
func (c *AWSCompositeCollector) CollectWithDiagnostics(ctx context.Context) ([]providers.RawAsset, []providers.SourceError, error) {
	if c == nil {
		return nil, nil, errors.New("aws composite collector is not initialized")
	}

	var (
		assets       []providers.RawAsset
		sourceErrors []providers.SourceError
		serviceErrs  []error
		attempted    int
	)
	for _, service := range c.services {
		if service == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		attempted++

		scope := AWSCollectorScope{
			AccountID: c.accountID,
			Region:    c.region,
			Service:   service.ServiceName(),
		}

		serviceAssets, serviceSourceErrors, err := service.CollectWithDiagnostics(ctx, scope)
		if len(serviceAssets) > 0 {
			assets = append(assets, serviceAssets...)
		}
		for _, sourceError := range serviceSourceErrors {
			sourceErrors = append(sourceErrors, enrichSourceError(scope, sourceError))
		}

		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, nil, err
			}
			sourceErrors = append(sourceErrors, sourceServiceFailureDiagnostic(scope, err))
			serviceErrs = append(serviceErrs, fmt.Errorf("%s: %w", serviceNameOrUnknown(scope.Service), err))
		}
	}

	// Tolerate partial failures, but do not mask a total collection failure as an
	// empty partial success: if every attempted service collector failed, surface
	// an error so the scan fails instead of silently reporting zero assets.
	if attempted > 0 && len(serviceErrs) == attempted {
		return nil, sourceErrors, fmt.Errorf("all aws service collectors failed: %w", errors.Join(serviceErrs...))
	}

	return dedupeAndSortAssets(assets), sourceErrors, nil
}

// Collect preserves compatibility with providers.Collector by dropping diagnostics.
func (c *AWSCompositeCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.CollectWithDiagnostics(ctx)
	return assets, err
}

func enrichSourceError(scope AWSCollectorScope, sourceError providers.SourceError) providers.SourceError {
	sourceError.Collector = compositeCollectorName(scope.Service, sourceError.Collector)
	sourceError.Message = appendSourceContextToMessage(scope, sourceError.Message)
	if strings.TrimSpace(sourceError.SourceID) == "" {
		sourceError.SourceID = compositeSourceID(scope, "")
	} else {
		sourceError.SourceID = compositeSourceID(scope, sourceError.SourceID)
	}
	return sourceError
}

func sourceServiceFailureDiagnostic(scope AWSCollectorScope, err error) providers.SourceError {
	return providers.SourceError{
		Collector: compositeCollectorName(scope.Service, ""),
		Code:      "service_collection_failed",
		Message:   appendSourceContextToMessage(scope, err.Error()),
		SourceID:  compositeSourceID(scope, ""),
		Retryable: true,
	}
}

func compositeCollectorName(serviceName string, collector string) string {
	trimmed := strings.TrimSpace(strings.ToLower(serviceName))
	if trimmed == "" {
		trimmed = "aws"
	}
	if strings.TrimSpace(collector) == "" {
		return "aws_" + trimmed
	}
	return "aws_" + trimmed + "/" + strings.TrimSpace(collector)
}

func appendSourceContextToMessage(scope AWSCollectorScope, message string) string {
	contextSuffix := serviceContextFromScope(scope)
	if message == "" {
		return contextSuffix
	}
	if strings.Contains(message, contextSuffix) {
		return message
	}
	return message + " " + contextSuffix
}

func serviceContextFromScope(scope AWSCollectorScope) string {
	return fmt.Sprintf("[service=%s account=%s region=%s]", serviceNameOrUnknown(scope.Service), strings.TrimSpace(scope.AccountID), strings.TrimSpace(scope.Region))
}

func serviceNameOrUnknown(serviceName string) string {
	trimmed := strings.TrimSpace(strings.ToLower(serviceName))
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func compositeSourceID(scope AWSCollectorScope, sourceID string) string {
	if strings.TrimSpace(sourceID) == "" {
		sourceID = "source"
	}
	return fmt.Sprintf("service=%s|account=%s|region=%s|source=%s", serviceNameOrUnknown(scope.Service), strings.TrimSpace(scope.AccountID), strings.TrimSpace(scope.Region), sourceID)
}

func dedupeAndSortAssets(assets []providers.RawAsset) []providers.RawAsset {
	sort.SliceStable(assets, func(i, j int) bool {
		leftKind := strings.TrimSpace(assets[i].Kind)
		rightKind := strings.TrimSpace(assets[j].Kind)
		if leftKind != rightKind {
			return leftKind < rightKind
		}
		return strings.TrimSpace(assets[i].SourceID) < strings.TrimSpace(assets[j].SourceID)
	})

	seen := make(map[string]struct{}, len(assets))
	deduped := make([]providers.RawAsset, 0, len(assets))
	for _, asset := range assets {
		kind := strings.TrimSpace(asset.Kind)
		sourceID := strings.TrimSpace(asset.SourceID)
		key := kind + "\x00" + sourceID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, asset)
	}
	return deduped
}

// iamCollectorAdapter wraps the existing IAM collector without changing behavior.
type iamCollectorAdapter struct {
	collector *Collector
}

func (a *iamCollectorAdapter) ServiceName() string {
	return "iam"
}

func (a *iamCollectorAdapter) CollectWithDiagnostics(ctx context.Context, _ AWSCollectorScope) ([]providers.RawAsset, []providers.SourceError, error) {
	if a == nil || a.collector == nil {
		return nil, nil, errors.New("iam collector is not initialized")
	}
	return a.collector.CollectWithDiagnostics(ctx)
}

var _ AWSServiceCollector = (*iamCollectorAdapter)(nil)
