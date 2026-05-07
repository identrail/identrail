package providers

import (
	"context"
	"errors"
	"testing"

	"github.com/identrail/identrail/internal/domain"
)

type fakeCollector struct{ err error }

func (f fakeCollector) Collect(_ context.Context) ([]RawAsset, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []RawAsset{{Kind: "role", SourceID: "arn:aws:iam::123:role/demo"}}, nil
}

type fakeRuleSet struct{}

func (fakeRuleSet) Evaluate(_ context.Context, _ NormalizedBundle, _ []domain.Relationship) ([]domain.Finding, error) {
	return []domain.Finding{{ID: "f1", Type: domain.FindingStaleIdentity, Severity: domain.SeverityMedium, Title: "stale"}}, nil
}

func TestCollectorContract(t *testing.T) {
	collector := fakeCollector{}
	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
}

func TestCollectorError(t *testing.T) {
	collector := fakeCollector{err: errors.New("rate limit")}
	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRuleSetContract(t *testing.T) {
	rules := fakeRuleSet{}
	findings, err := rules.Evaluate(context.Background(), NormalizedBundle{}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != domain.FindingStaleIdentity {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}
