package connectors

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

type fakeDriver struct {
	probeResult     ProbeResult
	probeErr        error
	revokeErr       error
	reactivateErr   error
	probeCalls      int
	revokeCalls     int
	reactivateCalls int
}

func (f *fakeDriver) TestConnection(context.Context, domain.Connector) (ProbeResult, error) {
	f.probeCalls++
	return f.probeResult, f.probeErr
}

func (f *fakeDriver) RevokeConnection(context.Context, domain.Connector) error {
	f.revokeCalls++
	return f.revokeErr
}

func (f *fakeDriver) ReactivateConnection(context.Context, domain.Connector) error {
	f.reactivateCalls++
	return f.reactivateErr
}

func testConnector(status domain.ConnectorStatus) domain.Connector {
	return domain.Connector{
		ID:          "connector-gh",
		WorkspaceID: "workspace-a",
		ProjectID:   "project-a",
		Type:        domain.ConnectorTypeGitHub,
		DisplayName: "GitHub Cloud",
		Status:      status,
	}
}

func TestNormalizeHealthStatus(t *testing.T) {
	cases := []struct {
		raw  string
		err  error
		want HealthStatus
	}{
		{raw: "healthy", want: HealthStatusHealthy},
		{raw: "ok", want: HealthStatusHealthy},
		{raw: "degraded", want: HealthStatusWarning},
		{raw: "warning", want: HealthStatusWarning},
		{raw: "failed", want: HealthStatusError},
		{raw: "unknown", want: HealthStatusUnknown},
		{raw: "", want: HealthStatusUnknown},
		{raw: "vendor-custom", want: HealthStatusUnknown},
		{raw: "healthy", err: errors.New("timeout"), want: HealthStatusError},
	}
	for _, tc := range cases {
		got := NormalizeHealthStatus(tc.raw, tc.err)
		if got != tc.want {
			t.Fatalf("NormalizeHealthStatus(%q)=%q want=%q", tc.raw, got, tc.want)
		}
	}
}

func TestServiceTestConnectionPendingToActive(t *testing.T) {
	driver := &fakeDriver{probeResult: ProbeResult{RawHealth: "healthy", Message: "ok"}}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	}).WithClock(func() time.Time { return time.Unix(123, 0).UTC() })

	mutation, err := svc.TestConnection(context.Background(), testConnector(domain.ConnectorStatusPending))
	if err != nil {
		t.Fatalf("TestConnection error: %v", err)
	}
	if mutation.FromStatus != domain.ConnectorStatusPending || mutation.ToStatus != domain.ConnectorStatusActive {
		t.Fatalf("unexpected status transition: %+v", mutation)
	}
	if mutation.Health != HealthStatusHealthy {
		t.Fatalf("unexpected health: %+v", mutation)
	}
	if driver.probeCalls != 1 {
		t.Fatalf("expected probe hook call, got %d", driver.probeCalls)
	}
}

func TestServiceTestConnectionDegradesOnProbeError(t *testing.T) {
	driver := &fakeDriver{probeErr: errors.New("network timeout")}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	})

	mutation, err := svc.TestConnection(context.Background(), testConnector(domain.ConnectorStatusPending))
	if err != nil {
		t.Fatalf("TestConnection error: %v", err)
	}
	if mutation.ToStatus != domain.ConnectorStatusDegraded {
		t.Fatalf("expected degraded transition, got %+v", mutation)
	}
	if mutation.Health != HealthStatusError {
		t.Fatalf("expected error health, got %+v", mutation)
	}
}

func TestServiceTestConnectionActiveToDegradedOnError(t *testing.T) {
	driver := &fakeDriver{probeErr: errors.New("connection refused")}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	})

	mutation, err := svc.TestConnection(context.Background(), testConnector(domain.ConnectorStatusActive))
	if err != nil {
		t.Fatalf("TestConnection error: %v", err)
	}
	if mutation.FromStatus != domain.ConnectorStatusActive || mutation.ToStatus != domain.ConnectorStatusDegraded {
		t.Fatalf("expected Active->Degraded, got %s->%s", mutation.FromStatus, mutation.ToStatus)
	}
	if mutation.Health != HealthStatusError {
		t.Fatalf("expected error health, got %s", mutation.Health)
	}
}

func TestServiceTestConnectionActiveToDegradedOnWarning(t *testing.T) {
	driver := &fakeDriver{probeResult: ProbeResult{RawHealth: "degraded", Message: "high latency"}}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	})

	mutation, err := svc.TestConnection(context.Background(), testConnector(domain.ConnectorStatusActive))
	if err != nil {
		t.Fatalf("TestConnection error: %v", err)
	}
	if mutation.FromStatus != domain.ConnectorStatusActive || mutation.ToStatus != domain.ConnectorStatusDegraded {
		t.Fatalf("expected Active->Degraded, got %s->%s", mutation.FromStatus, mutation.ToStatus)
	}
	if mutation.Health != HealthStatusWarning {
		t.Fatalf("expected warning health, got %s", mutation.Health)
	}
}

func TestServiceTestConnectionRejectsDisconnectedConnector(t *testing.T) {
	driver := &fakeDriver{probeResult: ProbeResult{RawHealth: "healthy"}}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	})
	if _, err := svc.TestConnection(context.Background(), testConnector(domain.ConnectorStatusDisconnected)); err == nil {
		t.Fatal("expected disconnected connector probe rejection")
	}
	if driver.probeCalls != 0 {
		t.Fatalf("expected no probe hook call, got %d", driver.probeCalls)
	}
}

func TestServiceRevokeAndReactivate(t *testing.T) {
	driver := &fakeDriver{}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	})

	revoked, err := svc.Revoke(context.Background(), testConnector(domain.ConnectorStatusActive))
	if err != nil {
		t.Fatalf("Revoke error: %v", err)
	}
	if revoked.ToStatus != domain.ConnectorStatusDisconnected || revoked.Health != HealthStatusError {
		t.Fatalf("unexpected revoke mutation: %+v", revoked)
	}
	if driver.revokeCalls != 1 {
		t.Fatalf("expected revoke hook call, got %d", driver.revokeCalls)
	}

	reactivated, err := svc.Reactivate(context.Background(), testConnector(domain.ConnectorStatusDisconnected))
	if err != nil {
		t.Fatalf("Reactivate error: %v", err)
	}
	if reactivated.ToStatus != domain.ConnectorStatusPending || reactivated.Health != HealthStatusUnknown {
		t.Fatalf("unexpected reactivate mutation: %+v", reactivated)
	}
	if driver.reactivateCalls != 1 {
		t.Fatalf("expected reactivate hook call, got %d", driver.reactivateCalls)
	}
}

func TestServiceRevokeDisconnectedIsIdempotent(t *testing.T) {
	driver := &fakeDriver{}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	})
	mutation, err := svc.Revoke(context.Background(), testConnector(domain.ConnectorStatusDisconnected))
	if err != nil {
		t.Fatalf("Revoke idempotent error: %v", err)
	}
	if mutation.ToStatus != domain.ConnectorStatusDisconnected {
		t.Fatalf("expected disconnected no-op, got %+v", mutation)
	}
	if driver.revokeCalls != 0 {
		t.Fatalf("expected no revoke hook call for idempotent disconnect, got %d", driver.revokeCalls)
	}
}

func TestServiceReactivateRejectsNonDisconnected(t *testing.T) {
	driver := &fakeDriver{}
	svc := NewService(map[domain.ConnectorType]Driver{
		domain.ConnectorTypeGitHub: driver,
	})
	if _, err := svc.Reactivate(context.Background(), testConnector(domain.ConnectorStatusActive)); err == nil {
		t.Fatal("expected non-disconnected reactivate rejection")
	}
	if driver.reactivateCalls != 0 {
		t.Fatalf("expected no reactivate hook call, got %d", driver.reactivateCalls)
	}
}

func TestServiceRejectsUnsupportedConnectorType(t *testing.T) {
	svc := NewService(map[domain.ConnectorType]Driver{})
	unsupported := testConnector(domain.ConnectorStatusActive)
	unsupported.Type = domain.ConnectorTypeAWS

	if _, err := svc.TestConnection(context.Background(), unsupported); err == nil {
		t.Fatal("expected unsupported connector type error")
	}
}
