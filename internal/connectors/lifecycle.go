package connectors

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

// HealthStatus normalizes provider-specific connection health into one shared model.
type HealthStatus string

const (
	HealthStatusUnknown HealthStatus = "unknown"
	HealthStatusHealthy HealthStatus = "healthy"
	HealthStatusWarning HealthStatus = "warning"
	HealthStatusError   HealthStatus = "error"
)

var (
	// ErrUnsupportedConnectorType indicates no provider driver was registered.
	ErrUnsupportedConnectorType = errors.New("unsupported connector type")
	// ErrInvalidConnector indicates connector payload is invalid for lifecycle operations.
	ErrInvalidConnector = errors.New("invalid connector")
	// ErrInvalidLifecycleTransition indicates requested lifecycle action is not allowed.
	ErrInvalidLifecycleTransition = errors.New("invalid connector lifecycle transition")
)

// ProbeResult captures one provider test-connection outcome.
type ProbeResult struct {
	RawHealth string
	Message   string
}

// LifecycleMutation describes a status/health update after one lifecycle action.
type LifecycleMutation struct {
	FromStatus domain.ConnectorStatus `json:"from_status"`
	ToStatus   domain.ConnectorStatus `json:"to_status"`
	Health     HealthStatus           `json:"health_status"`
	Message    string                 `json:"message,omitempty"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// Driver is the provider-agnostic connection hook contract.
type Driver interface {
	TestConnection(ctx context.Context, connector domain.Connector) (ProbeResult, error)
	RevokeConnection(ctx context.Context, connector domain.Connector) error
	ReactivateConnection(ctx context.Context, connector domain.Connector) error
}

// Service executes normalized lifecycle operations across registered provider drivers.
type Service struct {
	now     func() time.Time
	drivers map[domain.ConnectorType]Driver
}

// NewService builds one lifecycle service with registered provider drivers.
func NewService(drivers map[domain.ConnectorType]Driver) *Service {
	cloned := make(map[domain.ConnectorType]Driver, len(drivers))
	for provider, driver := range drivers {
		cloned[provider] = driver
	}
	return &Service{
		now:     time.Now,
		drivers: cloned,
	}
}

// WithClock overrides lifecycle timestamps for deterministic tests.
func (s *Service) WithClock(now func() time.Time) *Service {
	if now != nil {
		s.now = now
	}
	return s
}

// TestConnection runs one provider test-connection hook and normalizes health/status.
func (s *Service) TestConnection(ctx context.Context, connector domain.Connector) (LifecycleMutation, error) {
	driver, err := s.resolveDriver(connector)
	if err != nil {
		return LifecycleMutation{}, err
	}
	if connector.Status == domain.ConnectorStatusDisconnected {
		return LifecycleMutation{}, fmt.Errorf("%w: disconnected connector must be reactivated before probe", ErrInvalidLifecycleTransition)
	}

	result, probeErr := driver.TestConnection(ctx, connector)
	health := NormalizeHealthStatus(result.RawHealth, probeErr)
	targetStatus := statusFromHealth(connector.Status, health)
	if !domain.CanTransitionConnectorStatus(connector.Status, targetStatus) {
		return LifecycleMutation{}, fmt.Errorf("%w: %s -> %s", ErrInvalidLifecycleTransition, connector.Status, targetStatus)
	}

	message := strings.TrimSpace(result.Message)
	if message == "" && probeErr != nil {
		message = probeErr.Error()
	}
	return LifecycleMutation{
		FromStatus: connector.Status,
		ToStatus:   targetStatus,
		Health:     health,
		Message:    message,
		UpdatedAt:  s.now().UTC(),
	}, nil
}

// Revoke transitions a connector to disconnected state and executes provider revoke hooks.
func (s *Service) Revoke(ctx context.Context, connector domain.Connector) (LifecycleMutation, error) {
	driver, err := s.resolveDriver(connector)
	if err != nil {
		return LifecycleMutation{}, err
	}
	if connector.Status == domain.ConnectorStatusDisconnected {
		return LifecycleMutation{
			FromStatus: connector.Status,
			ToStatus:   connector.Status,
			Health:     HealthStatusError,
			Message:    "connector already disconnected",
			UpdatedAt:  s.now().UTC(),
		}, nil
	}
	if !domain.CanTransitionConnectorStatus(connector.Status, domain.ConnectorStatusDisconnected) {
		return LifecycleMutation{}, fmt.Errorf("%w: %s -> %s", ErrInvalidLifecycleTransition, connector.Status, domain.ConnectorStatusDisconnected)
	}

	if err := driver.RevokeConnection(ctx, connector); err != nil {
		return LifecycleMutation{}, err
	}
	return LifecycleMutation{
		FromStatus: connector.Status,
		ToStatus:   domain.ConnectorStatusDisconnected,
		Health:     HealthStatusError,
		Message:    "connector revoked",
		UpdatedAt:  s.now().UTC(),
	}, nil
}

// Reactivate moves disconnected connectors back to pending state and executes provider hooks.
func (s *Service) Reactivate(ctx context.Context, connector domain.Connector) (LifecycleMutation, error) {
	driver, err := s.resolveDriver(connector)
	if err != nil {
		return LifecycleMutation{}, err
	}
	if connector.Status != domain.ConnectorStatusDisconnected {
		return LifecycleMutation{}, fmt.Errorf("%w: only disconnected connectors can be reactivated", ErrInvalidLifecycleTransition)
	}
	if !domain.CanTransitionConnectorStatus(connector.Status, domain.ConnectorStatusPending) {
		return LifecycleMutation{}, fmt.Errorf("%w: %s -> %s", ErrInvalidLifecycleTransition, connector.Status, domain.ConnectorStatusPending)
	}

	if err := driver.ReactivateConnection(ctx, connector); err != nil {
		return LifecycleMutation{}, err
	}
	return LifecycleMutation{
		FromStatus: connector.Status,
		ToStatus:   domain.ConnectorStatusPending,
		Health:     HealthStatusUnknown,
		Message:    "connector reactivated",
		UpdatedAt:  s.now().UTC(),
	}, nil
}

// NormalizeHealthStatus maps provider-specific health strings into one shared enum.
func NormalizeHealthStatus(raw string, probeErr error) HealthStatus {
	if probeErr != nil {
		return HealthStatusError
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "healthy", "ok", "pass", "ready", "up", "connected", "active":
		return HealthStatusHealthy
	case "warning", "warn", "degraded", "partial":
		return HealthStatusWarning
	case "error", "failed", "fail", "down", "disconnected", "revoked":
		return HealthStatusError
	case "", "unknown", "pending", "initializing":
		return HealthStatusUnknown
	default:
		return HealthStatusUnknown
	}
}

func statusFromHealth(current domain.ConnectorStatus, health HealthStatus) domain.ConnectorStatus {
	switch health {
	case HealthStatusHealthy:
		return domain.ConnectorStatusActive
	case HealthStatusWarning, HealthStatusError:
		if current == domain.ConnectorStatusPending || current == domain.ConnectorStatusActive {
			return domain.ConnectorStatusDegraded
		}
		return current
	case HealthStatusUnknown:
		if current == domain.ConnectorStatusPending {
			return domain.ConnectorStatusDegraded
		}
		return current
	default:
		return current
	}
}

func (s *Service) resolveDriver(connector domain.Connector) (Driver, error) {
	if err := connector.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConnector, err)
	}
	driver, ok := s.drivers[connector.Type]
	if !ok || driver == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedConnectorType, connector.Type)
	}
	return driver, nil
}
