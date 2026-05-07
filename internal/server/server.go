package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/audit"
	"github.com/identrail/identrail/internal/config"
	"github.com/identrail/identrail/internal/runtime"
	"github.com/identrail/identrail/internal/telemetry"
	"go.uber.org/zap"
)

// Bootstrap contains dependencies for the HTTP API runtime.
type Bootstrap struct {
	Logger        *zap.Logger
	Metrics       *telemetry.Metrics
	Router        http.Handler
	TraceShutdown func(context.Context) error
	StoreClose    func() error
	AuditClose    func() error
}

// NewBootstrap initializes logger, metrics, tracing, and router in one place.
func NewBootstrap(ctx context.Context, cfg config.Config) (Bootstrap, error) {
	logger, err := telemetry.NewLogger(cfg.LogLevel)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("initialize logger: %w", err)
	}
	if err := config.ValidateSecurity(cfg); err != nil {
		_ = logger.Sync()
		return Bootstrap{}, fmt.Errorf("validate security config: %w", err)
	}
	for _, warning := range config.SecurityWarnings(cfg) {
		logger.Warn("security configuration warning", telemetry.String("detail", warning))
	}
	for _, diagnostic := range config.StartupDiagnostics(cfg) {
		logger.Info("startup configuration diagnostic", telemetry.String("detail", diagnostic))
	}

	metrics := telemetry.NewMetrics()
	traceShutdown, err := telemetry.SetupTracing(ctx, cfg.ServiceName)
	if err != nil {
		_ = logger.Sync()
		return Bootstrap{}, fmt.Errorf("initialize tracing: %w", err)
	}

	svc, closeStore, err := runtime.BuildScanServiceWithContext(ctx, cfg)
	if err != nil {
		_ = logger.Sync()
		return Bootstrap{}, fmt.Errorf("initialize runtime: %w", err)
	}
	svc.OnAlertError = func(alertErr error) {
		logger.Warn("scan alert delivery failed", telemetry.ZapError(alertErr))
	}
	auditSinks := []audit.AuditSink{}
	if cfg.AuditLogFile != "" {
		fileSink, sinkErr := audit.NewFileAuditSink(cfg.AuditLogFile)
		if sinkErr != nil {
			_ = closeStore()
			_ = logger.Sync()
			return Bootstrap{}, fmt.Errorf("initialize audit sink: %w", sinkErr)
		}
		auditSinks = append(auditSinks, fileSink)
	}
	if cfg.AuditForwardURL != "" {
		forwardSink, sinkErr := audit.NewHTTPAuditSink(
			cfg.AuditForwardURL,
			cfg.AuditForwardTimeout,
			cfg.AuditForwardHMACSecret,
			cfg.AuditForwardMaxRetries,
			cfg.AuditForwardRetryBackoff,
		)
		if sinkErr != nil {
			for _, sink := range auditSinks {
				_ = sink.Close()
			}
			_ = closeStore()
			_ = logger.Sync()
			return Bootstrap{}, fmt.Errorf("initialize audit forward sink: %w", sinkErr)
		}
		auditSinks = append(auditSinks, forwardSink)
	}
	auditSink := audit.AuditSink(audit.NopAuditSink{})
	if len(auditSinks) == 1 {
		auditSink = auditSinks[0]
	} else if len(auditSinks) > 1 {
		auditSink = audit.NewMultiAuditSink(auditSinks...)
	}

	var tokenVerifier api.TokenVerifier
	if cfg.OIDCIssuerURL != "" {
		verifier, verifierErr := api.NewOIDCTokenVerifier(
			ctx,
			cfg.OIDCIssuerURL,
			cfg.OIDCAudience,
			cfg.OIDCTenantClaim,
			cfg.OIDCWorkspaceClaim,
			cfg.OIDCGroupsClaim,
			cfg.OIDCRolesClaim,
		)
		if verifierErr != nil {
			for _, sink := range auditSinks {
				_ = sink.Close()
			}
			_ = closeStore()
			_ = logger.Sync()
			return Bootstrap{}, fmt.Errorf("initialize oidc verifier: %w", verifierErr)
		}
		tokenVerifier = verifier
	}

	var auditFingerprinter *audit.Fingerprinter
	if strings.TrimSpace(cfg.AuditFingerprintSecret) != "" {
		auditFingerprinter = audit.NewFingerprinter(cfg.AuditFingerprintSecret)
	}

	router := api.NewRouter(logger, metrics, svc, api.RouterOptions{
		APIKeys:              cfg.APIKeys,
		WriteAPIKeys:         cfg.WriteAPIKeys,
		APIKeyScopes:         cfg.APIKeyScopes,
		OIDCTokenVerifier:    tokenVerifier,
		OIDCWriteScopes:      cfg.OIDCWriteScopes,
		RateLimitRPM:         cfg.RateLimitRPM,
		RateLimitBurst:       cfg.RateLimitBurst,
		AuditSink:            auditSink,
		AuditFingerprinter:   auditFingerprinter,
		TrustedProxies:       cfg.TrustedProxies,
		CORSAllowedOrigins:   cfg.CORSAllowedOrigins,
		DefaultTenantID:      cfg.DefaultTenantID,
		DefaultWorkspaceID:   cfg.DefaultWorkspaceID,
		RequireExplicitScope: cfg.RequireExplicitScope,
	})
	return Bootstrap{
		Logger:        logger,
		Metrics:       metrics,
		Router:        router,
		TraceShutdown: traceShutdown,
		StoreClose:    closeStore,
		AuditClose:    auditSink.Close,
	}, nil
}

// NewHTTPServer builds an http.Server with hardened defaults.
func NewHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// Run starts the API runtime and gracefully shuts down on signal or context cancellation.
func Run(ctx context.Context, cfg config.Config, signals <-chan os.Signal) error {
	bootstrap, err := NewBootstrap(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = bootstrap.Logger.Sync() }()
	defer func() {
		if bootstrap.StoreClose != nil {
			_ = bootstrap.StoreClose()
		}
	}()
	defer func() {
		if bootstrap.AuditClose != nil {
			_ = bootstrap.AuditClose()
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = bootstrap.TraceShutdown(shutdownCtx)
	}()

	srv := NewHTTPServer(cfg, bootstrap.Router)
	if cfg.RunMigrationsOnly {
		bootstrap.Logger.Info("migrations completed; exiting because IDENTRAIL_RUN_MIGRATIONS_ONLY=true")
		return nil
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			errCh <- nil
			return
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		bootstrap.Logger.Info("shutdown requested by context")
	case <-signals:
		bootstrap.Logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	return nil
}
