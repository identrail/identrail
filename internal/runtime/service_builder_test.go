package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/api"
	"github.com/identrail/identrail/internal/app"
	"github.com/identrail/identrail/internal/config"
	"github.com/identrail/identrail/internal/providers/aws"
	"github.com/identrail/identrail/internal/scheduler"
	"github.com/identrail/identrail/internal/userexport"
)

func TestBuildScanServiceMemoryStore(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		ScanInterval:     5 * time.Minute,
	}

	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc == nil || closeFn == nil {
		t.Fatal("expected non-nil service and close function")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

type noopIAMCollectorAPI struct{}

func (noopIAMCollectorAPI) ListRoles(context.Context, string, int32) (aws.ListRolesPage, error) {
	return aws.ListRolesPage{}, nil
}

func TestNewAWSScannerUsesCompositeCollectorScope(t *testing.T) {
	// list roles never called in this test, but the composite collector should
	// be constructed with exactly the account/region scope from the call site.
	scanner := newAWSScanner(noopIAMCollectorAPI{}, "account-xyz", "us-east-2")
	composite, ok := scanner.Collector.(*aws.AWSCompositeCollector)
	if !ok {
		t.Fatalf("expected aws composite collector, got %T", scanner.Collector)
	}
	if composite.AccountID() != "account-xyz" || composite.Region() != "us-east-2" {
		t.Fatalf("unexpected composite scope account=%q region=%q", composite.AccountID(), composite.Region())
	}
}

func TestBuildScanServiceRequiresPersistentStoreByDefault(t *testing.T) {
	cfg := config.Config{
		Provider:       "aws",
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected missing database url to fail without memory-store opt-in")
	}
}

func TestBuildScanServiceRepoScanSettings(t *testing.T) {
	cfg := config.Config{
		Provider:                "aws",
		AllowMemoryStore:        true,
		AWSFixturePath:          []string{"testdata/aws/role_with_policies.json"},
		RepoScanEnabled:         true,
		RepoScanHistoryLimit:    700,
		RepoScanMaxFindings:     120,
		RepoScanHistoryLimitMax: 2500,
		RepoScanMaxFindingsMax:  900,
		RepoScanAllowlist:       []string{"trusted/*"},
		ScanQueueMaxPending:     30,
		RepoQueueMaxPending:     140,
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if !svc.RepoScanEnabled || svc.RepoScanDefaultHistoryLimit != 700 || svc.RepoScanDefaultMaxFindings != 120 {
		t.Fatalf("unexpected repo scan defaults on service: enabled=%t history=%d findings=%d", svc.RepoScanEnabled, svc.RepoScanDefaultHistoryLimit, svc.RepoScanDefaultMaxFindings)
	}
	if svc.RepoScanMaxHistoryLimit != 2500 || svc.RepoScanMaxFindingsLimit != 900 {
		t.Fatalf("unexpected repo scan max bounds on service: history=%d findings=%d", svc.RepoScanMaxHistoryLimit, svc.RepoScanMaxFindingsLimit)
	}
	if len(svc.RepoScanAllowedTargets) != 1 || svc.RepoScanAllowedTargets[0] != "trusted/*" {
		t.Fatalf("unexpected repo scan allowlist %+v", svc.RepoScanAllowedTargets)
	}
	if svc.ScanQueueMaxPending != 30 || svc.RepoQueueMaxPending != 140 {
		t.Fatalf("unexpected queue pending limits scan=%d repo=%d", svc.ScanQueueMaxPending, svc.RepoQueueMaxPending)
	}
}

func TestBuildScanServiceInitializesUserExportStorageWithoutSigningKey(t *testing.T) {
	cfg := config.Config{
		Provider:           "aws",
		AllowMemoryStore:   true,
		AWSFixturePath:     []string{"testdata/aws/role_with_policies.json"},
		UserDataExportPath: filepath.Join(t.TempDir(), "exports"),
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()
	if svc.UserExportStorage == nil {
		t.Fatal("expected export storage for worker processing")
	}
	if len(svc.UserExportTokenSecret) != 0 {
		t.Fatal("expected download signing to remain disabled without a session key")
	}
}

func TestBuildScanServiceRejectsWeakUserExportSigningKey(t *testing.T) {
	cfg := config.Config{
		Provider:           "aws",
		AllowMemoryStore:   true,
		AWSFixturePath:     []string{"testdata/aws/role_with_policies.json"},
		UserDataExportPath: filepath.Join(t.TempDir(), "exports"),
		SessionKey:         "short",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected weak export signing key error")
	}
}

func TestBuildScanServiceInitializesS3UserExportStorage(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	cfg := config.Config{
		Provider:               "aws",
		AllowMemoryStore:       true,
		AWSFixturePath:         []string{"testdata/aws/role_with_policies.json"},
		AWSRegion:              "us-east-1",
		UserDataExportS3Bucket: "identrail-dev-user-data-exports",
		UserDataExportS3Prefix: "exports/",
		UserDataExportS3Region: "us-east-1",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()
	storage, ok := svc.UserExportStorage.(*userexport.S3Storage)
	if !ok {
		t.Fatalf("expected s3 export storage, got %T", svc.UserExportStorage)
	}
	if storage.Bucket != "identrail-dev-user-data-exports" || storage.Prefix != "exports/" {
		t.Fatalf("unexpected s3 storage bucket=%q prefix=%q", storage.Bucket, storage.Prefix)
	}
}

func TestBuildScanServiceRejectsMultipleUserExportStorageBackends(t *testing.T) {
	cfg := config.Config{
		Provider:               "aws",
		AllowMemoryStore:       true,
		AWSFixturePath:         []string{"testdata/aws/role_with_policies.json"},
		UserDataExportPath:     filepath.Join(t.TempDir(), "exports"),
		UserDataExportS3Bucket: "identrail-dev-user-data-exports",
	}
	if _, _, err := BuildScanService(cfg); err == nil || !strings.Contains(err.Error(), "cannot both be set") {
		t.Fatalf("expected multiple export backend error, got %v", err)
	}
}

func TestBuildScanServiceLockDefaults(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		LockBackend:      "inmemory",
		LockNamespace:    "tenant-a",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if svc.LockNamespace != "tenant-a" {
		t.Fatalf("unexpected lock namespace %q", svc.LockNamespace)
	}
	if _, ok := svc.Locker.(*scheduler.InMemoryLocker); !ok {
		t.Fatalf("expected in-memory locker, got %T", svc.Locker)
	}
}

func TestBuildScanServiceLockBackendAutoWithoutDatabase(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		LockBackend:      "auto",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if _, ok := svc.Locker.(*scheduler.InMemoryLocker); !ok {
		t.Fatalf("expected in-memory locker for auto mode without database, got %T", svc.Locker)
	}
}

func TestBuildScanServiceKubernetesProvider(t *testing.T) {
	cfg := config.Config{
		Provider:         "kubernetes",
		AllowMemoryStore: true,
		KubernetesFixturePath: []string{
			repoFixturePathForProvider(t, "kubernetes", "service_account_payments.json"),
			repoFixturePathForProvider(t, "kubernetes", "role_binding_cluster_admin.json"),
			repoFixturePathForProvider(t, "kubernetes", "pod_payments.json"),
		},
		ScanInterval: 5 * time.Minute,
	}

	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc == nil || closeFn == nil {
		t.Fatal("expected non-nil service and close function")
	}
	if _, err := svc.RunScan(context.Background()); err != nil {
		t.Fatalf("kubernetes scan failed: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestBuildScanServiceUnsupportedProvider(t *testing.T) {
	cfg := config.Config{
		Provider:         "azure",
		AllowMemoryStore: true,
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected unsupported provider error")
	}
}

func TestBuildScanServiceUnsupportedAWSSource(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSSource:        "unknown",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected unsupported aws source error")
	}
}

func TestBuildScanServiceAWSSDKMode(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSSource:        "sdk",
		AWSRegion:        "us-east-1",
		AWSAccountID:     "123456789012",
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "ASIAXXXXXXXXXXXXXXXX")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example-secret-key-replace-me")
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc == nil || closeFn == nil {
		t.Fatal("expected non-nil service and close function")
	}
	scannerRunner, ok := svc.Scanner.(app.Scanner)
	if !ok {
		t.Fatalf("expected app.Scanner scanner runner, got %T", svc.Scanner)
	}
	if composite, ok := scannerRunner.Collector.(*aws.AWSCompositeCollector); !ok {
		t.Fatalf("expected composite collector, got %T", scannerRunner.Collector)
	} else if composite.AccountID() != cfg.AWSAccountID || composite.Region() != cfg.AWSRegion {
		t.Fatalf("unexpected composite scope: account=%q region=%q", composite.AccountID(), composite.Region())
	} else {
		assertAWSCompositeServiceNames(t, composite, []string{"iam", "ec2", "ecs", "lambda", "codebuild", "codepipeline", "stepfunctions", "eventbridge", "managed-compute", "sagemaker", "iam-passrole", "eks"})
	}
	connectorScanner, err := svc.AWSScannerFactory(context.Background(), api.AWSConnectionStatus{
		AccountID:  cfg.AWSAccountID,
		Region:     cfg.AWSRegion,
		RoleARN:    "arn:aws:iam::123456789012:role/identrail-readonly",
		ExternalID: "external-id",
	})
	if err != nil {
		t.Fatalf("build connector scanner failed: %v", err)
	}
	connectorAppScanner, ok := connectorScanner.(app.Scanner)
	if !ok {
		t.Fatalf("expected connector app.Scanner, got %T", connectorScanner)
	}
	if connectorComposite, ok := connectorAppScanner.Collector.(*aws.AWSCompositeCollector); !ok {
		t.Fatalf("expected connector composite collector, got %T", connectorAppScanner.Collector)
	} else {
		assertAWSCompositeServiceNames(t, connectorComposite, []string{"iam", "ec2", "ecs", "lambda", "codebuild", "codepipeline", "stepfunctions", "eventbridge", "managed-compute", "sagemaker", "iam-passrole", "eks"})
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func assertAWSCompositeServiceNames(t *testing.T, composite *aws.AWSCompositeCollector, want []string) {
	t.Helper()
	got := composite.ServiceNames()
	if len(got) != len(want) {
		t.Fatalf("service names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("service names = %v, want %v", got, want)
		}
	}
}

func TestBuildScanServiceUnsupportedKubernetesSource(t *testing.T) {
	cfg := config.Config{
		Provider:         "kubernetes",
		AllowMemoryStore: true,
		KubernetesSource: "unknown",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected unsupported kubernetes source error")
	}
}

func TestBuildScanServiceKubernetesKubectlMode(t *testing.T) {
	cfg := config.Config{
		Provider:         "kubernetes",
		AllowMemoryStore: true,
		KubernetesSource: "kubectl",
		KubectlPath:      "/path/does/not/exist/kubectl",
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()
	if _, runErr := svc.RunScan(context.Background()); runErr == nil {
		t.Fatal("expected kubectl runtime error")
	}
}

func TestBuildScanServiceWiresKubernetesPreflightFactory(t *testing.T) {
	cfg := config.Config{
		Provider:         "kubernetes",
		AllowMemoryStore: true,
		KubernetesFixturePath: []string{
			repoFixturePathForProvider(t, "kubernetes", "service_account_payments.json"),
			repoFixturePathForProvider(t, "kubernetes", "role_binding_cluster_admin.json"),
			repoFixturePathForProvider(t, "kubernetes", "pod_payments.json"),
		},
		KubectlPath: "/path/does/not/exist/kubectl",
		KubeContext: "prod-default",
	}

	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()
	if svc.KubernetesPreflightFactory == nil {
		t.Fatal("expected kubernetes preflight factory to be wired")
	}

	defaultResult := svc.KubernetesPreflightFactory("").Preflight(context.Background())
	if defaultResult.Cluster.Context != "prod-default" {
		t.Fatalf("expected default kube context to reach preflight driver, got %q", defaultResult.Cluster.Context)
	}
	requestedResult := svc.KubernetesPreflightFactory("prod-request").Preflight(context.Background())
	if requestedResult.Cluster.Context != "prod-request" {
		t.Fatalf("expected request kube context to override default, got %q", requestedResult.Cluster.Context)
	}
}

func TestNewStoreMemoryAndInvalidPostgres(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("expected memory store, got err: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close memory store: %v", err)
	}

	_, err = NewStore("postgres://user:pass@127.0.0.1:1/identrail?sslmode=disable&connect_timeout=1")
	if err == nil {
		t.Fatal("expected postgres init error")
	}
}

func TestBuildScanServiceInvalidAlertWebhookConfig(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		AlertWebhookURL:  "http://example.com/hook",
		AlertMinSeverity: "high",
	}
	if _, _, err := BuildScanService(cfg); err == nil {
		t.Fatal("expected alert webhook validation error")
	}
}

func TestBuildScanServiceConfiguresConnectorSecretManagerAndDataExport(t *testing.T) {
	exportPath := t.TempDir()

	cfg := config.Config{
		Provider:            "aws",
		AllowMemoryStore:    true,
		AWSFixturePath:      []string{"testdata/aws/role_with_policies.json"},
		ConnectorSecretKeys: "v1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		UserDataExportPath:  exportPath,
		SessionKey:          "abcdefghijklmnopqrstuvwxyz0123456789",
		LockBackend:         "invalid",
	}

	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()
	if svc.ConnectorSecretManager == nil {
		t.Fatal("expected connector secret manager to be configured")
	}
	if svc.UserExportStorage == nil {
		t.Fatal("expected user export storage to be configured")
	}
	if svc.UserExportTokenSecret == nil {
		t.Fatal("expected user export token secret to be derived from session key")
	}
	if svc.Locker == nil {
		t.Fatal("expected fallback locker to be configured")
	}
	if _, ok := svc.Locker.(*scheduler.InMemoryLocker); !ok {
		t.Fatalf("expected in-memory locker for invalid backend, got %T", svc.Locker)
	}
}

func TestBuildScanServiceRejectsInvalidConnectorSecretKeys(t *testing.T) {
	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		ConnectorSecretKeys: "v1:" +
			"YWJj", // not 32-byte key material
	}
	_, _, err := BuildScanService(cfg)
	if err == nil {
		t.Fatal("expected connector secret manager initialization error")
	}
}

func TestBuildScanServiceWithAlertWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.Config{
		Provider:         "aws",
		AllowMemoryStore: true,
		AWSFixturePath:   []string{"testdata/aws/role_with_policies.json"},
		AlertWebhookURL:  server.URL,
		AlertMinSeverity: "high",
		AlertTimeout:     2 * time.Second,
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	if svc.Alerter == nil {
		t.Fatal("expected alerter to be configured")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
}

func TestBuildScanServiceAlertWebhookRetriesOnTransientFailure(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&requests, 1)
		if current < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("retry"))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cfg := config.Config{
		Provider:          "aws",
		AllowMemoryStore:  true,
		AWSFixturePath:    []string{repoFixturePath(t, "role_with_policies.json")},
		AlertWebhookURL:   server.URL,
		AlertMinSeverity:  "high",
		AlertTimeout:      2 * time.Second,
		AlertMaxRetries:   3,
		AlertRetryBackoff: 1 * time.Millisecond,
	}
	svc, closeFn, err := BuildScanService(cfg)
	if err != nil {
		t.Fatalf("build service failed: %v", err)
	}
	defer func() { _ = closeFn() }()

	if _, err := svc.RunScan(context.Background()); err != nil {
		t.Fatalf("run scan failed: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got < 3 {
		t.Fatalf("expected at least 3 webhook attempts, got %d", got)
	}
}

func repoFixturePath(t *testing.T, name string) string {
	return repoFixturePathForProvider(t, "aws", name)
}

func repoFixturePathForProvider(t *testing.T, provider string, name string) string {
	t.Helper()
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("could not resolve caller path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(root, "testdata", provider, name)
}
