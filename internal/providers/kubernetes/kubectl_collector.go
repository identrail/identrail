package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

const defaultKubectlPath = "kubectl"

const (
	defaultKubectlRetryCount       = 2
	defaultKubectlRetryBaseDelay   = 250 * time.Millisecond
	defaultKubectlRetryMaxDelay    = 2 * time.Second
	defaultKubectlRetryJitterRatio = 0.20
)

// CommandRunner executes external commands. It is injectable for deterministic tests.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// KubectlRetryPolicy controls bounded retries for transient kubectl command failures.
type KubectlRetryPolicy struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
	Jitter     float64
}

// KubectlSleeper abstracts sleep for deterministic retry tests.
type KubectlSleeper func(ctx context.Context, delay time.Duration) error

// KubectlOption customizes collector runtime behavior.
type KubectlOption func(*KubectlCollector)

// KubectlCollector collects Kubernetes assets through read-only kubectl list calls.
type KubectlCollector struct {
	kubectlPath string
	contextName string
	run         CommandRunner
	retry       KubectlRetryPolicy
	sleep       KubectlSleeper
	randFn      func() float64
	now         func() time.Time
	issues      []providers.SourceError
}

var _ providers.Collector = (*KubectlCollector)(nil)
var _ providers.DiagnosticCollector = (*KubectlCollector)(nil)

// NewKubectlCollector builds a collector that reads data from the active kube context.
func NewKubectlCollector(kubectlPath string, contextName string, runner CommandRunner, opts ...KubectlOption) *KubectlCollector {
	path := strings.TrimSpace(kubectlPath)
	if path == "" {
		path = defaultKubectlPath
	}
	if runner == nil {
		runner = defaultCommandRunner
	}
	collector := &KubectlCollector{
		kubectlPath: path,
		contextName: strings.TrimSpace(contextName),
		run:         runner,
		retry: KubectlRetryPolicy{
			MaxRetries: defaultKubectlRetryCount,
			BaseDelay:  defaultKubectlRetryBaseDelay,
			MaxDelay:   defaultKubectlRetryMaxDelay,
			Jitter:     defaultKubectlRetryJitterRatio,
		},
		sleep:  defaultKubectlSleeper,
		randFn: rand.Float64,
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(collector)
	}
	return collector
}

// WithKubectlRetryPolicy customizes transient command retry behavior.
func WithKubectlRetryPolicy(policy KubectlRetryPolicy) KubectlOption {
	return func(c *KubectlCollector) {
		if policy.MaxRetries >= 0 {
			c.retry.MaxRetries = policy.MaxRetries
		}
		if policy.BaseDelay > 0 {
			c.retry.BaseDelay = policy.BaseDelay
		}
		if policy.MaxDelay > 0 {
			c.retry.MaxDelay = policy.MaxDelay
		}
		if policy.Jitter >= 0 {
			c.retry.Jitter = policy.Jitter
		}
	}
}

// WithKubectlSleeper injects deterministic sleep behavior for tests.
func WithKubectlSleeper(sleeper KubectlSleeper) KubectlOption {
	return func(c *KubectlCollector) {
		if sleeper != nil {
			c.sleep = sleeper
		}
	}
}

// WithKubectlRetryRandFunc injects deterministic retry jitter randomization for tests.
func WithKubectlRetryRandFunc(randFn func() float64) KubectlOption {
	return func(c *KubectlCollector) {
		if randFn != nil {
			c.randFn = randFn
		}
	}
}

type rawList struct {
	Items []json.RawMessage `json:"items"`
}

// Collect fetches service accounts, role bindings, roles, and pods using read-only kubectl calls.
func (c *KubectlCollector) Collect(ctx context.Context) ([]providers.RawAsset, error) {
	assets, _, err := c.collectInternal(ctx)
	return assets, err
}

// CollectWithDiagnostics fetches assets and returns non-fatal source-level errors.
func (c *KubectlCollector) CollectWithDiagnostics(ctx context.Context) ([]providers.RawAsset, []providers.SourceError, error) {
	return c.collectInternal(ctx)
}

func (c *KubectlCollector) collectInternal(ctx context.Context) ([]providers.RawAsset, []providers.SourceError, error) {
	c.issues = c.issues[:0]
	collectedAt := c.now().UTC().Format(time.RFC3339Nano)
	assets := make([]providers.RawAsset, 0, 128)
	seen := map[string]struct{}{}

	added, err := c.collectServiceAccounts(ctx, collectedAt, seen)
	if err != nil {
		return nil, nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectRoleBindings(ctx, "rolebindings", true, collectedAt, seen)
	if err != nil {
		return nil, nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectRoleBindings(ctx, "clusterrolebindings", false, collectedAt, seen)
	if err != nil {
		return nil, nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectRoles(ctx, "roles", true, collectedAt, seen)
	if err != nil {
		return nil, nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectRoles(ctx, "clusterroles", false, collectedAt, seen)
	if err != nil {
		return nil, nil, err
	}
	assets = append(assets, added...)

	added, err = c.collectPods(ctx, collectedAt, seen)
	if err != nil {
		return nil, nil, err
	}
	assets = append(assets, added...)

	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Kind == assets[j].Kind {
			return assets[i].SourceID < assets[j].SourceID
		}
		return assets[i].Kind < assets[j].Kind
	})
	issues := append([]providers.SourceError(nil), c.issues...)
	return assets, issues, nil
}

func (c *KubectlCollector) collectServiceAccounts(ctx context.Context, collectedAt string, seen map[string]struct{}) ([]providers.RawAsset, error) {
	items, err := c.list(ctx, "serviceaccounts", true)
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	assets := make([]providers.RawAsset, 0, len(items))
	for i, item := range items {
		var sa ServiceAccount
		if err := json.Unmarshal(item, &sa); err != nil {
			c.addIssue(providers.SourceError{
				Collector: "kubernetes_kubectl_collector",
				SourceID:  fmt.Sprintf("serviceaccounts[%d]", i),
				Code:      "decode_error",
				Message:   err.Error(),
				Retryable: false,
			})
			continue
		}
		sourceID := sourceIDFor("k8s_service_account", sa.Metadata)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      "k8s_service_account",
			SourceID:  sourceID,
			Payload:   item,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func (c *KubectlCollector) collectRoleBindings(ctx context.Context, resource string, allNamespaces bool, collectedAt string, seen map[string]struct{}) ([]providers.RawAsset, error) {
	items, err := c.list(ctx, resource, allNamespaces)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", resource, err)
	}
	assets := make([]providers.RawAsset, 0, len(items))
	for i, item := range items {
		var binding RoleBinding
		if err := json.Unmarshal(item, &binding); err != nil {
			c.addIssue(providers.SourceError{
				Collector: "kubernetes_kubectl_collector",
				SourceID:  fmt.Sprintf("%s[%d]", resource, i),
				Code:      "decode_error",
				Message:   err.Error(),
				Retryable: false,
			})
			continue
		}
		sourceID := sourceIDFor("k8s_role_binding", binding.Metadata)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      "k8s_role_binding",
			SourceID:  sourceID,
			Payload:   item,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func (c *KubectlCollector) collectRoles(ctx context.Context, resource string, allNamespaces bool, collectedAt string, seen map[string]struct{}) ([]providers.RawAsset, error) {
	items, err := c.list(ctx, resource, allNamespaces)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", resource, err)
	}
	assets := make([]providers.RawAsset, 0, len(items))
	for i, item := range items {
		var role RBACRole
		if err := json.Unmarshal(item, &role); err != nil {
			c.addIssue(providers.SourceError{
				Collector: "kubernetes_kubectl_collector",
				SourceID:  fmt.Sprintf("%s[%d]", resource, i),
				Code:      "decode_error",
				Message:   err.Error(),
				Retryable: false,
			})
			continue
		}
		sourceID := roleSourceID(role.Kind, role.Metadata.Namespace, role.Metadata.Name)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      "k8s_role",
			SourceID:  sourceID,
			Payload:   item,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func (c *KubectlCollector) collectPods(ctx context.Context, collectedAt string, seen map[string]struct{}) ([]providers.RawAsset, error) {
	items, err := c.list(ctx, "pods", true)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	assets := make([]providers.RawAsset, 0, len(items))
	for i, item := range items {
		var pod Pod
		if err := json.Unmarshal(item, &pod); err != nil {
			c.addIssue(providers.SourceError{
				Collector: "kubernetes_kubectl_collector",
				SourceID:  fmt.Sprintf("pods[%d]", i),
				Code:      "decode_error",
				Message:   err.Error(),
				Retryable: false,
			})
			continue
		}
		sourceID := sourceIDFor("k8s_pod", pod.Metadata)
		if sourceID == "" {
			continue
		}
		if _, exists := seen[sourceID]; exists {
			continue
		}
		seen[sourceID] = struct{}{}
		assets = append(assets, providers.RawAsset{
			Kind:      "k8s_pod",
			SourceID:  sourceID,
			Payload:   item,
			Collected: collectedAt,
		})
	}
	return assets, nil
}

func (c *KubectlCollector) list(ctx context.Context, resource string, allNamespaces bool) ([]json.RawMessage, error) {
	args := make([]string, 0, 8)
	if c.contextName != "" {
		args = append(args, "--context", c.contextName)
	}
	args = append(args, "get", resource)
	if allNamespaces {
		args = append(args, "--all-namespaces")
	}
	args = append(args, "-o", "json")

	var output []byte
	var err error
	for attempt := 0; attempt <= c.retry.MaxRetries; attempt++ {
		output, err = c.run(ctx, c.kubectlPath, args...)
		if err == nil {
			break
		}
		if !isRetryableKubectlError(err) || attempt == c.retry.MaxRetries {
			return nil, fmt.Errorf("run %s %s: %w", c.kubectlPath, strings.Join(args, " "), err)
		}
		delay := c.retryBackoff(attempt)
		if sleepErr := c.sleep(ctx, delay); sleepErr != nil {
			return nil, sleepErr
		}
	}

	var list rawList
	if err := json.Unmarshal(output, &list); err != nil {
		return nil, fmt.Errorf("decode kubectl output: %w", err)
	}
	return list.Items, nil
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func defaultKubectlSleeper(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *KubectlCollector) retryBackoff(attempt int) time.Duration {
	delay := c.retry.BaseDelay << attempt
	if delay > c.retry.MaxDelay {
		delay = c.retry.MaxDelay
	}
	if c.retry.Jitter <= 0 {
		return delay
	}
	randFn := c.randFn
	if randFn == nil {
		randFn = rand.Float64
	}
	jitterRange := float64(delay) * c.retry.Jitter
	jitterOffset := (randFn()*2 - 1) * jitterRange
	jittered := time.Duration(float64(delay) + jitterOffset)
	if jittered < 0 {
		return 0
	}
	if jittered > c.retry.MaxDelay {
		return c.retry.MaxDelay
	}
	return jittered
}

func isRetryableKubectlError(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(strings.ToLower(err.Error()), "context canceled") {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, needle := range []string{
		"too many requests",
		"throttl",
		"timeout",
		"temporarily unavailable",
		"connection refused",
		"connection reset",
		"i/o timeout",
	} {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func (c *KubectlCollector) addIssue(issue providers.SourceError) {
	if strings.TrimSpace(issue.Code) == "" || strings.TrimSpace(issue.Message) == "" {
		return
	}
	c.issues = append(c.issues, issue)
}
