package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/connectors"
	"github.com/identrail/identrail/internal/domain"
)

var requiredKubernetesPreflightChecks = []KubernetesPermissionCheck{
	{Verb: "list", Resource: "serviceaccounts", Scope: "cluster"},
	{Verb: "list", Resource: "rolebindings", Scope: "cluster"},
	{Verb: "list", Resource: "clusterrolebindings", Scope: "cluster"},
	{Verb: "list", Resource: "roles", Scope: "cluster"},
	{Verb: "list", Resource: "clusterroles", Scope: "cluster"},
	{Verb: "list", Resource: "pods", Scope: "cluster"},
}

// KubernetesPermissionCheck describes one read permission required for safe cluster scans.
type KubernetesPermissionCheck struct {
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
}

// KubernetesPermissionCheckResult captures one kubectl auth can-i outcome.
type KubernetesPermissionCheckResult struct {
	KubernetesPermissionCheck
	Allowed     bool   `json:"allowed"`
	Diagnostic  string `json:"diagnostic,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// KubernetesClusterIdentity contains non-secret cluster metadata discovered during onboarding.
type KubernetesClusterIdentity struct {
	Context    string `json:"context,omitempty"`
	Cluster    string `json:"cluster,omitempty"`
	Server     string `json:"server,omitempty"`
	GitVersion string `json:"git_version,omitempty"`
	Platform   string `json:"platform,omitempty"`
}

// KubernetesPreflightDiagnostic explains a failed or degraded onboarding check.
type KubernetesPreflightDiagnostic struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// KubernetesPreflightResult is the structured health contract for Kubernetes onboarding.
type KubernetesPreflightResult struct {
	Health      connectors.HealthStatus           `json:"health"`
	Message     string                            `json:"message"`
	Cluster     KubernetesClusterIdentity         `json:"cluster"`
	Checks      []KubernetesPermissionCheckResult `json:"checks"`
	Diagnostics []KubernetesPreflightDiagnostic   `json:"diagnostics,omitempty"`
	ObservedAt  time.Time                         `json:"observed_at"`
}

// KubectlPreflightDriver implements connector lifecycle hooks through kubectl preflight checks.
type KubectlPreflightDriver struct {
	kubectlPath string
	contextName string
	run         CommandRunner
	now         func() time.Time
}

var _ connectors.Driver = (*KubectlPreflightDriver)(nil)

// NewKubectlPreflightDriver builds a Kubernetes connector driver for onboarding and health checks.
func NewKubectlPreflightDriver(kubectlPath string, contextName string, runner CommandRunner) *KubectlPreflightDriver {
	path := strings.TrimSpace(kubectlPath)
	if path == "" {
		path = defaultKubectlPath
	}
	if runner == nil {
		runner = defaultCommandRunner
	}
	return &KubectlPreflightDriver{
		kubectlPath: path,
		contextName: strings.TrimSpace(contextName),
		run:         runner,
		now:         time.Now,
	}
}

// TestConnection runs Kubernetes onboarding preflight and returns normalized connector health.
func (d *KubectlPreflightDriver) TestConnection(ctx context.Context, connector domain.Connector) (connectors.ProbeResult, error) {
	if connector.Type != domain.ConnectorTypeKubernetes {
		return connectors.ProbeResult{}, fmt.Errorf("kubernetes preflight cannot probe connector type %q", connector.Type)
	}
	result := d.Preflight(ctx)
	return connectors.ProbeResult{
		RawHealth: string(result.Health),
		Message:   result.Message,
	}, nil
}

// RevokeConnection is intentionally side-effect free because Kubernetes credential revocation
// happens in the external secret provider or cluster RBAC binding.
func (d *KubectlPreflightDriver) RevokeConnection(context.Context, domain.Connector) error {
	return nil
}

// ReactivateConnection is intentionally side-effect free; reactivation is proven by the next preflight.
func (d *KubectlPreflightDriver) ReactivateConnection(context.Context, domain.Connector) error {
	return nil
}

// Preflight verifies cluster identity and the read permissions required by the Kubernetes scanner.
func (d *KubectlPreflightDriver) Preflight(ctx context.Context) KubernetesPreflightResult {
	result := KubernetesPreflightResult{
		Health:     connectors.HealthStatusHealthy,
		ObservedAt: d.now().UTC(),
	}
	result.Cluster, result.Diagnostics = d.discoverClusterIdentity(ctx)
	for _, check := range requiredKubernetesPreflightChecks {
		checkResult, diagnostic := d.runPermissionCheck(ctx, check)
		result.Checks = append(result.Checks, checkResult)
		if diagnostic.Code != "" {
			result.Diagnostics = append(result.Diagnostics, diagnostic)
		}
	}
	result.Health = healthFromKubernetesPreflight(result.Diagnostics)
	result.Message = summarizeKubernetesPreflight(result)
	return result
}

func (d *KubectlPreflightDriver) discoverClusterIdentity(ctx context.Context) (KubernetesClusterIdentity, []KubernetesPreflightDiagnostic) {
	var diagnostics []KubernetesPreflightDiagnostic
	identity := KubernetesClusterIdentity{Context: d.contextName}
	if identity.Context == "" {
		output, err := d.runKubectl(ctx, "config", "current-context")
		if err != nil {
			diagnostics = append(diagnostics, KubernetesPreflightDiagnostic{
				Code:        "kubernetes_context_unavailable",
				Severity:    "error",
				Message:     commandErrorMessage("read current Kubernetes context", err),
				Remediation: "Configure kubeconfig access or pass an explicit Kubernetes context for this connector.",
			})
		} else {
			identity.Context = strings.TrimSpace(string(output))
		}
	}
	if output, err := d.runKubectl(ctx, "config", "view", "--minify", "-o", "json"); err != nil {
		diagnostics = append(diagnostics, KubernetesPreflightDiagnostic{
			Code:        "kubernetes_cluster_metadata_unavailable",
			Severity:    "warning",
			Message:     commandErrorMessage("read Kubernetes cluster metadata", err),
			Remediation: "Confirm the kubeconfig context can read its cluster stanza before onboarding automation depends on it.",
		})
	} else {
		if err := mergeClusterConfig(&identity, output); err != nil {
			diagnostics = append(diagnostics, KubernetesPreflightDiagnostic{
				Code:        "kubernetes_cluster_metadata_invalid",
				Severity:    "warning",
				Message:     commandErrorMessage("decode Kubernetes cluster metadata", err),
				Remediation: "Verify kubectl config view returns valid JSON for the selected context.",
			})
		}
	}
	if output, err := d.runKubectl(ctx, "version", "-o", "json"); err != nil {
		diagnostics = append(diagnostics, KubernetesPreflightDiagnostic{
			Code:        "kubernetes_version_unavailable",
			Severity:    "warning",
			Message:     commandErrorMessage("read Kubernetes server version", err),
			Remediation: "Verify API-server reachability from the Identrail runtime network path.",
		})
	} else {
		if err := mergeServerVersion(&identity, output); err != nil {
			diagnostics = append(diagnostics, KubernetesPreflightDiagnostic{
				Code:        "kubernetes_version_invalid",
				Severity:    "warning",
				Message:     commandErrorMessage("decode Kubernetes server version", err),
				Remediation: "Verify kubectl version returns valid JSON for the selected cluster.",
			})
		}
	}
	return identity, diagnostics
}

func (d *KubectlPreflightDriver) runPermissionCheck(ctx context.Context, check KubernetesPermissionCheck) (KubernetesPermissionCheckResult, KubernetesPreflightDiagnostic) {
	result := KubernetesPermissionCheckResult{
		KubernetesPermissionCheck: check,
		Remediation:               permissionRemediation(check),
	}
	args := []string{"auth", "can-i", check.Verb, check.Resource}
	if requiresAllNamespaces(check.Resource) {
		args = append(args, "--all-namespaces")
	}
	output, err := d.runKubectl(ctx, args...)
	if err != nil {
		result.Diagnostic = commandErrorMessage(permissionCommandLabel(check), err)
		return result, KubernetesPreflightDiagnostic{
			Code:        "kubernetes_permission_check_failed",
			Severity:    "error",
			Message:     result.Diagnostic,
			Remediation: result.Remediation,
		}
	}
	answer := strings.ToLower(strings.TrimSpace(string(output)))
	if answer == "yes" {
		result.Allowed = true
		return result, KubernetesPreflightDiagnostic{}
	}
	if answer == "no" {
		result.Diagnostic = fmt.Sprintf("missing Kubernetes permission: %s %s", check.Verb, check.Resource)
		return result, KubernetesPreflightDiagnostic{
			Code:        "kubernetes_permission_denied",
			Severity:    "error",
			Message:     result.Diagnostic,
			Remediation: result.Remediation,
		}
	}
	result.Diagnostic = fmt.Sprintf("unexpected kubectl auth can-i response for %s %s: %q", check.Verb, check.Resource, answer)
	return result, KubernetesPreflightDiagnostic{
		Code:        "kubernetes_permission_unknown",
		Severity:    "warning",
		Message:     result.Diagnostic,
		Remediation: "Re-run the preflight with kubectl output enabled and verify the active kubectl version is compatible with the cluster.",
	}
}

func (d *KubectlPreflightDriver) runKubectl(ctx context.Context, args ...string) ([]byte, error) {
	fullArgs := make([]string, 0, len(args)+2)
	if d.contextName != "" {
		fullArgs = append(fullArgs, "--context", d.contextName)
	}
	fullArgs = append(fullArgs, args...)
	return d.run(ctx, d.kubectlPath, fullArgs...)
}

func healthFromKubernetesPreflight(diagnostics []KubernetesPreflightDiagnostic) connectors.HealthStatus {
	health := connectors.HealthStatusHealthy
	for _, diagnostic := range diagnostics {
		switch strings.ToLower(strings.TrimSpace(diagnostic.Severity)) {
		case "error":
			return connectors.HealthStatusError
		case "warning":
			health = connectors.HealthStatusWarning
		}
	}
	return health
}

func summarizeKubernetesPreflight(result KubernetesPreflightResult) string {
	cluster := strings.TrimSpace(result.Cluster.Context)
	if cluster == "" {
		cluster = strings.TrimSpace(result.Cluster.Cluster)
	}
	if cluster == "" {
		cluster = "kubernetes cluster"
	}
	switch result.Health {
	case connectors.HealthStatusHealthy:
		return fmt.Sprintf("%s preflight passed; connector can continuously scan RBAC and service-account posture", cluster)
	case connectors.HealthStatusWarning:
		return fmt.Sprintf("%s preflight passed with metadata warnings; review diagnostics before relying on automation", cluster)
	case connectors.HealthStatusError:
		missing := missingPermissionResources(result.Checks)
		if missing != "" {
			return fmt.Sprintf("%s preflight failed; grant read access for %s before activating the connector", cluster, missing)
		}
		return fmt.Sprintf("%s preflight failed; review Kubernetes diagnostics before activating the connector", cluster)
	default:
		return fmt.Sprintf("%s preflight returned unknown health", cluster)
	}
}

func missingPermissionResources(checks []KubernetesPermissionCheckResult) string {
	missing := make([]string, 0, len(checks))
	for _, check := range checks {
		if !check.Allowed {
			missing = append(missing, check.Resource)
		}
	}
	return strings.Join(missing, ", ")
}

func permissionRemediation(check KubernetesPermissionCheck) string {
	return fmt.Sprintf("Bind the Identrail Kubernetes identity to a ClusterRole that allows %s on %s.", check.Verb, check.Resource)
}

func permissionCommandLabel(check KubernetesPermissionCheck) string {
	args := []string{"kubectl", "auth", "can-i", check.Verb, check.Resource}
	if requiresAllNamespaces(check.Resource) {
		args = append(args, "--all-namespaces")
	}
	return strings.Join(args, " ")
}

func requiresAllNamespaces(resource string) bool {
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "serviceaccounts", "rolebindings", "roles", "pods":
		return true
	default:
		return false
	}
}

func commandErrorMessage(action string, err error) string {
	return fmt.Sprintf("%s: %v", action, err)
}

type kubeConfigView struct {
	CurrentContext string `json:"current-context"`
	Clusters       []struct {
		Name    string `json:"name"`
		Cluster struct {
			Server string `json:"server"`
		} `json:"cluster"`
	} `json:"clusters"`
	Contexts []struct {
		Name    string `json:"name"`
		Context struct {
			Cluster string `json:"cluster"`
		} `json:"context"`
	} `json:"contexts"`
}

func mergeClusterConfig(identity *KubernetesClusterIdentity, payload []byte) error {
	var config kubeConfigView
	if err := json.Unmarshal(payload, &config); err != nil {
		return err
	}
	if identity.Context == "" {
		identity.Context = strings.TrimSpace(config.CurrentContext)
	}
	for _, contextEntry := range config.Contexts {
		if identity.Context == "" || contextEntry.Name == identity.Context {
			identity.Cluster = strings.TrimSpace(contextEntry.Context.Cluster)
			break
		}
	}
	for _, cluster := range config.Clusters {
		if identity.Cluster == "" || cluster.Name == identity.Cluster {
			if identity.Cluster == "" {
				identity.Cluster = strings.TrimSpace(cluster.Name)
			}
			identity.Server = strings.TrimSpace(cluster.Cluster.Server)
			break
		}
	}
	return nil
}

type kubeVersion struct {
	ServerVersion struct {
		GitVersion string `json:"gitVersion"`
		Platform   string `json:"platform"`
	} `json:"serverVersion"`
}

func mergeServerVersion(identity *KubernetesClusterIdentity, payload []byte) error {
	var version kubeVersion
	if err := json.Unmarshal(payload, &version); err != nil {
		return err
	}
	identity.GitVersion = strings.TrimSpace(version.ServerVersion.GitVersion)
	identity.Platform = strings.TrimSpace(version.ServerVersion.Platform)
	return nil
}
