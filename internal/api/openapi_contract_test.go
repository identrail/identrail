package api

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var (
	v1RoutePattern  = regexp.MustCompile(`v1\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\("([^"]+)"`)
	pathVarPattern  = regexp.MustCompile(`:([A-Za-z0-9_]+)`)
	scopeHeaderRefs = []string{
		`#/components/parameters/scopeTenantID`,
		`#/components/parameters/scopeWorkspaceID`,
	}
)

func TestOpenAPIV1SpecCoversRegisteredV1Routes(t *testing.T) {
	spec := readOpenAPISpec(t)
	router := readRouterSource(t)
	for _, path := range registeredV1OpenAPIPaths(t, router) {
		if !strings.Contains(spec, "  "+path+":") {
			t.Fatalf("openapi spec missing router path %q", path)
		}
	}
}

func TestOpenAPIV1SpecDeclaresAuthSecurity(t *testing.T) {
	spec := readOpenAPISpec(t)
	required := []string{
		"security:",
		"- ApiKeyAuth: []",
		"- BearerAuth: []",
		"securitySchemes:",
		"ApiKeyAuth:",
		"BearerAuth:",
		"name: X-API-Key",
		"scheme: bearer",
	}
	for _, item := range required {
		if !strings.Contains(spec, item) {
			t.Fatalf("openapi spec missing %q", item)
		}
	}
}

func TestOpenAPIV1SpecDocumentsGitHubWebhookSignatureSecurity(t *testing.T) {
	spec := readOpenAPISpec(t)
	required := []string{
		"GitHubWebhookSignature:",
		"name: X-Hub-Signature-256",
		"description: GitHub HMAC SHA-256 signature of the raw webhook request body.",
	}
	for _, item := range required {
		if !strings.Contains(spec, item) {
			t.Fatalf("openapi spec missing %q", item)
		}
	}

	block := pathBlock(t, spec, "/webhooks/github")
	if !strings.Contains(block, "- GitHubWebhookSignature: []") {
		t.Fatalf("openapi path %q missing GitHub webhook signature security requirement", "/webhooks/github")
	}
	if strings.Contains(block, "name: X-Hub-Signature-256") {
		t.Fatalf("openapi path %q should declare X-Hub-Signature-256 via security scheme, not as a duplicate header parameter", "/webhooks/github")
	}
}

func TestOpenAPIV1SpecDocumentsRequestScopeHeaders(t *testing.T) {
	spec := readOpenAPISpec(t)
	required := []string{
		"scopeTenantID:",
		"scopeWorkspaceID:",
		"name: X-Identrail-Tenant-ID",
		"name: X-Identrail-Workspace-ID",
	}
	for _, item := range required {
		if !strings.Contains(spec, item) {
			t.Fatalf("openapi spec missing %q", item)
		}
	}

	router := readRouterSource(t)
	for _, path := range registeredV1OpenAPIPaths(t, router) {
		block := pathBlock(t, spec, path)
		for _, scopeRef := range scopeHeaderRefs {
			if !strings.Contains(block, scopeRef) {
				t.Fatalf("openapi path %q missing scope header ref %q", path, scopeRef)
			}
		}
	}
}

func TestOpenAPIV1SpecContainsPagingFilterSortParameters(t *testing.T) {
	spec := readOpenAPISpec(t)
	required := []string{
		"name: limit",
		"name: cursor",
		"name: sort_by",
		"name: sort_order",
		"name: scan_id",
		"name: severity",
		"name: type",
		"name: lifecycle_status",
		"name: assignee",
		"name: previous_scan_id",
		"next_cursor:",
	}
	for _, item := range required {
		if !strings.Contains(spec, item) {
			t.Fatalf("openapi spec missing %q", item)
		}
	}
}

func TestOpenAPIV1SpecContainsTenancyProjectContracts(t *testing.T) {
	spec := readOpenAPISpec(t)
	required := []string{
		"/v1/whoami:",
		"/v1/organizations/current:",
		"/v1/workspaces:",
		"/v1/workspaces/active:",
		"/v1/workspaces/{workspace_id}:",
		"/v1/workspaces/{workspace_id}/members:",
		"/v1/workspaces/{workspace_id}/members/{member_id}:",
		"/v1/workspaces/{workspace_id}/projects:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}/kubernetes/connection:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}/aws/connection:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}/github/connect/start:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}/github/connect/complete:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}/github/connection:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}/github/repositories:",
		"/v1/workspaces/{workspace_id}/projects/{project_id}/github/secret/rotate:",
		"OrganizationUpsertRequest:",
		"WorkspaceUpsertRequest:",
		"WorkspaceMemberUpsertRequest:",
		"ProjectUpsertRequest:",
		"KubernetesConnectionUpsertRequest:",
		"KubernetesConnectionStatus:",
		"AWSConnectionUpsertRequest:",
		"AWSConnectionStatus:",
		"GitHubConnectionStartRequest:",
		"GitHubConnectionCompleteRequest:",
		"GitHubConnectionRepositorySelectionRequest:",
		"GitHubConnectionSecretRotationRequest:",
		"GitHubConnectionStatus:",
		"WorkspacePage:",
		"WorkspaceMemberPage:",
		"ProjectPage:",
	}
	for _, item := range required {
		if !strings.Contains(spec, item) {
			t.Fatalf("openapi spec missing %q", item)
		}
	}
}

func TestOpenAPIV1SpecDocumentsRouteAuthorizationMetadata(t *testing.T) {
	spec := readOpenAPISpec(t)
	for _, route := range defaultBuiltInRoutePolicyDefinitions() {
		path := pathVarPattern.ReplaceAllString(route.Path, `{$1}`)
		lines := []string{
			fmt.Sprintf("  - method: %s", route.Method),
			fmt.Sprintf("    path: %s", path),
			fmt.Sprintf("    action: %s", route.Action),
			fmt.Sprintf("    resource_type: %s", route.ResourceType),
		}
		if route.ResourceIDParam != "" {
			lines = append(lines, fmt.Sprintf("    resource_id_param: %s", route.ResourceIDParam))
		}
		if !strings.Contains(spec, strings.Join(lines, "\n")) {
			t.Fatalf("openapi authz metadata missing route authorization entry for %s %s", route.Method, path)
		}
	}
}

func TestOpenAPIV1SpecDocumentsActionRoleGrants(t *testing.T) {
	spec := readOpenAPISpec(t)
	grants := defaultRouteActionRoleGrants()
	actions := make([]string, 0, len(grants))
	for action := range grants {
		actions = append(actions, action)
	}
	sort.Strings(actions)

	for _, action := range actions {
		lines := []string{fmt.Sprintf("  %s:", action)}
		for _, role := range uniqueStrings(grants[action]) {
			lines = append(lines, fmt.Sprintf("    - %s", role))
		}
		if !strings.Contains(spec, strings.Join(lines, "\n")) {
			t.Fatalf("openapi authz metadata missing role grants for action %q", action)
		}
	}
}

func readOpenAPISpec(t *testing.T) string {
	t.Helper()
	return readRepositoryFile(t, filepath.Join("docs", "openapi-v1.yaml"))
}

func readRouterSource(t *testing.T) string {
	t.Helper()
	return readRepositoryFile(t, filepath.Join("internal", "api", "router.go"))
}

func readRepositoryFile(t *testing.T, relPath string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	path := filepath.Join(root, relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return string(data)
}

func registeredV1OpenAPIPaths(t *testing.T, routerSource string) []string {
	t.Helper()
	matches := v1RoutePattern.FindAllStringSubmatch(routerSource, -1)
	if len(matches) == 0 {
		t.Fatal("no /v1 routes found in router source")
	}

	seen := map[string]struct{}{}
	for _, match := range matches {
		route := strings.TrimSpace(match[2])
		if route == "" || !strings.HasPrefix(route, "/") {
			continue
		}
		path := "/v1" + pathVarPattern.ReplaceAllString(route, `{$1}`)
		seen[path] = struct{}{}
	}

	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func pathBlock(t *testing.T, spec string, path string) string {
	t.Helper()
	start := strings.Index(spec, "\n  "+path+":")
	if start >= 0 {
		start++
	} else {
		prefix := "  " + path + ":"
		if strings.HasPrefix(spec, prefix) {
			start = 0
		} else {
			t.Fatalf("openapi path block not found for %q", path)
		}
	}

	end := len(spec)
	if nextPath := strings.Index(spec[start+1:], "\n  /"); nextPath >= 0 {
		end = start + 1 + nextPath
	}
	if components := strings.Index(spec[start+1:], "\ncomponents:"); components >= 0 {
		componentPos := start + 1 + components
		if componentPos < end {
			end = componentPos
		}
	}

	return spec[start:end]
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
