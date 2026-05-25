package providers

import (
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
)

func TestValidateNormalizedBundle(t *testing.T) {
	bundle := NormalizedBundle{
		Identities: []domain.Identity{{
			ID:       "aws:identity:arn:aws:iam::123456789012:role/demo",
			Provider: domain.ProviderAWS,
			Type:     domain.IdentityTypeRole,
			Name:     "demo",
		}},
		Policies: []domain.Policy{{
			ID:       "policy:1",
			Provider: domain.ProviderAWS,
			Name:     "inline",
			RawRef:   "raw",
			Normalized: map[string]any{
				"policy_type": "permission",
				"identity_id": "aws:identity:arn:aws:iam::123456789012:role/demo",
				"statements": []map[string]any{{
					"effect":    "Allow",
					"actions":   []string{"s3:GetObject"},
					"resources": []string{"*"},
				}},
			},
		}},
	}
	if err := ValidateNormalizedBundle(bundle); err != nil {
		t.Fatalf("expected valid bundle, got %v", err)
	}
}

func TestValidateNormalizedBundleInvalidPolicyIdentity(t *testing.T) {
	bundle := NormalizedBundle{
		Identities: []domain.Identity{{
			ID:       "id-1",
			Provider: domain.ProviderAWS,
			Type:     domain.IdentityTypeRole,
			Name:     "demo",
		}},
		Policies: []domain.Policy{{
			ID:       "policy-1",
			Provider: domain.ProviderAWS,
			Name:     "inline",
			RawRef:   "raw",
			Normalized: map[string]any{
				"policy_type": "permission",
				"identity_id": "missing",
				"statements": []map[string]any{{
					"effect":    "Allow",
					"actions":   []string{"*"},
					"resources": []string{"*"},
				}},
			},
		}},
	}
	if err := ValidateNormalizedBundle(bundle); err == nil {
		t.Fatal("expected invalid policy identity error")
	}
}

func TestValidateGraphContract(t *testing.T) {
	now := time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC)
	identityID := "aws:identity:arn:aws:iam::123456789012:role/demo"
	policyID := "policy:1"
	bundle := NormalizedBundle{
		Identities: []domain.Identity{{
			ID:       identityID,
			Provider: domain.ProviderAWS,
			Type:     domain.IdentityTypeRole,
			Name:     "demo",
		}},
		Policies: []domain.Policy{{
			ID:       policyID,
			Provider: domain.ProviderAWS,
			Name:     "inline",
			RawRef:   "raw",
			Normalized: map[string]any{
				"policy_type": "permission",
				"identity_id": identityID,
				"statements": []map[string]any{{
					"effect":    "Allow",
					"actions":   []string{"*"},
					"resources": []string{"*"},
				}},
			},
		}},
	}
	relationships := []domain.Relationship{
		{
			ID:           "rel-1",
			Type:         domain.RelationshipAttachedPolicy,
			FromNodeID:   identityID,
			ToNodeID:     policyID,
			DiscoveredAt: now,
		},
		{
			ID:           "rel-2",
			Type:         domain.RelationshipCanAccess,
			FromNodeID:   identityID,
			ToNodeID:     "aws:access:s3%3AGetObject:%2A",
			DiscoveredAt: now,
		},
	}
	if err := ValidateGraphContract(bundle, relationships); err != nil {
		t.Fatalf("expected valid graph contract, got %v", err)
	}
}

func TestValidateGraphContractInvalidEdge(t *testing.T) {
	now := time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC)
	bundle := NormalizedBundle{
		Identities: []domain.Identity{{
			ID:       "id-1",
			Provider: domain.ProviderAWS,
			Type:     domain.IdentityTypeRole,
			Name:     "demo",
		}},
	}
	relationships := []domain.Relationship{
		{
			ID:           "rel-1",
			Type:         domain.RelationshipCanAccess,
			FromNodeID:   "id-1",
			ToNodeID:     "invalid-node",
			DiscoveredAt: now,
		},
	}
	if err := ValidateGraphContract(bundle, relationships); err == nil {
		t.Fatal("expected invalid graph contract error")
	}
}

func TestValidateNormalizedBundleDuplicateAndSchemaFailures(t *testing.T) {
	baseIdentity := domain.Identity{
		ID:       "id-1",
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		Name:     "demo",
	}
	baseResource := domain.Resource{
		ID:       "res-1",
		Provider: domain.ProviderAWS,
		Type:     domain.ResourceTypeS3Bucket,
		Name:     "bucket-a",
	}
	baseAgent := domain.Agent{
		ID:       "agent-1",
		Provider: domain.ProviderAWS,
		Type:     domain.AgentTypeAI,
		Name:     "agent-one",
		RawRef:   "agent-ref",
	}
	tests := []struct {
		name   string
		bundle NormalizedBundle
		needle string
	}{
		{
			name: "duplicate identity id",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{
					baseIdentity,
					baseIdentity,
				},
			},
			needle: "duplicate identity id",
		},
		{
			name: "invalid workload",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				Workloads: []domain.Workload{{
					ID:       "w1",
					Provider: domain.ProviderAWS,
					Name:     "missing-type",
				}},
			},
			needle: "invalid workload",
		},
		{
			name: "duplicate workload",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				Workloads: []domain.Workload{
					{ID: "w1", Provider: domain.ProviderAWS, Type: "pod", Name: "a"},
					{ID: "w1", Provider: domain.ProviderAWS, Type: "pod", Name: "b"},
				},
			},
			needle: "duplicate workload id",
		},
		{
			name: "duplicate policy",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				Policies: []domain.Policy{
					{
						ID:       "p1",
						Provider: domain.ProviderAWS,
						Name:     "trust-1",
						RawRef:   "raw-1",
						Normalized: map[string]any{
							"policy_type": "trust",
							"identity_id": "id-1",
							"principals":  []string{"aws:123"},
						},
					},
					{
						ID:       "p1",
						Provider: domain.ProviderAWS,
						Name:     "trust-2",
						RawRef:   "raw-2",
						Normalized: map[string]any{
							"policy_type": "trust",
							"identity_id": "id-1",
							"principals":  []string{"aws:456"},
						},
					},
				},
			},
			needle: "duplicate policy id",
		},
		{
			name: "unsupported policy type",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				Policies: []domain.Policy{{
					ID:       "p1",
					Provider: domain.ProviderAWS,
					Name:     "bad",
					RawRef:   "raw",
					Normalized: map[string]any{
						"policy_type": "unknown",
						"identity_id": "id-1",
					},
				}},
			},
			needle: "unsupported policy_type",
		},
		{
			name: "trust principals missing",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				Policies: []domain.Policy{{
					ID:       "p1",
					Provider: domain.ProviderAWS,
					Name:     "trust",
					RawRef:   "raw",
					Normalized: map[string]any{
						"policy_type": "trust",
						"identity_id": "id-1",
					},
				}},
			},
			needle: "missing trust principals",
		},
		{
			name: "permission statement shape",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				Policies: []domain.Policy{{
					ID:       "p1",
					Provider: domain.ProviderAWS,
					Name:     "permission",
					RawRef:   "raw",
					Normalized: map[string]any{
						"policy_type": "permission",
						"identity_id": "id-1",
						"statements": []any{
							map[string]any{
								"effect":    "Allow",
								"actions":   []any{"s3:GetObject", "s3:GetObject"},
								"resources": []any{"*"},
							},
						},
					},
				}},
			},
		},
		{
			name: "duplicate resource id",
			bundle: NormalizedBundle{
				Resources: []domain.Resource{
					baseResource,
					baseResource,
				},
			},
			needle: "duplicate resource id",
		},
		{
			name: "invalid credential",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				Resources:  []domain.Resource{baseResource},
				Credentials: []domain.Credential{{
					ID:        "cred-1",
					Provider:  domain.ProviderAWS,
					Type:      domain.CredentialTypeAccessKey,
					Reference: "ref-1",
					Name:      "access-key",
					RawRef:    "raw-cred",
					OwnerID:   baseIdentity.ID,
					RawValue:  "must-not-be-stored",
				}},
			},
			needle: "contains unredacted raw value",
		},
		{
			name: "credential missing owner/reference/resource",
			bundle: NormalizedBundle{
				Credentials: []domain.Credential{{
					ID:       "cred-missing",
					Provider: domain.ProviderAWS,
					Type:     domain.CredentialTypeAccessKey,
					Name:     "access-key",
					RawRef:   "raw-cred",
				}},
			},
			needle: "missing reference",
		},
		{
			name: "credential owned by agent",
			bundle: NormalizedBundle{
				Agents: []domain.Agent{baseAgent},
				Credentials: []domain.Credential{{
					ID:        "cred-agent",
					Provider:  domain.ProviderAWS,
					Type:      domain.CredentialTypeAccessKey,
					Name:      "access-key",
					RawRef:    "raw-cred",
					Reference: "ref-agent",
					OwnerID:   baseAgent.ID,
				}},
			},
			needle: "",
		},
		{
			name: "credential unknown resource_id",
			bundle: NormalizedBundle{
				Credentials: []domain.Credential{{
					ID:         "cred-2",
					Provider:   domain.ProviderAWS,
					Type:       domain.CredentialTypeAccessKey,
					Name:       "access-key",
					RawRef:     "raw-cred",
					Reference:  "ref",
					ResourceID: "missing-resource",
				}},
			},
			needle: "unknown resource_id",
		},
		{
			name: "runtime event synthetic actor allowed",
			bundle: NormalizedBundle{
				RuntimeEvents: []domain.RuntimeEvent{{
					ID:         "event-1",
					Provider:   domain.ProviderAWS,
					Type:       domain.RuntimeEventTypeRuntimeSession,
					ActorID:    "aws:session:sts:abc123",
					SourceRef:  "source-1",
					ObservedAt: time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC),
				}},
			},
			needle: "",
		},
		{
			name: "runtime event unknown target",
			bundle: NormalizedBundle{
				Identities: []domain.Identity{baseIdentity},
				RuntimeEvents: []domain.RuntimeEvent{{
					ID:         "event-2",
					Provider:   domain.ProviderAWS,
					Type:       domain.RuntimeEventTypeInvoke,
					ActorID:    baseIdentity.ID,
					TargetID:   "missing-target",
					SourceRef:  "source-2",
					ObservedAt: time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC),
				}},
			},
			needle: "unknown target_id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNormalizedBundle(tc.bundle)
			if tc.needle == "" {
				if err != nil {
					t.Fatalf("expected valid bundle, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q", tc.needle)
			}
			if !strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("expected %q in error, got %v", tc.needle, err)
			}
		})
	}
}

func TestValidateStatement(t *testing.T) {
	if err := validateStatement(map[string]any{
		"effect":    "Allow",
		"actions":   []string{"iam:PassRole"},
		"resources": []string{"*"},
	}); err != nil {
		t.Fatalf("expected valid statement, got %v", err)
	}
	tests := []struct {
		name      string
		statement map[string]any
		needle    string
	}{
		{
			name: "missing effect",
			statement: map[string]any{
				"actions":   []string{"iam:PassRole"},
				"resources": []string{"*"},
			},
			needle: "statement missing effect",
		},
		{
			name: "missing actions",
			statement: map[string]any{
				"effect":    "Allow",
				"resources": []string{"*"},
			},
			needle: "statement missing actions",
		},
		{
			name: "missing resources",
			statement: map[string]any{
				"effect":  "Allow",
				"actions": []string{"iam:PassRole"},
			},
			needle: "statement missing resources",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStatement(tc.statement)
			if err == nil || !strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("expected error containing %q, got %v", tc.needle, err)
			}
		})
	}
}

func TestExtractStringSlice(t *testing.T) {
	fromStrings := extractStringSlice([]string{"b", "a", "b"})
	if got := strings.Join(fromStrings, ","); got != "a,b" {
		t.Fatalf("expected sorted compact []string, got %q", got)
	}
	fromAny := extractStringSlice([]any{" b ", "", "a", "b", 99})
	if got := strings.Join(fromAny, ","); got != "a,b" {
		t.Fatalf("expected normalized []any strings, got %q", got)
	}
	if got := extractStringSlice(map[string]string{"a": "b"}); got != nil {
		t.Fatalf("expected nil for unsupported type, got %+v", got)
	}
}

func TestValidateGraphContractCoverageBranches(t *testing.T) {
	now := time.Date(2026, 3, 19, 12, 0, 0, 0, time.UTC)
	bundle := NormalizedBundle{
		Identities: []domain.Identity{
			{ID: "id-a", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "a"},
			{ID: "id-b", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "b"},
			{ID: "user-a", Provider: domain.ProviderAWS, Type: domain.IdentityTypeUser, Name: "human-a"},
		},
		Workloads: []domain.Workload{
			{ID: "wl-a", Provider: domain.ProviderKubernetes, Type: "pod", Name: "api"},
		},
		Resources: []domain.Resource{
			{
				ID:       "res-bucket",
				Provider: domain.ProviderAWS,
				Type:     domain.ResourceTypeS3Bucket,
				Name:     "bucket",
			},
		},
		Policies: []domain.Policy{
			{
				ID:       "policy-a",
				Provider: domain.ProviderAWS,
				Name:     "policy",
				RawRef:   "raw",
				Normalized: map[string]any{
					"policy_type": "permission",
					"identity_id": "id-a",
					"statements": []map[string]any{{
						"effect":    "Allow",
						"actions":   []string{"*"},
						"resources": []string{"*"},
					}},
				},
			},
		},
	}

	valid := []domain.Relationship{
		{ID: "r1", Type: domain.RelationshipAttachedPolicy, FromNodeID: "id-a", ToNodeID: "policy-a", DiscoveredAt: now},
		{ID: "r2", Type: domain.RelationshipAttachedTo, FromNodeID: "wl-a", ToNodeID: "id-a", DiscoveredAt: now},
		{ID: "r3", Type: domain.RelationshipBoundTo, FromNodeID: "wl-a", ToNodeID: "id-b", DiscoveredAt: now},
		{ID: "r4", Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:111122223333:root", ToNodeID: "id-a", DiscoveredAt: now},
		{ID: "r5", Type: domain.RelationshipCanImpersonate, FromNodeID: "wl-a", ToNodeID: "id-a", DiscoveredAt: now},
		{ID: "r6", Type: domain.RelationshipCanAccess, FromNodeID: "id-a", ToNodeID: "k8s:access:get:pods", DiscoveredAt: now},
		{ID: "r7", Type: domain.RelationshipRunsAs, FromNodeID: "wl-a", ToNodeID: "id-a", DiscoveredAt: now},
		{ID: "r8", Type: domain.RelationshipUsesSecret, FromNodeID: "id-a", ToNodeID: "aws:secret:secretsmanager:prod/db", DiscoveredAt: now},
		{ID: "r9", Type: domain.RelationshipCanDecrypt, FromNodeID: "id-a", ToNodeID: "aws:kms:key/abcd", DiscoveredAt: now},
		{ID: "r10", Type: domain.RelationshipCanPassRole, FromNodeID: "id-a", ToNodeID: "id-b", DiscoveredAt: now},
		{ID: "r11", Type: domain.RelationshipInvokes, FromNodeID: "wl-a", ToNodeID: "aws:lambda:function:rotate", DiscoveredAt: now},
		{ID: "r12", Type: domain.RelationshipCallsTool, FromNodeID: "agent:bedrock:reviewer", ToNodeID: "tool:mcp:github.search", DiscoveredAt: now},
		{ID: "r13", Type: domain.RelationshipActsForUser, FromNodeID: "agent:bedrock:reviewer", ToNodeID: "user-a", DiscoveredAt: now},
		{ID: "r14", Type: domain.RelationshipRuntimeSession, FromNodeID: "id-a", ToNodeID: "aws:session:sts:session-1", DiscoveredAt: now},
		{ID: "r15", Type: domain.RelationshipObservedAction, FromNodeID: "aws:session:sts:session-1", ToNodeID: "aws:access:s3%3AGetObject:arn%3Aaws%3As3%3A%3A%3Aprod%2F%2A", DiscoveredAt: now},
	}
	if err := ValidateGraphContract(bundle, valid); err != nil {
		t.Fatalf("expected valid relationships, got %v", err)
	}

	tests := []struct {
		name          string
		relationships []domain.Relationship
		needle        string
	}{
		{
			name: "duplicate relationship id",
			relationships: []domain.Relationship{
				{ID: "dup", Type: domain.RelationshipCanAccess, FromNodeID: "id-a", ToNodeID: "aws:access:a:*", DiscoveredAt: now},
				{ID: "dup", Type: domain.RelationshipCanAccess, FromNodeID: "id-b", ToNodeID: "aws:access:b:*", DiscoveredAt: now},
			},
			needle: "duplicate relationship id",
		},
		{
			name: "duplicate semantic",
			relationships: []domain.Relationship{
				{ID: "s1", Type: domain.RelationshipCanAccess, FromNodeID: "id-a", ToNodeID: "aws:access:a:*", DiscoveredAt: now},
				{ID: "s2", Type: domain.RelationshipCanAccess, FromNodeID: "id-a", ToNodeID: "aws:access:a:*", DiscoveredAt: now},
			},
			needle: "duplicate relationship semantic",
		},
		{
			name: "missing discovered at",
			relationships: []domain.Relationship{
				{ID: "z", Type: domain.RelationshipCanAccess, FromNodeID: "id-a", ToNodeID: "aws:access:a:*"},
			},
			needle: "missing discovered_at",
		},
		{
			name: "bad can_assume source",
			relationships: []domain.Relationship{
				{ID: "x", Type: domain.RelationshipCanAssume, FromNodeID: "missing", ToNodeID: "id-a", DiscoveredAt: now},
			},
			needle: "unknown source",
		},
		{
			name: "bad can_impersonate source",
			relationships: []domain.Relationship{
				{ID: "y", Type: domain.RelationshipCanImpersonate, FromNodeID: "missing", ToNodeID: "id-a", DiscoveredAt: now},
			},
			needle: "unknown source",
		},
		{
			name: "bad uses_secret target",
			relationships: []domain.Relationship{
				{ID: "secret", Type: domain.RelationshipUsesSecret, FromNodeID: "id-a", ToNodeID: "plain-secret", DiscoveredAt: now},
			},
			needle: "invalid secret node",
		},
		{
			name: "bad can_pass_role target",
			relationships: []domain.Relationship{
				{ID: "pass", Type: domain.RelationshipCanPassRole, FromNodeID: "id-a", ToNodeID: "user-a", DiscoveredAt: now},
			},
			needle: "target role identity",
		},
		{
			name: "bad invokes target non-invocable resource",
			relationships: []domain.Relationship{
				{ID: "bad-invoke", Type: domain.RelationshipInvokes, FromNodeID: "wl-a", ToNodeID: "res-bucket", DiscoveredAt: now},
			},
			needle: "invalid invocable node",
		},
		{
			name: "bad acts_for_user target",
			relationships: []domain.Relationship{
				{ID: "delegate", Type: domain.RelationshipActsForUser, FromNodeID: "agent:bedrock:reviewer", ToNodeID: "id-a", DiscoveredAt: now},
			},
			needle: "target user identity",
		},
		{
			name: "bad observed_action target",
			relationships: []domain.Relationship{
				{ID: "observed", Type: domain.RelationshipObservedAction, FromNodeID: "aws:session:sts:session-1", ToNodeID: "plain-action", DiscoveredAt: now},
			},
			needle: "invalid action node",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGraphContract(bundle, tc.relationships)
			if err == nil || !strings.Contains(err.Error(), tc.needle) {
				t.Fatalf("expected error containing %q, got %v", tc.needle, err)
			}
		})
	}
}
