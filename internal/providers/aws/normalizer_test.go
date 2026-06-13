package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
	"github.com/identrail/identrail/internal/providers/awscontract"
)

func TestRoleNormalizerNormalizeFromFixture(t *testing.T) {
	normalizer := NewRoleNormalizer()
	raw := []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_policies.json")}

	bundle, err := normalizer.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if got := len(bundle.Identities); got != 1 {
		t.Fatalf("expected 1 identity, got %d", got)
	}
	identity := bundle.Identities[0]
	if identity.OwnerHint != "payments" {
		t.Fatalf("expected owner hint payments, got %q", identity.OwnerHint)
	}
	if !strings.Contains(identity.ID, "arn:aws:iam::123456789012:role/payments-app") {
		t.Fatalf("unexpected identity id %q", identity.ID)
	}

	if got := len(bundle.Policies); got != 2 {
		t.Fatalf("expected 2 policies (permission + trust), got %d", got)
	}

	policyTypeCount := map[string]int{}
	for _, policy := range bundle.Policies {
		typeName, _ := policy.Normalized[policyTypeKey].(string)
		policyTypeCount[typeName]++
	}
	if policyTypeCount[policyTypePerm] != 1 {
		t.Fatalf("expected 1 permission policy, got %d", policyTypeCount[policyTypePerm])
	}
	if policyTypeCount[policyTypeTrust] != 1 {
		t.Fatalf("expected 1 trust policy, got %d", policyTypeCount[policyTypeTrust])
	}
}

func TestRoleNormalizerDecodesURLTrustPolicy(t *testing.T) {
	normalizer := NewRoleNormalizer()
	raw := []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_urlencoded_trust.json")}

	bundle, err := normalizer.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected 1 trust policy, got %d", len(bundle.Policies))
	}

	principals := parseStringList(bundle.Policies[0].Normalized[principalsKey])
	if len(principals) != 1 || principals[0] != "arn:aws:iam::123456789012:role/etl-runner" {
		t.Fatalf("unexpected principals: %+v", principals)
	}
}

func TestRoleNormalizerSkipsUnsupportedAndDeduplicates(t *testing.T) {
	normalizer := NewRoleNormalizer()
	asset := loadRawRoleAssetFixture(t, "role_with_policies.json")

	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		{Kind: "unknown", SourceID: "noop", Payload: []byte("{}")},
		asset,
		asset,
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Identities) != 1 {
		t.Fatalf("expected deduplicated identity count 1, got %d", len(bundle.Identities))
	}
}

func TestRoleNormalizerPreservesIAMRoleMetadataWhenEC2ReferencesSameRole(t *testing.T) {
	normalizer := NewRoleNormalizer()
	roleARN := "arn:aws:iam::123456789012:role/payments-ec2"
	createdAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	lastUsedAt := time.Date(2026, 6, 1, 8, 30, 0, 0, time.UTC)
	role := IAMRole{
		ARN:        roleARN,
		Name:       "payments-authoritative",
		CreatedAt:  &createdAt,
		LastUsedAt: &lastUsedAt,
		Tags:       map[string]string{"owner": "iam-team", "env": "prod"},
	}
	ec2Reference := EC2InstanceProfile{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			RoleARN: roleARN,
		},
		RoleName: "payments-placeholder",
		Tags:     map[string]string{"owner": "ec2-team"},
	}
	rolePayload, err := json.Marshal(role)
	if err != nil {
		t.Fatalf("marshal role: %v", err)
	}
	ec2Payload, err := json.Marshal(ec2Reference)
	if err != nil {
		t.Fatalf("marshal ec2 reference: %v", err)
	}

	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindEC2InstanceProfile, SourceID: "ec2-profile", Payload: ec2Payload},
		{Kind: "iam_role", SourceID: "iam-role", Payload: rolePayload},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Identities) != 1 {
		t.Fatalf("expected one role identity, got %+v", bundle.Identities)
	}

	identity := bundle.Identities[0]
	if identity.Name != "payments-authoritative" {
		t.Fatalf("expected IAM role name, got %q", identity.Name)
	}
	if identity.RawRef != "iam-role" {
		t.Fatalf("expected IAM raw ref, got %q", identity.RawRef)
	}
	if identity.OwnerHint != "iam-team" {
		t.Fatalf("expected IAM owner hint, got %q", identity.OwnerHint)
	}
	if got := identity.Tags["env"]; got != "prod" {
		t.Fatalf("expected IAM env tag, got %q", got)
	}
	if got := identity.Tags["owner"]; got != "iam-team" {
		t.Fatalf("expected IAM owner tag, got %q", got)
	}
	if !identity.CreatedAt.Equal(createdAt) {
		t.Fatalf("expected IAM created_at %s, got %s", createdAt, identity.CreatedAt)
	}
	if identity.LastUsedAt == nil || !identity.LastUsedAt.Equal(lastUsedAt) {
		t.Fatalf("expected IAM last_used_at %s, got %v", lastUsedAt, identity.LastUsedAt)
	}
}

func TestRoleNormalizerInvalidPayload(t *testing.T) {
	normalizer := NewRoleNormalizer()
	_, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{Kind: "iam_role", Payload: []byte("not-json")}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decode iam role") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoleNormalizerKeepsDistinctGatewayOnlyAIAgents(t *testing.T) {
	normalizer := NewRoleNormalizer()
	recordA := AIAgentIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: "123456789012",
			Region:    "us-east-1",
			Service:   "bedrock",
		},
		AgentType:  "agent_gateway",
		AgentName:  "payments gateway a",
		GatewayID:  "payments-gateway-a",
		GatewayARN: "arn:aws:bedrock:us-east-1:123456789012:agent-gateway/payments-gateway-a",
	}
	recordB := AIAgentIdentity{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{
			AccountID: "123456789012",
			Region:    "us-east-1",
			Service:   "bedrock",
		},
		AgentType:  "agent_gateway",
		AgentName:  "payments gateway b",
		GatewayID:  "payments-gateway-b",
		GatewayARN: "arn:aws:bedrock:us-east-1:123456789012:agent-gateway/payments-gateway-b",
	}
	payloadA, err := json.Marshal(recordA)
	if err != nil {
		t.Fatalf("marshal record A: %v", err)
	}
	payloadB, err := json.Marshal(recordB)
	if err != nil {
		t.Fatalf("marshal record B: %v", err)
	}

	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		{Kind: rawKindAIAgentIdentity, SourceID: "gateway-a", Payload: payloadA},
		{Kind: rawKindAIAgentIdentity, SourceID: "gateway-b", Payload: payloadB},
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Agents) != 2 {
		t.Fatalf("expected two gateway agents, got %+v", bundle.Agents)
	}
	if bundle.Agents[0].ID == bundle.Agents[1].ID {
		t.Fatalf("expected distinct gateway agent IDs, got %q", bundle.Agents[0].ID)
	}
	if strings.Contains(bundle.Agents[0].ID, "/unknown") || strings.Contains(bundle.Agents[1].ID, "/unknown") {
		t.Fatalf("gateway-only agents should not collapse to unknown IDs: %+v", bundle.Agents)
	}
}

func TestAIAgentExecutionEndpointNodeIDPreservesAgentNodeCase(t *testing.T) {
	agentNodeID := "aws:agent:123456789012:us-east-1:custom_agent/CaseSensitiveGateway"
	endpointARN := "arn:aws:bedrock-agentcore:us-east-1:123456789012:agent-runtime-endpoint/runtime/Blue"

	nodeID := awsAIAgentExecutionEndpointNodeID(agentNodeID, endpointARN)
	if !strings.Contains(nodeID, agentNodeID) {
		t.Fatalf("expected endpoint node id to preserve agent node case, got %q", nodeID)
	}
}

func TestRoleNormalizerInvalidPermissionPolicyDocument(t *testing.T) {
	role := IAMRole{
		ARN:                "arn:aws:iam::1:role/demo",
		Name:               "demo",
		PermissionPolicies: []IAMPermissionPolicy{{Name: "bad", Document: "{"}},
	}
	payload, _ := json.Marshal(role)

	normalizer := NewRoleNormalizer()
	_, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{Kind: "iam_role", Payload: payload, SourceID: role.ARN}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "normalize permission policies") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoleNormalizerSkipsPermissionStatementsWithInvalidEffect(t *testing.T) {
	role := IAMRole{
		ARN:  "arn:aws:iam::1:role/demo",
		Name: "demo",
		PermissionPolicies: []IAMPermissionPolicy{{
			Name: "mixed",
			Document: `{
				"Version":"2012-10-17",
				"Statement":[
					{"Effect":"Alow","Action":"s3:GetObject","Resource":"*"},
					{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}
				]
			}`,
		}},
	}
	payload, _ := json.Marshal(role)

	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{Kind: "iam_role", Payload: payload, SourceID: role.ARN}})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected one normalized permission policy, got %d", len(bundle.Policies))
	}
	statements, ok := bundle.Policies[0].Normalized[statementsKey].([]map[string]any)
	if !ok {
		t.Fatalf("expected normalized statements slice, got %T", bundle.Policies[0].Normalized[statementsKey])
	}
	if len(statements) != 1 {
		t.Fatalf("expected invalid-effect statements to be skipped, got %d statements", len(statements))
	}
	if got := statements[0]["effect"]; got != "Allow" {
		t.Fatalf("expected surviving statement effect Allow, got %#v", got)
	}
}

func TestRoleNormalizerSkipsPermissionPolicyWhenNoValidEffectsRemain(t *testing.T) {
	role := IAMRole{
		ARN:  "arn:aws:iam::1:role/demo",
		Name: "demo",
		PermissionPolicies: []IAMPermissionPolicy{{
			Name: "invalid-only",
			Document: `{
				"Version":"2012-10-17",
				"Statement":[
					{"Effect":"","Action":"s3:GetObject","Resource":"*"},
					{"Effect":"Alow","Action":"s3:ListBucket","Resource":"*"}
				]
			}`,
		}},
	}
	payload, _ := json.Marshal(role)

	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{Kind: "iam_role", Payload: payload, SourceID: role.ARN}})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Policies) != 0 {
		t.Fatalf("expected no normalized policies when no valid effects exist, got %d", len(bundle.Policies))
	}
}

func TestRoleNormalizerPreservesDynamoDBRDSReachabilityRelationships(t *testing.T) {
	record := DynamoDBRDSReachability{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: dynamoDBServiceName, AccountID: "123456789012", Region: "us-east-1"},
		ResourceType:           "dynamodb_table",
		ResourceARN:            "arn:aws:dynamodb:us-east-1:123456789012:table/payments",
		ResourceName:           "payments",
		IdentityGrants: []DynamoDBRDSIdentityGrant{{
			PrincipalARN: "arn:aws:iam::123456789012:role/reader",
			Effect:       "Allow",
			Actions:      []string{"dynamodb:GetItem", "dynamodb:Query"},
		}},
		AssociatedRoleARNs: []string{"arn:aws:iam::123456789012:role/associated"},
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindDynamoDBRDSReachability,
		SourceID: "ddb|payments",
		Payload:  recordPayload,
	}})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if len(bundle.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(bundle.Resources))
	}
	if len(bundle.Identities) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(bundle.Identities))
	}
	if len(bundle.Policies) != 2 {
		t.Fatalf("expected 2 generated policies, got %d", len(bundle.Policies))
	}

	permissions, err := NewPolicyPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}
	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, permissions)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	resourceID := bundle.Resources[0].ARN
	expect := map[string]bool{
		accessNodeID("dynamodb:GetItem", resourceID): false,
		accessNodeID("dynamodb:Query", resourceID):   false,
		accessNodeID("dynamodb:*", resourceID):       false,
	}
	for _, relationship := range relationships {
		if relationship.Type != domain.RelationshipCanAccess {
			continue
		}
		expect[relationship.ToNodeID] = true
	}
	for toNodeID, found := range expect {
		if !found {
			t.Fatalf("missing can_access relationship to %q", toNodeID)
		}
	}
}

func TestRoleNormalizerSkipsNonIAMPrincipalsInDynamoDBRDSReachability(t *testing.T) {
	record := DynamoDBRDSReachability{
		ServiceCollectorRecord: awscontract.ServiceCollectorRecord{Service: dynamoDBServiceName, AccountID: "123456789012", Region: "us-east-1"},
		ResourceType:           "dynamodb_table",
		ResourceARN:            "arn:aws:dynamodb:us-east-1:123456789012:table/payments",
		ResourceName:           "payments",
		IdentityGrants: []DynamoDBRDSIdentityGrant{
			{
				PrincipalARN: "*",
				Effect:       "Allow",
				Actions:      []string{"dynamodb:ListTables"},
			},
			{
				PrincipalARN: "arn:aws:iam::123456789012:role/reader",
				Effect:       "Allow",
				Actions:      []string{"dynamodb:GetItem"},
			},
			{
				PrincipalARN: "svc-ops.amazonaws.com",
				Effect:       "Allow",
				Actions:      []string{"dynamodb:UpdateItem"},
			},
			{
				PrincipalARN: "arn:aws:iam::999999999999:user/analyzer",
				Effect:       "Allow",
				Actions:      []string{"dynamodb:GetItem"},
			},
		},
		AssociatedRoleARNs: []string{
			"arn:aws:iam::123456789012:role/associated",
		},
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{
		Kind:     rawKindDynamoDBRDSReachability,
		SourceID: "ddb|payments",
		Payload:  recordPayload,
	}})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if len(bundle.Identities) != 3 {
		t.Fatalf("expected 3 identities (1 IAM user, 1 IAM role grant, 1 associated role), got %d", len(bundle.Identities))
	}
	if len(bundle.Policies) != 3 {
		t.Fatalf("expected 3 generated policies, got %d", len(bundle.Policies))
	}
	for _, identity := range bundle.Identities {
		switch identity.ID {
		case "*", "svc-ops.amazonaws.com":
			t.Fatalf("non-IAM principal should be skipped, got %q", identity.ID)
		}
	}
}
