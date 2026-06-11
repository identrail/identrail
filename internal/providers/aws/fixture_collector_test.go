package aws

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFixtureCollectorCollectFilesAndDirectories(t *testing.T) {
	dir := t.TempDir()

	roleA := `{"arn":"arn:aws:iam::123456789012:role/a","name":"a","assume_role_policy_document":"{}","permission_policies":[]}`
	roleB := `{"arn":"arn:aws:iam::123456789012:role/b","name":"b","assume_role_policy_document":"{}","permission_policies":[]}`
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(roleA), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(roleB), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fixedNow := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	collector := NewFixtureCollector([]string{filepath.Join(dir, "a.json"), dir}, WithFixtureClock(func() time.Time { return fixedNow }))

	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 deduplicated assets, got %d", len(assets))
	}
	for _, asset := range assets {
		if asset.Collected != "2026-03-16T12:00:00Z" {
			t.Fatalf("unexpected collected time: %q", asset.Collected)
		}
	}
}

func TestFixtureCollectorErrors(t *testing.T) {
	collector := NewFixtureCollector(nil)
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected error for empty fixture list")
	}

	dir := t.TempDir()
	collector = NewFixtureCollector([]string{dir})
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected error for empty directory")
	}

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write bad fixture: %v", err)
	}
	collector = NewFixtureCollector([]string{badFile})
	if _, err := collector.Collect(context.Background()); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFixtureCollectorSkipsMalformedAndMissingARNFixturesWhenValidRecordsExist(t *testing.T) {
	dir := t.TempDir()

	validRole := `{"arn":"arn:aws:iam::123456789012:role/valid","name":"valid","assume_role_policy_document":"{}","permission_policies":[]}`
	missingARNRole := `{"name":"missing-arn","assume_role_policy_document":"{}","permission_policies":[]}`
	if err := os.WriteFile(filepath.Join(dir, "01-valid.json"), []byte(validRole), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "02-bad.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "03-missing-arn.json"), []byte(missingARNRole), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "04-duplicate.json"), []byte(validRole), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	collector := NewFixtureCollector([]string{dir})
	assets, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect with partial malformed fixtures: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected one deduplicated valid asset, got %d", len(assets))
	}
	if assets[0].SourceID != "arn:aws:iam::123456789012:role/valid" {
		t.Fatalf("unexpected source id for retained fixture: %q", assets[0].SourceID)
	}
}

func TestFixtureCollectorClassifiesECSTaskRoleWithWorkloadIDAsECS(t *testing.T) {
	payload := []byte(`{
		"service":"ecs",
		"collector_name":"ecs_task_role",
		"account_id":"123456789012",
		"region":"us-east-1",
		"workload_id":"arn:aws:ecs:us-east-1:123456789012:service/prod/payments",
		"workload_type":"ecs_service",
		"role_kind":"task_role",
		"role_arn":"arn:aws:iam::123456789012:role/payments-task",
		"task_definition_arn":"arn:aws:ecs:us-east-1:123456789012:task-definition/payments:4"
	}`)

	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindECSTaskRole {
		t.Fatalf("expected ECS task role fixture, got kind=%q sourceID=%q", kind, sourceID)
	}
	if sourceID == "" {
		t.Fatal("expected ECS source ID")
	}
}

func TestFixtureCollectorClassifiesSSMParameterMetadataBeforeSecretsManager(t *testing.T) {
	// kms_key_id and referenced_by are shared field names with the Secrets
	// Manager record shape; an SSM fixture carrying them must still classify
	// as SSM parameter metadata.
	payload := []byte(`{
		"service":"ssm",
		"collector_name":"ssm_parameter_metadata",
		"account_id":"123456789012",
		"region":"us-east-1",
		"parameter_arn":"arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password",
		"parameter_name":"/payments/db/password",
		"parameter_type":"secure_string",
		"kms_key_id":"alias/payments-parameters",
		"referenced_by":[{"reference":"DATABASE_PASSWORD=arn:aws:ssm:us-east-1:123456789012:parameter/payments/db/password","reference_kind":"arn","confidence":0.9}]
	}`)

	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindSSMParameterMetadata {
		t.Fatalf("expected SSM parameter metadata fixture, got kind=%q sourceID=%q", kind, sourceID)
	}
	if sourceID == "" {
		t.Fatal("expected SSM parameter source ID")
	}
}

func TestFixtureCollectorStillClassifiesSecretsManagerAfterSSMMatcher(t *testing.T) {
	payload := []byte(`{
		"service":"secretsmanager",
		"collector_name":"secrets_manager_metadata",
		"account_id":"123456789012",
		"region":"us-east-1",
		"secret_arn":"arn:aws:secretsmanager:us-east-1:123456789012:secret:payments/db-AbCdEf",
		"secret_name":"payments/db",
		"kms_key_id":"alias/payments"
	}`)

	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindSecretsManagerMetadata {
		t.Fatalf("expected Secrets Manager metadata fixture, got kind=%q sourceID=%q", kind, sourceID)
	}
	if sourceID == "" {
		t.Fatal("expected Secrets Manager source ID")
	}
}

func TestFixtureCollectorDoesNotClassifyECSClusterARNAsEKS(t *testing.T) {
	payload := []byte(`{
		"account_id":"123456789012",
		"region":"us-east-1",
		"cluster_arn":"arn:aws:ecs:us-east-1:123456789012:cluster/prod",
		"workload_type":"ecs_service"
	}`)

	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindECSTaskRole {
		t.Fatalf("expected ECS task role fixture, got kind=%q sourceID=%q", kind, sourceID)
	}
	if sourceID == "" {
		t.Fatal("expected ECS source ID")
	}
}

func TestFixtureCollectorClassifiesEKSWorkloadBeforeGenericRoleKindFallback(t *testing.T) {
	payload := []byte(`{
		"account_id":"123456789012",
		"region":"us-east-1",
		"workload_id":"prod-cluster/jobs/batch-worker",
		"workload_type":"eks_service_account",
		"role_kind":"pod_identity",
		"role_arn":"arn:aws:iam::123456789012:role/batch-pod-identity",
		"cluster_name":"prod-cluster",
		"namespace":"jobs",
		"service_account":"batch-worker"
	}`)

	kind, sourceID := fixtureAssetKindAndSourceID(payload)
	if kind != rawKindEKSWorkloadIdentity {
		t.Fatalf("expected EKS workload identity fixture, got kind=%q sourceID=%q", kind, sourceID)
	}
	if sourceID == "" {
		t.Fatal("expected EKS source ID")
	}
}

func TestFixtureCollectorDoesNotClassifyGenericRoleKindAsCodePipeline(t *testing.T) {
	if isCodePipelineDeploymentRoleFixture(CodePipelineDeploymentRole{RoleKind: "action_role"}) {
		t.Fatal("expected role_kind alone not to classify a fixture as CodePipeline")
	}
}

func TestFixtureCollectorDoesNotClassifyGenericEnvironmentKeysAsLambda(t *testing.T) {
	genericPayload := []byte(`{
		"role_arn":"arn:aws:iam::123456789012:role/shared-runtime",
		"environment_keys":["APP_ENV"]
	}`)
	kind, sourceID := fixtureAssetKindAndSourceID(genericPayload)
	if kind != "" || sourceID != "" {
		t.Fatalf("expected generic environment key fixture to stay unclassified, got kind=%q sourceID=%q", kind, sourceID)
	}

	lambdaPayload := []byte(`{
		"function_arn":"arn:aws:lambda:us-east-1:123456789012:function:payments-worker",
		"role_arn":"arn:aws:iam::123456789012:role/payments-lambda-execution",
		"environment_keys":["APP_ENV"]
	}`)
	kind, sourceID = fixtureAssetKindAndSourceID(lambdaPayload)
	if kind != rawKindLambdaExecutionRole || sourceID == "" {
		t.Fatalf("expected explicit Lambda fixture to classify, got kind=%q sourceID=%q", kind, sourceID)
	}
}
