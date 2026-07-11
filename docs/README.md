# Documentation Index

This index maps Identrail docs by operator, developer, security/compliance, and release workflows.

## Start here

- Enterprise quickstart: `enterprise-quickstart.md`
- Operator readiness handoff: `operator-readiness.md`
- Deployment runbook: `deploy-runbook.md`
- AWS OIDC deployment role: `aws-oidc-deployment.md`
- AWS deployment foundation: `aws-deployment-foundation.md`
- AWS API hosting: `aws-api-hosting.md`

## Operator track

- Deployment options:
  - `../deploy/README.md`
  - `deployment-anywhere.md`
  - `../deploy/docker/README.md`
  - `../deploy/kubernetes/README.md`
  - `../deploy/helm/README.md`
  - `../deploy/terraform/README.md`
  - `../deploy/aws/README.md`
  - `aws-api-hosting.md`
- Day-2 operations:
  - `observability.md`
  - `troubleshooting.md`
  - `incident-response.md`
- Source setup:
  - `source-onboarding.md`
- Worker/scheduler behavior:
  - `worker.md`
  - `scheduler.md`

## Authorization and policy operations

- AuthZ operations runbook: `authz-operator-runbook.md`
- Auth scope and OIDC claims mapping: `auth-scope-and-claims.md`
- AuthZ rollout lifecycle: `authz-policy-rollout-runbook.md`
- Security hardening guidance: `security-hardening.md`

## Auth and identity foundation

- Architecture and contracts: `auth/README.md`

## API and developer track

- API contract (OpenAPI): `openapi-v1.yaml`
- Frontend topology: `frontend-topology.md`
- Development workflow: `development-workflow.md`
- Local token hygiene (Vercel OIDC): `local-token-hygiene.md`
- Install Identrail CLI: `install.md`
- CLI reference: `cli-reference.md`
- Documentation quality checks: `documentation-quality-checks.md`
- Testing strategy: `testing.md`
- Migrations strategy: `migrations.md`
- Artifact persistence notes: `persistence-artifacts.md`
- Repository exposure scanner: `repo-exposure.md`
- Execution model (API enqueue + worker processing): `execution-model.md`
- Configuration reference: `configuration-reference.md`
- Email routing: `email-routing.md`
- Domain entity model: `domain-entities.md`

## Release and supply chain track

- Release pipeline: `release-pipeline.md`
- Supply chain trust artifacts: `supply-chain-trust.md`
- Versioning and support policy: `versioning-support-policy.md`
- Release qualification checklist: `v1_release_qualification.md`

## Security and governance track

- Threat model: `threat_model.md`
- Contributor trust scoring (Good Egg): `contributor-trust-scoring.md`
- Architecture decisions: `ADR.md`
- Current product baseline: `v1_scope_and_baseline.md`
- Security policy: `../SECURITY.md`
- Contributing guide: `../CONTRIBUTING.md`
- Code of conduct: `../CODE_OF_CONDUCT.md`

## Architecture and provider internals

- Architecture overview: `architecture.md`
- AWS access key quarantine planner: `aws-access-key-quarantine-planner.md`
- AWS account/region coverage planner: `aws-account-region-coverage-planner.md`
- AWS account/region coverage: `aws-account-region-coverage.md`
- AWS account/region fan-out worker: `aws-account-region-fanout-worker.md`
- AWS advisory authorization decision API: `aws-advisory-authorization.md`
- AWS agent identity detail: `aws-agent-identity-detail.md`
- AWS agent runtime access: `aws-agent-runtime-access.md`
- AWS AgentCore gateway policy advisory: `aws-agentcore-gateway-policy-advisory.md`
- AWS AI agent identities: `aws-ai-agent-identities.md`
- AWS AI agent risk engine: `aws-ai-agent-risk-engine.md`
- AWS API hosting: `aws-api-hosting.md`
- AWS Bedrock agents: `aws-bedrock-agents.md`
- AWS blast radius engine: `aws-blast-radius-engine.md`
- AWS CodeBuild service roles: `aws-codebuild-service-roles.md`
- AWS CodePipeline deployment roles: `aws-codepipeline-deployment-roles.md`
- AWS collector details: `aws-collector.md`
- AWS credential references: `aws-credential-references.md`
- AWS cross-account trust engine: `aws-cross-account-trust-engine.md`
- AWS deployment foundation: `aws-deployment-foundation.md`
- AWS DynamoDB and RDS reachability: `aws-dynamodb-rds-reachability.md`
- AWS EC2 instance profiles: `aws-ec2-instance-profiles.md`
- AWS ECR repository metadata: `aws-ecr-repository-metadata.md`
- AWS ECS task roles: `aws-ecs-task-roles.md`
- AWS EKS workload identities: `aws-eks-workload-identities.md`
- AWS event-driven roles: `aws-event-driven-roles.md`
- AWS executive outcome view: `aws-executive-outcome-view.md`
- AWS GA demo hardening: `aws-ga-demo-hardening.md`
- AWS governance audit reporting: `aws-governance-audit-reporting.md`
- AWS graph explorer: `aws-graph-explorer.md`
- AWS IaC remediation PR and verification plan generator: `aws-iac-remediation-planner.md`
- AWS IAM PassRole relationships: `aws-iam-passrole-relationships.md`
- AWS IAM policy least-privilege diff: `aws-iam-policy-least-privilege-diff.md`
- AWS identity sprawl engine: `aws-identity-sprawl-engine.md`
- AWS KMS decrypt reachability: `aws-kms-decrypt-reachability.md`
- AWS Lambda execution roles: `aws-lambda-execution-roles.md`
- AWS least-privilege engine: `aws-least-privilege-engine.md`
- AWS high-confidence limited enforcement pilot: `aws-limited-enforcement-pilot.md`
- AWS limited enforcement framework: `aws-limited-enforcement.md`
- AWS low-risk live remediation: `aws-low-risk-live-remediation.md`
- AWS machine identity detail: `aws-machine-identity-detail.md`
- AWS managed compute roles: `aws-managed-compute-roles.md`
- AWS normalizer and graph: `aws-normalizer-graph.md`
- AWS OIDC deployment role: `aws-oidc-deployment.md`
- AWS Organizations topology: `aws-organizations-topology.md`
- AWS approved permission boundary executor: `aws-permission-boundary-executor.md`
- AWS permission boundary and SCP planner: `aws-permission-boundary-scp-planner.md`
- AWS platform baseline: `aws-platform-baseline.md`
- AWS platform dependency index: `aws-platform-dependency-index.md`
- AWS platform observability: `aws-platform-observability.md`
- AWS platform validation harness: `aws-platform-validation-harness.md`
- AWS post-remediation verification and rollback: `aws-post-remediation-verification.md`
- AWS privilege escalation engine: `aws-privilege-escalation-engine.md`
- AWS remediation approval workflow and RBAC gates: `aws-remediation-approval-rbac.md`
- AWS remediation case model: `aws-remediation-case-model.md`
- AWS Remediation Center unified experience: `aws-remediation-center.md`
- AWS remediation dry-run executor: `aws-remediation-dry-run-executor.md`
- AWS risk engine: `aws-risk-engine.md`
- AWS runtime events: `aws-runtime-events.md`
- AWS S3 bucket reachability: `aws-s3-bucket-reachability.md`
- AWS S3 runtime access: `aws-s3-runtime-access.md`
- AWS SageMaker workload roles: `aws-sagemaker-workload-roles.md`
- AWS approved SCP guardrail executor: `aws-scp-guardrail-executor.md`
- AWS secret and key rotation planner: `aws-secret-key-rotation-planner.md`
- AWS secret permission equivalence engine: `aws-secret-permission-equivalence-engine.md`
- AWS Secrets/KMS runtime access: `aws-secrets-kms-runtime-access.md`
- AWS Secrets Manager metadata: `aws-secrets-manager-metadata.md`
- AWS service collector contract: `aws-service-collector-contract.md`
- AWS session policy recommendation path: `aws-session-policy-recommendation.md`
- AWS SQS/SNS reachability: `aws-sqs-sns-reachability.md`
- AWS SSM parameter metadata: `aws-ssm-parameter-metadata.md`
- AWS StackSet onboarding: `aws-stackset-onboarding.md`
- AWS Step Functions state machine roles: `aws-stepfunctions-state-machine-roles.md`
- AWS approved trust-policy hardening executor: `aws-trust-policy-hardening-executor.md`
- AWS trust policy hardening planner: `aws-trust-policy-hardening-planner.md`
- AWS unused and dormant access engine: `aws-unused-dormant-access-engine.md`

## Historical Records

These files are retained for audit and release-history context. They are not
the active product contract.

- Archive index: `archive/README.md`
- Phase 1: `archive/phase-1.md`
- Phase 2: `archive/phase-2.md`
- Phase 3: `archive/phase-3.md`
- Phase 4: `archive/phase-4.md`
- Auth twelve-PR plan: `archive/auth-12-pr-plan.md`

## Supply chain implementation notes

- GUAC scaffold notes: `supply-chain-guac.md`
- Copilot autofix policy: `copilot-autofix.md`
