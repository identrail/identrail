module github.com/identrail/identrail

go 1.26.9

toolchain go1.27.2

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/aws/aws-sdk-go-v2 v1.47.2
	github.com/aws/aws-sdk-go-v2/config v1.33.8
	github.com/aws/aws-sdk-go-v2/credentials v1.20.8
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.57.3
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.48.3
	github.com/aws/aws-sdk-go-v2/service/batch v1.78.2
	github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol v1.72.2
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.82.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.65.3
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.78.3
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.55.3
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.70.2
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.338.3
	github.com/aws/aws-sdk-go-v2/service/ecr v1.66.3
	github.com/aws/aws-sdk-go-v2/service/ecs v1.100.2
	github.com/aws/aws-sdk-go-v2/service/eks v1.104.0
	github.com/aws/aws-sdk-go-v2/service/emr v1.70.3
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.55.2
	github.com/aws/aws-sdk-go-v2/service/glue v1.169.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.3
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.3
	github.com/aws/aws-sdk-go-v2/service/lambda v1.112.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.61.2
	github.com/aws/aws-sdk-go-v2/service/pipes v1.32.3
	github.com/aws/aws-sdk-go-v2/service/rds v1.130.2
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.2
	github.com/aws/aws-sdk-go-v2/service/s3control v1.79.3
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.282.2
	github.com/aws/aws-sdk-go-v2/service/scheduler v1.25.3
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.3
	github.com/aws/aws-sdk-go-v2/service/sfn v1.51.3
	github.com/aws/aws-sdk-go-v2/service/sns v1.47.4
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.3
	github.com/aws/aws-sdk-go-v2/service/ssm v1.79.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.3
	github.com/aws/smithy-go v1.28.4
	github.com/beevik/etree v1.8.1
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/crewjam/saml v0.5.1
	github.com/gin-gonic/gin v1.12.0
	github.com/goccy/go-yaml v1.19.2
	github.com/google/uuid v1.6.0
	github.com/hashicorp/hcl/v2 v2.25.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/prometheus/client_golang v1.25.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/spf13/cobra v1.10.2
	github.com/workos/workos-go/v6 v6.5.0
	github.com/zclconf/go-cty v1.19.0
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
	go.uber.org/zap v1.28.0
	golang.org/x/time v0.16.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/agext/levenshtein v1.2.1 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/apparentlymart/go-textseg/v17 v17.0.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.21 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.20 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/arch v0.22.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
