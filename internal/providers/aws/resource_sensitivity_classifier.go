package aws

import (
	"sort"
	"strings"
)

const (
	sensitivityClassificationSourceAuto      = "auto_rules"
	sensitivityClassificationSourceOverride  = "operator_override"
	secretsManagerSensitivityOverrideTagName = "identrail:sensitivity_classification"
)

var validSecretsManagerSensitivityClassifications = map[string]struct{}{
	"secret_bearing":           {},
	"runtime_secret_reference": {},
	"customer_kms_secret":      {},
}

func classifySecretsManagerSensitivity(record SecretsManagerSecretMetadata) (classification string, source string, override string) {
	if overrideValue := secretsManagerSensitivityOverride(record.Tags); overrideValue != "" {
		return overrideValue, sensitivityClassificationSourceOverride, overrideValue
	}
	return secretsManagerSensitivityAuto(record), sensitivityClassificationSourceAuto, ""
}

func secretsManagerSensitivityOverride(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		key := strings.ToLower(strings.TrimSpace(k))
		if key != secretsManagerSensitivityOverrideTagName {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := tags[k]
		value := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), "-", "_"))
		if _, ok := validSecretsManagerSensitivityClassifications[value]; ok {
			return value
		}
	}
	return ""
}

func secretsManagerSensitivityAuto(record SecretsManagerSecretMetadata) string {
	if len(record.ReferencedBy) > 0 {
		return "runtime_secret_reference"
	}
	if secretsManagerUsesCustomerManagedKMS(record.KMSKeyID, record.KMSKeyARN) {
		return "customer_kms_secret"
	}
	return "secret_bearing"
}

func secretsManagerUsesCustomerManagedKMS(keyID string, keyARN string) bool {
	key := strings.TrimSpace(strings.ToLower(keyID))
	arn := strings.TrimSpace(strings.ToLower(keyARN))
	if key == "" && arn == "" {
		return false
	}
	if key == "alias/aws/secretsmanager" {
		return false
	}
	if strings.Contains(arn, "alias/aws/secretsmanager") {
		return false
	}
	return true
}
