package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/identrail/identrail/internal/domain"
	"github.com/identrail/identrail/internal/providers"
)

// RelationshipOption customizes graph relationship builder behavior.
type RelationshipOption func(*RelationshipBuilder)

// RelationshipBuilder constructs graph edges from normalized data and permissions.
type RelationshipBuilder struct {
	now func() time.Time
}

var _ providers.RelationshipResolver = (*RelationshipBuilder)(nil)

// NewRelationshipBuilder returns the AWS relationship resolver.
func NewRelationshipBuilder(opts ...RelationshipOption) *RelationshipBuilder {
	builder := &RelationshipBuilder{now: time.Now}
	for _, opt := range opts {
		opt(builder)
	}
	return builder
}

// WithRelationshipClock injects a deterministic clock for tests.
func WithRelationshipClock(now func() time.Time) RelationshipOption {
	return func(builder *RelationshipBuilder) {
		if now != nil {
			builder.now = now
		}
	}
}

// ResolveRelationships creates policy attachment, trust, and can_access edges.
func (b *RelationshipBuilder) ResolveRelationships(ctx context.Context, bundle providers.NormalizedBundle, perms []providers.PermissionTuple) ([]domain.Relationship, error) {
	timestamp := b.now().UTC()
	relationships := make([]domain.Relationship, 0, len(bundle.Policies)+len(perms))
	seen := map[string]struct{}{}

	arnToIdentity := make(map[string]string, len(bundle.Identities))
	identityIDs := make(map[string]struct{}, len(bundle.Identities))
	for _, identity := range bundle.Identities {
		arnToIdentity[identity.ARN] = identity.ID
		identityIDs[identity.ID] = struct{}{}
	}

	for _, workload := range bundle.Workloads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		identityID := strings.TrimSpace(workload.RawRef)
		if identityID == "" {
			continue
		}
		if _, exists := identityIDs[identityID]; !exists {
			continue
		}
		relationshipType := workloadRelationshipType(workload.Type)
		relationship := domain.Relationship{
			ID:           relationshipID(relationshipType, workload.ID, identityID),
			Type:         relationshipType,
			FromNodeID:   workload.ID,
			ToNodeID:     identityID,
			EvidenceRef:  workload.ID,
			DiscoveredAt: timestamp,
		}
		appendRelationship(&relationships, seen, relationship)
	}

	secretIndex := secretsManagerResourceIndex(bundle.Resources)
	parameterIndex := ssmParameterResourceIndex(bundle.Resources)
	imageIndex := ecrRepositoryResourceIndex(bundle.Resources)
	for _, resource := range bundle.Resources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		refs := parseStringList(resource.Metadata["secret_refs"])
		for _, ref := range refs {
			secretID := matchSecretsManagerReference(ref, secretIndex)
			if secretID == "" {
				secretID = matchSSMParameterReference(ref, parameterIndex)
			}
			if secretID == "" {
				continue
			}
			fromNodeID := strings.TrimSpace(resource.SourceEntityID)
			if fromNodeID == "" {
				fromNodeID = resource.ID
			}
			relationship := domain.Relationship{
				ID:           relationshipID(domain.RelationshipUsesSecret, fromNodeID, secretID),
				Type:         domain.RelationshipUsesSecret,
				FromNodeID:   fromNodeID,
				ToNodeID:     secretID,
				EvidenceRef:  strings.TrimSpace(ref),
				DiscoveredAt: timestamp,
			}
			appendRelationship(&relationships, seen, relationship)
		}
		for _, ref := range imageRefsFromResource(resource) {
			repositoryID := matchECRImageReference(ref, imageIndex)
			if repositoryID == "" {
				continue
			}
			fromNodeID := strings.TrimSpace(resource.SourceEntityID)
			if fromNodeID == "" {
				fromNodeID = resource.ID
			}
			relationship := domain.Relationship{
				ID:           relationshipID(domain.RelationshipUsesImage, fromNodeID, repositoryID),
				Type:         domain.RelationshipUsesImage,
				FromNodeID:   fromNodeID,
				ToNodeID:     repositoryID,
				EvidenceRef:  strings.TrimSpace(ref),
				DiscoveredAt: timestamp,
			}
			appendRelationship(&relationships, seen, relationship)
		}
	}

	// Credential/secret reference edges across workloads. Resolved references
	// reuse the same uses_secret edge IDs as the secret/parameter matching above
	// (deduped by appendRelationship); unresolved external provider keys add
	// edges to the synthesized credential-reference nodes from the normalizer.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, credentialEdges := MapBundleCredentialReferences(bundle)
	for _, edge := range credentialEdges {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		edge.DiscoveredAt = timestamp
		appendRelationship(&relationships, seen, edge)
	}

	for _, policy := range bundle.Policies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		policyType, _ := policy.Normalized[policyTypeKey].(string)
		identityID, _ := policy.Normalized[identityIDKey].(string)
		if identityID == "" {
			continue
		}

		switch policyType {
		case policyTypePerm:
			relationship := domain.Relationship{
				ID:           relationshipID(domain.RelationshipAttachedPolicy, identityID, policy.ID),
				Type:         domain.RelationshipAttachedPolicy,
				FromNodeID:   identityID,
				ToNodeID:     policy.ID,
				EvidenceRef:  policy.RawRef,
				DiscoveredAt: timestamp,
			}
			appendRelationship(&relationships, seen, relationship)
		case policyTypeTrust:
			principals := parseStringList(policy.Normalized[principalsKey])
			for _, principal := range principals {
				fromNodeID := principalNodeID(principal, arnToIdentity)
				if fromNodeID == "" {
					continue
				}
				relationship := domain.Relationship{
					ID:           relationshipID(domain.RelationshipCanAssume, fromNodeID, identityID),
					Type:         domain.RelationshipCanAssume,
					FromNodeID:   fromNodeID,
					ToNodeID:     identityID,
					EvidenceRef:  policy.RawRef,
					DiscoveredAt: timestamp,
				}
				appendRelationship(&relationships, seen, relationship)
			}
		}
	}

	for _, permission := range perms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if permission.Effect != "Allow" {
			continue
		}
		toNodeID := accessNodeID(permission.Action, permission.Resource)
		relationship := domain.Relationship{
			ID:           relationshipID(domain.RelationshipCanAccess, permission.IdentityID, toNodeID),
			Type:         domain.RelationshipCanAccess,
			FromNodeID:   permission.IdentityID,
			ToNodeID:     toNodeID,
			EvidenceRef:  permission.Action,
			DiscoveredAt: timestamp,
		}
		appendRelationship(&relationships, seen, relationship)
	}

	return relationships, nil
}

func ecrRepositoryResourceIndex(resources []domain.Resource) map[string]string {
	index := map[string]string{}
	for _, resource := range resources {
		if resource.Type != domain.ResourceTypeECRRepository {
			continue
		}
		for _, key := range ecrRepositoryReferenceKeys(resource.ARN, resource.Name, resource.Metadata["repository_uri"]) {
			index[strings.ToLower(key)] = resource.ID
		}
	}
	return index
}

func matchECRImageReference(ref string, index map[string]string) string {
	for _, key := range ecrRepositoryReferenceKeysFromRef(ref) {
		if id := index[strings.ToLower(key)]; id != "" {
			return id
		}
	}
	return ""
}

func imageRefsFromResource(resource domain.Resource) []string {
	refs := []string{}
	refs = append(refs, parseStringList(resource.Metadata["container_images"])...)
	refs = append(refs, parseStringList(resource.Metadata["image_uris"])...)
	if image := strings.TrimSpace(fmt.Sprint(resource.Metadata["image"])); image != "" && image != "<nil>" {
		refs = append(refs, image)
	}
	return dedupeStrings(refs)
}

func ecrRepositoryReferenceKeys(repositoryARN string, repositoryName string, repositoryURI any) []string {
	keys := []string{}
	if arn := strings.TrimSpace(repositoryARN); arn != "" {
		keys = append(keys, arn)
		keys = append(keys, ecrRepositoryNameFromARN(arn))
	}
	if name := strings.TrimSpace(repositoryName); name != "" {
		keys = append(keys, name)
	}
	if uri := strings.TrimSpace(fmt.Sprint(repositoryURI)); uri != "" && uri != "<nil>" {
		keys = append(keys, uri)
		keys = append(keys, ecrRepositoryNameFromURI(uri))
	}
	return dedupeStrings(keys)
}

func isECRImageURI(uri string) bool {
	host := strings.SplitN(strings.TrimSpace(uri), "/", 2)
	if len(host) == 0 || host[0] == "" {
		return false
	}
	return ecrAccountIDFromURI(host[0]) != "" && ecrRegionFromURI(host[0]) != ""
}

func ecrRepositoryReferenceKeysFromRef(ref string) []string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return nil
	}
	if idx := strings.Index(trimmed, "="); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[idx+1:])
	}
	withoutDigest := trimmed
	if idx := strings.Index(withoutDigest, "@"); idx > 0 {
		withoutDigest = withoutDigest[:idx]
	}
	withoutTag := withoutDigest
	if colon := strings.LastIndex(withoutTag, ":"); colon >= 0 {
		slash := strings.LastIndex(withoutTag, "/")
		if slash == -1 || colon > slash {
			withoutTag = withoutTag[:colon]
		}
	}
	keys := []string{trimmed, withoutDigest}
	if isECRImageURI(withoutTag) {
		keys = append(keys, withoutTag)
	}
	return dedupeStrings(keys)
}

func secretsManagerResourceIndex(resources []domain.Resource) map[string]string {
	index := map[string]string{}
	for _, resource := range resources {
		if resource.Type != domain.ResourceTypeSecretsManager {
			continue
		}
		for _, key := range secretsManagerReferenceKeys(resource.ARN, resource.Name) {
			index[strings.ToLower(key)] = resource.ID
		}
	}
	return index
}

func matchSecretsManagerReference(ref string, index map[string]string) string {
	for _, key := range secretsManagerReferenceKeysFromRef(ref) {
		if id := index[strings.ToLower(key)]; id != "" {
			return id
		}
	}
	return ""
}

func ssmParameterResourceIndex(resources []domain.Resource) map[string]string {
	index := map[string]string{}
	for _, resource := range resources {
		if resource.Type != domain.ResourceTypeSSMParameter {
			continue
		}
		for _, key := range ssmParameterReferenceKeys(resource.ARN, resource.Name) {
			index[strings.ToLower(key)] = resource.ID
		}
	}
	return index
}

func matchSSMParameterReference(ref string, index map[string]string) string {
	for _, key := range ssmParameterReferenceKeysFromRef(ref) {
		if id := index[strings.ToLower(key)]; id != "" {
			return id
		}
	}
	return ""
}

func workloadRelationshipType(workloadType string) domain.RelationshipType {
	normalized := strings.ToLower(strings.TrimSpace(workloadType))
	switch {
	case normalized == "ec2_launch_template":
		return domain.RelationshipAttachedTo
	case strings.Contains(normalized, "execution_role"), strings.Contains(normalized, "access_role"):
		return domain.RelationshipAttachedTo
	default:
		return domain.RelationshipRunsAs
	}
}

func appendRelationship(destination *[]domain.Relationship, seen map[string]struct{}, relationship domain.Relationship) {
	if relationship.FromNodeID == "" || relationship.ToNodeID == "" {
		return
	}
	if _, exists := seen[relationship.ID]; exists {
		return
	}
	seen[relationship.ID] = struct{}{}
	*destination = append(*destination, relationship)
}
