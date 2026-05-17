package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/enterprise"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/identrail/identrail/internal/workflow"
	"go.uber.org/zap"
)

const (
	scimContentType                 = "application/scim+json"
	scimCoreUserSchema              = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimListResponseSchema          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchOpSchema               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	scimDefaultListLimit            = 100
	scimMaxListLimit                = 500
)

var scimUserNameFilterRE = regexp.MustCompile(`(?i)^\s*userName\s+eq\s+"([^"]+)"\s*$`)

type enterpriseSCIMRouteOptions struct {
	Enabled       bool
	PublicBaseURL string
}

type scimAuthContext struct {
	Connection db.IdentityConnection
	Provider   string
}

type scimUserResponse struct {
	Schemas []string `json:"schemas"`
	enterprise.SCIMUser
}

type scimListResponse struct {
	Schemas      []string           `json:"schemas"`
	TotalResults int                `json:"totalResults"`
	Resources    []scimUserResponse `json:"Resources"`
	StartIndex   int                `json:"startIndex"`
	ItemsPerPage int                `json:"itemsPerPage"`
}

type scimPatchRequest struct {
	Schemas    []string             `json:"schemas,omitempty"`
	Operations []scimPatchOperation `json:"Operations"`
}

type scimPatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

func registerEnterpriseSCIMRoutes(r *gin.Engine, logger *zap.Logger, svc *Service, opts enterpriseSCIMRouteOptions) {
	if !opts.Enabled {
		return
	}
	scim := r.Group("/scim/v2")
	scim.Use(jsonBodyLimitMiddleware(defaultJSONBodyLimit))
	scim.Use(scimAuthMiddleware(logger, svc))
	scim.GET("/ServiceProviderConfig", getSCIMServiceProviderConfig)
	scim.GET("/Schemas", getSCIMSchemas)
	scim.GET("/ResourceTypes", getSCIMResourceTypes)
	scim.GET("/Users", listSCIMUsers(logger, svc, opts.PublicBaseURL))
	scim.POST("/Users", createSCIMUser(logger, svc, opts.PublicBaseURL))
	scim.GET("/Users/:id", getSCIMUser(logger, svc, opts.PublicBaseURL))
	scim.PUT("/Users/:id", putSCIMUser(logger, svc, opts.PublicBaseURL))
	scim.PATCH("/Users/:id", patchSCIMUser(logger, svc, opts.PublicBaseURL))
	scim.DELETE("/Users/:id", deleteSCIMUser(logger, svc, opts.PublicBaseURL))
}

func scimAuthMiddleware(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if svc == nil || svc.Store == nil {
			writeSCIMError(c, http.StatusServiceUnavailable, "", "SCIM service is unavailable")
			c.Abort()
			return
		}
		auth := strings.TrimSpace(c.GetHeader("Authorization"))
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			c.Header("WWW-Authenticate", `Bearer realm="Identrail SCIM"`)
			writeSCIMError(c, http.StatusUnauthorized, "", "missing bearer token")
			c.Abort()
			return
		}
		token := strings.TrimSpace(auth[len("Bearer "):])
		if token == "" {
			c.Header("WWW-Authenticate", `Bearer realm="Identrail SCIM"`)
			writeSCIMError(c, http.StatusUnauthorized, "", "missing bearer token")
			c.Abort()
			return
		}
		tokenHash := HashSCIMBearerToken(token)
		conn, err := svc.Store.GetIdentityConnectionBySCIMBearerTokenHash(c.Request.Context(), tokenHash)
		if err != nil {
			if logger != nil && !errors.Is(err, db.ErrNotFound) {
				logger.Error("resolve scim bearer token", telemetry.ZapError(err))
			}
			c.Header("WWW-Authenticate", `Bearer realm="Identrail SCIM"`)
			writeSCIMError(c, http.StatusUnauthorized, "", "invalid bearer token")
			c.Abort()
			return
		}
		if subtle.ConstantTimeCompare([]byte(conn.SCIMBearerTokenHash), []byte(tokenHash)) != 1 {
			c.Header("WWW-Authenticate", `Bearer realm="Identrail SCIM"`)
			writeSCIMError(c, http.StatusUnauthorized, "", "invalid bearer token")
			c.Abort()
			return
		}
		if !conn.IsNativeSAML() || conn.Status != "active" {
			writeSCIMError(c, http.StatusForbidden, "", "SCIM provisioning is not active for this connection")
			c.Abort()
			return
		}
		c.Set("enterprise.scim", scimAuthContext{
			Connection: conn,
			Provider:   scimProviderForConnection(conn.ID),
		})
		c.Next()
	}
}

func getSCIMServiceProviderConfig(c *gin.Context) {
	writeSCIMJSON(c, http.StatusOK, gin.H{
		"schemas":          []string{scimServiceProviderConfigSchema},
		"documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
		"patch":            gin.H{"supported": true},
		"bulk":             gin.H{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           gin.H{"supported": true, "maxResults": scimMaxListLimit},
		"changePassword":   gin.H{"supported": false},
		"sort":             gin.H{"supported": false},
		"etag":             gin.H{"supported": false},
		"authenticationSchemes": []gin.H{{
			"type":        "oauthbearertoken",
			"name":        "Bearer Token",
			"description": "Per-connection bearer token",
			"primary":     true,
		}},
	})
}

func getSCIMSchemas(c *gin.Context) {
	writeSCIMJSON(c, http.StatusOK, gin.H{
		"schemas":      []string{scimListResponseSchema},
		"totalResults": 1,
		"Resources": []gin.H{{
			"id":          scimCoreUserSchema,
			"name":        "User",
			"description": "User Account",
			"attributes": []gin.H{
				{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
				{"name": "displayName", "type": "string"},
				{"name": "active", "type": "boolean"},
				{"name": "emails", "type": "complex", "multiValued": true, "required": true},
			},
		}},
		"startIndex":   1,
		"itemsPerPage": 1,
	})
}

func getSCIMResourceTypes(c *gin.Context) {
	writeSCIMJSON(c, http.StatusOK, gin.H{
		"schemas":      []string{scimListResponseSchema},
		"totalResults": 1,
		"Resources": []gin.H{{
			"id":               "User",
			"name":             "User",
			"endpoint":         "/Users",
			"description":      "User Account",
			"schema":           scimCoreUserSchema,
			"schemaExtensions": []any{},
		}},
		"startIndex":   1,
		"itemsPerPage": 1,
	})
}

func listSCIMUsers(logger *zap.Logger, svc *Service, publicBaseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := mustSCIMAuth(c)
		startIndex := positiveQueryInt(c, "startIndex", 1)
		count := positiveQueryInt(c, "count", scimDefaultListLimit)
		if count > scimMaxListLimit {
			count = scimMaxListLimit
		}
		var users []scimUserResponse
		if filter := strings.TrimSpace(c.Query("filter")); filter != "" {
			match := scimUserNameFilterRE.FindStringSubmatch(filter)
			if len(match) != 2 {
				writeSCIMError(c, http.StatusBadRequest, "invalidFilter", `only filter=userName eq "value" is supported`)
				return
			}
			user, err := loadSCIMUserBySubject(c, svc, auth, match[1], publicBaseURL)
			if err != nil {
				if !errors.Is(err, db.ErrNotFound) {
					writeSCIMStoreError(c, logger, err, "filter scim users")
					return
				}
				users = []scimUserResponse{}
			} else {
				users = []scimUserResponse{user}
			}
		} else {
			var err error
			users, err = loadSCIMUsers(c, svc, auth, publicBaseURL)
			if err != nil {
				writeSCIMStoreError(c, logger, err, "list scim users")
				return
			}
		}
		total := len(users)
		start := startIndex - 1
		if start > total {
			users = []scimUserResponse{}
		} else {
			end := start + count
			if end > total {
				end = total
			}
			users = users[start:end]
		}
		writeSCIMJSON(c, http.StatusOK, scimListResponse{
			Schemas:      []string{scimListResponseSchema},
			TotalResults: total,
			Resources:    users,
			StartIndex:   startIndex,
			ItemsPerPage: len(users),
		})
	}
}

func createSCIMUser(logger *zap.Logger, svc *Service, publicBaseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := mustSCIMAuth(c)
		req, err := bindSCIMUserDefaultActive(c)
		if err != nil {
			writeSCIMError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM user payload")
			return
		}
		if strings.TrimSpace(req.ID) != "" {
			writeSCIMError(c, http.StatusBadRequest, "mutability", "id is server assigned")
			return
		}
		req.UserName = strings.TrimSpace(req.UserName)
		if _, err := svc.Store.GetUserIdentity(c.Request.Context(), auth.Provider, req.UserName); err == nil {
			writeSCIMError(c, http.StatusConflict, "uniqueness", "userName already exists")
			return
		} else if !errors.Is(err, db.ErrNotFound) {
			writeSCIMStoreError(c, logger, err, "check scim user uniqueness")
			return
		}
		user, err := saveSCIMUser(c, svc, auth, req, "", publicBaseURL)
		if err != nil {
			writeSCIMSaveError(c, logger, err)
			return
		}
		if err := recordSCIMEvent(c, svc, auth.Connection, enterprise.SCIMProvisioningCreate, user.SCIMUser, publicBaseURL); err != nil {
			writeSCIMStoreError(c, logger, err, "record scim create")
			return
		}
		c.Header("Location", user.Meta.Location)
		writeSCIMJSON(c, http.StatusCreated, user)
	}
}

func getSCIMUser(logger *zap.Logger, svc *Service, publicBaseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := mustSCIMAuth(c)
		user, err := loadSCIMUserByID(c, svc, auth, c.Param("id"), publicBaseURL)
		if err != nil {
			writeSCIMStoreError(c, logger, err, "get scim user")
			return
		}
		writeSCIMJSON(c, http.StatusOK, user)
	}
}

func putSCIMUser(logger *zap.Logger, svc *Service, publicBaseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := mustSCIMAuth(c)
		if _, err := loadSCIMUserByID(c, svc, auth, c.Param("id"), publicBaseURL); err != nil {
			writeSCIMStoreError(c, logger, err, "load scim user for put")
			return
		}
		req, err := bindSCIMUserDefaultActive(c)
		if err != nil {
			writeSCIMError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM user payload")
			return
		}
		req.ID = c.Param("id")
		user, err := saveSCIMUser(c, svc, auth, req, req.ID, publicBaseURL)
		if err != nil {
			writeSCIMSaveError(c, logger, err)
			return
		}
		op := enterprise.SCIMProvisioningUpdate
		if !user.Active {
			op = enterprise.SCIMProvisioningDeactivate
		}
		if err := recordSCIMEvent(c, svc, auth.Connection, op, user.SCIMUser, publicBaseURL); err != nil {
			writeSCIMStoreError(c, logger, err, "record scim update")
			return
		}
		writeSCIMJSON(c, http.StatusOK, user)
	}
}

func patchSCIMUser(logger *zap.Logger, svc *Service, publicBaseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := mustSCIMAuth(c)
		existing, err := loadSCIMUserByID(c, svc, auth, c.Param("id"), publicBaseURL)
		if err != nil {
			writeSCIMStoreError(c, logger, err, "load scim user for patch")
			return
		}
		var req scimPatchRequest
		if err := c.ShouldBindJSON(&req); err != nil || len(req.Operations) == 0 {
			writeSCIMError(c, http.StatusBadRequest, "invalidSyntax", "invalid SCIM PATCH payload")
			return
		}
		updated := existing.SCIMUser
		for _, op := range req.Operations {
			if !strings.EqualFold(strings.TrimSpace(op.Op), "replace") {
				writeSCIMError(c, http.StatusBadRequest, "mutability", "only PATCH replace operations are supported")
				return
			}
			if err := applySCIMReplace(&updated, op); err != nil {
				writeSCIMError(c, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
		}
		user, err := saveSCIMUser(c, svc, auth, updated, updated.ID, publicBaseURL)
		if err != nil {
			writeSCIMSaveError(c, logger, err)
			return
		}
		op := enterprise.SCIMProvisioningUpdate
		if !user.Active {
			op = enterprise.SCIMProvisioningDeactivate
		}
		if err := recordSCIMEvent(c, svc, auth.Connection, op, user.SCIMUser, publicBaseURL); err != nil {
			writeSCIMStoreError(c, logger, err, "record scim patch")
			return
		}
		writeSCIMJSON(c, http.StatusOK, user)
	}
}

func deleteSCIMUser(logger *zap.Logger, svc *Service, publicBaseURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := mustSCIMAuth(c)
		existing, err := loadSCIMUserByID(c, svc, auth, c.Param("id"), publicBaseURL)
		if err != nil {
			writeSCIMStoreError(c, logger, err, "load scim user for delete")
			return
		}
		updated := existing.SCIMUser
		updated.Active = false
		if _, err := saveSCIMUser(c, svc, auth, updated, updated.ID, publicBaseURL); err != nil {
			writeSCIMSaveError(c, logger, err)
			return
		}
		if err := recordSCIMEvent(c, svc, auth.Connection, enterprise.SCIMProvisioningDelete, updated, publicBaseURL); err != nil {
			writeSCIMStoreError(c, logger, err, "record scim delete")
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func bindSCIMUserDefaultActive(c *gin.Context) (enterprise.SCIMUser, error) {
	var req enterprise.SCIMUser
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		return enterprise.SCIMUser{}, err
	}
	var activeAttr struct {
		Active *bool `json:"active"`
	}
	raw, ok := c.Get(gin.BodyBytesKey)
	if !ok {
		return enterprise.SCIMUser{}, fmt.Errorf("missing request body")
	}
	body, ok := raw.([]byte)
	if !ok {
		return enterprise.SCIMUser{}, fmt.Errorf("invalid request body")
	}
	if err := json.Unmarshal(body, &activeAttr); err != nil {
		return enterprise.SCIMUser{}, err
	}
	if activeAttr.Active == nil {
		req.Active = true
	}
	return req, nil
}

func saveSCIMUser(c *gin.Context, svc *Service, auth scimAuthContext, incoming enterprise.SCIMUser, existingID string, publicBaseURL string) (scimUserResponse, error) {
	incoming.UserName = strings.TrimSpace(incoming.UserName)
	incoming.DisplayName = strings.TrimSpace(incoming.DisplayName)
	if err := incoming.Validate(); err != nil {
		return scimUserResponse{}, fmt.Errorf("invalid scim user: %w", err)
	}
	now := time.Now().UTC()
	userID := strings.TrimSpace(existingID)
	if userID == "" {
		userID = uuid.NewString()
	}
	if _, err := uuid.Parse(userID); err != nil {
		return scimUserResponse{}, db.ErrNotFound
	}
	primaryEmail := strings.ToLower(strings.TrimSpace(incoming.PrimaryEmail()))
	status := "deactivated"
	if incoming.Active {
		status = "active"
	}
	user := db.User{
		ID:           userID,
		PrimaryEmail: primaryEmail,
		DisplayName:  incoming.DisplayName,
		Status:       status,
		UpdatedAt:    now,
	}
	var existingIdentity db.UserIdentity
	subjectChanged := false
	if existingID != "" {
		existing, err := svc.Store.GetUser(c.Request.Context(), existingID)
		if err != nil {
			return scimUserResponse{}, err
		}
		user.CreatedAt = existing.CreatedAt
		existingIdentity, err = findSCIMIdentityByUserID(c, svc, auth.Provider, existingID)
		if err != nil {
			return scimUserResponse{}, err
		}
		subjectChanged = existingIdentity.Subject != incoming.UserName
		if subjectChanged {
			if bySubject, err := svc.Store.GetUserIdentity(c.Request.Context(), auth.Provider, incoming.UserName); err == nil && bySubject.UserID != existingID {
				return scimUserResponse{}, db.ErrConflict
			} else if err != nil && !errors.Is(err, db.ErrNotFound) {
				return scimUserResponse{}, err
			}
		}
	}
	savedUser, err := svc.Store.UpsertUser(c.Request.Context(), user)
	if err != nil {
		return scimUserResponse{}, err
	}
	incoming.ID = savedUser.ID
	incoming.Meta = enterprise.SCIMMeta{
		ResourceType: "User",
		Created:      savedUser.CreatedAt,
		LastModified: now,
		Location:     scimUserLocation(c, publicBaseURL, savedUser.ID),
		Version:      fmt.Sprintf(`W/"%s"`, savedUser.UpdatedAt.UTC().Format(time.RFC3339Nano)),
	}
	rawClaims, err := json.Marshal(incoming)
	if err != nil {
		return scimUserResponse{}, err
	}
	identity := db.UserIdentity{
		UserID:              savedUser.ID,
		Provider:            auth.Provider,
		Subject:             incoming.UserName,
		Email:               primaryEmail,
		EmailVerified:       true,
		RawClaims:           rawClaims,
		LastAuthenticatedAt: now,
	}
	if existingID != "" {
		if subjectChanged {
			if err := svc.Store.DeleteUserIdentity(c.Request.Context(), auth.Provider, existingIdentity.Subject); err != nil && !errors.Is(err, db.ErrNotFound) {
				return scimUserResponse{}, err
			}
		} else {
			identity.ID = existingIdentity.ID
			identity.CreatedAt = existingIdentity.CreatedAt
		}
	}
	savedIdentity, err := svc.Store.UpsertUserIdentity(c.Request.Context(), identity)
	if err != nil {
		return scimUserResponse{}, err
	}
	return scimUserFromRecords(c, publicBaseURL, savedUser, savedIdentity), nil
}

func loadSCIMUsers(c *gin.Context, svc *Service, auth scimAuthContext, publicBaseURL string) ([]scimUserResponse, error) {
	identities, err := svc.Store.ListUserIdentitiesByProvider(c.Request.Context(), auth.Provider, 0)
	if err != nil {
		return nil, err
	}
	users := make([]scimUserResponse, 0, len(identities))
	for _, identity := range identities {
		user, err := svc.Store.GetUser(c.Request.Context(), identity.UserID)
		if errors.Is(err, db.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		users = append(users, scimUserFromRecords(c, publicBaseURL, user, identity))
	}
	return users, nil
}

func loadSCIMUserBySubject(c *gin.Context, svc *Service, auth scimAuthContext, subject string, publicBaseURL string) (scimUserResponse, error) {
	identity, err := svc.Store.GetUserIdentity(c.Request.Context(), auth.Provider, strings.TrimSpace(subject))
	if err != nil {
		return scimUserResponse{}, err
	}
	user, err := svc.Store.GetUser(c.Request.Context(), identity.UserID)
	if err != nil {
		return scimUserResponse{}, err
	}
	return scimUserFromRecords(c, publicBaseURL, user, identity), nil
}

func loadSCIMUserByID(c *gin.Context, svc *Service, auth scimAuthContext, id string, publicBaseURL string) (scimUserResponse, error) {
	if _, err := uuid.Parse(strings.TrimSpace(id)); err != nil {
		return scimUserResponse{}, db.ErrNotFound
	}
	identity, err := findSCIMIdentityByUserID(c, svc, auth.Provider, id)
	if err != nil {
		return scimUserResponse{}, err
	}
	user, err := svc.Store.GetUser(c.Request.Context(), identity.UserID)
	if err != nil {
		return scimUserResponse{}, err
	}
	return scimUserFromRecords(c, publicBaseURL, user, identity), nil
}

func findSCIMIdentityByUserID(c *gin.Context, svc *Service, provider string, userID string) (db.UserIdentity, error) {
	return svc.Store.GetUserIdentityByProviderUserID(c.Request.Context(), provider, userID)
}

func scimUserFromRecords(c *gin.Context, publicBaseURL string, user db.User, identity db.UserIdentity) scimUserResponse {
	scimUser := enterprise.SCIMUser{}
	if len(identity.RawClaims) > 0 {
		_ = json.Unmarshal(identity.RawClaims, &scimUser)
	}
	scimUser.ID = user.ID
	if strings.TrimSpace(scimUser.UserName) == "" {
		scimUser.UserName = identity.Subject
	}
	if strings.TrimSpace(scimUser.DisplayName) == "" {
		scimUser.DisplayName = user.DisplayName
	}
	email := strings.TrimSpace(user.PrimaryEmail)
	if email == "" {
		email = strings.TrimSpace(identity.Email)
	}
	if len(scimUser.Emails) == 0 && email != "" {
		scimUser.Emails = []enterprise.SCIMEmail{{Value: email, Type: "work", Primary: true}}
	}
	scimUser.Active = user.Status == "active"
	scimUser.Meta = enterprise.SCIMMeta{
		ResourceType: "User",
		Created:      user.CreatedAt,
		LastModified: user.UpdatedAt,
		Location:     scimUserLocation(c, publicBaseURL, user.ID),
		Version:      fmt.Sprintf(`W/"%s"`, user.UpdatedAt.UTC().Format(time.RFC3339Nano)),
	}
	return scimUserResponse{
		Schemas:  []string{scimCoreUserSchema},
		SCIMUser: scimUser,
	}
}

func recordSCIMEvent(c *gin.Context, svc *Service, conn db.IdentityConnection, op enterprise.SCIMProvisioningOp, user enterprise.SCIMUser, publicBaseURL string) error {
	payloadBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}
	payload := map[string]any{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return err
	}
	now := time.Now().UTC()
	if svc != nil && svc.Now != nil {
		now = svc.Now().UTC()
	}
	_, err = svc.Store.CreateSCIMProvisioningEvent(c.Request.Context(), db.SCIMProvisioningEventRecord{
		OrgID:        conn.OrgID,
		ConnectionID: conn.ID,
		Op:           string(op),
		ExternalID:   user.ExternalID,
		UserID:       user.ID,
		Payload:      payload,
		OccurredAt:   now,
	})
	if err != nil {
		return err
	}
	if svc == nil || svc.WorkflowRouter == nil {
		return nil
	}
	if _, err := svc.WorkflowRouter.Dispatch(c.Request.Context(), workflow.Event{
		Kind: workflow.EventSCIMProvisioned,
		SCIMProvisioning: &workflow.SCIMProvisioningEvent{
			OrgID:        conn.OrgID,
			ConnectionID: conn.ID,
			Operation:    string(op),
			UserID:       user.ID,
			UserName:     user.UserName,
			ExternalID:   user.ExternalID,
			Active:       user.Active,
		},
		Actor:      "scim:" + strings.TrimSpace(conn.ID),
		EmittedAt:  now,
		RelatedURL: scimUserLocation(c, publicBaseURL, user.ID),
	}); err != nil {
		_ = c.Error(err)
	}
	return nil
}

func applySCIMReplace(user *enterprise.SCIMUser, op scimPatchOperation) error {
	path := strings.TrimSpace(op.Path)
	if path == "" {
		values := map[string]json.RawMessage{}
		if err := json.Unmarshal(op.Value, &values); err != nil {
			return fmt.Errorf("replace value must be an object when path is omitted")
		}
		for key, raw := range values {
			if err := replaceSCIMField(user, key, raw); err != nil {
				return err
			}
		}
		return nil
	}
	return replaceSCIMField(user, path, op.Value)
}

func replaceSCIMField(user *enterprise.SCIMUser, path string, raw json.RawMessage) error {
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "active":
		return json.Unmarshal(raw, &user.Active)
	case "username":
		return json.Unmarshal(raw, &user.UserName)
	case "displayname":
		return json.Unmarshal(raw, &user.DisplayName)
	case "externalid":
		return json.Unmarshal(raw, &user.ExternalID)
	case "emails":
		return json.Unmarshal(raw, &user.Emails)
	default:
		return fmt.Errorf("unsupported replace path %q", path)
	}
}

func mustSCIMAuth(c *gin.Context) scimAuthContext {
	value, _ := c.Get("enterprise.scim")
	auth, _ := value.(scimAuthContext)
	return auth
}

func scimProviderForConnection(connectionID string) string {
	return "scim:" + strings.TrimSpace(connectionID)
}

func positiveQueryInt(c *gin.Context, key string, fallback int) int {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func scimUserLocation(c *gin.Context, publicBaseURL string, userID string) string {
	base := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	if base == "" {
		scheme := "http"
		if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
		base = scheme + "://" + c.Request.Host
	}
	return base + "/scim/v2/Users/" + userID
}

func writeSCIMSaveError(c *gin.Context, logger *zap.Logger, err error) {
	if err == nil {
		return
	}
	if strings.HasPrefix(err.Error(), "invalid scim user:") {
		writeSCIMError(c, http.StatusBadRequest, "invalidValue", strings.TrimPrefix(err.Error(), "invalid scim user: "))
		return
	}
	if errors.Is(err, db.ErrConflict) {
		writeSCIMError(c, http.StatusConflict, "uniqueness", "SCIM user conflicts with an existing user")
		return
	}
	writeSCIMStoreError(c, logger, err, "save scim user")
}

func writeSCIMStoreError(c *gin.Context, logger *zap.Logger, err error, msg string) {
	if errors.Is(err, db.ErrNotFound) {
		writeSCIMError(c, http.StatusNotFound, "", "SCIM resource not found")
		return
	}
	if errors.Is(err, db.ErrConflict) {
		writeSCIMError(c, http.StatusConflict, "uniqueness", "SCIM resource conflict")
		return
	}
	if logger != nil {
		logger.Error(msg, telemetry.ZapError(err))
	}
	writeSCIMError(c, http.StatusInternalServerError, "", "SCIM request failed")
}

func writeSCIMError(c *gin.Context, status int, scimType string, detail string) {
	body := gin.H{
		"schemas": []string{scimErrorSchema},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	}
	if strings.TrimSpace(scimType) != "" {
		body["scimType"] = scimType
	}
	writeSCIMJSON(c, status, body)
}

func writeSCIMJSON(c *gin.Context, status int, body any) {
	c.Header("Content-Type", scimContentType)
	c.JSON(status, body)
}
