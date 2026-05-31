package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	sessionauth "github.com/identrail/identrail/internal/api/auth"
	"github.com/identrail/identrail/internal/db"
	"github.com/identrail/identrail/internal/telemetry"
	"github.com/identrail/identrail/internal/userexport"
	"go.uber.org/zap"
)

// Rate-limit window for /v1/me/export. Caps how often one user can enqueue an
// export so the worker queue cannot be flooded by a held-down button or a
// runaway script. Matches GitHub's "Settings → Account → Export account data"
// rate limit (one per ten-minute window) loosened to ten per hour.
const (
	userExportRateLimit       = 10
	userExportRateLimitWindow = time.Hour
)

// registerMeExportRoutes mounts the /v1/me/export endpoints from issue #1421.
// The download route is registered on the public route group (no
// session-auth middleware) so the HMAC-signed URL can be opened in a fresh
// browser tab — authorization is proven by the token, not the cookie.
func registerMeExportRoutes(v1 *gin.RouterGroup, publicV1 *gin.RouterGroup, logger *zap.Logger, svc *Service) {
	v1.POST("/me/export", postMeExportHandler(logger, svc))
	v1.GET("/me/export", listMeExportsHandler(logger, svc))
	v1.GET("/me/export/:job_id", getMeExportHandler(logger, svc))
	publicV1.GET("/me/export/:job_id/download", downloadMeExportHandler(logger, svc))
}

type meExportResponse struct {
	ID                string     `json:"id"`
	Status            string     `json:"status"`
	RequestedAt       time.Time  `json:"requested_at"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	DownloadURL       string     `json:"download_url,omitempty"`
	DownloadExpiresAt *time.Time `json:"download_expires_at,omitempty"`
	BundleSizeBytes   int64      `json:"bundle_size_bytes,omitempty"`
	BundleSHA256      string     `json:"bundle_sha256,omitempty"`
	ErrorMessage      string     `json:"error_message,omitempty"`
}

func postMeExportHandler(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		if svc == nil || svc.Locker == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data export is not configured"})
			return
		}
		release, acquired := svc.Locker.TryAcquire(c.Request.Context(), svc.lockKey("user-export:"+current.Session.UserID))
		if !acquired {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too many export requests; try again later",
				"code":  "rate_limited",
			})
			return
		}
		defer release(c.Request.Context())
		if !exportFeatureEnabled(svc) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data export is not configured"})
			return
		}
		ctx := c.Request.Context()
		now := nowFromService(svc)
		// Cap the rate before allocating a row so a flood does not balloon
		// the table even if every request is later rejected.
		recent, err := svc.Store.ListUserDataExports(ctx, current.Session.UserID, userExportRateLimit+1)
		if err != nil {
			if logger != nil {
				logger.Error("list user data exports", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue export"})
			return
		}
		windowStart := now.Add(-userExportRateLimitWindow)
		recentCount := 0
		for _, prior := range recent {
			if prior.RequestedAt.After(windowStart) {
				recentCount++
			}
		}
		if recentCount >= userExportRateLimit {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too many export requests; try again later",
				"code":  "rate_limited",
			})
			return
		}
		job, err := svc.Store.CreateUserDataExport(ctx, db.UserDataExport{
			UserID:      current.Session.UserID,
			RequestedAt: now,
			Status:      db.UserDataExportStatusQueued,
		})
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
				return
			}
			if logger != nil {
				logger.Error("create user data export", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue export"})
			return
		}
		auditAuthAction(ctx, "auth.user.export.request", job.ID, "success")
		c.JSON(http.StatusAccepted, toMeExportResponse(svc, c, job))
	}
}

func getMeExportHandler(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		if svc == nil || svc.Store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data export is not configured"})
			return
		}
		jobID := strings.TrimSpace(c.Param("job_id"))
		if jobID == "" {
			c.JSON(http.StatusNotFound, gin.H{"error": "export not found"})
			return
		}
		ctx := c.Request.Context()
		job, err := svc.Store.GetUserDataExport(ctx, current.Session.UserID, jobID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "export not found"})
				return
			}
			if logger != nil {
				logger.Error("get user data export", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load export"})
			return
		}
		c.JSON(http.StatusOK, toMeExportResponse(svc, c, job))
	}
}

func listMeExportsHandler(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		current, ok := sessionauth.CurrentFromGin(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		if svc == nil || svc.Store == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data export is not configured"})
			return
		}
		ctx := c.Request.Context()
		items, err := svc.Store.ListUserDataExports(ctx, current.Session.UserID, 25)
		if err != nil {
			if logger != nil {
				logger.Error("list user data exports", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list exports"})
			return
		}
		out := make([]meExportResponse, 0, len(items))
		for _, job := range items {
			out = append(out, toMeExportResponse(svc, c, job))
		}
		c.JSON(http.StatusOK, gin.H{"items": out})
	}
}

func downloadMeExportHandler(logger *zap.Logger, svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !exportFeatureEnabled(svc) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "data export is not configured"})
			return
		}
		jobID := strings.TrimSpace(c.Param("job_id"))
		rawToken := strings.TrimSpace(c.Query("token"))
		if jobID == "" || rawToken == "" {
			c.JSON(http.StatusNotFound, gin.H{"error": "export not found"})
			return
		}
		now := nowFromService(svc)
		verifiedJobID, err := userexport.VerifySignedDownloadURL(svc.UserExportTokenSecret, rawToken, now)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "export not found or download link expired"})
			return
		}
		// Belt-and-suspenders: the path's job_id must match the signed one
		// so a leaked token for job A cannot be combined with a guessed
		// job_id for job B.
		if verifiedJobID != jobID {
			c.JSON(http.StatusNotFound, gin.H{"error": "export not found"})
			return
		}
		ctx := c.Request.Context()
		job, err := svc.Store.GetUserDataExportByID(ctx, jobID)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "export not found"})
				return
			}
			if logger != nil {
				logger.Error("get user data export by id", telemetry.ZapError(err))
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to download export"})
			return
		}
		if job.Status != db.UserDataExportStatusReady || job.BundlePath == "" {
			c.JSON(http.StatusGone, gin.H{"error": "export bundle has been purged"})
			return
		}
		f, err := svc.UserExportStorage.Open(userexport.StorageKey(job))
		if err != nil {
			if logger != nil {
				logger.Error("open export bundle", telemetry.ZapError(err))
			}
			c.JSON(http.StatusGone, gin.H{"error": "export bundle has been purged"})
			return
		}
		defer f.Close()
		auditAuthAction(ctx, "auth.user.export.download", job.ID, "success")
		filename := "identrail-data-export-" + job.ID + ".zip"
		c.Writer.Header().Set("Content-Type", "application/zip")
		c.Writer.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		if job.BundleSizeBytes > 0 {
			c.Writer.Header().Set("Content-Length", strconv.FormatInt(job.BundleSizeBytes, 10))
		}
		if job.BundleSHA256 != "" {
			c.Writer.Header().Set("X-Bundle-SHA256", job.BundleSHA256)
		}
		c.Status(http.StatusOK)
		if _, copyErr := io.Copy(c.Writer, f); copyErr != nil && logger != nil {
			logger.Warn("stream export bundle", telemetry.ZapError(copyErr))
		}
	}
}

func toMeExportResponse(svc *Service, c *gin.Context, job db.UserDataExport) meExportResponse {
	resp := meExportResponse{
		ID:              job.ID,
		Status:          job.Status,
		RequestedAt:     job.RequestedAt,
		StartedAt:       job.StartedAt,
		CompletedAt:     job.CompletedAt,
		BundleSizeBytes: job.BundleSizeBytes,
		BundleSHA256:    job.BundleSHA256,
		ErrorMessage:    job.ErrorMessage,
	}
	if job.DownloadExpiresAt != nil {
		t := *job.DownloadExpiresAt
		resp.DownloadExpiresAt = &t
	}
	if job.Status == db.UserDataExportStatusReady && len(svc.UserExportTokenSecret) > 0 && job.DownloadExpiresAt != nil {
		now := nowFromService(svc)
		if !job.DownloadExpiresAt.IsZero() && now.Before(*job.DownloadExpiresAt) {
			if token, err := userexport.SignedDownloadURL(svc.UserExportTokenSecret, job.ID, *job.DownloadExpiresAt); err == nil {
				resp.DownloadURL = "/v1/me/export/" + job.ID + "/download?token=" + token
			}
		}
	}
	return resp
}

func exportFeatureEnabled(svc *Service) bool {
	return svc != nil && svc.Store != nil && svc.UserExportStorage != nil && len(svc.UserExportTokenSecret) > 0
}

func nowFromService(svc *Service) time.Time {
	if svc != nil && svc.Now != nil {
		return svc.Now().UTC()
	}
	return time.Now().UTC()
}
