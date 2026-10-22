package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/new-api-tools/backend/internal/models"
	"github.com/new-api-tools/backend/internal/service"
)

// RegisterDeviceFingerprintRoutes registers /api/fingerprint endpoints
func RegisterDeviceFingerprintRoutes(r *gin.RouterGroup) {
	g := r.Group("/fingerprint")
	{
		g.GET("/users/recent", GetRecentUserIPs)
		g.GET("/users/:user_id", GetUserDeviceFingerprint)
		g.GET("/same-ip-accounts", GetSameIPMultiAccounts)
		g.GET("/same-account-ips", GetSameAccountMultiIPs)
	}
}

// GET /api/fingerprint/users/recent?user_ids=1,2,3
func GetRecentUserIPs(c *gin.Context) {
	raw := c.Query("user_ids")
	parts := strings.Split(raw, ",")
	ids := make([]int64, 0, len(parts))
	seen := map[int64]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := strconv.ParseInt(p, 10, 64)
		if err != nil || id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
		if len(ids) >= maxIPLimit {
			break
		}
	}

	svc := service.NewDeviceFingerprintService()
	data, err := svc.GetRecentIPs(ids)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResp("QUERY_ERROR", err.Error(), ""))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

// GET /api/fingerprint/users/:user_id
func GetUserDeviceFingerprint(c *gin.Context) {
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_PARAMS", "Invalid user ID", ""))
		return
	}

	svc := service.NewDeviceFingerprintService()
	data, err := svc.GetUserDeviceFingerprint(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResp("QUERY_ERROR", err.Error(), ""))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

// GET /api/fingerprint/same-ip-accounts?window=24h&min_users=2&limit=50
func GetSameIPMultiAccounts(c *gin.Context) {
	window := c.DefaultQuery("window", "24h")
	if !validWindow(window) {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_PARAMS", "Invalid window value", ""))
		return
	}
	minUsers, _ := strconv.Atoi(c.DefaultQuery("min_users", "2"))
	limit := parseLimit(c, 50, maxIPLimit)

	svc := service.NewDeviceFingerprintService()
	data, err := svc.GetSameIPMultiAccounts(window, minUsers, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResp("QUERY_ERROR", err.Error(), ""))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

// GET /api/fingerprint/same-account-ips?window=24h&min_ips=2&limit=50
func GetSameAccountMultiIPs(c *gin.Context) {
	window := c.DefaultQuery("window", "24h")
	if !validWindow(window) {
		c.JSON(http.StatusBadRequest, models.ErrorResp("INVALID_PARAMS", "Invalid window value", ""))
		return
	}
	minIPs, _ := strconv.Atoi(c.DefaultQuery("min_ips", "2"))
	limit := parseLimit(c, 50, maxIPLimit)

	svc := service.NewDeviceFingerprintService()
	data, err := svc.GetSameAccountMultiIPs(window, minIPs, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResp("QUERY_ERROR", err.Error(), ""))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}
