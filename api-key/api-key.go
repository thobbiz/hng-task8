package apikey

import (
	"errors"
	"fmt"
	"hng-stage8/definitions"
	"hng-stage8/util"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// CreateApiKeyHandler creates a new api key
// @Summary      Creates new api key
// @Description  Creates a new api key for the user to access services.
// @Tags         auth
// @Produce      json
// @Param        response_type query string false "Set to 'json' to receive the URL in JSON response instead of redirect"
// @Success      307  {string}  string "Redirects to Google"
// //@Success      200  {object}  map[string]string "Returns {google_auth_url: ...}"
// // @Router       /auth/google [get]p
func CreateApiKeyHandler(ctx *gin.Context) {
	ID, exists := ctx.Get("user_id")
	if !exists {
		log.Printf("user id not found in context\n")
		ctx.JSON(http.StatusUnauthorized, util.ErrorResponse(errors.New("User id not found in context")))
		return
	}
	userID := ID.(string)

	// Bind request body to struct
	var req definitions.ApiKey
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Printf("failed to bind request: %v\n", err)
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(err))
		return
	}

	// Validate expiry date
	if _, err := util.ValidateExpiry(req.ExpiryTimeFrame); err != nil {
		log.Printf("invalid expiry: %v\n", err)
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("invalid expiry: %w", err)))
		return
	}

	// Validate permissions
	if err := util.ValidatePermissions(req.Permissions); err != nil {
		log.Printf("invalid permisssions: %v\n", err)
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("invalid permisssions: %w", err)))
		return
	}

	// Insert api key to DB
	apiKeyID, expiresAt, err := GenerateApiKey(ctx, req, userID)
	if err != nil {
		log.Printf("Failed to generate or save API key for user %s: %v\n", userID, err)
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to insert API key: %w", err)))
		return
	}

	ctx.JSON(http.StatusCreated, definitions.ApiKeyResponse{ApiKey: apiKeyID, Expiry: expiresAt})
}

func RollOverApiKeyHandler(ctx *gin.Context) {
	ID, exists := ctx.Get("user_id")
	if !exists {
		log.Printf("user_id not found in context\n")
		ctx.JSON(http.StatusUnauthorized, util.ErrorResponse(errors.New("User id not found in context")))
		return
	}
	userID := ID.(string)

	// Bind request body to struct
	var req definitions.RolloverApiReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Printf("failed to bind request body: %v\n", err)
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(err))
		return
	}

	// Validate expiry date
	expiryDate, err := util.ValidateExpiry(req.ExpiryTimeFrame)
	if err != nil {
		log.Printf("invalid expiry: %v\n", err)
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("invalid expiry: %w", err)))
		return
	}

	// Convert expiryDate to time.Time
	duration, _ := definitions.ExpiryTime[*expiryDate]

	currentTime := time.Now().UTC()
	expiryTime := currentTime.Add(duration)

	// Check if expiration time has passed
	isExpired := util.CheckIfTimeIsExpired(expiryTime)
	if !isExpired {
		log.Printf("API key has not yet expired\n")
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("API key has not yet expired")))
		return
	}

	// Rollover API key
	apiKeyID, expiresAt, err := RolloverApiKey(ctx, req, userID)
	if err != nil {
		log.Printf("failed to rollover API key for user %s: %v\n", userID, err)
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("failed to rollover API key: %w", err)))
		return
	}

	ctx.JSON(http.StatusCreated, definitions.ApiKeyResponse{ApiKey: apiKeyID, Expiry: expiresAt})
}
