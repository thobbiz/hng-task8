package apikey

import (
	"errors"
	"fmt"
	"hng-stage8/definitions"
	"hng-stage8/util"
	"log"
	"net/http"

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
		ctx.JSON(http.StatusUnauthorized, util.ErrorResponse(errors.New("User id not found in context")))
		return
	}
	userID := ID.(string)

	// Bind request body to struct
	var req definitions.ApiKey
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(err))
		return
	}

	// Validate expiry date
	if err := validateExpiry(req.Expiry); err != nil {
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("invalid expiry: %w", err)))
		return
	}

	// Validate permissions
	if err := validatePermission(req.Permissions); err != nil {
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("invalid permisssions: %w", err)))
		return
	}

	// Insert api key to DB
	apiKeyID, expiresAt, err := GenerateApiKey(ctx, req, userID)
	if err != nil {
		log.Printf("Failed to generate or save API key for user %s: %v", userID, err)

		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to insert API key: %w", err)))
		return
	}

	ctx.JSON(http.StatusCreated, definitions.ApiKeyResponse{ApiKey: apiKeyID, Expiry: expiresAt})
}
