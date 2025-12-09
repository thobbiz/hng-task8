package auth

import (
	"fmt"
	"hng-stage8/definitions"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// GoogleLoginHandler initiates the Google OAuth process
// @Summary      Initiate Google Login
// @Description  Redirects the user to Google's OAuth page. If response_type=json is passed, it returns the URL in the body instead.
// @Tags         auth
// @Produce      json
// @Param        response_type query string false "Set to 'json' to receive the URL in JSON response instead of redirect"
// @Success      307  {string}  string "Redirects to Google"
// //@Success      200  {object}  map[string]string "Returns {google_auth_url: ...}"
// // @Router       /auth/google [get]
func GoogleLoginHandler(ctx *gin.Context) {
	url := definitions.GoogleOAuthConfig.AuthCodeURL(definitions.OauthStateString)

	if ctx.Query("response_type") == "json" {
		ctx.JSON(http.StatusOK, gin.H{"google_auth_url": url})
		return
	}

	ctx.Redirect(http.StatusTemporaryRedirect, url)
}

// GoogleCallbackHandler handles the redirect from Google
// @Summary      Google Auth Callback
// @Description  Exchanges the code for a token, fetches user info, and logs them in.
// @Tags         auth
// @Produce      json
// @Param        state query string true "OAuth state parameter"
// @Param        code  query string true "OAuth authorization code"
// @Success      200   {object} definitions.User
// @Failure      400   {object} map[string]string "Missing code"
// @Failure      401   {object} map[string]string "Invalid state or code exchange failed"
// @Failure      500   {object} map[string]string "Database or Provider error"
// @Router       /auth/google/callback [get]
// handleGoogleCallback handles the redirect from Google
// @Summary      Google Auth Callback
// @Description  Exchanges the code for a token, fetches user info, and logs them in.
// @Tags         auth
// @Produce      json
// @Param        state query string true "OAuth state parameter"
// @Param        code  query string true "OAuth authorization code"
// @Success      200   {object} map[string]any
// @Failure      400   {object} map[string]string "Missing code"
// @Failure      401   {object} map[string]string "Invalid state or code exchange failed"
// @Failure      500   {object} map[string]string "Database or Provider error"
// @Router       /auth/google/callback [get]
func GoogleCallbackHandler(ctx *gin.Context) {
	state := ctx.Query("state")
	if state != definitions.OauthStateString {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid state parameter"})
		return
	}

	// Get authorization code
	code := ctx.Query("code")
	if code == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'code' parameter"})
		return
	}

	// Exchange authorization code for token
	oauthToken, err := definitions.GoogleOAuthConfig.Exchange(ctx.Request.Context(), code)
	if err != nil {
		log.Printf("Code exchange failed: %v", err)
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Inavlid code or provider error"})
		return
	}

	// Fetch user info
	googleUser, err := fetchUserInfo(ctx.Request.Context(), oauthToken)
	if err != nil {
		log.Printf("Failed to fetch user info: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Provider error fetching user info"})
		return
	}

	// Update or Create user in DB
	user, err := updateOrCreateUser(ctx.Request.Context(), googleUser)
	if err != nil {
		log.Printf("Failed to save user to db: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal DB error"})
		return
	}

	// Create JWT token
	tokenString, err := CreateJWTtoken(user)
	if err != nil {
		log.Printf("Failed to create JWT token: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"user":  user,
		"token": tokenString,
	})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
			}
			return definitions.JwtSecretKey, nil
		})

		if err != nil {
			// This catches expired tokens, bad signatures, etc.
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token", "details": err.Error()})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token structure or status"})
			return
		}

		email, ok := claims["email"].(string)
		if !ok || email == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid 'email' claim"})
			return
		}
		c.Set("user_email", email)

		userID, ok := claims["user_id"].(string)
		fmt.Println(userID)
		if !ok || userID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid 'user_id' claim"})
			return
		}
		c.Set("user_id", userID)

		c.Next()
	}
}
