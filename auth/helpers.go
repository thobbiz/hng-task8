package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"hng-stage8/definitions"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func fetchUserInfo(ctx context.Context, token *oauth2.Token) (definitions.GoogleUserInfo, error) {
	client := definitions.GoogleOAuthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return definitions.GoogleUserInfo{}, fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return definitions.GoogleUserInfo{}, fmt.Errorf("received non-200 status from userinfo endpoint: %d", resp.StatusCode)
	}

	var userInfo definitions.GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return definitions.GoogleUserInfo{}, fmt.Errorf("failed to decode user info into struct: %w", err)
	}

	if userInfo.ID == "" {
		return definitions.GoogleUserInfo{}, fmt.Errorf("user ID is missing in Google response")
	}

	return userInfo, nil
}

func updateOrCreateUser(ctx context.Context, googleUser definitions.GoogleUserInfo) (definitions.User, error) {
	user := definitions.User{
		ID:    googleUser.ID,
		Email: googleUser.Email,
		Name:  googleUser.Name,
	}

	currentTime := time.Now().UTC()
	formattedTime := currentTime.Format(time.RFC3339)

	query := `
        INSERT INTO users (id, email, name, created_at)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            email = VALUES(email),
            name = VALUES(name);
    `

	_, err := definitions.DB.ExecContext(ctx, query, user.ID, user.Email, user.Name, formattedTime)
	if err != nil {
		return definitions.User{}, err
	}

	log.Printf("User created/updated in MySQL: ID=%s, Email=%s", user.ID, user.Email)
	return user, nil
}

func CreateJWTtoken(user definitions.User) (*string, error) {
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // Expires in 24 hours
	})

	tokenString, err := jwtToken.SignedString(definitions.JwtSecretKey)
	if err != nil {
		return nil, err
	}

	return &tokenString, nil
}
