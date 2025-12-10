package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hng-stage8/definitions"
	"hng-stage8/wallet"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func FetchUserInfo(ctx context.Context, token *oauth2.Token) (definitions.GoogleUserInfo, error) {
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

func CreateUserAndWallet(ctx context.Context, googleUser definitions.GoogleUserInfo) (*definitions.User, *string, error) {
	user := definitions.User{
		ID:    googleUser.ID,
		Email: googleUser.Email,
		Name:  googleUser.Name,
	}

	var walletNumber string

	// Start transaction
	tx, err := definitions.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start transaction: %w\n", err)
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
		if err != nil {
			log.Println("Rolling back tx...")
			tx.Rollback()
		}
	}()

	// Create or update user in the db
	log.Printf("Creating user with ID: %s", user.ID)
	user, err = updateOrCreateUser(ctx, tx, user)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Created user successfully : %s", user.ID)

	// Check if user wallet exists
	log.Println("Checking if user wallet exists")
	exists, err := wallet.CheckIfWalletExists(ctx, tx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	// If user wallet does not exist
	if !exists {
		// Create Users' Wallet
		log.Println("Creating user wallet with ID")
		walletNo, err := wallet.CreateWallet(tx, ctx, user.ID)
		if err != nil {
			return nil, nil, err
		}
		walletNumber = walletNo
		log.Println("Created user wallet successfully")
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w\n", err)
	}

	return &user, &walletNumber, nil
}

func updateOrCreateUser(ctx context.Context, tx *sql.Tx, user definitions.User) (definitions.User, error) {
	currentTime := time.Now().UTC()
	formattedTime := currentTime.Format(time.RFC3339)

	query := `
        INSERT INTO users (id, email, name, created_at)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            email = VALUES(email),
            name = VALUES(name);
    `

	_, err := tx.ExecContext(ctx, query, user.ID, user.Email, user.Name, formattedTime)
	if err != nil {
		return definitions.User{}, err
	}

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
