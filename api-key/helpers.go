package apikey

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hng-stage8/definitions"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
)

func GenerateApiKey(ctx context.Context, apikey definitions.ApiKey, userID string) (string, string, error) {
	// Start transaction
	tx, err := definitions.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to start transaction: %w", err)
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

	// Check how many api keys the user has
	limitReached, err := checkKeyLimit(tx, ctx, userID)
	if err != nil {
		log.Printf("Failed to check API key count: %v", err)
		return "", "", err
	}
	if limitReached {
		return "", "", errors.New("user has reached the maximum number of API keys")
	}

	// Insert API key into db
	apiKeyID, expiryTime, err := insertApiKey(tx, ctx, userID, apikey)
	if err != nil {
		log.Printf("Failed to generate API key: %v", err)
		return "", "", err
	}

	// Insert permissions after API key is created
	if err := insertPermissions(tx, ctx, apiKeyID, apikey.Permissions); err != nil {
		log.Printf("Failed to insert permissions: %v", err)
		return "", "", err
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return "", "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	return apiKeyID, expiryTime, nil
}

func insertApiKey(tx *sql.Tx, ctx context.Context, userID string, apiKey definitions.ApiKey) (string, string, error) {
	// Get current time for created_at
	currentTime := time.Now().UTC()
	formattedCurrentTime := currentTime.Format(time.RFC3339)

	// Get current time for expires_at
	expiryDate := definitions.ExpiryDate(apiKey.Expiry)
	formattedExpiryTime, ok := getExpiredTime(currentTime, expiryDate)
	if !ok {
		return "", "", errors.New("invalid expiry date")
	}

	// Generate a unique uuid for the API key ID
	uuid := strings.ReplaceAll(uuid.New().String(), "-", "")

	finalID := "sk_live_" + uuid

	query := `
        INSERT INTO api_keys (id, user_id, name, expiry, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?);
    `

	// Insert the API key into the database
	_, err := tx.ExecContext(ctx, query, finalID, userID, apiKey.Name, apiKey.Expiry, formattedCurrentTime, formattedExpiryTime)
	if err != nil {
		return "", "", fmt.Errorf("failed to save api key to DB: %w", err)
	}

	log.Printf("Api key created in DB: ID=%s", finalID)
	return finalID, formattedExpiryTime, nil
}

func insertPermissions(tx *sql.Tx, ctx context.Context, apiKeyID string, perms []string) error {
	if len(perms) == 0 {
		return nil
	}

	valuePlaceholders := make([]string, len(perms))
	args := make([]any, 0, len(perms)*2)

	for i, p := range perms {
		// Get and validate permission ID
		permID, valid := getPermissionID(definitions.Permission(p))
		if !valid {
			return fmt.Errorf("invalid permission: %s", p)
		}

		valuePlaceholders[i] = "(?, ?)"
		args = append(args, apiKeyID, permID)
	}

	// If all permissions already exist, return early
	if len(args) == 0 {
		return nil
	}

	query := fmt.Sprintf(
		"INSERT IGNORE INTO api_key_permissions (api_key_id, permission_id) VALUES %s",
		strings.Join(valuePlaceholders, ", "),
	)

	_, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to save permissions to DB: %w", err)
	}

	log.Printf("Permissions inserted into DB for API key %s", apiKeyID)
	return nil
}

func checkKeyLimit(tx *sql.Tx, ctx context.Context, userID string) (bool, error) {
	query := `
		SELECT COUNT(id)
		FROM api_keys
		WHERE user_id = ?;
	`

	var currentCount int

	err := tx.QueryRowContext(ctx, query, userID).Scan(&currentCount)
	if err != nil {
		return false, fmt.Errorf("failed to check API key count for user %s: %w", userID, err)
	}

	return currentCount >= definitions.MaxKeysPerUser, nil
}

func validatePermission(perm []string) error {
	if len(perm) == 0 {
		return errors.New("no permissions provided")
	}

	if len(perm) > 3 {
		return errors.New("too many permissions (max 3 allowed)")
	}

	for _, p := range perm {
		perm := definitions.Permission(p)

		if !definitions.ValidPermissions[perm] {
			return fmt.Errorf("invalid permission: %s", p)
		}
	}
	return nil
}

func validateExpiry(expiry string) error {
	exp := definitions.ExpiryDate(expiry)

	if !definitions.ValidExpiry[exp] {
		return errors.New("invalid expiry")
	}

	return nil
}

func getExpiredTime(currentTime time.Time, expiry definitions.ExpiryDate) (string, bool) {
	duration, ok := definitions.ExpiryTime[expiry]
	if !ok {
		return "", false
	}

	expiryTime := currentTime.Add(duration)
	return expiryTime.Format(time.RFC3339), true
}

func getPermissionID(perm definitions.Permission) (string, bool) {
	permissionID, ok := definitions.PermissionKeys[perm]
	if !ok {
		return "", false
	}

	return permissionID, true
}
