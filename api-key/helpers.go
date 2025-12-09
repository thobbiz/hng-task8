package apikey

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hng-stage8/definitions"
	"hng-stage8/util"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
)

func GenerateApiKey(ctx context.Context, apikey definitions.ApiKey, userID string) (string, string, error) {
	// Start transaction
	tx, err := definitions.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to start transaction: %w\n", err)
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
		log.Printf("Failed to check API key count: %v\n", err)
		return "", "", err
	}
	if limitReached {
		return "", "", errors.New("user has reached the maximum number of API keys")
	}

	// Insert API key into db
	apiKeyID, expiryTime, err := insertApiKey(tx, ctx, userID, apikey.Name, apikey.ExpiryTimeFrame)
	if err != nil {
		log.Printf("Failed to generate API key: %v\n", err)
		return "", "", err
	}

	// Insert permissions after API key is created
	if err := insertPermissions(tx, ctx, apiKeyID, apikey.Permissions); err != nil {
		log.Printf("Failed to insert permissions: %v\n", err)
		return "", "", err
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return "", "", fmt.Errorf("failed to commit transaction: %w\n", err)
	}

	return apiKeyID, expiryTime, nil
}

func RolloverApiKey(ctx context.Context, rolloverReq definitions.RolloverApiReq, userID string) (string, string, error) {
	// Start Transaction
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

	// Get api key name
	apiKeyName, err := getApiKeyName(tx, ctx, userID, rolloverReq.ExpiredKeyID)
	if err != nil {
		log.Println(err)
		return "", "", errors.New(err.Error())
	}

	// insert a new api key and delete the old api key
	newApiKeyID, expiryTime, err := insertAndDeleteApiKey(tx, ctx, userID, apiKeyName, rolloverReq.ExpiredKeyID, rolloverReq.ExpiryTimeFrame)
	if err != nil {
		log.Printf("Failed to refresh API key: %v\n", err)
		return "", "", fmt.Errorf("failed to refresh API key: %w", err)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return "", "", fmt.Errorf("failed to commit transaction: %w\n", err)
	}

	return newApiKeyID, expiryTime, nil
}

func insertAndDeleteApiKey(tx *sql.Tx, ctx context.Context, userID string, apiKeyName string, apiKeyID string, expiryTimeFrame string) (string, string, error) {
	// Insert API key into db
	newApiKeyID, expiryTime, err := insertApiKey(tx, ctx, userID, apiKeyName, expiryTimeFrame)
	if err != nil {
		log.Printf("Failed to insert new API key: %v\n", err)
		return "", "", err
	}

	// Update ID for permissions to the new API key
	if err := updatePermissionsForApiKey(tx, ctx, apiKeyID, newApiKeyID); err != nil {
		return "", "", err
	}

	// Delete old api key
	if err := deleteApiKey(tx, ctx, apiKeyID); err != nil {
		return "", "", err
	}

	return newApiKeyID, expiryTime, nil
}

func insertApiKey(tx *sql.Tx, ctx context.Context, userID string, apiKeyName, expiryTimeFrame string) (string, string, error) {
	// Get current time for created_at
	currentTime := time.Now().UTC()
	formattedCurrentTime := currentTime.Format(time.RFC3339)

	// Get current time for expires_at
	expiryDate := definitions.ExpiryDate(expiryTimeFrame)
	formattedExpiryTime, ok := util.GetExpiredTime(currentTime, expiryDate)
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
	_, err := tx.ExecContext(ctx, query, finalID, userID, apiKeyName, expiryTimeFrame, formattedCurrentTime, formattedExpiryTime)
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
		permID, valid := util.GetPermissionID(definitions.Permission(p))
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

func updatePermissionsForApiKey(tx *sql.Tx, ctx context.Context, oldApiKeyID string, newApiKeyID string) error {
	query := `
        UPDATE api_key_permissions
        SET api_key_id =?
        WHERE api_key_id = ?;
    `

	result, err := tx.ExecContext(ctx, query, newApiKeyID, oldApiKeyID)
	if err != nil {
		return fmt.Errorf("failed to update permissions for key %s: %w", oldApiKeyID, err)
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("Updated %d api_key_id for API Key %s to %s\n", rowsAffected, oldApiKeyID, newApiKeyID)
	return nil
}

func deleteApiKey(tx *sql.Tx, ctx context.Context, apiKeyID string) error {
	query := `
		DELETE FROM api_keys
        WHERE id = ?;
    `

	result, err := tx.ExecContext(ctx, query, apiKeyID)
	if err != nil {
		return fmt.Errorf("failed to delete api key %s: %w", apiKeyID, err)
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("Deleted API Key %d to %s\n", rowsAffected, apiKeyID)
	return nil
}

func getApiKeyName(tx *sql.Tx, ctx context.Context, userID string, apiKeyID string) (string, error) {
	query := `
		SELECT name
		FROM api_keys
		WHERE user_id = ? AND id = ?;
	`

	var expTime string

	err := tx.QueryRowContext(ctx, query, userID, apiKeyID).Scan(&expTime)
	if err != nil {
		return "", fmt.Errorf("failed to check API key name for user %s: %w", userID, err)
	}

	return expTime, nil
}
