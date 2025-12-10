package wallet

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hng-stage8/definitions"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

func CreateWallet(tx *sql.Tx, ctx context.Context, userId string) (string, error) {
	// Get created at time in rfc format
	currentTime := time.Now().UTC()
	formattedTime := currentTime.Format(time.RFC3339)

	// Generate a unique uuid for the wallet ID
	uuid := strings.ReplaceAll(uuid.New().String(), "-", "")

	walletNumber := GenerateRandomWalletNumber()

	query := `
	INSERT INTO wallets (id, user_id, balance, created_at, number)
	VALUES (?, ?, ?, ?, ?);
	`

	_, err := tx.ExecContext(ctx, query, uuid, userId, 0, formattedTime, walletNumber)
	if err != nil {
		return "", err
	}

	return walletNumber, nil
}

func CreateDepositTransaction(db *sql.DB, ctx context.Context, walletID string, amount int64, reference string) error {
	// Get created at time in rfc format
	currentTime := time.Now().UTC()
	formattedTime := currentTime.Format(time.RFC3339)

	// Generate a unique uuid for the transaction ID
	uuid := strings.ReplaceAll(uuid.New().String(), "-", "")

	query := `
	INSERT INTO transactions (id, wallet_id, type, amount, created_at, reference)
	VALUES (?, ?, ?, ?, ?, ?);
	`
	_, err := db.ExecContext(ctx, query, uuid, walletID, "deposit", amount, formattedTime, reference)
	if err != nil {
		return err
	}

	return nil
}

func CreateTransferTransaction(tx *sql.Tx, ctx context.Context, walletID string, amount int64) error {
	// Get created at time in rfc format
	currentTime := time.Now().UTC()
	formattedTime := currentTime.Format(time.RFC3339)

	// Generate a unique uuid for the transaction ID
	uuid := strings.ReplaceAll(uuid.New().String(), "-", "")

	query := `
	INSERT INTO transactions (id, wallet_id, type, amount, created_at)
	VALUES (?, ?, ?, ?, ?);
	`
	_, err := tx.ExecContext(ctx, query, uuid, walletID, "transfer", amount, formattedTime)
	if err != nil {
		return err
	}

	return nil
}

func TransferBetweenUser(db *sql.DB, ctx context.Context, amount int64, userWalletID string, receiverWalletID string) error {
	tx, err := definitions.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w\n", err)
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

	// Remove Amount From Wallet
	if err := RemoveAmountFromWallet(tx, ctx, amount, userWalletID); err != nil {
		return err
	}

	// Add Amount To Receiver Wallet
	if err := AddAmountToWallet(tx, ctx, amount, receiverWalletID); err != nil {
		return err
	}

	// Add transaction to history
	if err := CreateTransferTransaction(tx, ctx, userWalletID, amount); err != nil {
		return err
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w\n", err)
	}

	return nil
}

func GetWalletTransactionHistory(db *sql.DB, ctx context.Context, userWalletID string) ([]definitions.TransactionHistory, error) {
	query := `
	SELECT type, amount, status FROM transactions WHERE wallet_id = ?;
	`

	rows, err := db.QueryContext(ctx, query, userWalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to execute transaction history query: %w", err)
	}
	defer rows.Close()

	var history []definitions.TransactionHistory
	for rows.Next() {
		var transaction definitions.TransactionHistory
		if err := rows.Scan(&transaction.Type, &transaction.Amount, &transaction.Status); err != nil {
			return nil, fmt.Errorf("failed to scan transaction history row: %w", err)
		}
		history = append(history, transaction)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate transaction history rows: %w", err)
	}

	return history, nil
}

func AddAmountToWallet(tx *sql.Tx, ctx context.Context, amount int64, walletID string) error {
	query := `
	UPDATE wallets SET balance = balance + ? WHERE id = ?;
	`

	result, err := tx.ExecContext(ctx, query, amount, walletID)
	if err != nil {
		return fmt.Errorf("failed to execute wallet update: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("wallet not found with ID: %s", walletID)
	}

	return nil
}

func RemoveAmountFromWallet(tx *sql.Tx, ctx context.Context, amount int64, walletID string) error {
	query := `
	UPDATE wallets SET balance = balance - ? WHERE id = ?;
	`

	result, err := tx.ExecContext(ctx, query, amount, walletID)
	if err != nil {
		return fmt.Errorf("failed to execute wallet update: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("wallet not found with ID: %s", walletID)
	}

	return nil
}

func CallPaystackVerify(ref string) (string, error) {
	url := "https://api.paystack.co/transaction/verify/" + ref
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("PAYSTACK_SECRET_KEY"))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var payload struct {
		Status bool `json:"status"`
		Data   struct {
			Status string `json:"status"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.Data.Status, nil
}

func UpdateTransactionStatus(tx *sql.Tx, ctx context.Context, transactionID string, status string) error {
	query := `
	UPDATE transactions SET status = ? WHERE id = ?;
	`

	result, err := tx.ExecContext(ctx, query, status, transactionID)
	if err != nil {
		return fmt.Errorf("failed to execute transaction update: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("transaction not found with ID: %s", transactionID)
	}

	return nil
}

func GetWalletIDFromUserID(db *sql.DB, ctx context.Context, userId string) (string, error) {
	var walletID string
	query := "SELECT id FROM wallets WHERE user_id = ?"

	err := db.QueryRowContext(ctx, query, userId).Scan(&walletID)

	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("error getting wallet ID: %w", err)
	}

	return walletID, nil
}

func GetWalletIDFromWalletNo(db *sql.DB, ctx context.Context, walletNo string) (string, error) {
	var walletID string
	query := "SELECT id FROM wallets WHERE number = ?"

	err := db.QueryRowContext(ctx, query, walletNo).Scan(&walletID)

	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("error getting wallet ID: %w", err)
	}

	return walletID, nil
}

func GetWalletBalance(db *sql.DB, ctx context.Context, userID string) (*int64, error) {
	var walletBalance int64
	query := "SELECT balance FROM wallets WHERE user_id = ?"

	err := db.QueryRowContext(ctx, query, userID).Scan(&walletBalance)

	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("error getting wallet ID: %w", err)
	}

	return &walletBalance, nil
}

func GetTransactionAndWalletIDAndAmount(db *sql.DB, ctx context.Context, reference string) (string, string, int64, error) {
	query := "SELECT id, wallet_id, amount FROM transactions WHERE reference = ?"

	var transactionID string
	var walletID string
	var amount int64

	err := db.QueryRowContext(ctx, query, reference).Scan(&transactionID, &walletID, &amount)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", 0, fmt.Errorf("transaction with reference '%s' not found", reference)
		}

		return "", "", 0, fmt.Errorf("database error retrieving transaction: %w", err)
	}

	return transactionID, walletID, amount, nil
}

func CheckIfWalletExists(ctx context.Context, tx *sql.Tx, userId string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM wallets WHERE user_id = ?)"

	err := tx.QueryRowContext(ctx, query, userId).Scan(&exists)

	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("error checking for existing wallet: %w", err)
	}

	return exists, nil
}

func CheckIfApiKeyHasPermit(tx *sql.Tx, ctx context.Context, apiKeyID string, permissionID string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM api_key_permissions WHERE api_key_id = ? AND permission_id = ?)"

	err := tx.QueryRowContext(ctx, query, apiKeyID, permissionID).Scan(&exists)

	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("error checking for existing wallet: %w", err)
	}

	return exists, nil
}

func GenerateRandomWalletNumber() string {
	var sb strings.Builder

	for range 13 {
		num := rand.N(10)
		sb.WriteString(fmt.Sprintf("%d", num))
	}

	return sb.String()
}

func verifySignature(body []byte, signature string) bool {
	mac := hmac.New(sha512.New, []byte(definitions.PaystackSecretKey))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expectedSignature := hex.EncodeToString(expectedMAC)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func verifyBalanceIsSufficient(db *sql.DB, walletId string, amount int64) (bool, error) {
	query := "SELECT balance FROM wallets WHERE id = ?"

	var balance int64
	err := db.QueryRow(query, walletId).Scan(&balance)

	if err != nil {
		return false, fmt.Errorf("error checking balance: %w", err)
	}

	return balance >= amount, nil
}
