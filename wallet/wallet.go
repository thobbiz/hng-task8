package wallet

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"hng-stage8/definitions"
	"hng-stage8/util"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// DepositInWallet initializes a Paystack deposit transaction
// @Summary      Initiate Deposit
// @Description  Creates a payment link for the user to deposit into their wallet
// @Tags         payments
// @Accept       json
// @Produce      json
// @Param        request body PaystackInitRequest true "Payment Request"
// @Success      201  {object}  map[string]any
// @Failure      400  {object}  map[string]string
// @Failure      502  {object}  map[string]string
// @Router       /payments/paystack/initiate [post]
func DepositInWallet(ctx *gin.Context) {
	email, exists := ctx.Get("user_email")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User email not found in context"})
		return
	}
	userEmail := email.(string)

	id, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User id not found in context"})
		return
	}
	userId := id.(string)

	var req definitions.DepositReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Printf("failed to bind request: %v\n", err)
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(err))
		return
	}

	paystackResp, err := callPaystackInitialize(req.Amount, userEmail)
	if err != nil {
		ctx.JSON(http.StatusBadGateway, util.ErrorResponse(err))
		return
	}

	// Get wallet ID
	walletID, err := GetWalletID(definitions.DB, ctx, userId)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to get wallet id for user %s: %v", userId, err)))
		return
	}

	// Create transaction
	err = CreateTransaction(definitions.DB, ctx, "deposit", walletID, req.Amount)
	if err != nil {
		log.Printf("DB Error: %v", err)
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to create transaction: %v", err)))
		return
	}

	ctx.JSON(http.StatusCreated, paystackResp)
}

// PaystackWebHookHandler retrieves a stream of the transaction status
// @Summary      Checks and saves Deposit status
// @Description  Get the current status of a transaction from Paystack
// @Tags         payments
// @Produce      json
// @Success      200  {object}  Transaction
// @Router       /payments/{reference}/status [get]
func PaystackWebHookHandler(ctx *gin.Context) {
	paystackSignature := ctx.GetHeader("x-paystack-signature")
	payloadBytes, err := ctx.GetRawData()
	if err != nil {
		log.Printf("Internal Error reading body: %v", err)
		ctx.Status(http.StatusOK)
		return
	}

	if !verifySignature(payloadBytes, paystackSignature) {
		log.Printf("Security Alert: Invalid signature received: %s", paystackSignature)
		ctx.Status(http.StatusOK)
		return
	}

	var payload definitions.PaystackWebhookPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		log.Printf("Payload Unmarshal Error: %v", err)
		ctx.Status(http.StatusOK)
		return
	}

	if payload.Event == "charge.success" {
		go processChargeSuccess(payload, ctx)
	}

	ctx.Status(http.StatusOK)
}

// VerifyDepositStatus retrieves the transaction status
// @Summary      Check Deposit status
// @Description  Get the current status of a transaction from DB (or Paystack)
// @Tags         payments
// @Produce      json
// @Param        reference path string true "Transaction Reference"
// @Param        refresh query boolean false "Force refresh from Paystack"
// @Success      200  {object}  Transaction
// @Failure      404  {object}  map[string]string
// @Router       /payments/{reference}/status [get]
func VerifyDepositStatus(c *gin.Context) {
	ref := c.Param("reference")

	var tx definitions.Transaction
	query := `SELECT reference, amount, status FROM transactions WHERE reference = ?`
	err := definitions.DB.QueryRow(query, ref).Scan(&tx.Reference, &tx.Amount, &tx.Status)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found"})
		return
	}

	if tx.Status == "pending" {
		realStatus, err := callPaystackVerify(ref)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify transaction status"})
			return
		}

		tx.Status = realStatus
	}

	c.JSON(http.StatusOK, tx)
}

func GetWalletBalance(c *gin.Context) {

}

func processChargeSuccess(payload definitions.PaystackWebhookPayload, ctx *gin.Context) {
	txID, walletID, amount, err := GetTransactionAndWalletIDAndAmount(definitions.DB, ctx, payload.Data.Reference)
	if err != nil {
		log.Printf("Webhook DB Error (GetTx): Ref: %s, Error: %v", payload.Data.Reference, err)
		return
	}

	tx, err := definitions.DB.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("DB Error: Failed to start transaction: %v", err)
		return
	}
	defer tx.Rollback()

	// Update transaction status
	err = UpdateTransactionStatus(tx, ctx, txID, "success")
	if err != nil {
		log.Printf("DB Error: Failed to update transaction status for tx %s: %v", txID, err)
		return
	}

	// Update transaction balance
	err = AddAmountToWallet(tx, ctx, amount, walletID)
	if err != nil {
		log.Printf("CRITICAL DB Error: Failed to add amount to wallet %s for tx %s: %v", walletID, txID, err)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("CRITICAL DB Error: Failed to commit transaction for tx %s: %v", txID, err)
		return
	}

	log.Printf("SUCCESS: Wallet %s credited %.2f for transaction %s", walletID, float64(amount)/100, txID)
}

func WalletAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		jwtErr := tryJWTAuth(ctx)
		if jwtErr == nil {
			ctx.Next()
			return
		}

		apiKeyErr := tryAPIKeyAuth(ctx)
		if apiKeyErr == nil {
			ctx.Next()
			return
		}

		finalError := "Authentication required or credentials invalid."
		if jwtErr != nil && !strings.Contains(jwtErr.Error(), "header missing") {
			finalError = fmt.Sprintf("JWT validation failed: %s", jwtErr.Error())
		} else if apiKeyErr != nil {
			finalError = fmt.Sprintf("API Key validation failed: %s", apiKeyErr.Error())
		}

		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": finalError})
	}
}

func tryJWTAuth(ctx *gin.Context) error {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return fmt.Errorf("Authorization header missing")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method)
		}
		return definitions.JwtSecretKey, nil
	})

	if err != nil {
		return fmt.Errorf("Invalid or expired token: %s", err.Error())
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return fmt.Errorf("Invalid token structure or status")
	}

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return fmt.Errorf("Missing or invalid 'email' claim")
	}
	ctx.Set("user_email", email)

	userID, ok := claims["user_id"].(string)
	fmt.Println(userID)
	if !ok || userID == "" {
		return fmt.Errorf("Missing or invalid 'user_id' claim")
	}
	ctx.Set("user_id", userID)

	return nil
}

func tryAPIKeyAuth(ctx *gin.Context) error {
	apiKey := ctx.GetHeader("X-API-Key")
	if apiKey == "" {
		return fmt.Errorf("X-API-Key header missing")
	}

	var userID string

	err := definitions.DB.QueryRowContext(
		ctx,
		"SELECT * FROM api_key_permissions WHERE api_key_id = ? AND permission_id = ?",
		apiKey,
		"deposit",
	).Scan(&userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("API Key not found")
		}
		// General database error
		return fmt.Errorf("database error checking API key: %w", err)
	}

	ctx.Set(definitions.UserIDKey, userID)

	return nil
}
