package wallet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hng-stage8/definitions"
	"hng-stage8/util"
	"log"
	"net/http"
	"strings"
	"time"

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
	walletID, err := GetWalletIDFromUserID(definitions.DB, ctx, userId)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to get wallet id for user %s: %v", userId, err)))
		return
	}

	// Create transaction
	err = CreateDepositTransaction(definitions.DB, ctx, walletID, req.Amount, paystackResp.Reference)
	if err != nil {
		log.Printf("DB Error: %v", err)
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to create transaction: %v", err)))
		return
	}

	ctx.JSON(http.StatusCreated, paystackResp)
}

func GetWalletBalanceHandler(ctx *gin.Context) {
	id, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User id not found in context"})
		return
	}
	userId := id.(string)

	balance, err := GetWalletBalance(definitions.DB, ctx, userId)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to get wallet balance for user %s: %v", userId, err)))
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"balance": balance})
}

func GetWalletTransactionHistoryHandler(ctx *gin.Context) {
	id, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User id not found in context"})
		return
	}
	userId := id.(string)

	walletID, err := GetWalletIDFromUserID(definitions.DB, ctx, userId)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to get wallet ID for user %s: %v", userId, err)))
		return
	}

	history, err := GetWalletTransactionHistory(definitions.DB, ctx, walletID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to get wallet transaction history for user %s: %v", userId, err)))
		return
	}

	ctx.JSON(http.StatusOK, history)
}

// PaystackWebHookHandler retrieves a stream of the deposit transaction status
// @Summary      Checks and saves deposit status from Paystack
// @Description  Get and saves the current status of a transaction from Paystack
// @Tags         payments
// @Produce      json
// @Success      200  {object}  Transaction
// @Router       /payments/{reference}/status [get]
func PaystackWebHookHandler(ctx *gin.Context) {
	for name, values := range ctx.Request.Header {
		for _, value := range values {
			fmt.Printf("Header: %s = %s\n", name, value)
		}
	}

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
		go processChargeSuccess(payload)
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

	var resp definitions.VerifyStatusResponse
	var tx definitions.Transaction
	query := `SELECT reference, amount, status FROM transactions WHERE reference = ?`
	err := definitions.DB.QueryRow(query, ref).Scan(&tx.Reference, &tx.Amount, &tx.Status)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found"})
		return
	}

	if tx.Status == "pending" {
		realStatus, err := CallPaystackVerify(ref)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify transaction status"})
			return
		}

		tx.Status = realStatus

		resp.Amount = tx.Amount
		resp.Reference = tx.Reference
		resp.Status = realStatus
	}

	c.JSON(http.StatusOK, resp)
}

func TransferBetweenUserHandler(ctx *gin.Context) {
	id, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, util.ErrorResponse(errors.New("User id not found in context")))
		return
	}
	userId := id.(string)

	var req definitions.TransferBetweenUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Printf("failed to bind request: %v\n", err)
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("Failed to bind request: %v", err)))
		return
	}

	userWalletID, err := GetWalletIDFromUserID(definitions.DB, ctx, userId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ctx.JSON(http.StatusNotFound, util.ErrorResponse(errors.New("User wallet not found")))
		} else {
			ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to get user wallet ID: %v", err)))
		}
		return
	}

	receiverWalletID, err := GetWalletIDFromWalletNo(definitions.DB, ctx, req.WalletNo)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ctx.JSON(http.StatusNotFound, util.ErrorResponse(errors.New("Wallet not found")))
		} else {
			ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to get receiver wallet ID: %v", err)))
		}
		return
	}

	// Check If user has sufficient balance
	isSufficient, err := verifyBalanceIsSufficient(definitions.DB, userWalletID, req.Amount)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Could not verify balance: %v", err)))
		return
	}
	if !isSufficient {
		ctx.JSON(http.StatusBadRequest, util.ErrorResponse(fmt.Errorf("Insufficient balance")))
		return
	}

	// Transfer Money between the two users
	err = TransferBetweenUser(definitions.DB, ctx, req.Amount, userWalletID, receiverWalletID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, util.ErrorResponse(fmt.Errorf("Failed to transfer money: %v", err)))
		return
	}
}

func processChargeSuccess(payload definitions.PaystackWebhookPayload) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	txID, walletID, amount, err := GetTransactionAndWalletIDAndAmount(definitions.DB, ctx, payload.Data.Reference)
	if err != nil {
		fmt.Printf("Webhook DB Error (GetTx): Ref: %s, Error: %v\n", payload.Data.Reference, err)
		return
	}

	tx, err := definitions.DB.BeginTx(ctx, nil)
	if err != nil {
		fmt.Printf("DB Error: Failed to start transaction: %v\n", err)
		return
	}
	defer tx.Rollback()

	// Update transaction status
	err = UpdateTransactionStatus(tx, ctx, txID, "success")
	if err != nil {
		fmt.Printf("DB Error: Failed to update transaction status for tx %s: %v\n", txID, err)
		return
	}

	// Update transaction balance
	err = AddAmountToWallet(tx, ctx, amount, walletID)
	if err != nil {
		fmt.Printf("CRITICAL DB Error: Failed to add amount to wallet %s for tx %s: %v\n", walletID, txID, err)
		return
	}

	if err := tx.Commit(); err != nil {
		fmt.Printf("CRITICAL DB Error: Failed to commit transaction for tx %s: %v\n", txID, err)
		return
	}

	fmt.Printf("SUCCESS: Wallet %s credited %.2f for transaction %s\n", walletID, float64(amount)/100, txID)
}

// Middleware for transfer operations
func TransferAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		jwtErr := tryJWTAuth(ctx)
		if jwtErr == nil {
			ctx.Next()
			return
		}

		valid, apiKeyErr := tryAPIKeyAuth(ctx, "perm_transfer")
		if valid && apiKeyErr == nil {
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

// Middleware for read operations
func ReadAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		jwtErr := tryJWTAuth(ctx)
		if jwtErr == nil {
			ctx.Next()
			return
		}

		valid, apiKeyErr := tryAPIKeyAuth(ctx, "perm_read")
		if valid && apiKeyErr == nil {
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

// Middleware for deposit operations
func DepositAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		jwtErr := tryJWTAuth(ctx)
		if jwtErr == nil {
			ctx.Next()
			return
		}

		valid, apiKeyErr := tryAPIKeyAuth(ctx, "perm_deposit")
		if valid && apiKeyErr == nil {
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

// Checks if jwt from header is valid
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

// Checks if Api key from header is valid and has the right permissions
func tryAPIKeyAuth(ctx *gin.Context, permissionID string) (bool, error) {
	apiKey := ctx.GetHeader("X-API-Key")
	if apiKey == "" {
		return false, fmt.Errorf("X-API-Key header missing")
	}

	query := `
        SELECT u.email, u.id
        FROM users u
        INNER JOIN api_keys ak ON u.id = ak.user_id
        INNER JOIN api_key_permissions akp ON ak.id = akp.api_key_id
        WHERE ak.id = ? AND akp.permission_id = ?
    `

	var userEmail, userID string
	err := definitions.DB.QueryRow(query, apiKey, permissionID).Scan(&userEmail, &userID)

	if err == sql.ErrNoRows {
		return false, fmt.Errorf("Invalid API key or missing permission")
	}
	if err != nil {
		return false, err // Database error
	}

	ctx.Set(definitions.UserEmailKey, userEmail)
	ctx.Set(definitions.UserIDKey, userID)

	return true, nil
}
