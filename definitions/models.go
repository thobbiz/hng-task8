package definitions

import (
	"database/sql"
	"os"
	"time"

	"golang.org/x/oauth2"
)

type Permission string

type ExpiryDate string

const (
	PaystackBaseURL = "https://api.paystack.co"
	MaxKeysPerUser  = 5

	UserIDKey    = "user_id"
	UserEmailKey = "user_email"

	PermissionDeposit  Permission = "deposit"
	PermissionTransfer Permission = "transfer"
	PermissionRead     Permission = "read"

	ExpireHour  ExpiryDate = "1H"
	ExpireDay   ExpiryDate = "1D"
	ExpireMonth ExpiryDate = "1M"
	ExpireYear  ExpiryDate = "1Y"
)

var (
	GoogleOAuthConfig *oauth2.Config
	OauthStateString  = "randomStateString"
	PaystackSecretKey string
	JwtSecretKey      = []byte(os.Getenv("JWT_SECRET_KEY"))
	DB                *sql.DB
)

var ValidPermissions = map[Permission]bool{
	PermissionDeposit:  true,
	PermissionTransfer: true,
	PermissionRead:     true,
}

var PermissionKeys = map[Permission]string{
	PermissionDeposit:  "perm_deposit",
	PermissionTransfer: "perm_transfer",
	PermissionRead:     "perm_read",
}

var ExpiryTime = map[ExpiryDate]time.Duration{
	ExpireHour:  time.Hour,
	ExpireDay:   24 * time.Hour,
	ExpireMonth: 30 * 24 * time.Hour,
	ExpireYear:  365 * 24 * time.Hour,
}

var ValidExpiry = map[ExpiryDate]bool{
	ExpireHour:  true,
	ExpireDay:   true,
	ExpireMonth: true,
	ExpireYear:  true,
}

// TransferBetweenUserRequest represents a transfer request between users
// @Description Request body for transferring funds between user wallets
type TransferBetweenUserRequest struct {
	WalletNo string `json:"wallet_number" binding:"required" example:"1234567890"`
	Amount   int64  `json:"amount" binding:"required" example:"5000"`
}

// TransactionHistory represents a wallet transaction record
// @Description Transaction history entry for a wallet
type TransactionHistory struct {
	Type   string `json:"type" example:"deposit"`
	Amount int64  `json:"amount" example:"10000"`
	Status string `json:"status" example:"success"`
}

// VerifyStatusResponse represents the payment verification response
// @Description Response containing payment verification status
type VerifyStatusResponse struct {
	Reference string `json:"reference" example:"txn_ref_123456"`
	Status    string `json:"status" example:"success"`
	Amount    int64  `json:"amount" example:"10000"`
}

// PaystackInitResponse represents the Paystack initialization response
// @Description Response containing Paystack payment authorization details
type PaystackInitResponse struct {
	AuthorizationURL string `json:"authorization_url" example:"https://checkout.paystack.com/abc123"`
	Reference        string `json:"reference" example:"txn_ref_123456"`
}

type Transaction struct {
	ID        string `json:"id"`
	WalletID  string `json:"user_id"`
	Reference string `json:"reference"`
	Amount    int64  `json:"amount"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// PaystackInitRequest represents a payment initialization request in Kobo
// @Description Request body for initializing a Paystack payment
type PaystackInitRequest struct {
	Amount int64 `json:"amount" binding:"required,gt=0" example:"10000"`
}

// PaystackWebhookPayload represents the Paystack webhook event payload
// @Description Webhook payload sent by Paystack for payment events
type PaystackWebhookPayload struct {
	Event string `json:"event" example:"charge.success"`
	Data  struct {
		Reference string `json:"reference" example:"txn_ref_123456"`
		Status    string `json:"status" example:"success"`
		Amount    int64  `json:"amount" example:"10000"`
	} `json:"data"`
}

// ApiKey represents an API key creation request
// @Description Request body for creating a new API key
type ApiKey struct {
	Name            string   `json:"name" binding:"required" example:"Production API Key"`
	Permissions     []string `json:"permissions" binding:"required" example:"deposit,transfer"`
	ExpiryTimeFrame string   `json:"expiry" binding:"required" example:"1y"`
}

// ApiKeyResponse represents the API key creation response
// @Description Response containing the generated API key and expiry details
type ApiKeyResponse struct {
	ApiKey string `json:"api_key" example:"sk_live_abc123def456"`
	Expiry string `json:"expires_at" example:"2025-12-10T15:30:00Z"`
}

// DepositReq represents a deposit request
// @Description Request body for deposit operations
type DepositReq struct {
	Amount int64 `json:"amount" binding:"required,gt=0" example:"5000"`
}

// RolloverApiReq represents an API key rollover request
// @Description Request body for rolling over an expired API key
type RolloverApiReq struct {
	ExpiredKeyID    string `json:"expired_key_id" binding:"required" example:"key_abc123"`
	ExpiryTimeFrame string `json:"expiry" binding:"required" example:"6m"`
}

type GoogleUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// User represents a user in the system
// @Description User account information
type User struct {
	ID    string `json:"user_id" example:"usr_abc123def456"`
	Email string `json:"email" example:"user@example.com"`
	Name  string `json:"name" example:"John Doe"`
}
