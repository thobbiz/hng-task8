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

var (
	GoogleOAuthConfig *oauth2.Config
	OauthStateString  = "randomStateString"
	PaystackSecretKey string
	JwtSecretKey      = []byte(os.Getenv("JWT_SECRET_KEY"))
	DB                *sql.DB
)

type TransferBetweenUserRequest struct {
	WalletNo string `json:"wallet_number" binding:"required"`
	Amount   int64  `json:"amount" binding:"required"`
}

type TransactionHistory struct {
	Type   string `json:"type"`
	Amount int64  `json:"amount"`
	Status string `json:"status"`
}

type VerifyStatusResponse struct {
	Reference string `json:"reference"`
	Status    string `json:"status"`
	Amount    int64  `json:"amount"`
}

type PaystackInitResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	Reference        string `json:"reference"`
}

type Transaction struct {
	ID        string `json:"id"`
	WalletID  string `json:"user_id"`
	Reference string `json:"reference"`
	Amount    int64  `json:"amount"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type PaystackInitRequest struct {
	Amount int64 `json:"amount" binding:"required,gt=0"`
}

type PaystackWebhookPayload struct {
	Event string `json:"event"`
	Data  struct {
		Reference string `json:"reference"`
		Status    string `json:"status"`
		Amount    int64  `json:"amount"`
	} `json:"data"`
}

type ApiKey struct {
	Name            string   `json:"name"`
	Permissions     []string `json:"permissions"`
	ExpiryTimeFrame string   `json:"expiry"`
}

type ApiKeyResponse struct {
	ApiKey string `json:"api_key"`
	Expiry string `json:"expires_at"`
}

type DepositReq struct {
	Amount int64 `json:"amount"`
}

type RolloverApiReq struct {
	ExpiredKeyID    string `json:"expired_key_id"`
	ExpiryTimeFrame string `json:"expiry"`
}

type GoogleUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type User struct {
	ID    string `json:"user_id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}
