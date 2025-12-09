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

type ApiKey struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Expiry      string   `json:"expiry"`
}

type ApiKeyResponse struct {
	ApiKey string `json:"api_key"`
	Expiry string `json:"expires_at"`
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
