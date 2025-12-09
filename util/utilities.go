package util

import (
	"errors"
	"fmt"
	"hng-stage8/definitions"
	"time"

	"github.com/gin-gonic/gin"
)

func ErrorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}

func ConvertRFC3339ToTime(RFC3339 string) (time.Time, error) {
	return time.Parse(time.RFC3339, RFC3339)
}

func CheckIfTimeIsExpired(expiryTime time.Time) bool {
	return time.Now().After(expiryTime)
}

func ValidateExpiry(expiry string) (*definitions.ExpiryDate, error) {
	exp := definitions.ExpiryDate(expiry)

	if !definitions.ValidExpiry[exp] {
		return nil, errors.New("invalid expiry")
	}

	return &exp, nil
}

func GetExpiredTime(currentTime time.Time, expiry definitions.ExpiryDate) (string, bool) {
	duration, ok := definitions.ExpiryTime[expiry]
	if !ok {
		return "", false
	}

	expiryTime := currentTime.Add(duration)
	return expiryTime.Format(time.RFC3339), true
}

func GetPermissionID(perm definitions.Permission) (string, bool) {
	permissionID, ok := definitions.PermissionKeys[perm]
	if !ok {
		return "", false
	}

	return permissionID, true
}

func ValidatePermissions(perm []string) error {
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
