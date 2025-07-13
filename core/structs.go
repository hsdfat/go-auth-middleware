package core

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents a user for authentication
type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"-"`
	PasswordHash string `json:"-"`
}

type MapUserProvider struct {
	users map[string]User
}

type DatabaseUserProvider struct {
	// Add your database connection or client here
}

type tokenData struct {
	token     string
	expiresAt time.Time
}

type InMemoryTokenStorage struct {
	tokens map[string]tokenData
}

// Claims represents JWT claims
type Claims struct {
	UserID   interface{} `json:"user_id"`
	Username string      `json:"username"`
	jwt.RegisteredClaims
}
