package fiberauth

import (
	"time"

	"github.com/gofiber/fiber/v2"
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

// AuthConfig holds configuration for the authentication middleware
type AuthConfig struct {
	SecretKey       string
	TokenLookup     string
	TokenHeadName   string
	Realm           string
	IdentityKey     string
	IdentityHandler func(c *fiber.Ctx) interface{}
	Authenticator   func(c *fiber.Ctx) (interface{}, error)
	Authorizator    func(data interface{}, c *fiber.Ctx) bool
	PayloadFunc     func(data interface{}) jwt.MapClaims
	Unauthorized    func(c *fiber.Ctx, code int, message string)
	LoginResponse   func(c *fiber.Ctx, code int, token string, expire time.Time)
	LogoutResponse  func(c *fiber.Ctx, code int)
	RefreshResponse func(c *fiber.Ctx, code int, token string, expire time.Time)
	TimeFunc        func() time.Time
	Timeout         time.Duration
	MaxRefresh      time.Duration
	SendCookie      bool
	CookieName      string
	CookieMaxAge    int
	CookieDomain    string
	CookieHTTPOnly  bool
	CookieSameSite  string
	TokenStorage    TokenStorage
	UseBcrypt       bool
	// Token storage configuration
	EnableTokenStorage     bool   // Whether to use token storage
	TokenStorageMode       string // "jwt", "bcrypt", or "both"
	StoreTokenOnLogin      bool   // Whether to store token on login
	ValidateTokenOnRequest bool   // Whether to validate token from storage on each request
}

type FiberAuthMiddleware struct {
	Config AuthConfig
}

type Claims struct {
	UserID   interface{} `json:"user_id"`
	Username string      `json:"username"`
	jwt.RegisteredClaims
}
