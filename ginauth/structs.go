package ginauth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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
	IdentityHandler func(c *gin.Context) interface{}
	Authenticator   func(c *gin.Context) (interface{}, error)
	Authorizator    func(data interface{}, c *gin.Context) bool
	PayloadFunc     func(data interface{}) jwt.MapClaims
	Unauthorized    func(c *gin.Context, code int, message string)
	LoginResponse   func(c *gin.Context, code int, token string, expire time.Time)
	LogoutResponse  func(c *gin.Context, code int)
	RefreshResponse func(c *gin.Context, code int, token string, expire time.Time)
	TimeFunc        func() time.Time
	Timeout         time.Duration
	MaxRefresh      time.Duration
	SendCookie      bool
	CookieName      string
	CookieMaxAge    int
	CookieDomain    string
	CookieHTTPOnly  bool
	CookieSameSite  http.SameSite
	TokenStorage    TokenStorage
	UseBcrypt       bool
	// Token storage configuration
	EnableTokenStorage     bool   // Whether to use token storage
	TokenStorageMode       string // "jwt", "bcrypt", or "both"
	StoreTokenOnLogin      bool   // Whether to store token on login
	ValidateTokenOnRequest bool   // Whether to validate token from storage on each request
}

type GinAuthMiddleware struct {
	Config AuthConfig
}

type Claims struct {
	UserID   interface{} `json:"user_id"`
	Username string      `json:"username"`
	jwt.RegisteredClaims
}
