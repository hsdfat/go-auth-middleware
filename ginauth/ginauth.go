package ginauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthConfig holds configuration for the authentication middleware
type AuthConfig struct {
	SecretKey       string
	TokenLookup     string // "header:Authorization,query:token,cookie:jwt"
	TokenHeadName   string // "Bearer"
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
}

// GinAuthMiddleware holds the middleware instance
type GinAuthMiddleware struct {
	Config AuthConfig
}

// Claims represents the JWT claims
type Claims struct {
	UserID   interface{} `json:"user_id"`
	Username string      `json:"username"`
	jwt.RegisteredClaims
}

// New creates a new authentication middleware instance
func New(config AuthConfig) *GinAuthMiddleware {
	// Set default values
	if config.Realm == "" {
		config.Realm = "gin auth"
	}
	if config.IdentityKey == "" {
		config.IdentityKey = "identity"
	}
	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization"
	}
	if config.TokenHeadName == "" {
		config.TokenHeadName = "Bearer"
	}
	if config.Timeout == 0 {
		config.Timeout = time.Hour
	}
	if config.MaxRefresh == 0 {
		config.MaxRefresh = time.Hour
	}
	if config.TimeFunc == nil {
		config.TimeFunc = time.Now
	}
	if config.CookieName == "" {
		config.CookieName = "jwt"
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = 86400 // 24 hours
	}

	// Set default handlers
	if config.Unauthorized == nil {
		config.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	if config.LoginResponse == nil {
		config.LoginResponse = func(c *gin.Context, code int, token string, expire time.Time) {
			c.JSON(code, gin.H{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if config.LogoutResponse == nil {
		config.LogoutResponse = func(c *gin.Context, code int) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": "Successfully logged out",
			})
		}
	}

	if config.RefreshResponse == nil {
		config.RefreshResponse = func(c *gin.Context, code int, token string, expire time.Time) {
			c.JSON(code, gin.H{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	return &GinAuthMiddleware{
		Config: config,
	}
}

// MiddlewareFunc returns the Gin middleware function
func (mw *GinAuthMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		mw.middlewareImpl(c)
	})
}

// middlewareImpl implements the middleware logic
func (mw *GinAuthMiddleware) middlewareImpl(c *gin.Context) {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	if mw.Config.IdentityHandler != nil {
		identity := mw.Config.IdentityHandler(c)
		c.Set(mw.Config.IdentityKey, identity)
	}

	if mw.Config.Authorizator != nil && !mw.Config.Authorizator(claims, c) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		return
	}

	c.Next()
}

// GetClaimsFromJWT extracts claims from JWT token
func (mw *GinAuthMiddleware) GetClaimsFromJWT(c *gin.Context) (jwt.MapClaims, error) {
	token, err := mw.parseToken(c)
	if err != nil {
		return nil, err
	}

	if mw.Config.TimeFunc().Unix() > token.Claims.(*Claims).ExpiresAt.Unix() {
		return nil, ErrExpiredToken
	}

	claims := token.Claims.(*Claims)
	c.Set("JWT_PAYLOAD", claims)
	c.Set(mw.Config.IdentityKey, claims.UserID)

	return jwt.MapClaims{
		"user_id":  claims.UserID,
		"username": claims.Username,
		"exp":      claims.ExpiresAt.Unix(),
		"iat":      claims.IssuedAt.Unix(),
	}, nil
}

// parseToken parses the JWT token from the request
func (mw *GinAuthMiddleware) parseToken(c *gin.Context) (*jwt.Token, error) {
	var token string

	methods := strings.Split(mw.Config.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch k {
		case "header":
			token = mw.jwtFromHeader(c, v)
		case "query":
			token = mw.jwtFromQuery(c, v)
		case "cookie":
			token = mw.jwtFromCookie(c, v)
		}
	}

	if token == "" {
		return nil, ErrEmptyAuthorizationHeader
	}

	return jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		return []byte(mw.Config.SecretKey), nil
	})
}

// jwtFromHeader extracts JWT token from header
func (mw *GinAuthMiddleware) jwtFromHeader(c *gin.Context, key string) string {
	authHeader := c.Request.Header.Get(key)
	if authHeader == "" {
		return ""
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != strings.ToLower(mw.Config.TokenHeadName) {
		return ""
	}

	return authHeaderParts[1]
}

// jwtFromQuery extracts JWT token from query parameter
func (mw *GinAuthMiddleware) jwtFromQuery(c *gin.Context, key string) string {
	token := c.Query(key)
	if token == "" {
		return ""
	}
	return token
}

// jwtFromCookie extracts JWT token from cookie
func (mw *GinAuthMiddleware) jwtFromCookie(c *gin.Context, key string) string {
	cookie, _ := c.Cookie(key)
	return cookie
}

// LoginHandler handles user login
func (mw *GinAuthMiddleware) LoginHandler(c *gin.Context) {
	if mw.Config.Authenticator == nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, c))
		return
	}

	data, err := mw.Config.Authenticator(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mw.GetClaimsFunc()(data))
	tokenString, err := token.SignedString([]byte(mw.Config.SecretKey))
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	expire := mw.Config.TimeFunc().Add(mw.Config.Timeout)

	if mw.Config.SendCookie {
		c.SetCookie(
			mw.Config.CookieName,
			tokenString,
			mw.Config.CookieMaxAge,
			"/",
			mw.Config.CookieDomain,
			false,
			mw.Config.CookieHTTPOnly,
		)
	}

	mw.Config.LoginResponse(c, http.StatusOK, tokenString, expire)
}

// LogoutHandler handles user logout
func (mw *GinAuthMiddleware) LogoutHandler(c *gin.Context) {
	if mw.Config.SendCookie {
		c.SetCookie(
			mw.Config.CookieName,
			"",
			-1,
			"/",
			mw.Config.CookieDomain,
			false,
			mw.Config.CookieHTTPOnly,
		)
	}

	mw.Config.LogoutResponse(c, http.StatusOK)
}

// RefreshHandler handles token refresh
func (mw *GinAuthMiddleware) RefreshHandler(c *gin.Context) {
	tokenString, expire, err := mw.RefreshToken(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	if mw.Config.SendCookie {
		c.SetCookie(
			mw.Config.CookieName,
			tokenString,
			mw.Config.CookieMaxAge,
			"/",
			mw.Config.CookieDomain,
			false,
			mw.Config.CookieHTTPOnly,
		)
	}

	mw.Config.RefreshResponse(c, http.StatusOK, tokenString, expire)
}

// RefreshToken refreshes the JWT token
func (mw *GinAuthMiddleware) RefreshToken(c *gin.Context) (string, time.Time, error) {
	token, err := mw.parseToken(c)
	if err != nil {
		return "", time.Time{}, err
	}

	claims := token.Claims.(*Claims)

	origIat := claims.IssuedAt.Unix()
	if origIat < mw.Config.TimeFunc().Add(-mw.Config.MaxRefresh).Unix() {
		return "", time.Time{}, ErrExpiredToken
	}

	// Create a new token with a new expiration time
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		UserID:   claims.UserID,
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(mw.Config.TimeFunc()),
			ExpiresAt: jwt.NewNumericDate(mw.Config.TimeFunc().Add(mw.Config.Timeout)),
		},
	})

	tokenString, err := newToken.SignedString([]byte(mw.Config.SecretKey))
	if err != nil {
		return "", time.Time{}, err
	}

	expire := mw.Config.TimeFunc().Add(mw.Config.Timeout)
	return tokenString, expire, nil
}

// GetClaimsFunc returns the function to extract claims from user data
func (mw *GinAuthMiddleware) GetClaimsFunc() func(interface{}) *Claims {
	return func(data interface{}) *Claims {
		claims := &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(mw.Config.TimeFunc()),
				ExpiresAt: jwt.NewNumericDate(mw.Config.TimeFunc().Add(mw.Config.Timeout)),
			},
		}

		if mw.Config.PayloadFunc != nil {
			payload := mw.Config.PayloadFunc(data)
			if userID, ok := payload["user_id"]; ok {
				claims.UserID = userID
			}
			if username, ok := payload["username"]; ok {
				claims.Username = username.(string)
			}
		}

		return claims
	}
}

// unauthorized handles unauthorized requests
func (mw *GinAuthMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Config.Realm)
	c.Abort()
	mw.Config.Unauthorized(c, code, message)
}

// HTTPStatusMessageFunc returns HTTP status message based on error
func (mw *GinAuthMiddleware) HTTPStatusMessageFunc(err error, c *gin.Context) string {
	switch err {
	case ErrEmptyAuthorizationHeader:
		return "Authorization header is required"
	case ErrInvalidSigningAlgorithm:
		return "Invalid signing algorithm"
	case ErrExpiredToken:
		return "Token is expired"
	case ErrMissingAuthenticatorFunc:
		return "Missing authenticator function"
	case ErrForbidden:
		return "You don't have permission to access this resource"
	default:
		return err.Error()
	}
}

// Error definitions
var (
	ErrEmptyAuthorizationHeader = errors.New("authorization header is empty")
	ErrInvalidSigningAlgorithm  = errors.New("invalid signing algorithm")
	ErrExpiredToken            = errors.New("token is expired")
	ErrMissingAuthenticatorFunc = errors.New("missing authenticator function")
	ErrForbidden               = errors.New("you don't have permission to access this resource")
)

// User represents a user for authentication
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
}

// Helper function to create a basic authenticator
func BasicAuthenticator(users map[string]User) func(*gin.Context) (interface{}, error) {
	return func(c *gin.Context) (interface{}, error) {
		var loginVals struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginVals); err != nil {
			return nil, err
		}

		user, exists := users[loginVals.Username]
		if !exists || user.Password != loginVals.Password {
			return nil, errors.New("invalid username or password")
		}

		return map[string]interface{}{
			"user_id":  user.ID,
			"username": user.Username,
		}, nil
	}
}

// Helper function to create a basic payload function
func BasicPayloadFunc() func(interface{}) jwt.MapClaims {
	return func(data interface{}) jwt.MapClaims {
		if v, ok := data.(map[string]interface{}); ok {
			return jwt.MapClaims{
				"user_id":  v["user_id"],
				"username": v["username"],
			}
		}
		return jwt.MapClaims{}
	}
}

// Helper function to create a basic identity handler
func BasicIdentityHandler() func(*gin.Context) interface{} {
	return func(c *gin.Context) interface{} {
		claims := c.MustGet("JWT_PAYLOAD").(*Claims)
		return map[string]interface{}{
			"user_id":  claims.UserID,
			"username": claims.Username,
		}
	}
}