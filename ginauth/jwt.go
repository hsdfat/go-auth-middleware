package ginauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Error definitions
var (
	ErrEmptyAuthorizationHeader = errors.New("authorization header is empty")
	ErrInvalidSigningAlgorithm  = errors.New("invalid signing algorithm")
	ErrExpiredToken             = errors.New("token is expired")
	ErrMissingAuthenticatorFunc = errors.New("missing authenticator function")
	ErrForbidden                = errors.New("you don't have permission to access this resource")
)

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

	// Set default token storage if not provided
	if config.TokenStorage == nil {
		config.TokenStorage = NewInMemoryTokenStorage()
	}

	// Set default token storage configuration
	if config.TokenStorageMode == "" {
		config.TokenStorageMode = "jwt" // Default to JWT mode
	}
	if !config.EnableTokenStorage {
		config.EnableTokenStorage = true // Default to enabled
	}
	if !config.StoreTokenOnLogin {
		config.StoreTokenOnLogin = true // Default to storing tokens on login
	}
	if !config.ValidateTokenOnRequest {
		config.ValidateTokenOnRequest = true // Default to validating tokens on requests
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

// NewInMemoryTokenStorage creates a new in-memory token storage
func NewInMemoryTokenStorage() *InMemoryTokenStorage {
	return &InMemoryTokenStorage{
		tokens: make(map[string]tokenData),
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

	// Check token storage if enabled and configured
	if mw.Config.EnableTokenStorage && mw.Config.ValidateTokenOnRequest && mw.Config.TokenStorage != nil {
		// Extract token from request
		tokenString := mw.extractTokenString(c)
		if tokenString != "" {
			// Generate token ID to check in storage
			tokenID := generateTokenID(map[string]interface{}{
				"user_id":  claims["user_id"],
				"username": claims["username"],
			})

			// Check if token is valid in storage
			if valid, err := mw.Config.TokenStorage.IsTokenValid(tokenID); err != nil || !valid {
				mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
				return
			}

			// Additional validation based on storage mode
			if storedToken, err := mw.Config.TokenStorage.GetToken(tokenID); err == nil {
				switch mw.Config.TokenStorageMode {
				case "bcrypt":
					// For bcrypt mode, verify the token hash
					if mw.Config.UseBcrypt {
						if !CheckPasswordHash(tokenString, storedToken) {
							mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
							return
						}
					}
				case "both":
					// For both mode, check if stored token contains the current token
					if mw.Config.UseBcrypt {
						parts := strings.Split(storedToken, ":")
						if len(parts) == 2 {
							// Check JWT part
							if parts[0] != tokenString {
								mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
								return
							}
							// Check bcrypt hash part
							if !CheckPasswordHash(tokenString, parts[1]) {
								mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
								return
							}
						}
					}
				}
			}
		}
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

// extractTokenString extracts the token string from the request
func (mw *GinAuthMiddleware) extractTokenString(c *gin.Context) string {
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

	return token
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

	// Store token in storage based on configuration
	if mw.Config.EnableTokenStorage && mw.Config.StoreTokenOnLogin && mw.Config.TokenStorage != nil {
		// Generate a unique token ID
		tokenID := generateTokenID(data)

		// Determine what to store based on TokenStorageMode
		var tokenToStore string
		switch mw.Config.TokenStorageMode {
		case "jwt":
			tokenToStore = tokenString
		case "bcrypt":
			// For bcrypt mode, we could store a hash of the token
			if mw.Config.UseBcrypt {
				hashedToken, hashErr := HashPassword(tokenString)
				if hashErr != nil {
					mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
					return
				}
				tokenToStore = hashedToken
			} else {
				tokenToStore = tokenString
			}
		case "both":
			// Store both JWT and bcrypt hash
			if mw.Config.UseBcrypt {
				hashedToken, hashErr := HashPassword(tokenString)
				if hashErr != nil {
					mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
					return
				}
				tokenToStore = tokenString + ":" + hashedToken
			} else {
				tokenToStore = tokenString
			}
		default:
			tokenToStore = tokenString
		}

		err = mw.Config.TokenStorage.StoreToken(tokenID, tokenToStore, expire)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
			return
		}
		// Store token ID in context for later use
		c.Set("token_id", tokenID)
		c.Set("token_storage_mode", mw.Config.TokenStorageMode)
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

	mw.Config.LoginResponse(c, http.StatusOK, tokenString, expire)
}

// LogoutHandler handles user logout
func (mw *GinAuthMiddleware) LogoutHandler(c *gin.Context) {
	// Handle token storage cleanup based on configuration
	if mw.Config.EnableTokenStorage && mw.Config.TokenStorage != nil {
		// Get token ID from context if available
		if tokenID, exists := c.Get("token_id"); exists {
			if tokenIDStr, ok := tokenID.(string); ok {
				// Delete the specific token
				mw.Config.TokenStorage.DeleteToken(tokenIDStr)
			}
		}

		// Revoke all tokens for the current user if available
		if claims, exists := c.Get("JWT_PAYLOAD"); exists {
			if jwtClaims, ok := claims.(*Claims); ok {
				mw.Config.TokenStorage.RevokeAllUserTokens(jwtClaims.UserID)
			}
		}
	}

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

	// Store new token in storage based on configuration
	if mw.Config.EnableTokenStorage && mw.Config.StoreTokenOnLogin && mw.Config.TokenStorage != nil {
		// Get user data from existing claims
		if claims, exists := c.Get("JWT_PAYLOAD"); exists {
			if jwtClaims, ok := claims.(*Claims); ok {
				tokenID := generateTokenID(map[string]interface{}{
					"user_id":  jwtClaims.UserID,
					"username": jwtClaims.Username,
				})

				// Determine what to store based on TokenStorageMode
				var tokenToStore string
				switch mw.Config.TokenStorageMode {
				case "jwt":
					tokenToStore = tokenString
				case "bcrypt":
					if mw.Config.UseBcrypt {
						hashedToken, hashErr := HashPassword(tokenString)
						if hashErr != nil {
							mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
							return
						}
						tokenToStore = hashedToken
					} else {
						tokenToStore = tokenString
					}
				case "both":
					if mw.Config.UseBcrypt {
						hashedToken, hashErr := HashPassword(tokenString)
						if hashErr != nil {
							mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
							return
						}
						tokenToStore = tokenString + ":" + hashedToken
					} else {
						tokenToStore = tokenString
					}
				default:
					tokenToStore = tokenString
				}

				err = mw.Config.TokenStorage.StoreToken(tokenID, tokenToStore, expire)
				if err != nil {
					mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
					return
				}
				c.Set("token_id", tokenID)
				c.Set("token_storage_mode", mw.Config.TokenStorageMode)
			}
		}
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

// generateTokenID creates a simple token ID from user data
// In production, you might want to use a proper UUID library
func generateTokenID(data interface{}) string {
	if userData, ok := data.(map[string]interface{}); ok {
		if userID, exists := userData["user_id"]; exists {
			return fmt.Sprintf("token_%v_%d", userID, time.Now().Unix())
		}
	}
	return fmt.Sprintf("token_%d", time.Now().UnixNano())
}

// InMemoryTokenStorage methods
func (s *InMemoryTokenStorage) StoreToken(tokenID string, token string, expiresAt time.Time) error {
	s.tokens[tokenID] = tokenData{token: token, expiresAt: expiresAt}
	return nil
}

func (s *InMemoryTokenStorage) GetToken(tokenID string) (string, error) {
	if tokenData, exists := s.tokens[tokenID]; exists {
		if time.Now().Before(tokenData.expiresAt) {
			return tokenData.token, nil
		}
		// Token expired, remove it
		delete(s.tokens, tokenID)
	}
	return "", errors.New("token not found or expired")
}

func (s *InMemoryTokenStorage) DeleteToken(tokenID string) error {
	delete(s.tokens, tokenID)
	return nil
}

func (s *InMemoryTokenStorage) IsTokenValid(tokenID string) (bool, error) {
	if tokenData, exists := s.tokens[tokenID]; exists {
		return time.Now().Before(tokenData.expiresAt), nil
	}
	return false, nil
}

func (s *InMemoryTokenStorage) RevokeAllUserTokens(userID interface{}) error {
	// In a real implementation, you would need to maintain a mapping of userID to tokenIDs
	// For simplicity, this implementation clears all tokens
	s.tokens = make(map[string]tokenData)
	return nil
}
