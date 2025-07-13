package fiberauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// NewFiberAuthMiddleware creates a new FiberAuthMiddleware instance
func NewFiberAuthMiddleware(config AuthConfig) *FiberAuthMiddleware {
	if config.TimeFunc == nil {
		config.TimeFunc = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = time.Hour
	}
	if config.MaxRefresh == 0 {
		config.MaxRefresh = time.Hour * 24
	}
	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization"
	}
	if config.TokenHeadName == "" {
		config.TokenHeadName = "Bearer"
	}
	if config.Realm == "" {
		config.Realm = "jwt auth"
	}
	if config.IdentityKey == "" {
		config.IdentityKey = "identity"
	}
	if config.IdentityHandler == nil {
		config.IdentityHandler = func(c *fiber.Ctx) interface{} {
			claims := c.Locals("JWT_PAYLOAD")
			if claims == nil {
				return nil
			}
			if mapClaims, ok := claims.(jwt.MapClaims); ok {
				if userID, exists := mapClaims["user_id"]; exists {
					return userID
				}
			}
			return nil
		}
	}
	if config.PayloadFunc == nil {
		config.PayloadFunc = func(data interface{}) jwt.MapClaims {
			if mapClaims, ok := data.(jwt.MapClaims); ok {
				return mapClaims
			}
			return jwt.MapClaims{}
		}
	}
	if config.Unauthorized == nil {
		config.Unauthorized = func(c *fiber.Ctx, code int, message string) {
			c.Status(code).JSON(fiber.Map{
				"code":    code,
				"message": message,
			})
		}
	}
	if config.LoginResponse == nil {
		config.LoginResponse = func(c *fiber.Ctx, code int, token string, expire time.Time) {
			c.Status(code).JSON(fiber.Map{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}
	if config.LogoutResponse == nil {
		config.LogoutResponse = func(c *fiber.Ctx, code int) {
			c.Status(code).JSON(fiber.Map{
				"code":    code,
				"message": "Successfully logged out",
			})
		}
	}
	if config.RefreshResponse == nil {
		config.RefreshResponse = func(c *fiber.Ctx, code int, token string, expire time.Time) {
			c.Status(code).JSON(fiber.Map{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	return &FiberAuthMiddleware{
		Config: config,
	}
}

// MiddlewareFunc returns the middleware function
func (m *FiberAuthMiddleware) MiddlewareFunc() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse token
		token, err := m.parseToken(c)
		if err != nil {
			m.Config.Unauthorized(c, http.StatusUnauthorized, err.Error())
			return nil
		}

		// Validate token
		if m.Config.ValidateTokenOnRequest && m.Config.TokenStorage != nil {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				m.Config.Unauthorized(c, http.StatusUnauthorized, "Invalid token claims")
				return nil
			}

			tokenID, ok := claims["jti"].(string)
			if !ok {
				m.Config.Unauthorized(c, http.StatusUnauthorized, "Missing token ID")
				return nil
			}

			// Check if token is stored and valid
			isValid, err := m.Config.TokenStorage.IsTokenValid(tokenID)
			if err != nil || !isValid {
				m.Config.Unauthorized(c, http.StatusUnauthorized, "Token not found or invalid")
				return nil
			}

			// If using bcrypt mode, validate the stored hash
			if m.Config.TokenStorageMode == "bcrypt" || m.Config.TokenStorageMode == "both" {
				storedToken, err := m.Config.TokenStorage.GetToken(tokenID)
				if err != nil {
					m.Config.Unauthorized(c, http.StatusUnauthorized, "Token not found in storage")
					return nil
				}

				// Extract the actual token string from the JWT
				tokenString := c.Get("Authorization")
				if tokenString == "" {
					m.Config.Unauthorized(c, http.StatusUnauthorized, "Missing authorization header")
					return nil
				}
				tokenString = strings.TrimPrefix(tokenString, "Bearer ")

				if !CheckTokenHash(tokenString, storedToken) {
					m.Config.Unauthorized(c, http.StatusUnauthorized, "Token hash validation failed")
					return nil
				}
			}
		}

		// Set claims in context
		c.Locals("JWT_PAYLOAD", token.Claims)
		c.Locals("JWT_TOKEN", token)

		// Check authorization
		if m.Config.Authorizator != nil {
			identity := m.Config.IdentityHandler(c)
			if !m.Config.Authorizator(identity, c) {
				m.Config.Unauthorized(c, http.StatusForbidden, "You don't have permission to access this resource")
				return nil
			}
		}

		return c.Next()
	}
}

// LoginHandler handles user login
func (m *FiberAuthMiddleware) LoginHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m.Config.Authenticator == nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Missing authenticator")
			return nil
		}

		data, err := m.Config.Authenticator(c)
		if err != nil {
			m.Config.Unauthorized(c, http.StatusUnauthorized, err.Error())
			return nil
		}

		// Generate token
		token := jwt.New(jwt.GetSigningMethod("HS256"))
		now := m.Config.TimeFunc()
		expire := now.Add(m.Config.Timeout)

		// Generate unique token ID
		tokenID, err := generateTokenID()
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to generate token ID")
			return nil
		}

		// Set claims
		claims := m.Config.PayloadFunc(data)
		claims["jti"] = tokenID
		claims["exp"] = expire.Unix()
		claims["orig_iat"] = now.Unix()
		token.Claims = claims

		// Sign token
		tokenString, err := token.SignedString([]byte(m.Config.SecretKey))
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to sign token")
			return nil
		}

		// Store token if enabled
		if m.Config.EnableTokenStorage && m.Config.StoreTokenOnLogin && m.Config.TokenStorage != nil {
			var tokenToStore string
			if m.Config.TokenStorageMode == "bcrypt" || m.Config.TokenStorageMode == "both" {
				// Hash the token for storage
				hashedToken, err := HashToken(tokenString)
				if err != nil {
					m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to hash token")
					return nil
				}
				tokenToStore = hashedToken
			} else {
				tokenToStore = tokenString
			}

			err = m.Config.TokenStorage.StoreToken(tokenID, tokenToStore, expire)
			if err != nil {
				m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to store token")
				return nil
			}
		}

		// Set cookie if enabled
		if m.Config.SendCookie {
			c.Cookie(&fiber.Cookie{
				Name:     m.Config.CookieName,
				Value:    tokenString,
				MaxAge:   m.Config.CookieMaxAge,
				Path:     "/",
				Domain:   m.Config.CookieDomain,
				HTTPOnly: m.Config.CookieHTTPOnly,
				SameSite: m.Config.CookieSameSite,
			})
		}

		m.Config.LoginResponse(c, http.StatusOK, tokenString, expire)
		return nil
	}
}

// LogoutHandler handles user logout
func (m *FiberAuthMiddleware) LogoutHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get token from context
		token := c.Locals("JWT_TOKEN")
		if token == nil {
			m.Config.LogoutResponse(c, http.StatusOK)
			return nil
		}

		// Extract token ID and revoke from storage
		if m.Config.TokenStorage != nil {
			if jwtToken, ok := token.(*jwt.Token); ok {
				if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
					if tokenID, ok := claims["jti"].(string); ok {
						m.Config.TokenStorage.DeleteToken(tokenID)
					}
				}
			}
		}

		// Clear cookie if enabled
		if m.Config.SendCookie {
			c.Cookie(&fiber.Cookie{
				Name:     m.Config.CookieName,
				Value:    "",
				MaxAge:   -1,
				Path:     "/",
				Domain:   m.Config.CookieDomain,
				HTTPOnly: m.Config.CookieHTTPOnly,
				SameSite: m.Config.CookieSameSite,
			})
		}

		m.Config.LogoutResponse(c, http.StatusOK)
		return nil
	}
}

// RefreshHandler handles token refresh
func (m *FiberAuthMiddleware) RefreshHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get token from context
		token := c.Locals("JWT_TOKEN")
		if token == nil {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Missing token")
			return nil
		}

		jwtToken, ok := token.(*jwt.Token)
		if !ok {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Invalid token")
			return nil
		}

		claims, ok := jwtToken.Claims.(jwt.MapClaims)
		if !ok {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Invalid token claims")
			return nil
		}

		// Check if token can be refreshed
		origIat := int64(claims["orig_iat"].(float64))
		if origIat < m.Config.TimeFunc().Add(-m.Config.MaxRefresh).Unix() {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Token refresh period expired")
			return nil
		}

		// Generate new token
		newToken := jwt.New(jwt.GetSigningMethod("HS256"))
		now := m.Config.TimeFunc()
		expire := now.Add(m.Config.Timeout)

		// Generate new token ID
		newTokenID, err := generateTokenID()
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to generate token ID")
			return nil
		}

		// Set new claims
		newClaims := jwt.MapClaims{}
		for key, value := range claims {
			if key != "jti" && key != "exp" && key != "orig_iat" {
				newClaims[key] = value
			}
		}
		newClaims["jti"] = newTokenID
		newClaims["exp"] = expire.Unix()
		newClaims["orig_iat"] = now.Unix()
		newToken.Claims = newClaims

		// Sign new token
		newTokenString, err := newToken.SignedString([]byte(m.Config.SecretKey))
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to sign token")
			return nil
		}

		// Update token storage
		if m.Config.TokenStorage != nil {
			oldTokenID := claims["jti"].(string)
			m.Config.TokenStorage.DeleteToken(oldTokenID)

			if m.Config.EnableTokenStorage {
				var tokenToStore string
				if m.Config.TokenStorageMode == "bcrypt" || m.Config.TokenStorageMode == "both" {
					hashedToken, err := HashToken(newTokenString)
					if err != nil {
						m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to hash token")
						return nil
					}
					tokenToStore = hashedToken
				} else {
					tokenToStore = newTokenString
				}

				err = m.Config.TokenStorage.StoreToken(newTokenID, tokenToStore, expire)
				if err != nil {
					m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to store token")
					return nil
				}
			}
		}

		// Update cookie if enabled
		if m.Config.SendCookie {
			c.Cookie(&fiber.Cookie{
				Name:     m.Config.CookieName,
				Value:    newTokenString,
				MaxAge:   m.Config.CookieMaxAge,
				Path:     "/",
				Domain:   m.Config.CookieDomain,
				HTTPOnly: m.Config.CookieHTTPOnly,
				SameSite: m.Config.CookieSameSite,
			})
		}

		m.Config.RefreshResponse(c, http.StatusOK, newTokenString, expire)
		return nil
	}
}

// parseToken extracts and validates the JWT token from the request
func (m *FiberAuthMiddleware) parseToken(c *fiber.Ctx) (*jwt.Token, error) {
	var tokenString string

	// Parse token from different sources
	parts := strings.Split(m.Config.TokenLookup, ":")
	switch parts[0] {
	case "header":
		tokenString = c.Get(parts[1])
		if tokenString != "" && m.Config.TokenHeadName != "" {
			tokenString = strings.TrimPrefix(tokenString, m.Config.TokenHeadName+" ")
		}
	case "query":
		tokenString = c.Query(parts[1])
	case "cookie":
		tokenString = c.Cookies(parts[1])
	case "param":
		tokenString = c.Params(parts[1])
	}

	if tokenString == "" {
		return nil, fmt.Errorf("token not found")
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.Config.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

// generateTokenID generates a unique token ID
func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// NewMapUserProvider creates a new MapUserProvider
func NewMapUserProvider(users map[string]User) *MapUserProvider {
	return core.NewMapUserProvider(users)
}

// NewInMemoryTokenStorage creates a new InMemoryTokenStorage
func NewInMemoryTokenStorage() *InMemoryTokenStorage {
	return core.NewInMemoryTokenStorage()
}
