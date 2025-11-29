package ginauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// Enhanced error definitions
var (
	ErrEmptyAuthorizationHeader = errors.New("authorization header is empty")
	ErrInvalidSigningAlgorithm  = errors.New("invalid signing algorithm")
	ErrExpiredToken             = errors.New("token is expired")
	ErrMissingAuthenticatorFunc = errors.New("missing authenticator function")
	ErrForbidden                = errors.New("you don't have permission to access this resource")
	ErrInvalidRefreshToken      = errors.New("invalid refresh token")
	ErrInactiveUser             = errors.New("user account is inactive")
	ErrSessionNotFound          = errors.New("session not found")
)

// Enhanced GinAuthMiddleware with refresh token support
type EnhancedGinAuthMiddleware struct {
	Config EnhancedAuthConfig
}

// NewEnhanced creates a new enhanced authentication middleware instance
func NewEnhanced(config EnhancedAuthConfig) *EnhancedGinAuthMiddleware {
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
	if config.AccessTokenTimeout == 0 {
		config.AccessTokenTimeout = 15 * time.Minute // Short-lived access tokens
	}
	if config.RefreshTokenTimeout == 0 {
		config.RefreshTokenTimeout = 7 * 24 * time.Hour // 7 days
	}
	if config.TimeFunc == nil {
		config.TimeFunc = time.Now
	}
	if config.CookieName == "" {
		config.CookieName = "jwt"
	}
	if config.RefreshCookieName == "" {
		config.RefreshCookieName = "refresh_jwt"
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = int(config.RefreshTokenTimeout.Seconds())
	}

	// Set default token storage if not provided
	if config.TokenStorage == nil {
		config.TokenStorage = core.NewInMemoryTokenStorage()
	}

	// Set default handlers
	if config.Unauthorized == nil {
		config.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"error":   true,
				"code":    code,
				"message": message,
			})
		}
	}

	if config.LoginResponse == nil {
		config.LoginResponse = func(c *gin.Context, code int, tokenPair core.TokenPair, user *core.User) {
			c.JSON(code, gin.H{
				"success": true,
				"code":    code,
				"data": gin.H{
					"access_token":             tokenPair.AccessToken,
					"refresh_token":            tokenPair.RefreshToken,
					"access_token_expires_at":  tokenPair.AccessTokenExpiresAt.Unix(),
					"refresh_token_expires_at": tokenPair.RefreshTokenExpiresAt.Unix(),
					"token_type":               tokenPair.TokenType,
					"user": gin.H{
						"id":       user.ID,
						"username": user.Username,
						"email":    user.Email,
						"role":     user.Role,
					},
				},
			})
		}
	}

	if config.LogoutResponse == nil {
		config.LogoutResponse = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"success": true,
				"code":    code,
				"message": message,
			})
		}
	}

	if config.RefreshResponse == nil {
		config.RefreshResponse = func(c *gin.Context, code int, tokenPair core.TokenPair) {
			c.JSON(code, gin.H{
				"success": true,
				"code":    code,
				"data": gin.H{
					"access_token":             tokenPair.AccessToken,
					"refresh_token":            tokenPair.RefreshToken,
					"access_token_expires_at":  tokenPair.AccessTokenExpiresAt.Unix(),
					"refresh_token_expires_at": tokenPair.RefreshTokenExpiresAt.Unix(),
					"token_type":               tokenPair.TokenType,
				},
			})
		}
	}

	if config.RegisterResponse == nil {
		config.RegisterResponse = func(c *gin.Context, code int, user *core.User) {
			c.JSON(code, gin.H{
				"success": true,
				"code":    code,
				"message": "User registered successfully",
				"data": gin.H{
					"user_id":    user.ID,
					"username":   user.Username,
					"email":      user.Email,
					"role":       user.Role,
					"created_at": user.CreatedAt.Unix(),
				},
			})
		}
	}

	// Set default role for registrations
	if config.DefaultRole == "" {
		config.DefaultRole = "user"
	}

	return &EnhancedGinAuthMiddleware{
		Config: config,
	}
}

// MiddlewareFunc returns the enhanced Gin middleware function
func (mw *EnhancedGinAuthMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		mw.middlewareImpl(c)
	})
}

// middlewareImpl implements the enhanced middleware logic
func (mw *EnhancedGinAuthMiddleware) middlewareImpl(c *gin.Context) {
	claims, sessionID, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}
	// Validate session and token storage
	if mw.Config.TokenStorage != nil {
		// Check if access token is valid in storage
		if valid, err := mw.Config.TokenStorage.IsAccessTokenValid(sessionID); err != nil || !valid {
			mw.unauthorized(c, http.StatusUnauthorized, "Token not found or invalid")
			return
		}

		// Update session activity
		mw.Config.TokenStorage.UpdateSessionActivity(sessionID, mw.Config.TimeFunc())
	}
	// Check if user is still active
	if mw.Config.UserProvider != nil {
		if active, err := mw.Config.UserProvider.IsUserActive(claims.UserID); err != nil || !active {
			mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrInactiveUser, c))
			return
		}
	}

	// Set claims and user data in context
	c.Set("JWT_PAYLOAD", claims)
	c.Set("SESSION_ID", sessionID)
	c.Set(mw.Config.IdentityKey, claims.UserID)
	c.Set("user_email", claims.Email)
	c.Set("user_role", claims.Role)
	c.Set("username", claims.Username)

	// Check role-based authorization
	if mw.Config.RoleAuthorizator != nil && !mw.Config.RoleAuthorizator(claims.Role, c) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		return
	}

	// Check general authorization
	if mw.Config.Authorizator != nil && !mw.Config.Authorizator(claims, c) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		return
	}

	c.Next()
}

// GetClaimsFromJWT extracts claims from JWT token with session validation
func (mw *EnhancedGinAuthMiddleware) GetClaimsFromJWT(c *gin.Context) (*core.Claims, string, error) {
	token, err := mw.parseToken(c)
	if err != nil {
		return nil, "", err
	}

	claims, ok := token.Claims.(*core.Claims)
	if !ok {
		return nil, "", errors.New("invalid token claims")
	}

	// Check if token is expired
	if mw.Config.TimeFunc().Unix() > claims.ExpiresAt.Unix() {
		return nil, "", ErrExpiredToken
	}

	// Validate token type
	if claims.TokenType != "access" {
		return nil, "", errors.New("invalid token type")
	}

	return claims, claims.SessionID, nil
}

// parseToken parses the JWT token from the request
func (mw *EnhancedGinAuthMiddleware) parseToken(c *gin.Context) (*jwt.Token, error) {
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

	return jwt.ParseWithClaims(token, &core.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		return []byte(mw.Config.SecretKey), nil
	})
}

// jwtFromHeader extracts JWT token from header
func (mw *EnhancedGinAuthMiddleware) jwtFromHeader(c *gin.Context, key string) string {
	authHeader := c.Request.Header.Get(key)
	if authHeader == "" {
		return ""
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || !strings.EqualFold(authHeaderParts[0], mw.Config.TokenHeadName) {
		return ""
	}

	return authHeaderParts[1]
}

// jwtFromQuery extracts JWT token from query parameter
func (mw *EnhancedGinAuthMiddleware) jwtFromQuery(c *gin.Context, key string) string {
	return c.Query(key)
}

// jwtFromCookie extracts JWT token from cookie
func (mw *EnhancedGinAuthMiddleware) jwtFromCookie(c *gin.Context, key string) string {
	cookie, _ := c.Cookie(key)
	return cookie
}

// LoginHandler handles user login with enhanced token pair generation
func (mw *EnhancedGinAuthMiddleware) LoginHandler(c *gin.Context) {
	if mw.Config.Authenticator == nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, c))
		return
	}

	user, err := mw.Config.Authenticator(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	// Check if user is active
	if !user.IsActive {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrInactiveUser, c))
		return
	}

	// Generate session ID
	sessionID, err := core.GenerateSessionID()
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, "Failed to generate session ID")
		return
	}

	// Create token pair
	tokenPair, err := mw.generateTokenPair(user, sessionID)
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, "Failed to generate tokens")
		return
	}

	// Store token pair in storage
	if mw.Config.TokenStorage != nil {
		err = mw.Config.TokenStorage.StoreTokenPair(
			sessionID,
			tokenPair.AccessToken,
			tokenPair.RefreshToken,
			tokenPair.AccessTokenExpiresAt,
			tokenPair.RefreshTokenExpiresAt,
			user.ID,
		)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, "Failed to store tokens")
			return
		}

		// Store user session information
		session := core.UserSession{
			SessionID:    sessionID,
			UserID:       user.ID,
			Username:     user.Username,
			Email:        user.Email,
			Role:         user.Role,
			CreatedAt:    mw.Config.TimeFunc(),
			LastActivity: mw.Config.TimeFunc(),
			IPAddress:    c.ClientIP(),
			UserAgent:    c.Request.UserAgent(),
		}
		mw.Config.TokenStorage.StoreUserSession(session)
	}

	// Update user last login
	if mw.Config.UserProvider != nil {
		mw.Config.UserProvider.UpdateUserLastLogin(user.ID, mw.Config.TimeFunc())
	}

	// Set cookies if enabled
	if mw.Config.SendCookie {
		mw.setCookies(c, tokenPair)
	}

	// Store user and session in context for response
	c.Set("user", user)
	c.Set("session_id", sessionID)

	mw.Config.LoginResponse(c, http.StatusOK, *tokenPair, user)
}

// RegisterHandler handles user registration with role-based authorization
func (mw *EnhancedGinAuthMiddleware) RegisterHandler(c *gin.Context) {
	// Check if registration is enabled
	if !mw.Config.EnableRegistration {
		mw.unauthorized(c, http.StatusForbidden, "Registration is disabled")
		return
	}

	// Check if UserCreator is configured
	if mw.Config.UserCreator == nil {
		mw.unauthorized(c, http.StatusInternalServerError, "User creator not configured")
		return
	}

	// Parse registration request
	var regReq RegistrationRequest
	if err := c.ShouldBindJSON(&regReq); err != nil {
		mw.unauthorized(c, http.StatusBadRequest, "Invalid registration request: "+err.Error())
		return
	}

	// Determine the role for the new user
	userRole := mw.Config.DefaultRole
	if regReq.Role != "" {
		// If a role is requested, check if it's allowed
		if !mw.isRoleRegisterable(regReq.Role) {
			mw.unauthorized(c, http.StatusForbidden, fmt.Sprintf("Role '%s' cannot be assigned during registration", regReq.Role))
			return
		}
		userRole = regReq.Role
	}

	// Check if username and email are available
	if mw.Config.UserCreator != nil {
		usernameAvailable, err := mw.Config.UserCreator.IsUsernameAvailable(regReq.Username)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, "Failed to validate username")
			return
		}
		if !usernameAvailable {
			mw.unauthorized(c, http.StatusConflict, "Username already exists")
			return
		}

		emailAvailable, err := mw.Config.UserCreator.IsEmailAvailable(regReq.Email)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, "Failed to validate email")
			return
		}
		if !emailAvailable {
			mw.unauthorized(c, http.StatusConflict, "Email already registered")
			return
		}
	}

	// Hash the password
	passwordHash, err := HashPassword(regReq.Password)
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, "Failed to process password")
		return
	}

	// Generate unique user ID
	userID, err := core.GenerateSessionID() // Reuse session ID generator for unique IDs
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, "Failed to generate user ID")
		return
	}

	// Create new user
	now := mw.Config.TimeFunc()
	newUser := &core.User{
		ID:           userID,
		Username:     regReq.Username,
		Email:        regReq.Email,
		Password:     regReq.Password,     // Pass plain password to UserCreator
		PasswordHash: passwordHash,        // Also provide the hash
		Role:         userRole,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Store user in user creator
	if err := mw.Config.UserCreator.CreateUser(newUser); err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, "Failed to create user: "+err.Error())
		return
	}

	// Call the registration response handler
	mw.Config.RegisterResponse(c, http.StatusCreated, newUser)
}

// isRoleRegisterable checks if a role can be assigned during registration
func (mw *EnhancedGinAuthMiddleware) isRoleRegisterable(role string) bool {
	// If no registerable roles are specified, only allow the default role
	if len(mw.Config.RegisterableRoles) == 0 {
		return role == mw.Config.DefaultRole
	}

	// Check if role is in the registerable roles list
	for _, allowedRole := range mw.Config.RegisterableRoles {
		if allowedRole == role {
			return true
		}
	}

	return false
}

// LogoutHandler handles user logout with comprehensive cleanup
func (mw *EnhancedGinAuthMiddleware) LogoutHandler(c *gin.Context) {
	sessionID, exists := c.Get("SESSION_ID")
	if !exists {
		// Try to extract session ID from token
		if _, sID, err := mw.GetClaimsFromJWT(c); err == nil {
			sessionID = sID
		}
	}

	// Clean up tokens and session
	if mw.Config.TokenStorage != nil && sessionID != nil {
		if sessionIDStr, ok := sessionID.(string); ok {
			// Delete token pair and session
			mw.Config.TokenStorage.DeleteTokenPair(sessionIDStr)
		}
	}

	// Clear cookies if enabled
	if mw.Config.SendCookie {
		mw.clearCookies(c)
	}

	mw.Config.LogoutResponse(c, http.StatusOK, "Successfully logged out")
}

// LogoutAllHandler handles logout from all devices
func (mw *EnhancedGinAuthMiddleware) LogoutAllHandler(c *gin.Context) {
	userID := c.MustGet(mw.Config.IdentityKey).(string)

	// Revoke all user tokens
	if mw.Config.TokenStorage != nil {
		err := mw.Config.TokenStorage.RevokeAllUserTokens(userID)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, "Failed to logout from all devices")
			return
		}
	}

	// Clear cookies if enabled
	if mw.Config.SendCookie {
		mw.clearCookies(c)
	}

	mw.Config.LogoutResponse(c, http.StatusOK, "Successfully logged out from all devices")
}

// RefreshHandler handles token refresh
func (mw *EnhancedGinAuthMiddleware) RefreshHandler(c *gin.Context) {
	// Get refresh token from request
	refreshToken := mw.getRefreshToken(c)
	if refreshToken == "" {
		mw.unauthorized(c, http.StatusUnauthorized, "Missing refresh token")
		return
	}

	// Parse and validate refresh token
	token, err := jwt.ParseWithClaims(refreshToken, &core.RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		return []byte(mw.Config.RefreshSecretKey), nil
	})

	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrInvalidRefreshToken, c))
		return
	}

	claims, ok := token.Claims.(*core.RefreshTokenClaims)
	if !ok {
		mw.unauthorized(c, http.StatusUnauthorized, "Invalid refresh token claims")
		return
	}

	// Check if refresh token is expired
	if mw.Config.TimeFunc().Unix() > claims.ExpiresAt.Unix() {
		mw.unauthorized(c, http.StatusUnauthorized, "Refresh token is expired")
		return
	}

	// Validate token type
	if claims.TokenType != "refresh" {
		mw.unauthorized(c, http.StatusUnauthorized, "Invalid token type")
		return
	}

	// Validate refresh token in storage
	if mw.Config.TokenStorage != nil {
		if valid, err := mw.Config.TokenStorage.IsRefreshTokenValid(claims.SessionID); err != nil || !valid {
			mw.unauthorized(c, http.StatusUnauthorized, "Refresh token not found or invalid")
			return
		}
	}

	// Get user information
	var user *core.User
	if mw.Config.UserProvider != nil {
		user, err = mw.Config.UserProvider.GetUserByID(claims.UserID)
		if err != nil {
			mw.unauthorized(c, http.StatusUnauthorized, "User not found")
			return
		}

		// Check if user is still active
		if !user.IsActive {
			mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrInactiveUser, c))
			return
		}
	} else {
		// Create user from claims if no user provider
		user = &core.User{
			ID:       claims.UserID,
			Username: claims.Username,
			Email:    claims.Email,
			Role:     claims.Role,
			IsActive: true,
		}
	}

	// Generate new token pair
	newTokenPair, err := mw.generateTokenPair(user, claims.SessionID)
	if err != nil {
		mw.unauthorized(c, http.StatusInternalServerError, "Failed to generate new tokens")
		return
	}

	// Update token pair in storage
	if mw.Config.TokenStorage != nil {
		err = mw.Config.TokenStorage.RefreshTokenPair(
			claims.SessionID,
			newTokenPair.AccessToken,
			newTokenPair.RefreshToken,
			newTokenPair.AccessTokenExpiresAt,
			newTokenPair.RefreshTokenExpiresAt,
		)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, "Failed to update tokens")
			return
		}

		// Update session activity
		mw.Config.TokenStorage.UpdateSessionActivity(claims.SessionID, mw.Config.TimeFunc())
	}

	// Set new cookies if enabled
	if mw.Config.SendCookie {
		mw.setCookies(c, newTokenPair)
	}

	mw.Config.RefreshResponse(c, http.StatusOK, *newTokenPair)
}

// GetUserSessionsHandler returns active sessions for the current user
func (mw *EnhancedGinAuthMiddleware) GetUserSessionsHandler(c *gin.Context) {
	userID := c.MustGet(mw.Config.IdentityKey).(string)

	if mw.Config.TokenStorage != nil {
		sessions, err := mw.Config.TokenStorage.GetUserActiveSessions(userID)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, "Failed to get user sessions")
			return
		}

		var sessionDetails []gin.H
		for _, sessionID := range sessions {
			if session, err := mw.Config.TokenStorage.GetUserSession(sessionID); err == nil {
				sessionDetails = append(sessionDetails, gin.H{
					"session_id":    session.SessionID,
					"created_at":    session.CreatedAt.Unix(),
					"last_activity": session.LastActivity.Unix(),
					"ip_address":    session.IPAddress,
					"user_agent":    session.UserAgent,
				})
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"success":  true,
			"sessions": sessionDetails,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"sessions": []gin.H{},
	})
}

// generateTokenPair creates both access and refresh tokens
func (mw *EnhancedGinAuthMiddleware) generateTokenPair(user *core.User, sessionID string) (*core.TokenPair, error) {
	now := mw.Config.TimeFunc()
	accessExpire := now.Add(mw.Config.AccessTokenTimeout)
	refreshExpire := now.Add(mw.Config.RefreshTokenTimeout)

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &core.Claims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		TokenType: "access",
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExpire),
			Subject:   fmt.Sprintf("%v", user.ID),
		},
	})

	accessTokenString, err := accessToken.SignedString([]byte(mw.Config.SecretKey))
	if err != nil {
		return nil, err
	}

	// Create refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &core.RefreshTokenClaims{
		UserID:    user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		TokenType: "refresh",
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(refreshExpire),
			Subject:   fmt.Sprintf("%v", user.ID),
		},
	})

	refreshTokenString, err := refreshToken.SignedString([]byte(mw.Config.RefreshSecretKey))
	if err != nil {
		return nil, err
	}

	return &core.TokenPair{
		AccessToken:           accessTokenString,
		RefreshToken:          refreshTokenString,
		AccessTokenExpiresAt:  accessExpire,
		RefreshTokenExpiresAt: refreshExpire,
		TokenType:             "Bearer",
	}, nil
}

// getRefreshToken extracts refresh token from request
func (mw *EnhancedGinAuthMiddleware) getRefreshToken(c *gin.Context) string {
	// Try to get from request body first
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
		return req.RefreshToken
	}

	// Try to get from cookie
	if cookie, err := c.Cookie(mw.Config.RefreshCookieName); err == nil && cookie != "" {
		return cookie
	}

	// Try to get from header
	if token := c.GetHeader("X-Refresh-Token"); token != "" {
		return token
	}

	return ""
}

// setCookies sets both access and refresh token cookies
func (mw *EnhancedGinAuthMiddleware) setCookies(c *gin.Context, tokenPair *core.TokenPair) {
	// Set access token cookie (shorter expiry)
	c.SetCookie(
		mw.Config.CookieName,
		tokenPair.AccessToken,
		int(mw.Config.AccessTokenTimeout.Seconds()),
		"/",
		mw.Config.CookieDomain,
		mw.Config.CookieSecure,
		mw.Config.CookieHTTPOnly,
	)

	// Set refresh token cookie (longer expiry)
	c.SetCookie(
		mw.Config.RefreshCookieName,
		tokenPair.RefreshToken,
		int(mw.Config.RefreshTokenTimeout.Seconds()),
		"/",
		mw.Config.CookieDomain,
		mw.Config.CookieSecure,
		mw.Config.CookieHTTPOnly,
	)
}

// clearCookies clears both access and refresh token cookies
func (mw *EnhancedGinAuthMiddleware) clearCookies(c *gin.Context) {
	c.SetCookie(
		mw.Config.CookieName,
		"",
		-1,
		"/",
		mw.Config.CookieDomain,
		mw.Config.CookieSecure,
		mw.Config.CookieHTTPOnly,
	)

	c.SetCookie(
		mw.Config.RefreshCookieName,
		"",
		-1,
		"/",
		mw.Config.CookieDomain,
		mw.Config.CookieSecure,
		mw.Config.CookieHTTPOnly,
	)
}

// unauthorized handles unauthorized requests
func (mw *EnhancedGinAuthMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Config.Realm)
	c.Abort()
	mw.Config.Unauthorized(c, code, message)
}

// HTTPStatusMessageFunc returns HTTP status message based on error
func (mw *EnhancedGinAuthMiddleware) HTTPStatusMessageFunc(err error, c *gin.Context) string {
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
	case ErrInvalidRefreshToken:
		return "Invalid refresh token"
	case ErrInactiveUser:
		return "User account is inactive"
	case ErrSessionNotFound:
		return "Session not found"
	default:
		return err.Error()
	}
}
