package ginauth

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// Re-export core bcrypt functions for backward compatibility
var (
	HashPassword      = core.HashPassword
	CheckPasswordHash = core.CheckPasswordHash
	HashToken         = core.HashToken
	CheckTokenHash    = core.CheckTokenHash
)

// CreateUserWithBcrypt creates a new user with bcrypt password hashing
func CreateUserWithBcrypt(id int, username, password string) (*User, error) {
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:           id,
		Username:     username,
		PasswordHash: hashedPassword,
	}, nil
}

// CreateUserMapWithBcrypt creates a map of users with bcrypt password hashing
func CreateUserMapWithBcrypt(users []struct {
	ID       int
	Username string
	Password string
}) (map[string]User, error) {
	userMap := make(map[string]User)
	for _, userData := range users {
		user, err := CreateUserWithBcrypt(userData.ID, userData.Username, userData.Password)
		if err != nil {
			return nil, err
		}
		userMap[user.Username] = *user
	}
	return userMap, nil
}

// NewMapUserProvider creates a new map-based user provider
func NewMapUserProvider(users map[string]User) *MapUserProvider {
	return core.NewMapUserProvider(users)
}

// NewDatabaseUserProvider creates a new database-based user provider
func NewDatabaseUserProvider() *DatabaseUserProvider {
	return &DatabaseUserProvider{}
}

// BasicAuthenticator creates a basic authenticator using UserProvider
func BasicAuthenticator(userProvider UserProvider) func(*gin.Context) (interface{}, error) {
	return func(c *gin.Context) (interface{}, error) {
		var loginVals struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginVals); err != nil {
			return nil, err
		}

		user, err := userProvider.GetUserByUsername(loginVals.Username)
		if err != nil {
			return nil, errors.New("invalid username or password")
		}

		// Check password - support both plain text and bcrypt
		passwordValid := false
		if user.PasswordHash != "" {
			// Use bcrypt hash
			passwordValid = CheckPasswordHash(loginVals.Password, user.PasswordHash)
		} else if user.Password != "" {
			// Fallback to plain text (for backward compatibility)
			passwordValid = user.Password == loginVals.Password
		}

		if !passwordValid {
			return nil, errors.New("invalid username or password")
		}

		return map[string]interface{}{
			"user_id":  user.ID,
			"username": user.Username,
		}, nil
	}
}

// LegacyBasicAuthenticator maintains backward compatibility with map-based authentication
func LegacyBasicAuthenticator(users map[string]User) func(*gin.Context) (interface{}, error) {
	userProvider := NewMapUserProvider(users)
	return BasicAuthenticator(userProvider)
}

// BasicPayloadFunc creates a basic payload function
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

// BasicIdentityHandler creates a basic identity handler
func BasicIdentityHandler() func(*gin.Context) interface{} {
	return func(c *gin.Context) interface{} {
		claims := c.MustGet("JWT_PAYLOAD").(*Claims)
		return map[string]interface{}{
			"user_id":  claims.UserID,
			"username": claims.Username,
		}
	}
}
