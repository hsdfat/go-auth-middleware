package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/fiberauth"
)

func main() {
	app := fiber.New()

	// Create user provider with sample users
	users := map[string]fiberauth.User{
		"admin": {
			ID:       1,
			Username: "admin",
			Password: "admin123",
		},
		"user": {
			ID:       2,
			Username: "user",
			Password: "user123",
		},
	}
	userProvider := fiberauth.NewMapUserProvider(users)

	// Create token storage
	tokenStorage := fiberauth.NewInMemoryTokenStorage()

	// Create authentication middleware with different configurations
	authMiddleware := fiberauth.NewFiberAuthMiddleware(fiberauth.AuthConfig{
		SecretKey:       "your-secret-key",
		Timeout:         time.Hour,
		MaxRefresh:      time.Hour * 24,
		TokenLookup:     "header:Authorization",
		TokenHeadName:   "Bearer",
		Authenticator:   authenticator(userProvider),
		Authorizator:    authorizator,
		Unauthorized:    unauthorized,
		LoginResponse:   loginResponse,
		LogoutResponse:  logoutResponse,
		RefreshResponse: refreshResponse,
		TokenStorage:    tokenStorage,
		UseBcrypt:       true,
		// Token storage configuration
		EnableTokenStorage:     true,   // Enable token storage
		TokenStorageMode:       "both", // Use both JWT and bcrypt
		StoreTokenOnLogin:      true,   // Store token on login
		ValidateTokenOnRequest: true,   // Validate token on each request
	})

	// Public routes
	app.Post("/login", authMiddleware.LoginHandler())
	app.Post("/logout", authMiddleware.LogoutHandler())
	app.Post("/refresh", authMiddleware.RefreshHandler())

	// Protected routes
	protected := app.Group("/protected")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.Get("/", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "This is a protected route with configuration",
				"user_id": c.Locals("identity"),
			})
		})
	}

	// Public route
	app.Get("/public", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is a public route",
		})
	})

	log.Fatal(app.Listen(":3000"))
}

// authenticator validates user credentials
func authenticator(userProvider fiberauth.UserProvider) func(c *fiber.Ctx) (interface{}, error) {
	return func(c *fiber.Ctx) (interface{}, error) {
		var login struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&login); err != nil {
			return nil, err
		}

		user, err := userProvider.GetUserByUsername(login.Username)
		if err != nil {
			return nil, err
		}

		if user.Password != login.Password {
			return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
		}

		return jwt.MapClaims{
			"user_id":  user.ID,
			"username": user.Username,
		}, nil
	}
}

// authorizator checks if user has permission to access the resource
func authorizator(data interface{}, c *fiber.Ctx) bool {
	if userID, ok := data.(int); ok {
		// Simple authorization: allow all authenticated users
		return userID > 0
	}
	return false
}

// unauthorized handles unauthorized requests
func unauthorized(c *fiber.Ctx, code int, message string) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": message,
	})
}

// loginResponse handles login response
func loginResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}

// logoutResponse handles logout response
func logoutResponse(c *fiber.Ctx, code int) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": "Successfully logged out",
	})
}

// refreshResponse handles refresh response
func refreshResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}
