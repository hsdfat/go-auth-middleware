package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hsdfat/go-auth-middleware/ginauth"
)

func main() {
	r := gin.Default()

	// Create users with bcrypt password hashing
	users, err := ginauth.CreateUserMapWithBcrypt([]struct {
		ID       int
		Username string
		Password string
	}{
		{ID: 1, Username: "admin", Password: "admin123"},
		{ID: 2, Username: "user", Password: "user123"},
	})
	if err != nil {
		log.Fatal("Failed to create users:", err)
	}

	// Create user provider
	userProvider := ginauth.NewMapUserProvider(users)

	// Create token storage
	tokenStorage := ginauth.NewInMemoryTokenStorage()

	// Example 1: JWT-only token storage
	jwtAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "jwt-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// JWT-only configuration
		EnableTokenStorage:     true,
		TokenStorageMode:       "jwt",
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// Example 2: Bcrypt token storage
	bcryptAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "bcrypt-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// Bcrypt-only configuration
		EnableTokenStorage:     true,
		TokenStorageMode:       "bcrypt",
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// Example 3: Both JWT and Bcrypt token storage
	bothAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "both-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// Both JWT and Bcrypt configuration
		EnableTokenStorage:     true,
		TokenStorageMode:       "both",
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// Example 4: No token storage
	noStorageAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "no-storage-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// No token storage configuration
		EnableTokenStorage:     false,
		TokenStorageMode:       "jwt",
		StoreTokenOnLogin:      false,
		ValidateTokenOnRequest: false,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// JWT-only routes
	jwtGroup := r.Group("/jwt")
	{
		jwtGroup.POST("/login", jwtAuthMiddleware.LoginHandler)
		jwtGroup.POST("/logout", jwtAuthMiddleware.MiddlewareFunc(), jwtAuthMiddleware.LogoutHandler)
		jwtGroup.POST("/refresh", jwtAuthMiddleware.MiddlewareFunc(), jwtAuthMiddleware.RefreshHandler)
		jwtGroup.GET("/profile", jwtAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "JWT-only protected endpoint",
				"user_id": userID,
				"mode":    "jwt",
			})
		})
	}

	// Bcrypt-only routes
	bcryptGroup := r.Group("/bcrypt")
	{
		bcryptGroup.POST("/login", bcryptAuthMiddleware.LoginHandler)
		bcryptGroup.POST("/logout", bcryptAuthMiddleware.MiddlewareFunc(), bcryptAuthMiddleware.LogoutHandler)
		bcryptGroup.POST("/refresh", bcryptAuthMiddleware.MiddlewareFunc(), bcryptAuthMiddleware.RefreshHandler)
		bcryptGroup.GET("/profile", bcryptAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Bcrypt-only protected endpoint",
				"user_id": userID,
				"mode":    "bcrypt",
			})
		})
	}

	// Both JWT and Bcrypt routes
	bothGroup := r.Group("/both")
	{
		bothGroup.POST("/login", bothAuthMiddleware.LoginHandler)
		bothGroup.POST("/logout", bothAuthMiddleware.MiddlewareFunc(), bothAuthMiddleware.LogoutHandler)
		bothGroup.POST("/refresh", bothAuthMiddleware.MiddlewareFunc(), bothAuthMiddleware.RefreshHandler)
		bothGroup.GET("/profile", bothAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Both JWT and Bcrypt protected endpoint",
				"user_id": userID,
				"mode":    "both",
			})
		})
	}

	// No storage routes
	noStorageGroup := r.Group("/no-storage")
	{
		noStorageGroup.POST("/login", noStorageAuthMiddleware.LoginHandler)
		noStorageGroup.POST("/logout", noStorageAuthMiddleware.MiddlewareFunc(), noStorageAuthMiddleware.LogoutHandler)
		noStorageGroup.POST("/refresh", noStorageAuthMiddleware.MiddlewareFunc(), noStorageAuthMiddleware.RefreshHandler)
		noStorageGroup.GET("/profile", noStorageAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "No storage protected endpoint",
				"user_id": userID,
				"mode":    "no-storage",
			})
		})
	}

	log.Println("Configuration example server starting on :8084")
	log.Println("Available endpoints:")
	log.Println("  JWT-only:     POST /jwt/login, GET /jwt/profile")
	log.Println("  Bcrypt-only:  POST /bcrypt/login, GET /bcrypt/profile")
	log.Println("  Both:         POST /both/login, GET /both/profile")
	log.Println("  No storage:   POST /no-storage/login, GET /no-storage/profile")
	log.Println("Try logging in with:")
	log.Println("  Body: {\"username\": \"admin\", \"password\": \"admin123\"}")
	log.Fatal(r.Run(":8084"))
}
