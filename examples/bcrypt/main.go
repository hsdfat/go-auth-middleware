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

	// Create auth middleware with bcrypt
	authMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:       "your-secret-key",
		Timeout:         24 * 60 * 60, // 24 hours
		MaxRefresh:      24 * 60 * 60, // 24 hours
		TokenStorage:    tokenStorage,
		UseBcrypt:       true, // Enable bcrypt for this example
		Authenticator:   ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:     ginauth.BasicPayloadFunc(),
		IdentityHandler: ginauth.BasicIdentityHandler(),
	})

	// Public routes
	r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/logout", authMiddleware.MiddlewareFunc(), authMiddleware.LogoutHandler)
	r.POST("/refresh", authMiddleware.MiddlewareFunc(), authMiddleware.RefreshHandler)

	// Bcrypt utility endpoints
	r.GET("/hash/:password", func(c *gin.Context) {
		password := c.Param("password")
		hash, err := ginauth.HashPassword(password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"password": password,
			"hash":     hash,
		})
	})

	r.POST("/check", func(c *gin.Context) {
		var req struct {
			Password string `json:"password"`
			Hash     string `json:"hash"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isValid := ginauth.CheckPasswordHash(req.Password, req.Hash)
		c.JSON(http.StatusOK, gin.H{
			"password": req.Password,
			"hash":     req.Hash,
			"valid":    isValid,
		})
	})

	// Protected routes
	protected := r.Group("/api")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Protected profile endpoint",
				"user_id": userID,
			})
		})
	}

	log.Println("Bcrypt example server starting on :8083")
	log.Println("This example demonstrates bcrypt password hashing")
	log.Println("Try these endpoints:")
	log.Println("  GET  /hash/admin123 - Hash a password")
	log.Println("  POST /check - Check password against hash")
	log.Println("  POST /login - Login with bcrypt hashed passwords")
	log.Println("  Body: {\"username\": \"admin\", \"password\": \"admin123\"}")
	log.Fatal(r.Run(":8083"))
}
