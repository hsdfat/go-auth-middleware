package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hsdfat/go-auth-middleware/core"
	"github.com/hsdfat/go-auth-middleware/ginauth"
)

func main() {
	r := gin.Default()

	// Create enhanced users with roles and emails
	users, err := createEnhancedUsers()
	if err != nil {
		log.Fatal("Failed to create users:", err)
	}

	// Create user provider
	userProvider := core.NewMapUserProvider(users)

	// Create enhanced token storage
	tokenStorage := core.NewInMemoryTokenStorage()

	// Create enhanced auth middleware
	authMiddleware := ginauth.NewEnhanced(ginauth.EnhancedAuthConfig{
		SecretKey:           "your-access-token-secret-key",
		RefreshSecretKey:    "your-refresh-token-secret-key", // Should be different
		AccessTokenTimeout:  15 * time.Minute,                // Short-lived access tokens
		RefreshTokenTimeout: 7 * 24 * time.Hour,              // 7 days refresh tokens

		TokenLookup:   "header:Authorization,cookie:jwt",
		TokenHeadName: "Bearer",
		Realm:         "enhanced-auth",
		IdentityKey:   "identity",

		// Cookie configuration
		SendCookie:        true,
		CookieName:        "access_token",
		RefreshCookieName: "refresh_token",
		CookieHTTPOnly:    true,
		CookieSecure:      false, // Set to true in production with HTTPS
		CookieDomain:      "",

		// Storage and providers
		TokenStorage: tokenStorage,
		UserProvider: userProvider,
		UserCreator:  userProvider, // MapUserProvider implements both UserProvider and UserCreator

		// Authentication function
		Authenticator: ginauth.CreateEnhancedAuthenticator(userProvider),

		// Role-based authorization (example: only admin and user roles allowed)
		RoleAuthorizator: ginauth.CreateRoleAuthorizator("admin", "user", "moderator"),

		// Registration configuration
		EnableRegistration: true,             // Enable user registration
		RegisterableRoles:  []string{"user"}, // Only "user" role can be registered
		DefaultRole:        "user",           // New users get "user" role by default

		// Security settings
		MaxConcurrentSessions: 5,         // Max 5 concurrent sessions per user
		SingleSessionMode:     false,     // Allow multiple sessions
		EnableTokenRevocation: true,      // Enable token revocation on logout
		CleanupInterval:       time.Hour, // Cleanup expired tokens every hour
	})

	// Public routes
	r.POST("/auth/login", authMiddleware.LoginHandler)
	r.POST("/auth/register", authMiddleware.RegisterHandler)
	r.POST("/auth/refresh", authMiddleware.RefreshHandler)

	// Routes that require authentication
	authenticated := r.Group("/auth")
	authenticated.Use(authMiddleware.MiddlewareFunc())
	{
		authenticated.POST("/logout", authMiddleware.LogoutHandler)
		authenticated.POST("/logout-all", authMiddleware.LogoutAllHandler)
		authenticated.GET("/sessions", authMiddleware.GetUserSessionsHandler)
	}

	// Protected API routes
	api := r.Group("/api")
	api.Use(authMiddleware.MiddlewareFunc())
	{
		// User profile (all authenticated users)
		api.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("identity")
			userEmail := c.MustGet("user_email")
			userRole := c.MustGet("user_role")
			username := c.MustGet("username")
			sessionID := c.MustGet("SESSION_ID")

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"data": gin.H{
					"user_id":    userID,
					"username":   username,
					"email":      userEmail,
					"role":       userRole,
					"session_id": sessionID,
				},
			})
		})

		// Admin only routes
		admin := api.Group("/admin")
		admin.Use(requireRole("admin"))
		{
			admin.GET("/users", listUsersHandler)
			admin.POST("/users", createUserHandler)
			admin.PUT("/users/:id", updateUserHandler)
			admin.DELETE("/users/:id", deleteUserHandler)
		}

		// Moderator and Admin routes
		moderation := api.Group("/moderation")
		moderation.Use(requireRoles("admin", "moderator"))
		{
			moderation.GET("/reports", getReportsHandler)
			moderation.POST("/moderate/:id", moderateContentHandler)
		}
	}

	// Health check (public)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
		})
	})

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			if err := tokenStorage.CleanupExpiredTokens(); err != nil {
				log.Printf("Failed to cleanup expired tokens: %v", err)
			}
		}
	}()

	log.Println("Enhanced JWT Auth server starting on :8080")
	log.Println("Available endpoints:")
	log.Println("  POST /auth/login     - User login")
	log.Println("  POST /auth/register  - Register new user")
	log.Println("  POST /auth/refresh   - Refresh access token")
	log.Println("  POST /auth/logout    - Logout current session")
	log.Println("  POST /auth/logout-all - Logout all sessions")
	log.Println("  GET  /auth/sessions  - Get user active sessions")
	log.Println("  GET  /api/profile    - Get user profile")
	log.Println("  GET  /api/admin/*    - Admin routes")
	log.Println("  GET  /api/moderation/* - Moderation routes")
	log.Println("")
	log.Println("Test users:")
	log.Println("  Admin: username=admin, password=admin123, email=admin@example.com")
	log.Println("  User:  username=user, password=user123, email=user@example.com")
	log.Println("  Mod:   username=mod, password=mod123, email=mod@example.com")
	log.Println("")
	log.Println("Registration:")
	log.Println("  Only 'user' role can be registered (admin/moderator roles need to be created by admins)")
	log.Println("  Example request:")
	log.Println("  POST /auth/register")
	log.Println("  {")
	log.Println("    \"username\": \"newuser\",")
	log.Println("    \"email\": \"newuser@example.com\",")
	log.Println("    \"password\": \"securepass123\"")
	log.Println("  }")

	log.Fatal(r.Run(":8080"))
}

// createEnhancedUsers creates sample users with enhanced fields
func createEnhancedUsers() (map[string]core.User, error) {
	users := make(map[string]core.User)

	// Admin user
	adminHash, err := ginauth.HashPassword("admin123")
	if err != nil {
		return nil, err
	}
	users["admin"] = core.User{
		ID:           "1",
		Username:     "admin",
		Email:        "admin@example.com",
		Role:         "admin",
		PasswordHash: adminHash,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Regular user
	userHash, err := ginauth.HashPassword("user123")
	if err != nil {
		return nil, err
	}
	users["user"] = core.User{
		ID:           "2",
		Username:     "user",
		Email:        "user@example.com",
		Role:         "user",
		PasswordHash: userHash,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Moderator user
	modHash, err := ginauth.HashPassword("mod123")
	if err != nil {
		return nil, err
	}
	users["mod"] = core.User{
		ID:           "3",
		Username:     "mod",
		Email:        "mod@example.com",
		Role:         "moderator",
		PasswordHash: modHash,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return users, nil
}

// requireRole middleware to check for specific role
func requireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   true,
				"message": "Role information not found",
			})
			c.Abort()
			return
		}

		if userRole.(string) != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   true,
				"message": "Insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// requireRoles middleware to check for multiple possible roles
func requireRoles(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   true,
				"message": "Role information not found",
			})
			c.Abort()
			return
		}

		userRoleStr := userRole.(string)
		allowed := false
		for _, role := range allowedRoles {
			if userRoleStr == role {
				allowed = true
				break
			}
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"error":   true,
				"message": "Insufficient permissions",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Handler functions for admin routes
func listUsersHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"users": []gin.H{
				{"id": 1, "username": "admin", "email": "admin@example.com", "role": "admin"},
				{"id": 2, "username": "user", "email": "user@example.com", "role": "user"},
				{"id": 3, "username": "mod", "email": "mod@example.com", "role": "moderator"},
			},
		},
	})
}

func createUserHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Role     string `json:"role" binding:"required"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   true,
			"message": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "User created successfully",
		"data": gin.H{
			"id":       time.Now().Unix(),
			"username": req.Username,
			"email":    req.Email,
			"role":     req.Role,
		},
	})
}

func updateUserHandler(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Username string `json:"username,omitempty"`
		Email    string `json:"email,omitempty"`
		Role     string `json:"role,omitempty"`
		IsActive *bool  `json:"is_active,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   true,
			"message": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User updated successfully",
		"data": gin.H{
			"id":         userID,
			"updated_at": time.Now().Unix(),
		},
	})
}

func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "User deleted successfully",
		"data": gin.H{
			"id":         userID,
			"deleted_at": time.Now().Unix(),
		},
	})
}

// Handler functions for moderation routes
func getReportsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"reports": []gin.H{
				{
					"id":          1,
					"content_id":  123,
					"reported_by": 2,
					"reason":      "spam",
					"status":      "pending",
					"created_at":  time.Now().Add(-time.Hour).Unix(),
				},
				{
					"id":          2,
					"content_id":  456,
					"reported_by": 1,
					"reason":      "inappropriate",
					"status":      "reviewed",
					"created_at":  time.Now().Add(-2 * time.Hour).Unix(),
				},
			},
		},
	})
}

func moderateContentHandler(c *gin.Context) {
	contentID := c.Param("id")

	var req struct {
		Action string `json:"action" binding:"required,oneof=approve reject"`
		Reason string `json:"reason,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   true,
			"message": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	moderatorID := c.MustGet("identity")

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Content moderated successfully",
		"data": gin.H{
			"content_id":   contentID,
			"action":       req.Action,
			"reason":       req.Reason,
			"moderated_by": moderatorID,
			"moderated_at": time.Now().Unix(),
		},
	})
}
