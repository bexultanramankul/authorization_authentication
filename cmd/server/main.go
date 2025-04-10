package main

import (
	"authorization_authentication/config"
	"authorization_authentication/internal/handler"
	"authorization_authentication/internal/repository"
	"authorization_authentication/internal/service"
	"authorization_authentication/internal/storage"
	"authorization_authentication/pkg/logger"
	_ "github.com/lib/pq"
	"log"
	"net/http"
)

func main() {
	logger.InitLogger()
	logger.Log.Info("Loading configuration...")
	cfg := config.LoadConfig()

	logger.Log.Info("Connecting to the storage...")
	storage.InitDB()

	userRepo := repository.NewUserRepository(storage.DB)
	sessionRepo := repository.NewSessionRepository(storage.DB)
	jwtService, err := service.NewJWTService(cfg)
	if err != nil {
		log.Fatal(err)
	}
	authService := service.NewAuthService(*userRepo, *sessionRepo, jwtService)
	authHandler := handlers.NewAuthHandler(authService)

	http.HandleFunc("/register", authHandler.Register)
	http.HandleFunc("/login", authHandler.Login)
	http.HandleFunc("/refresh", authHandler.Refresh)
	http.HandleFunc("/verify", authHandler.Verify)

	logger.Log.Println("Auth service running on :8080")
	logger.Log.Fatal(http.ListenAndServe(":8080", nil))
}
