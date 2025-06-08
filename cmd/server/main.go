package main

import (
	"authorization_authentication/config"
	"authorization_authentication/internal/handler"
	"authorization_authentication/internal/repository"
	"authorization_authentication/internal/service"
	"authorization_authentication/internal/storage"
	"authorization_authentication/pkg/logger"
	"context"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/twilio/twilio-go"
	"log"
	"net/http"
)

func main() {
	logger.InitLogger()
	logger.Log.Info("Loading configuration...")
	cfg := config.LoadConfig()

	logger.Log.Info("Connecting to the database...")
	storage.InitDB()

	logger.Log.Info("Connecting to the redis...")
	storage.InitRedis()

	redisClient := redis.NewClient(&redis.Options{})
	twilioClient := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: cfg.AccountSID,
		Password: cfg.AuthToken,
	})

	userRepo := repository.NewUserRepository(storage.DB)
	sessionRepo := repository.NewSessionRepository(storage.DB)
	jwtService, err := service.NewJWTService(cfg)
	if err != nil {
		log.Fatal(err)
	}
	authService := service.NewAuthService(*userRepo, *sessionRepo, jwtService, redisClient, twilioClient, cfg.ServiceSID)
	authHandler := handlers.NewAuthHandler(authService)

	// Запускаем фоновую очистку
	ctx := context.Background()
	authService.StartCleanupRoutine(ctx)

	http.HandleFunc("/register", authHandler.Register)
	http.HandleFunc("/login", authHandler.Login)
	http.HandleFunc("/refresh", authHandler.Refresh)
	http.HandleFunc("/verify", authHandler.Verify)
	http.HandleFunc("/logout", authHandler.Logout)
	http.HandleFunc("/verify-phone", authHandler.VerifyPhone)

	logger.Log.Println("Auth service running on :8080")
	logger.Log.Fatal(http.ListenAndServe(":8080", nil))
}
