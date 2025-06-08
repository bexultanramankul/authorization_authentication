package storage

import (
	"authorization_authentication/config"
	"authorization_authentication/pkg/logger"
	"context"

	"github.com/redis/go-redis/v9"
)

var (
	RedisClient *redis.Client
	RedisCtx    = context.Background()
)

func InitRedis() {
	cfg := config.LoadConfig()

	RedisClient = redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Проверка соединения
	_, err := RedisClient.Ping(RedisCtx).Result()
	if err != nil {
		logger.Log.Fatalf("Redis connection error: %v", err)
	}
	logger.Log.Info("Redis connected successfully")
}

func CloseRedis() {
	if err := RedisClient.Close(); err != nil {
		logger.Log.Warn("Error closing Redis: ", err)
	} else {
		logger.Log.Info("Redis connection closed")
	}
}
