package config

import (
	"authorization_authentication/pkg/logger"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost        string
	DBPort        string
	DBUser        string
	DBPassword    string
	DBName        string
	JWTPublic     string
	JWTPrivate    string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	AccountSID    string
	AuthToken     string
	ServiceSID    string
	FromPhone     string
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		logger.Log.Println("No .env file found")
	}

	return &Config{
		DBHost:        getEnv("DB_HOST", "localhost"),
		DBPort:        getEnv("DB_PORT", "5432"),
		DBUser:        getEnv("DB_USER", "auth_user"),
		DBPassword:    getEnv("DB_PASSWORD", "auth_password"),
		DBName:        getEnv("DB_NAME", "auth"),
		JWTPublic:     getEnv("JWT_PUBLIC_KEY_PATH", "config/jwt_key/jwt_public.pem"),
		JWTPrivate:    getEnv("JWT_PRIVATE_KEY_PATH", "config/jwt_key/jwt_private.pem"),
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       0,
		AccountSID:    getEnv("ACCOUNT_SID", ""),
		AuthToken:     getEnv("AUTH_TOKEN", ""),
		ServiceSID:    getEnv("SERVICE_SID", ""),
		FromPhone:     getEnv("FROM_PHONE", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
