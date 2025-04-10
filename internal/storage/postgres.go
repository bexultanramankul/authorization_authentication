package storage

import (
	"authorization_authentication/config"
	"authorization_authentication/pkg/logger"
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/lib/pq"
)

var (
	DB   *sql.DB
	once sync.Once
)

func InitDB() {
	log := logger.Log

	once.Do(func() {
		cfg := config.LoadConfig()

		dsn := fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName,
		)

		var err error
		DB, err = sql.Open("postgres", dsn)
		if err != nil {
			log.Fatal("Database connection error: ", err)
		}

		if err = DB.Ping(); err != nil {
			log.Fatal("Database is unreachable: ", err)
		}

		log.Info("Connected to PostgreSQL")
	})
}

func CloseDB() {
	if DB != nil {
		if err := DB.Close(); err != nil {
			logger.Log.Warn("Error closing storage: ", err)
		} else {
			logger.Log.Info("Database connection closed")
		}
	}
}
