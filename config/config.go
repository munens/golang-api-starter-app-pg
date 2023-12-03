package config

import (
	"github.com/joho/godotenv"
	"log"
	"os"
)

var DBName string
var DBUser string
var DBPassword string
var DBHost string
var DBPort string
var Env string
var Port string
var RequestOriginURL string
var UserPassword string

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("No .env file found")
	}

	DBName, _ = os.LookupEnv("DATABASE_NAME")
	DBUser, _ = os.LookupEnv("DATABASE_USER")
	DBPassword, _ = os.LookupEnv("DATABASE_PASSWORD")
	DBHost, _ = os.LookupEnv("DATABASE_HOST")
	DBPort, _ = os.LookupEnv("DATABASE_PORT")
	Env, _ = os.LookupEnv("ENVIRONMENT")
	Port, _ = os.LookupEnv("PORT")
	RequestOriginURL, _ = os.LookupEnv("REQUEST_ORIGIN_URL")
	UserPassword, _ = os.LookupEnv("USER_PASSWORD")
}
