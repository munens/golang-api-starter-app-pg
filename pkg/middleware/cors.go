package middleware

import (
	"github.com/rs/cors"
	"quiz-app/config"
)

var Cors = cors.New(cors.Options{
	AllowedOrigins:   []string{config.RequestOriginURL},
	AllowedHeaders:   []string{"*"},
	AllowCredentials: true,
	ExposedHeaders:   []string{"Authorization", "Access-Control-Allow-Origin"},
	MaxAge:           5,
})
