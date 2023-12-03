package main

import (
	"database/sql"
	b64 "encoding/base64"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"quiz-app/api/handlers"
	"quiz-app/config"
	"quiz-app/pkg/middleware"
	accessCtrl "quiz-app/pkg/middleware/access-control"
	"quiz-app/pkg/user"
	"time"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("No .env file found")
	}
}

func main() {

	// encode password for database connection
	encodedPassword := string(b64.URLEncoding.EncodeToString([]byte(config.DBPassword)))

	// determine ssl mode
	sslMode := "disable"
	if config.Env == "production" {
		sslMode = "verify-full"
	}

	// connection string for db connection
	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", config.DBUser, encodedPassword, config.DBHost, config.DBPort, config.DBName, sslMode)
	// database connection
	pool, err := sql.Open("postgres", connString)
	// await database connection before continuing execution:
	defer func(pool *sql.DB) {
		err := pool.Close()
		if err != nil {
			log.Fatal("unable to close db pool")
		}
	}(pool)

	// if error with database connection
	if err != nil {
		log.Fatal(err)
	}

	// define repositories:
	accessCtrlRepo := accessCtrl.InitRepo(pool)
	userRepo := user.InitRepo(pool)

	// provide repository to services:
	accessCtrlService := accessCtrl.InitService(accessCtrlRepo)
	userService := user.InitService(userRepo)

	// create request multiplexer
	router := mux.NewRouter()

	http.Handle("/", middleware.Cors.Handler(router))

	router.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// pass services to handlers (controllers):
	handlers.UserHandlers(router, accessCtrlService, userService)

	server := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Addr:         fmt.Sprintf(":%s", config.Port),
		Handler:      middleware.Cors.Handler(router),
	}

	log.Println(fmt.Sprintf("Server to listen at port=%s", config.Port))
	err = server.ListenAndServe()
	if err != nil {
		log.Println("Unable to run server")
		log.Fatal(err.Error())
	}

	log.Println(fmt.Sprintf("Server listening at port=%s", config.Port))
}
