package handlers

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"quiz-app/pkg/entity"
	accessCtrl "quiz-app/pkg/middleware/access-control"
	"quiz-app/pkg/user"
)

func UserHandlers(router *mux.Router, accessCtrlService *accessCtrl.Service, service *user.Service) {

	authenticateHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u *entity.User
		errorMsg := "Unable to authenticate user"
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte(errorMsg)); err != nil {
				log.Println(err)
			}

			return
		}

		if u.Username == "" || u.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			if _, err := w.Write([]byte(errorMsg)); err != nil {
				log.Println(err)
			}

			return
		}

		authUser, err := service.AuthenticateUser(u.Username, u.Password)

		if err != nil {
			log.Println(err)
			if err == entity.ErrSecretKey || err == entity.ErrJwtCreation {
				w.WriteHeader(http.StatusInternalServerError)
				if _, err := w.Write([]byte(errorMsg)); err != nil {
					log.Println(err)
				}

				return
			}

			w.WriteHeader(http.StatusForbidden)
			if _, err := w.Write([]byte(errorMsg)); err != nil {
				log.Println(err)
			}

			return
		}

		if err := json.NewEncoder(w).Encode(authUser); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte(errorMsg)); err != nil {
				log.Println(err)
			}
		}

	})

	userHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		username := vars["username"]
		errorMsg := "Error finding user"

		u, err := service.GetUserByUsername(username)

		if u == nil {
			w.WriteHeader(http.StatusNotFound)
			log.Println(err)
			if _, err := w.Write([]byte(errorMsg)); err != nil {
				log.Println(err)
			}
			return
		}

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte(errorMsg)); err != nil {
				log.Println(err)
			}
			return
		}

		if err := json.NewEncoder(w).Encode(u); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte(errorMsg)); err != nil {
				log.Println(err)
			}
			return
		}
	})

	router.Handle("/user/authenticate", authenticateHandler).Methods("POST", "OPTIONS")
	router.Handle("/users/{username}", accessCtrlService.IsUserAuthenticated(userHandler)).Methods("GET", "OPTIONS")
}
