package access_control

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"os"
	"quiz-app/pkg/entity"
)

type Service struct {
	repo Repository
}

func InitService(r Repository) *Service {
	return &Service{
		repo: r,
	}
}

func (s *Service) IsUserAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.isUserAuthenticated(w, r); err != nil {
			log.Println(err.Error())
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Service) GetUser(next func(w http.ResponseWriter, r *http.Request, user *entity.User)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		user, err := s.getUser(w, r)

		if err != nil {
			log.Println(err.Error())
			return
		}

		next(w, r, user)
	})
}

func (s *Service) isUserAuthenticated(w http.ResponseWriter, r *http.Request) error {

	_, err := getParsedToken(r)
	if err != nil {
		if errors.Is(err, entity.ErrAppToken) {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}

		return err
	}

	return nil
}

func (s *Service) getUser(w http.ResponseWriter, r *http.Request) (*entity.User, error) {
	token, err := getParsedToken(r)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return nil, entity.NewAppError(err).Wrap(errors.New("unable to get token"))
	}

	userId := token.Claims.(*entity.JwtClaims).UserId
	if userId == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, entity.NewAppError(errors.New("unable to access jwt claims"))
	}

	user, err := s.repo.FindById(userId)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, entity.NewAppError(err).Wrap(errors.New("unable to get user"))
	}

	return user, nil
}

func getParsedToken(r *http.Request) (*jwt.Token, *entity.AppError) {
	//get token from header:
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return nil, entity.NewAppError(errors.New("unable to find token"))
	}

	// verify token string:
	token, err := parseJwt(tokenString)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func parseJwt(tokenString string) (*jwt.Token, *entity.AppError) {
	token, err := jwt.ParseWithClaims(tokenString, &entity.JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		// check token method:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, entity.NewAppError(errors.New("unable to determine token algorithm method"))
		}

		// get secret key:
		key, isFound := os.LookupEnv("SECRET_KEY")
		if isFound == false {
			return nil, entity.NewAppError(errors.New("unable to access secret key"))
		}

		return []byte(key), nil
	})

	if err, ok := err.(*jwt.ValidationError); ok {
		if err.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, entity.NewAppError(errors.New("jwt token has been malformed"))
		}

		if err.Errors&jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet != 0 {
			return nil, entity.NewAppError(errors.New("jwt token has expired or is not valid yet"))
		}
	}

	if token != nil && token.Valid {
		return token, nil
	}

	return nil, entity.NewAppError(err).Wrap(errors.New("jwt token could not be validated"))
}
