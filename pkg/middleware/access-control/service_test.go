package access_control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/http/httptest"
	"os"
	"quiz-app/pkg/entity"
	mockAccessCtrl "quiz-app/pkg/mocks/access-control"
	"reflect"
	"testing"
	"time"
)

func TestParseJwt(t *testing.T) {

	t.Run("parseJwt should return an error when token is an empty string", func(t *testing.T) {
		_, err := parseJwt("")

		if err == nil {
			t.Fail()
		}

		if err.Error() != "jwt token has been malformed" {
			t.Fail()
		}
	})

	t.Run("parseJwt should return an error wrong signing method is used", func(t *testing.T) {

		claims := struct {
			hello string
			jwt.StandardClaims
		}{
			hello: "hello",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("unable to create PS256 key: [%s]", err)
		}

		tokenString, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		_, err = parseJwt(tokenString)

		if err == nil {
			t.Fail()
		}

		if err.Error() != "jwt token has expired or is not valid yet" {
			t.Fail()
		}
	})

	t.Run("parseJwt should return an error when SECRET_KEY environment value cant be found", func(t *testing.T) {

		claims := struct {
			hello string
			jwt.StandardClaims
		}{
			hello: "hello",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString([]byte("hello"))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Unsetenv("SECRET_KEY"); err != nil {
			t.Fatalf("unable to unset env secret key: [%s]", err)
		}

		_, err = parseJwt(tokenString)

		if err == nil {
			t.Fail()
		}

		if err.Error() != "jwt token has expired or is not valid yet" {
			t.Fail()
		}
	})

	t.Run("parseJwt should return an error when token is invalid format", func(t *testing.T) {

		token, err := parseJwt("hello.hello")

		if token != nil {
			t.Fail()
		}

		if err == nil {
			t.Fail()
		}

		if err.Error() != "jwt token has been malformed" {
			t.Fail()
		}
	})

	t.Run("parseJwt should return a valid jwt token", func(t *testing.T) {
		claims := struct {
			hello string
			jwt.StandardClaims
		}{
			hello: "hello",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		token, err = parseJwt(tokenString)

		if err != nil {
			t.Fail()
		}

		if !token.Valid {
			t.Fail()
		}
	})
}

func TestGetToken(t *testing.T) {
	t.Run("getParsedToken should return error if request header does not have value for Authorization", func(t *testing.T) {

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		token, err := getParsedToken(r)

		if token != nil {
			t.Fail()
		}

		if err == nil {
			t.Fail()
		}

		if !errors.Is(err, entity.NewAppError("unable to find token")) {
			t.Fail()
		}
	})

	t.Run("getParsedToken should return error if authorization token cannot be parsed", func(t *testing.T) {

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "hello.hello")

		token, err := getParsedToken(r)

		if token != nil {
			t.Fail()
		}

		if err == nil {
			t.Fail()
		}

		if !errors.As(err, &entity.AppError{}) {
			t.Fail()
		}
	})

	t.Run("getParsedToken should return error if authorization token is parsed", func(t *testing.T) {

		claims := struct {
			hello string
			jwt.StandardClaims
		}{
			hello: "hello",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", tokenString)

		token, err = getParsedToken(r)

		if token == nil {
			t.Fail()
		}

		if err != nil {
			t.Fail()
		}

		if !token.Valid {
			t.Fail()
		}
	})
}

func TestIsUserAuthenticated(t *testing.T) {

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockRepo := mockAccessCtrl.NewMockRepository(mockCtrl)
	service := InitService(mockRepo)

	t.Run("isUserAuthenticated should return error if token authentication fails", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", "hello.hello")

		if err := service.isUserAuthenticated(w, r); err != nil {
			wErr := entity.WrapAppError(
				"unable to get token",
				entity.WrapAppError(
					"unable to authenticate token",
					entity.NewAppError("jwt token has been malformed")))
			if !errors.Is(err, wErr) {
				t.Fail()
			}
		} else {
			t.Fail()
		}
	})

	t.Run("isUserAuthenticated should return error if token has already expired", func(t *testing.T) {

		claims := entity.JwtClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().AddDate(0, 0, -1).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", tokenString)

		if err := service.isUserAuthenticated(w, r); err != nil {
			wErr := entity.WrapAppError(
				"unable to get token",
				entity.WrapAppError(
					"unable to authenticate token",
					entity.NewAppError("jwt token has expired or is not valid yet")))
			if !errors.Is(err, wErr) {
				t.Fail()
			}
		} else {
			t.Fail()
		}
	})

	t.Run("isUserAuthenticated should return nil if token is valid", func(t *testing.T) {

		claims := entity.JwtClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", tokenString)

		if err := service.isUserAuthenticated(w, r); err != nil {
			t.Fail()
		}
	})
}

func TestGetUser(t *testing.T) {

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockRepo := mockAccessCtrl.NewMockRepository(mockCtrl)
	service := InitService(mockRepo)

	t.Run("getUser should return error if token authentication fails", func(t *testing.T) {

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", "hello.hello")

		user, err := service.getUser(w, r)
		if err != nil {
			wErr := entity.WrapAppError(
				"unable to get token",
				entity.WrapAppError(
					"unable to authenticate token",
					entity.NewAppError("jwt token has been malformed")))
			if !errors.Is(err, wErr) {
				t.Fail()
			}
		}

		if user != nil {
			t.Fail()
		}
	})

	t.Run("getUser should return error if token has already expired", func(t *testing.T) {

		claims := entity.JwtClaims{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().AddDate(0, 0, -1).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", tokenString)

		user, err := service.getUser(w, r)
		if err != nil {
			wErr := entity.WrapAppError(
				"unable to get token",
				entity.WrapAppError(
					"unable to authenticate token",
					entity.NewAppError("jwt token has expired or is not valid yet")))
			if !errors.Is(err, wErr) {
				t.Fail()
			}
		}

		if user != nil {
			t.Fail()
		}
	})

	t.Run("getUser should return error if jwt claims cant be retrieved", func(t *testing.T) {

		claims := jwt.StandardClaims{}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", tokenString)

		user, err := service.getUser(w, r)
		if err != nil {
			if !errors.Is(err, entity.NewAppError("unable to access jwt claims")) {
				t.Fail()
			}
		}

		if user != nil {
			t.Fail()
		}
	})

	t.Run("getUser should return error if user cannot be found", func(t *testing.T) {

		claims := entity.JwtClaims{
			UserId: 1,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", tokenString)

		mockRepo.EXPECT().FindById(int64(1)).Return(nil, entity.MlErrEntityNotFound)

		user, err := service.getUser(w, r)
		if err != nil {
			if !errors.Is(err, entity.WrapAppError("unable to get user", entity.MlErrEntityNotFound)) {
				t.Fail()
			}
		}

		if user != nil {
			t.Fail()
		}
	})

	t.Run("getUser should return a user if user can be found", func(t *testing.T) {
		userId := int64(1)
		username := "munens"
		claims := entity.JwtClaims{
			Username: username,
			UserId:   userId,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := "hello"
		tokenString, err := token.SignedString([]byte(key))
		if err != nil {
			t.Fatalf("unable to create jwt authentication string: [%s]", err)
		}

		if err := os.Setenv("SECRET_KEY", key); err != nil {
			t.Fatalf("unable to set SECRET_KEY: [%s]", err)
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Add("Authorization", tokenString)

		mockRepo.EXPECT().FindById(userId).Return(&entity.User{
			Id:       userId,
			Username: "munens",
		}, nil)

		user, err := service.getUser(w, r)
		if err != nil {
			t.Fail()
		}

		if user == nil {
			t.Fail()
		}

		u := reflect.TypeOf(user)
		if u.String() != "*entity.User" {
			t.Fail()
		}

		if user.Username != username {
			t.Fail()
		}
	})
}
