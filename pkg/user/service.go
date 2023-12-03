package user

import (
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"quiz-app/pkg/entity"
	"time"
)

type Service struct {
	repo Repository
}

type AuthUser struct {
	User  *entity.User `json:"user"`
	Token string       `json:"token"`
}

func InitService(r Repository) *Service {
	return &Service{
		repo: r,
	}
}

func (s *Service) createJWTTokenString(user *entity.User) (string, *entity.AppError) {

	// set expiration time:
	expirationTime := time.Now().Add(2 * time.Hour)

	claims := &entity.JwtClaims{
		Username: user.Username,
		UserId:   user.Id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	// create a token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// get secret key:
	key, isFound := os.LookupEnv("SECRET_KEY")
	if isFound == false {
		return "", entity.ErrSecretKey
	}

	// create token string:
	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		log.Println(err)
		tokenCreateError := entity.ErrJwtCreation
		return "", tokenCreateError
	}

	return tokenString, nil
}

func (s *Service) AuthenticateUser(username string, password string) (*AuthUser, *entity.AppError) {

	// get user with username
	user, err := s.repo.FindByUsernameAndReturnPassword(username)
	if err != nil {
		return nil, err
	}

	// compare user password with provided password:
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, entity.NewAppError(err)
	}

	// create JWT token
	jwtTokenString, err := s.createJWTTokenString(user)
	if err != nil {
		return nil, err
	}

	if _, err := s.repo.UpdateWithLastLoginAt(user.Id); err != nil {
		return nil, err
	}

	updatedUser, err := s.repo.FindByUsername(username)
	if err != nil {
		return nil, err
	}

	authenticatedUser := &entity.User{
		Id:          user.Id,
		Username:    user.Username,
		CreatedAt:   user.CreatedAt,
		LastLoginAt: updatedUser.LastLoginAt,
	}

	return &AuthUser{
		User:  authenticatedUser,
		Token: jwtTokenString,
	}, nil
}

func (s *Service) GetUserByID(userId int64) (*entity.User, error) {
	return s.repo.FindByID(userId)
}

func (s *Service) GetUserByUsername(username string) (*entity.User, error) {
	return s.repo.FindByUsername(username)
}
