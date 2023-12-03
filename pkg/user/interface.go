package user

import (
	"database/sql"
	"quiz-app/pkg/entity"
)

type Reader interface {
	FindByID(user_id int64) (*entity.User, *entity.AppError)
	FindByUsername(username string) (*entity.User, *entity.AppError)
	FindByUsernameAndReturnPassword(username string) (*entity.User, *entity.AppError)
}

type Writer interface {
	UpdateWithLastLoginAt(user_id int64) (sql.Result, *entity.AppError)
}

// Repository interface
type Repository interface {
	Reader
	Writer
}
