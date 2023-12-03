package access_control

import "quiz-app/pkg/entity"

type reader interface {
	FindById(id int64) (*entity.User, *entity.AppError)
}

type writer interface {
}

type Repository interface {
	reader
	writer
}
