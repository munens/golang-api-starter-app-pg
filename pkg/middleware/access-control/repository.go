package access_control

import (
	"database/sql"
	"quiz-app/pkg/entity"
	"time"
)

type Repo struct {
	pool *sql.DB
}

func InitRepo(p *sql.DB) *Repo {
	return &Repo{
		pool: p,
	}
}

func (r *Repo) FindById(id int64) (*entity.User, *entity.AppError) {

	var userName string
	var createdAt time.Time
	var lastLoginAt time.Time

	queryStmt := "select id, username, created_at, last_login_at from users where id=$1"

	err := r.pool.QueryRow(queryStmt, id).Scan(&id, &userName, &createdAt, &lastLoginAt)

	if err == sql.ErrNoRows {
		return nil, entity.ErrEntityNotFound
	}

	if err != nil {
		return nil, entity.NewAppError(err)
	}

	return &entity.User{
		Id:          id,
		Username:    userName,
		CreatedAt:   createdAt,
		LastLoginAt: lastLoginAt,
	}, nil
}
