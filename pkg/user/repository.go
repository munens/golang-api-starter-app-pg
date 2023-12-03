package user

import (
	"database/sql"
	"quiz-app/pkg/entity"
	"time"
)

type PGRepository struct {
	pool *sql.DB
}

func InitRepo(p *sql.DB) *PGRepository {
	return &PGRepository{
		pool: p,
	}
}

func (r PGRepository) FindByID(userId int64) (*entity.User, *entity.AppError) {
	var id int64
	var username string
	var createdAt time.Time
	query := "select id, username, created_at from users where id=$1"
	err := r.pool.QueryRow(query, userId).Scan(&id, &username, &createdAt)

	if err != nil {
		return nil, entity.NewAppError(err)
	}

	if sql.ErrNoRows == err {
		return nil, entity.ErrEntityNotFound
	}

	user := entity.User{Id: id, Username: username, CreatedAt: createdAt}
	return &user, nil
}

func (r PGRepository) FindByUsername(username string) (*entity.User, *entity.AppError) {
	var id int64
	var userName string
	var createdAt time.Time

	query := "select id, username, created_at from users where username=$1"
	err := r.pool.QueryRow(query, username).Scan(&id, &userName, &createdAt)

	if err == sql.ErrNoRows {
		return nil, entity.ErrEntityNotFound
	}

	if err != nil {
		return nil, entity.NewAppError(err)
	}

	user := entity.User{Id: id, Username: userName, CreatedAt: createdAt}
	return &user, nil
}

func (r PGRepository) FindByUsernameAndReturnPassword(username string) (*entity.User, *entity.AppError) {
	var id int64
	var userName string
	var password string
	var createdAt time.Time

	query := "select id, username, password, created_at from users where username=$1"
	err := r.pool.QueryRow(query, username).Scan(&id, &userName, &password, &createdAt)

	if err == sql.ErrNoRows {
		return nil, entity.ErrEntityNotFound
	}

	if err != nil {
		return nil, entity.NewAppError(err)
	}

	user := entity.User{Id: id, Username: userName, Password: password, CreatedAt: createdAt}
	return &user, nil
}

func (r PGRepository) UpdateWithLastLoginAt(userId int64) (sql.Result, *entity.AppError) {

	query := "update users set last_login_at=$1 where id=$2"
	now := time.Now().UTC()

	res, err := r.pool.Exec(query, now, userId)
	if err != nil {
		return nil, entity.NewAppError(err)
	}

	return res, nil
}
