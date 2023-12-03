package entity

import (
	"time"
)

type User struct {
	Id			  int64 `json:"id"`
	Username	  string `json:"username"`
	Password      string `json:"password"`
	CreatedAt     time.Time `json:"createdAt"`
	LastLoginAt   time.Time `json:"lastLoginAt"`
}
