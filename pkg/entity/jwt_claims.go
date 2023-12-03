package entity

import "github.com/dgrijalva/jwt-go"

type JwtClaims struct {
	Username string `json:"username"`
	UserId  int64 `json:"userId"`
	jwt.StandardClaims
}