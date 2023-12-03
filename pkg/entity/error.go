package entity

import (
	"errors"
	"fmt"
)

// AppError is a global error type
type AppError struct {
	AppError error
	Msg      string
}

// NewAppError creates a new app error
func NewAppError(err error) *AppError {
	return &AppError{
		AppError: err,
		Msg:      err.Error(),
	}
}

// Wrap wraps an AppError, e with an AppError with message, s.
func (e *AppError) Wrap(err error) *AppError {
	return &AppError{
		AppError: err,
		Msg:      fmt.Sprintf("%s: [%s]", err, e.Error()),
	}
}

// Error returns an error message
func (e *AppError) Error() string {
	return e.Msg
}

func (e *AppError) Is(target error) bool {
	return e.Error() == target.Error()
}

func (e *AppError) As(target interface{}) bool {
	if ok := target.(AppError).AppError; ok != nil {
		return true
	}

	return false
}

// TODO:
// - create method to display all errors including wrapped ones
// - write tests

// ErrSecretKey is the motherland global error for a secret key that could not be found:
var ErrSecretKey = NewAppError(errors.New("secret key not found"))

var ErrJwtCreation = NewAppError(errors.New("unable to create jwt string"))

var ErrAppToken = NewAppError(errors.New("unable to authenticate token"))

var ErrEntityNotFound = NewAppError(errors.New("entity could not be found"))
