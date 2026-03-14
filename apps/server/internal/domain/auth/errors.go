package auth

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailNotVerified   = errors.New("email_not_verified")
	ErrLocked             = errors.New("account_locked")
	ErrConflict           = errors.New("already_exists")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidToken       = errors.New("invalid_token")
	ErrExpiredToken       = errors.New("expired_token")
)
