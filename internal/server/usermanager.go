package server

import (
	"errors"
)

type statusUpdate struct {
	UID        []byte
	active     bool
	numSession int

	upUsage   int64
	downUsage int64
	timestamp int64
}

var ErrUserNotFound = errors.New("UID does not correspond to a user")
var ErrSessionsCapReached = errors.New("Sessions cap has reached")
var ErrNoUpCredit = errors.New("No upload credit left")
var ErrNoDownCredit = errors.New("No download credit left")
var ErrUserExpired = errors.New("User has expired")

type UserManager interface {
	authenticateUser([]byte) (int64, int64, error)
	authoriseNewSession(*ActiveUser) error
	// TODO: fetch update's response
	uploadStatus([]statusUpdate) error
}
