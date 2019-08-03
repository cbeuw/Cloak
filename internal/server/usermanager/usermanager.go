package usermanager

import (
	"errors"
)

type StatusUpdate struct {
	UID        []byte
	Active     bool
	NumSession int

	UpUsage   int64
	DownUsage int64
	Timestamp int64
}

type StatusResponse struct {
	UID     []byte
	Action  int
	Message string
}

const (
	TERMINATE = iota + 1
)

var ErrUserNotFound = errors.New("UID does not correspond to a user")
var ErrSessionsCapReached = errors.New("Sessions cap has reached")

var ErrNoUpCredit = errors.New("No upload credit left")
var ErrNoDownCredit = errors.New("No download credit left")
var ErrUserExpired = errors.New("User has expired")

type UserManager interface {
	AuthenticateUser([]byte) (int64, int64, error)
	AuthoriseNewSession([]byte, int) error
	UploadStatus([]StatusUpdate) ([]StatusResponse, error)
}
