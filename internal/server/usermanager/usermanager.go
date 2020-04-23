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

type UserInfo struct {
	UID         []byte
	SessionsCap int32
	UpRate      int64
	DownRate    int64
	UpCredit    int64
	DownCredit  int64
	ExpiryTime  int64
}

type StatusResponse struct {
	UID     []byte
	Action  int
	Message string
}

type AuthorisationInfo struct {
	NumExistingSessions int
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
	AuthoriseNewSession([]byte, AuthorisationInfo) error
	UploadStatus([]StatusUpdate) ([]StatusResponse, error)
	ListAllUsers() ([]UserInfo, error)
	GetUserInfo(UID []byte) (UserInfo, error)
	WriteUserInfo(UserInfo) error
	DeleteUser(UID []byte) error
}
