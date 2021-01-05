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

type MaybeInt32 *int32
type MaybeInt64 *int64

type UserInfo struct {
	UID         []byte
	SessionsCap MaybeInt32
	UpRate      MaybeInt64
	DownRate    MaybeInt64
	UpCredit    MaybeInt64
	DownCredit  MaybeInt64
	ExpiryTime  MaybeInt64
}

func JustInt32(v int32) MaybeInt32 { return &v }

func JustInt64(v int64) MaybeInt64 { return &v }

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
var ErrMangerIsVoid = errors.New("cannot perform operation with user manager as database path is not specified")

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
