package usermanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var v = &Voidmanager{}

func Test_Voidmanager_AuthenticateUser(t *testing.T) {
	_, _, err := v.AuthenticateUser([]byte{})
	assert.Equal(t, ErrMangerIsVoid, err)
}

func Test_Voidmanager_AuthoriseNewSession(t *testing.T) {
	err := v.AuthoriseNewSession([]byte{}, AuthorisationInfo{})
	assert.Equal(t, ErrMangerIsVoid, err)
}

func Test_Voidmanager_DeleteUser(t *testing.T) {
	err := v.DeleteUser([]byte{})
	assert.Equal(t, ErrMangerIsVoid, err)
}

func Test_Voidmanager_GetUserInfo(t *testing.T) {
	_, err := v.GetUserInfo([]byte{})
	assert.Equal(t, ErrMangerIsVoid, err)
}

func Test_Voidmanager_ListAllUsers(t *testing.T) {
	_, err := v.ListAllUsers()
	assert.Equal(t, ErrMangerIsVoid, err)
}

func Test_Voidmanager_UploadStatus(t *testing.T) {
	_, err := v.UploadStatus([]StatusUpdate{})
	assert.Equal(t, ErrMangerIsVoid, err)
}

func Test_Voidmanager_WriteUserInfo(t *testing.T) {
	err := v.WriteUserInfo(UserInfo{})
	assert.Equal(t, ErrMangerIsVoid, err)
}
