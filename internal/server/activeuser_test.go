package server

import (
	"encoding/base64"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"os"
	"testing"
)

func TestActiveUser_Bypass(t *testing.T) {
	manager, err := usermanager.MakeLocalManager(MOCK_DB_NAME)
	if err != nil {
		t.Error("failed to make local manager", err)
	}
	panel := MakeUserPanel(manager)
	UID, _ := base64.StdEncoding.DecodeString("u97xvcc5YoQA8obCyt9q/w==")
	user, _ := panel.GetBypassUser(UID)
	var sesh0 *mux.Session
	var existing bool
	var sesh1 *mux.Session
	t.Run("get first session", func(t *testing.T) {
		sesh0, existing, err = user.GetSession(0, &mux.SessionConfig{})
		if err != nil {
			t.Error(err)
		}
		if existing {
			t.Error("first session returned as existing")
		}
		if sesh0 == nil {
			t.Error("no session returned")
		}
	})
	t.Run("get first session again", func(t *testing.T) {
		seshx, existing, err := user.GetSession(0, &mux.SessionConfig{})
		if err != nil {
			t.Error(err)
		}
		if !existing {
			t.Error("first session get again returned as not existing")
		}
		if seshx == nil {
			t.Error("no session returned")
		}
		if seshx != sesh0 {
			t.Error("returned a different instance")
		}
	})
	t.Run("get second session", func(t *testing.T) {
		sesh1, existing, err = user.GetSession(1, &mux.SessionConfig{})
		if err != nil {
			t.Error(err)
		}
		if existing {
			t.Error("second session returned as existing")
		}
		if sesh0 == nil {
			t.Error("no session returned")
		}
	})
	t.Run("number of sessions", func(t *testing.T) {
		if user.NumSession() != 2 {
			t.Error("number of session is not 2")
		}
	})
	t.Run("delete a session", func(t *testing.T) {
		user.DeleteSession(0, "")
		if user.NumSession() != 1 {
			t.Error("number of session is not 1 after deleting one")
		}
		if !sesh0.IsClosed() {
			t.Error("session not closed after deletion")
		}
	})
	t.Run("terminating user", func(t *testing.T) {
		user.Terminate("")
		if panel.isActive(user.arrUID[:]) {
			t.Error("user is still active after termination")
		}
		if !sesh1.IsClosed() {
			t.Error("session not closed after user termination")
		}
	})
	t.Run("get session again after termination", func(t *testing.T) {
		seshx, existing, err := user.GetSession(0, &mux.SessionConfig{})
		if err != nil {
			t.Error(err)
		}
		if existing {
			t.Error("session returned as existing")
		}
		if seshx == nil {
			t.Error("no session returned")
		}
		if seshx == sesh0 || seshx == sesh1 {
			t.Error("get session after termination returned the same instance")
		}
	})
	t.Run("delete last session", func(t *testing.T) {
		user.DeleteSession(0, "")
		if panel.isActive(user.arrUID[:]) {
			t.Error("user still active after last session deleted")
		}
	})
	err = manager.Close()
	if err != nil {
		t.Error("failed to close localmanager", err)
	}
	err = os.Remove(MOCK_DB_NAME)
	if err != nil {
		t.Error("failed to delete mockdb", err)
	}
}
