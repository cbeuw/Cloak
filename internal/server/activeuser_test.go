package server

import (
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cbeuw/Cloak/internal/common"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
)

func getSeshConfig(unordered bool) mux.SessionConfig {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	obfuscator, _ := mux.MakeObfuscator(0x00, sessionKey)

	seshConfig := mux.SessionConfig{
		Obfuscator: obfuscator,
		Valve:      nil,
		Unordered:  unordered,
	}
	return seshConfig
}

func TestActiveUser_Bypass(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())

	manager, err := usermanager.MakeLocalManager(tmpDB.Name(), common.RealWorldState)
	if err != nil {
		t.Fatal("failed to make local manager", err)
	}
	panel := MakeUserPanel(manager)
	UID, _ := base64.StdEncoding.DecodeString("u97xvcc5YoQA8obCyt9q/w==")
	user, _ := panel.GetBypassUser(UID)
	var sesh0 *mux.Session
	var existing bool
	var sesh1 *mux.Session

	// get first session
	sesh0, existing, err = user.GetSession(0, getSeshConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	if existing {
		t.Fatal("get first session: first session returned as existing")
	}
	if sesh0 == nil {
		t.Fatal("get first session: no session returned")
	}

	// get first session again
	seshx, existing, err := user.GetSession(0, mux.SessionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !existing {
		t.Fatal("get first session again: first session get again returned as not existing")
	}
	if seshx == nil {
		t.Fatal("get first session again: no session returned")
	}
	if seshx != sesh0 {
		t.Fatal("returned a different instance")
	}

	// get second session
	sesh1, existing, err = user.GetSession(1, getSeshConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	if existing {
		t.Fatal("get second session: second session returned as existing")
	}
	if sesh1 == nil {
		t.Fatal("get second session: no session returned")
	}

	if user.NumSession() != 2 {
		t.Fatal("number of session is not 2")
	}

	user.CloseSession(0, "")
	if user.NumSession() != 1 {
		t.Fatal("number of session is not 1 after deleting one")
	}
	if !sesh0.IsClosed() {
		t.Fatal("session not closed after deletion")
	}

	user.closeAllSessions("")
	if !sesh1.IsClosed() {
		t.Fatal("session not closed after user termination")
	}

	// get session again after termination
	seshy, existing, err := user.GetSession(0, getSeshConfig(false))
	if err != nil {
		t.Fatal(err)
	}
	if existing {
		t.Fatal("get session again after termination: session returned as existing")
	}
	if seshy == nil {
		t.Fatal("get session again after termination: no session returned")
	}
	if seshy == sesh0 || seshy == sesh1 {
		t.Fatal("get session after termination returned the same instance")
	}

	user.CloseSession(0, "")
	if panel.isActive(user.arrUID[:]) {
		t.Fatal("user still active after last session deleted")
	}

	err = manager.Close()
	if err != nil {
		t.Fatal("failed to close localmanager", err)
	}
}
