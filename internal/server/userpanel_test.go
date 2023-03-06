package server

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
)

func TestUserPanel_BypassUser(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())

	manager, err := usermanager.MakeLocalManager(tmpDB.Name(), common.RealWorldState)
	if err != nil {
		t.Error("failed to make local manager", err)
	}
	panel := MakeUserPanel(manager)
	UID, _ := base64.StdEncoding.DecodeString("u97xvcc5YoQA8obCyt9q/w==")
	user, _ := panel.GetBypassUser(UID)
	user.valve.AddRx(10)
	user.valve.AddTx(10)
	t.Run("isActive", func(t *testing.T) {
		a := panel.isActive(UID)
		if !a {
			t.Error("isActive returned ", a)
		}
	})
	t.Run("updateUsageQueue", func(t *testing.T) {
		panel.updateUsageQueue()
		if _, inQ := panel.usageUpdateQueue[user.arrUID]; inQ {
			t.Error("user in update queue")
		}
	})
	t.Run("updateUsageQueueForOne", func(t *testing.T) {
		panel.updateUsageQueueForOne(user)
		if _, inQ := panel.usageUpdateQueue[user.arrUID]; inQ {
			t.Error("user in update queue")
		}
	})
	t.Run("commitUpdate", func(t *testing.T) {
		err := panel.commitUpdate()
		if err != nil {
			t.Error("commit returned", err)
		}
	})
	t.Run("TerminateActiveUser", func(t *testing.T) {
		panel.TerminateActiveUser(user, "")
		if panel.isActive(user.arrUID[:]) {
			t.Error("user still active after deletion", err)
		}
	})
	t.Run("Repeated delete", func(t *testing.T) {
		panel.TerminateActiveUser(user, "")
	})
	err = manager.Close()
	if err != nil {
		t.Error("failed to close localmanager", err)
	}
}

var mockUID = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var mockWorldState = common.WorldOfTime(time.Unix(1, 0))
var validUserInfo = usermanager.UserInfo{
	UID:         mockUID,
	SessionsCap: usermanager.JustInt32(10),
	UpRate:      usermanager.JustInt64(100),
	DownRate:    usermanager.JustInt64(1000),
	UpCredit:    usermanager.JustInt64(10000),
	DownCredit:  usermanager.JustInt64(100000),
	ExpiryTime:  usermanager.JustInt64(1000000),
}

func TestUserPanel_GetUser(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	mgr, err := usermanager.MakeLocalManager(tmpDB.Name(), mockWorldState)
	if err != nil {
		t.Fatal(err)
	}
	panel := MakeUserPanel(mgr)

	t.Run("normal user", func(t *testing.T) {
		_ = mgr.WriteUserInfo(validUserInfo)

		activeUser, err := panel.GetUser(validUserInfo.UID)
		if err != nil {
			t.Error(err)
		}

		again, err := panel.GetUser(validUserInfo.UID)
		if err != nil {
			t.Errorf("can't get existing user: %v", err)
		}

		if activeUser != again {
			t.Error("got different references")
		}
	})
	t.Run("non existent user", func(t *testing.T) {
		_, err = panel.GetUser(make([]byte, 16))
		if err != usermanager.ErrUserNotFound {
			t.Errorf("expecting error %v, got %v", usermanager.ErrUserNotFound, err)
		}
	})
}

func TestUserPanel_UpdateUsageQueue(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	mgr, err := usermanager.MakeLocalManager(tmpDB.Name(), mockWorldState)
	if err != nil {
		t.Fatal(err)
	}
	panel := MakeUserPanel(mgr)

	t.Run("normal update", func(t *testing.T) {
		_ = mgr.WriteUserInfo(validUserInfo)

		user, err := panel.GetUser(validUserInfo.UID)
		if err != nil {
			t.Error(err)
		}

		user.valve.AddTx(1)
		user.valve.AddRx(2)
		panel.updateUsageQueue()
		err = panel.commitUpdate()
		if err != nil {
			t.Error(err)
		}

		if user.valve.GetRx() != 0 || user.valve.GetTx() != 0 {
			t.Error("rx and tx stats are not cleared")
		}

		updatedUinfo, _ := mgr.GetUserInfo(validUserInfo.UID)
		if *updatedUinfo.DownCredit != *validUserInfo.DownCredit-1 {
			t.Error("down credit incorrect update")
		}
		if *updatedUinfo.UpCredit != *validUserInfo.UpCredit-2 {
			t.Error("up credit incorrect update")
		}

		// another update
		user.valve.AddTx(3)
		user.valve.AddRx(4)
		panel.updateUsageQueue()
		err = panel.commitUpdate()
		if err != nil {
			t.Error(err)
		}

		updatedUinfo, _ = mgr.GetUserInfo(validUserInfo.UID)
		if *updatedUinfo.DownCredit != *validUserInfo.DownCredit-(1+3) {
			t.Error("down credit incorrect update")
		}
		if *updatedUinfo.UpCredit != *validUserInfo.UpCredit-(2+4) {
			t.Error("up credit incorrect update")
		}
	})
	t.Run("terminating update", func(t *testing.T) {
		_ = mgr.WriteUserInfo(validUserInfo)

		user, err := panel.GetUser(validUserInfo.UID)
		if err != nil {
			t.Error(err)
		}

		user.valve.AddTx(*validUserInfo.DownCredit + 100)
		panel.updateUsageQueue()
		err = panel.commitUpdate()
		if err != nil {
			t.Error(err)
		}

		if panel.isActive(validUserInfo.UID) {
			t.Error("user not terminated")
		}

		updatedUinfo, _ := mgr.GetUserInfo(validUserInfo.UID)
		if *updatedUinfo.DownCredit != -100 {
			t.Error("down credit not updated correctly after the user has been terminated")
		}
	})
}
