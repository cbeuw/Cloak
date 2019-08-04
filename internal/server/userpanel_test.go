package server

import (
	"encoding/base64"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"os"
	"testing"
)

const MOCK_DB_NAME = "userpanel_test_mock_database.db"

func TestUserPanel_BypassUser(t *testing.T) {
	manager, err := usermanager.MakeLocalManager(MOCK_DB_NAME)
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
		if user.valve.GetRx() != 10 || user.valve.GetTx() != 10 {
			t.Error("user rx or tx info altered")
		}
		if _, inQ := panel.usageUpdateQueue[user.arrUID]; inQ {
			t.Error("user in update queue")
		}
	})
	t.Run("updateUsageQueueForOne", func(t *testing.T) {
		panel.updateUsageQueueForOne(user)
		if user.valve.GetRx() != 10 || user.valve.GetTx() != 10 {
			t.Error("user rx or tx info altered")
		}
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
	t.Run("DeleteActiveUser", func(t *testing.T) {
		panel.DeleteActiveUser(user)
		if panel.isActive(user.arrUID[:]) {
			t.Error("user still active after deletion", err)
		}
	})
	t.Run("Repeated delete", func(t *testing.T) {
		panel.DeleteActiveUser(user)
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
