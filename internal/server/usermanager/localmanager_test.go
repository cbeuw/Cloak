package usermanager

import (
	"encoding/binary"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/stretchr/testify/assert"
)

var mockUID = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var mockWorldState = common.WorldOfTime(time.Unix(1, 0))
var mockUserInfo = UserInfo{
	UID:         mockUID,
	SessionsCap: JustInt32(10),
	UpRate:      JustInt64(100),
	DownRate:    JustInt64(1000),
	UpCredit:    JustInt64(10000),
	DownCredit:  JustInt64(100000),
	ExpiryTime:  JustInt64(1000000),
}

func makeManager(t *testing.T) (mgr *localManager, cleaner func()) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	cleaner = func() { os.Remove(tmpDB.Name()) }
	mgr, err := MakeLocalManager(tmpDB.Name(), mockWorldState)
	if err != nil {
		t.Fatal(err)
	}
	return mgr, cleaner
}

func TestLocalManager_WriteUserInfo(t *testing.T) {
	mgr, cleaner := makeManager(t)
	defer cleaner()

	err := mgr.WriteUserInfo(mockUserInfo)
	if err != nil {
		t.Error(err)
	}

	got, err := mgr.GetUserInfo(mockUID)
	assert.NoError(t, err)
	assert.EqualValues(t, mockUserInfo, got)

	/* Partial update */
	err = mgr.WriteUserInfo(UserInfo{
		UID:         mockUID,
		SessionsCap: JustInt32(*mockUserInfo.SessionsCap + 1),
	})
	assert.NoError(t, err)

	expected := mockUserInfo
	expected.SessionsCap = JustInt32(*mockUserInfo.SessionsCap + 1)
	got, err = mgr.GetUserInfo(mockUID)
	assert.NoError(t, err)
	assert.EqualValues(t, expected, got)
}

func TestLocalManager_GetUserInfo(t *testing.T) {
	mgr, cleaner := makeManager(t)
	defer cleaner()

	t.Run("simple fetch", func(t *testing.T) {
		_ = mgr.WriteUserInfo(mockUserInfo)
		gotInfo, err := mgr.GetUserInfo(mockUID)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(gotInfo, mockUserInfo) {
			t.Errorf("got wrong user info: %v", gotInfo)
		}
	})

	t.Run("update a field", func(t *testing.T) {
		_ = mgr.WriteUserInfo(mockUserInfo)
		updatedUserInfo := mockUserInfo
		updatedUserInfo.SessionsCap = JustInt32(*mockUserInfo.SessionsCap + 1)

		err := mgr.WriteUserInfo(updatedUserInfo)
		if err != nil {
			t.Error(err)
		}

		gotInfo, err := mgr.GetUserInfo(mockUID)
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(gotInfo, updatedUserInfo) {
			t.Errorf("got wrong user info: %v", updatedUserInfo)
		}
	})

	t.Run("non existent user", func(t *testing.T) {
		_, err := mgr.GetUserInfo(make([]byte, 16))
		if err != ErrUserNotFound {
			t.Errorf("expecting error %v, got %v", ErrUserNotFound, err)
		}
	})
}

func TestLocalManager_DeleteUser(t *testing.T) {
	mgr, cleaner := makeManager(t)
	defer cleaner()

	_ = mgr.WriteUserInfo(mockUserInfo)
	err := mgr.DeleteUser(mockUID)
	if err != nil {
		t.Error(err)
	}

	_, err = mgr.GetUserInfo(mockUID)
	if err != ErrUserNotFound {
		t.Error("user not deleted")
	}
}

var validUserInfo = mockUserInfo

func TestLocalManager_AuthenticateUser(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	mgr, err := MakeLocalManager(tmpDB.Name(), mockWorldState)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("normal auth", func(t *testing.T) {
		_ = mgr.WriteUserInfo(validUserInfo)
		upRate, downRate, err := mgr.AuthenticateUser(validUserInfo.UID)
		if err != nil {
			t.Error(err)
		}

		if upRate != *validUserInfo.UpRate || downRate != *validUserInfo.DownRate {
			t.Error("wrong up or down rate")
		}
	})

	t.Run("non existent user", func(t *testing.T) {
		_, _, err := mgr.AuthenticateUser(make([]byte, 16))
		if err != ErrUserNotFound {
			t.Error("user found")
		}
	})

	t.Run("expired user", func(t *testing.T) {
		expiredUserInfo := validUserInfo
		expiredUserInfo.ExpiryTime = JustInt64(mockWorldState.Now().Add(-10 * time.Second).Unix())

		_ = mgr.WriteUserInfo(expiredUserInfo)

		_, _, err := mgr.AuthenticateUser(expiredUserInfo.UID)
		if err != ErrUserExpired {
			t.Error("user not expired")
		}
	})

	t.Run("no credit", func(t *testing.T) {
		creditlessUserInfo := validUserInfo
		creditlessUserInfo.UpCredit, creditlessUserInfo.DownCredit = JustInt64(-1), JustInt64(-1)

		_ = mgr.WriteUserInfo(creditlessUserInfo)

		_, _, err := mgr.AuthenticateUser(creditlessUserInfo.UID)
		if err != ErrNoUpCredit && err != ErrNoDownCredit {
			t.Error("user not creditless")
		}
	})
}

func TestLocalManager_AuthoriseNewSession(t *testing.T) {
	mgr, cleaner := makeManager(t)
	defer cleaner()

	t.Run("normal auth", func(t *testing.T) {
		_ = mgr.WriteUserInfo(validUserInfo)
		err := mgr.AuthoriseNewSession(validUserInfo.UID, AuthorisationInfo{NumExistingSessions: 0})
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("non existent user", func(t *testing.T) {
		err := mgr.AuthoriseNewSession(make([]byte, 16), AuthorisationInfo{NumExistingSessions: 0})
		if err != ErrUserNotFound {
			t.Error("user found")
		}
	})

	t.Run("expired user", func(t *testing.T) {
		expiredUserInfo := validUserInfo
		expiredUserInfo.ExpiryTime = JustInt64(mockWorldState.Now().Add(-10 * time.Second).Unix())

		_ = mgr.WriteUserInfo(expiredUserInfo)
		err := mgr.AuthoriseNewSession(expiredUserInfo.UID, AuthorisationInfo{NumExistingSessions: 0})
		if err != ErrUserExpired {
			t.Error("user not expired")
		}
	})

	t.Run("too many sessions", func(t *testing.T) {
		_ = mgr.WriteUserInfo(validUserInfo)
		err := mgr.AuthoriseNewSession(validUserInfo.UID, AuthorisationInfo{NumExistingSessions: int(*validUserInfo.SessionsCap + 1)})
		if err != ErrSessionsCapReached {
			t.Error("session cap not reached")
		}
	})
}

func TestLocalManager_UploadStatus(t *testing.T) {
	mgr, cleaner := makeManager(t)
	defer cleaner()

	t.Run("simple update", func(t *testing.T) {
		_ = mgr.WriteUserInfo(validUserInfo)

		update := StatusUpdate{
			UID:        validUserInfo.UID,
			Active:     true,
			NumSession: 1,
			UpUsage:    10,
			DownUsage:  100,
			Timestamp:  mockWorldState.Now().Unix(),
		}

		_, err := mgr.UploadStatus([]StatusUpdate{update})
		if err != nil {
			t.Error(err)
		}

		updatedUserInfo, err := mgr.GetUserInfo(validUserInfo.UID)
		if err != nil {
			t.Error(err)
		}

		if *updatedUserInfo.UpCredit != *validUserInfo.UpCredit-update.UpUsage {
			t.Error("up usage incorrect")
		}
		if *updatedUserInfo.DownCredit != *validUserInfo.DownCredit-update.DownUsage {
			t.Error("down usage incorrect")
		}
	})

	badUpdates := []struct {
		name   string
		user   UserInfo
		update StatusUpdate
	}{
		{"out of up credit",
			validUserInfo,
			StatusUpdate{
				UID:        validUserInfo.UID,
				Active:     true,
				NumSession: 1,
				UpUsage:    *validUserInfo.UpCredit + 100,
				DownUsage:  0,
				Timestamp:  mockWorldState.Now().Unix(),
			},
		},
		{"out of down credit",
			validUserInfo,
			StatusUpdate{
				UID:        validUserInfo.UID,
				Active:     true,
				NumSession: 1,
				UpUsage:    0,
				DownUsage:  *validUserInfo.DownCredit + 100,
				Timestamp:  mockWorldState.Now().Unix(),
			},
		},
		{"expired",
			UserInfo{
				UID:         mockUID,
				SessionsCap: JustInt32(10),
				UpRate:      JustInt64(0),
				DownRate:    JustInt64(0),
				UpCredit:    JustInt64(0),
				DownCredit:  JustInt64(0),
				ExpiryTime:  JustInt64(-1),
			},
			StatusUpdate{
				UID:        mockUserInfo.UID,
				Active:     true,
				NumSession: 1,
				UpUsage:    0,
				DownUsage:  0,
				Timestamp:  mockWorldState.Now().Unix(),
			},
		},
	}

	for _, badUpdate := range badUpdates {
		t.Run(badUpdate.name, func(t *testing.T) {
			_ = mgr.WriteUserInfo(badUpdate.user)
			resps, err := mgr.UploadStatus([]StatusUpdate{badUpdate.update})
			if err != nil {
				t.Error(err)
			}

			if len(resps) == 0 {
				t.Fatal("expecting responses")
			}

			resp := resps[0]
			if resp.Action != TERMINATE {
				t.Errorf("didn't terminate when %v", badUpdate.name)
			}
		})

	}
}

func TestLocalManager_ListAllUsers(t *testing.T) {
	mgr, cleaner := makeManager(t)
	defer cleaner()

	var wg sync.WaitGroup
	var users []UserInfo
	for i := 0; i < 100; i++ {
		randUID := make([]byte, 16)
		rand.Read(randUID)
		newUser := UserInfo{
			UID:         randUID,
			SessionsCap: JustInt32(rand.Int31()),
			UpRate:      JustInt64(rand.Int63()),
			DownRate:    JustInt64(rand.Int63()),
			UpCredit:    JustInt64(rand.Int63()),
			DownCredit:  JustInt64(rand.Int63()),
			ExpiryTime:  JustInt64(rand.Int63()),
		}
		users = append(users, newUser)
		wg.Add(1)
		go func() {
			err := mgr.WriteUserInfo(newUser)
			if err != nil {
				t.Fatal(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	listedUsers, err := mgr.ListAllUsers()
	if err != nil {
		t.Error(err)
	}

	sort.Slice(users, func(i, j int) bool {
		return binary.BigEndian.Uint64(users[i].UID[0:8]) < binary.BigEndian.Uint64(users[j].UID[0:8])
	})
	sort.Slice(listedUsers, func(i, j int) bool {
		return binary.BigEndian.Uint64(listedUsers[i].UID[0:8]) < binary.BigEndian.Uint64(listedUsers[j].UID[0:8])
	})
	if !reflect.DeepEqual(users, listedUsers) {
		t.Error("listed users deviates from uploaded ones")
	}
}
