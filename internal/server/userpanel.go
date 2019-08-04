package server

import (
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"sync"
	"sync/atomic"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
)

type userPanel struct {
	Manager usermanager.UserManager

	activeUsersM      sync.RWMutex
	activeUsers       map[[16]byte]*ActiveUser
	usageUpdateQueueM sync.Mutex
	usageUpdateQueue  map[[16]byte]*usagePair
}

func MakeUserPanel(manager usermanager.UserManager) *userPanel {
	ret := &userPanel{
		Manager:          manager,
		activeUsers:      make(map[[16]byte]*ActiveUser),
		usageUpdateQueue: make(map[[16]byte]*usagePair),
	}
	go ret.regularQueueUpload()
	return ret
}

func (panel *userPanel) GetBypassUser(UID []byte) (*ActiveUser, error) {
	panel.activeUsersM.Lock()
	var arrUID [16]byte
	copy(arrUID[:], UID)
	if user, ok := panel.activeUsers[arrUID]; ok {
		panel.activeUsersM.Unlock()
		return user, nil
	}
	user := &ActiveUser{
		panel:    panel,
		valve:    mux.UNLIMITED_VALVE,
		sessions: make(map[uint32]*mux.Session),
		bypass:   true,
	}
	copy(user.arrUID[:], UID)
	panel.activeUsers[user.arrUID] = user
	panel.activeUsersM.Unlock()
	return user, nil
}

func (panel *userPanel) GetUser(UID []byte) (*ActiveUser, error) {
	panel.activeUsersM.Lock()
	var arrUID [16]byte
	copy(arrUID[:], UID)
	if user, ok := panel.activeUsers[arrUID]; ok {
		panel.activeUsersM.Unlock()
		return user, nil
	}

	upRate, downRate, err := panel.Manager.AuthenticateUser(UID)
	if err != nil {
		panel.activeUsersM.Unlock()
		return nil, err
	}
	valve := mux.MakeValve(upRate, downRate)
	user := &ActiveUser{
		panel:    panel,
		valve:    valve,
		sessions: make(map[uint32]*mux.Session),
	}

	copy(user.arrUID[:], UID)
	panel.activeUsers[user.arrUID] = user
	panel.activeUsersM.Unlock()
	return user, nil
}

func (panel *userPanel) DeleteActiveUser(user *ActiveUser) {
	panel.updateUsageQueueForOne(user)
	panel.activeUsersM.Lock()
	delete(panel.activeUsers, user.arrUID)
	panel.activeUsersM.Unlock()
}

func (panel *userPanel) isActive(UID []byte) bool {
	var arrUID [16]byte
	copy(arrUID[:], UID)
	panel.activeUsersM.RLock()
	_, ok := panel.activeUsers[arrUID]
	panel.activeUsersM.RUnlock()
	return ok
}

type usagePair struct {
	up   *int64
	down *int64
}

func (panel *userPanel) updateUsageQueue() {
	panel.activeUsersM.Lock()
	panel.usageUpdateQueueM.Lock()
	for _, user := range panel.activeUsers {
		if user.bypass {
			continue
		}

		upIncured, downIncured := user.valve.Nullify()
		if usage, ok := panel.usageUpdateQueue[user.arrUID]; ok {
			atomic.AddInt64(usage.up, upIncured)
			atomic.AddInt64(usage.down, downIncured)
		} else {
			// if the user hasn't been added to the queue
			usage = &usagePair{&upIncured, &downIncured}
			panel.usageUpdateQueue[user.arrUID] = usage
		}
	}
	panel.activeUsersM.Unlock()
	panel.usageUpdateQueueM.Unlock()
}

func (panel *userPanel) updateUsageQueueForOne(user *ActiveUser) {
	// used when one particular user deactivates
	if user.bypass {
		return
	}
	upIncured, downIncured := user.valve.Nullify()
	panel.usageUpdateQueueM.Lock()
	if usage, ok := panel.usageUpdateQueue[user.arrUID]; ok {
		atomic.AddInt64(usage.up, upIncured)
		atomic.AddInt64(usage.down, downIncured)
	} else {
		usage = &usagePair{&upIncured, &downIncured}
		panel.usageUpdateQueue[user.arrUID] = usage
	}
	panel.usageUpdateQueueM.Unlock()

}

func (panel *userPanel) commitUpdate() error {
	panel.usageUpdateQueueM.Lock()
	statuses := make([]usermanager.StatusUpdate, 0, len(panel.usageUpdateQueue))
	for arrUID, usage := range panel.usageUpdateQueue {
		panel.activeUsersM.RLock()
		user := panel.activeUsers[arrUID]
		panel.activeUsersM.RUnlock()
		var numSession int
		if user != nil {
			numSession = user.NumSession()
		}
		status := usermanager.StatusUpdate{
			UID:        arrUID[:],
			Active:     panel.isActive(arrUID[:]),
			NumSession: numSession,
			UpUsage:    *usage.up,
			DownUsage:  *usage.down,
			Timestamp:  time.Now().Unix(),
		}
		statuses = append(statuses, status)
	}

	responses, err := panel.Manager.UploadStatus(statuses)
	if err != nil {
		return err
	}
	for _, resp := range responses {
		var arrUID [16]byte
		copy(arrUID[:], resp.UID)
		switch resp.Action {
		case usermanager.TERMINATE:
			panel.activeUsersM.RLock()
			user := panel.activeUsers[arrUID]
			panel.activeUsersM.RUnlock()
			if user != nil {
				user.Terminate(resp.Message)
			}
		}
	}
	panel.usageUpdateQueue = make(map[[16]byte]*usagePair)
	panel.usageUpdateQueueM.Unlock()
	return nil
}

func (panel *userPanel) regularQueueUpload() {
	for {
		time.Sleep(1 * time.Minute)
		go func() {
			panel.updateUsageQueue()
			err := panel.commitUpdate()
			if err != nil {
				log.Error(err)
			}
		}()
	}
}
