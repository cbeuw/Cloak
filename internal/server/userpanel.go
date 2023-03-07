package server

import (
	"encoding/base64"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/Cloak/internal/server/usermanager"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
)

const defaultUploadInterval = 1 * time.Minute

// userPanel is used to authenticate new users and book keep active users
type userPanel struct {
	Manager usermanager.UserManager

	activeUsersM      sync.RWMutex
	activeUsers       map[[16]byte]*ActiveUser
	usageUpdateQueueM sync.Mutex
	usageUpdateQueue  map[[16]byte]*usagePair

	uploadInterval time.Duration
}

func MakeUserPanel(manager usermanager.UserManager) *userPanel {
	ret := &userPanel{
		Manager:          manager,
		activeUsers:      make(map[[16]byte]*ActiveUser),
		usageUpdateQueue: make(map[[16]byte]*usagePair),
		uploadInterval:   defaultUploadInterval,
	}
	go ret.regularQueueUpload()
	return ret
}

// GetBypassUser does the same as GetUser except it unconditionally creates an ActiveUser when the UID isn't already active
func (panel *userPanel) GetBypassUser(UID []byte) (*ActiveUser, error) {
	panel.activeUsersM.Lock()
	defer panel.activeUsersM.Unlock()
	var arrUID [16]byte
	copy(arrUID[:], UID)
	if user, ok := panel.activeUsers[arrUID]; ok {
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
	return user, nil
}

// GetUser retrieves the reference to an ActiveUser if it's already active, or creates a new ActiveUser of specified
// UID with UserInfo queried from the UserManger, should the particular UID is allowed to connect
func (panel *userPanel) GetUser(UID []byte) (*ActiveUser, error) {
	panel.activeUsersM.Lock()
	defer panel.activeUsersM.Unlock()
	var arrUID [16]byte
	copy(arrUID[:], UID)
	if user, ok := panel.activeUsers[arrUID]; ok {
		return user, nil
	}

	upRate, downRate, err := panel.Manager.AuthenticateUser(UID)
	if err != nil {
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
	log.WithFields(log.Fields{
		"UID": base64.StdEncoding.EncodeToString(UID),
	}).Info("New active user")
	return user, nil
}

// TerminateActiveUser terminates a user and deletes its references
func (panel *userPanel) TerminateActiveUser(user *ActiveUser, reason string) {
	log.WithFields(log.Fields{
		"UID":    base64.StdEncoding.EncodeToString(user.arrUID[:]),
		"reason": reason,
	}).Info("Terminating active user")
	panel.updateUsageQueueForOne(user)
	user.closeAllSessions(reason)
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

// updateUsageQueue zeroes the accumulated usage all ActiveUsers valve and put the usage data im usageUpdateQueue
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

// updateUsageQueueForOne is the same as updateUsageQueue except it only updates one user's usage
// this is useful when the user is being terminated
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

// commitUpdate put all usageUpdates into a slice of StatusUpdate, calls Manager.UploadStatus, gets the responses
// and act to each user according to the responses
func (panel *userPanel) commitUpdate() error {
	panel.usageUpdateQueueM.Lock()
	statuses := make([]usermanager.StatusUpdate, 0, len(panel.usageUpdateQueue))
	for arrUID, usage := range panel.usageUpdateQueue {
		panel.activeUsersM.RLock()
		user := panel.activeUsers[arrUID]
		panel.activeUsersM.RUnlock()
		var numSession int
		if user != nil {
			if user.bypass {
				continue
			}
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
	panel.usageUpdateQueue = make(map[[16]byte]*usagePair)
	panel.usageUpdateQueueM.Unlock()

	if len(statuses) == 0 {
		return nil
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
				panel.TerminateActiveUser(user, resp.Message)
			}
		}
	}
	return nil
}

func (panel *userPanel) regularQueueUpload() {
	for {
		time.Sleep(panel.uploadInterval)
		go func() {
			panel.updateUsageQueue()
			err := panel.commitUpdate()
			if err != nil {
				log.Error(err)
			}
		}()
	}
}
