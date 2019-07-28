package server

import (
	"net"
	"sync"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

type ActiveUser struct {
	panel *userPanel

	arrUID [16]byte

	valve *mux.Valve

	sessionsM sync.RWMutex
	sessions  map[uint32]*mux.Session
}

func (u *ActiveUser) DelSession(sessionID uint32) {
	u.sessionsM.Lock()
	delete(u.sessions, sessionID)
	if len(u.sessions) == 0 {
		u.panel.updateUsageQueueForOne(u)
		u.panel.activeUsersM.Lock()
		delete(u.panel.activeUsers, u.arrUID)
		u.panel.activeUsersM.Unlock()
	}
	u.sessionsM.Unlock()
}

func (u *ActiveUser) GetSession(sessionID uint32, obfs mux.Obfser, deobfs mux.Deobfser, obfsedRead func(net.Conn, []byte) (int, error)) (sesh *mux.Session, existing bool, err error) {
	u.sessionsM.Lock()
	defer u.sessionsM.Unlock()
	if sesh = u.sessions[sessionID]; sesh != nil {
		return sesh, true, nil
	} else {
		err := u.panel.Manager.authoriseNewSession(u)
		if err != nil {
			return nil, false, err
		}
		sesh = mux.MakeSession(sessionID, u.valve, obfs, deobfs, obfsedRead)
		u.sessions[sessionID] = sesh
		return sesh, false, nil
	}
}

func (u *ActiveUser) Terminate(reason string) {
	u.sessionsM.Lock()
	for _, sesh := range u.sessions {
		if reason != "" {
			sesh.SetTerminalMsg(reason)
		}
		go sesh.Close()
	}
	u.sessionsM.Unlock()
	u.panel.activeUsersM.Lock()
	delete(u.panel.activeUsers, u.arrUID)
	u.panel.activeUsersM.Unlock()
}

func (u *ActiveUser) NumSession() int {
	u.sessionsM.RLock()
	defer u.sessionsM.RUnlock()
	return len(u.sessions)
}
