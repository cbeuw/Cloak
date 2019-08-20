package server

import (
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"sync"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

type ActiveUser struct {
	panel *userPanel

	arrUID [16]byte

	valve mux.Valve

	bypass bool

	sessionsM sync.RWMutex
	sessions  map[uint32]*mux.Session
}

func (u *ActiveUser) DeleteSession(sessionID uint32, reason string) {
	u.sessionsM.Lock()
	sesh, existing := u.sessions[sessionID]
	if existing {
		delete(u.sessions, sessionID)
		sesh.SetTerminalMsg(reason)
		sesh.Close()
	}
	if len(u.sessions) == 0 {
		u.panel.DeleteActiveUser(u)
	}
	u.sessionsM.Unlock()
}

func (u *ActiveUser) GetSession(sessionID uint32, config *mux.SessionConfig) (sesh *mux.Session, existing bool, err error) {
	u.sessionsM.Lock()
	defer u.sessionsM.Unlock()
	if sesh = u.sessions[sessionID]; sesh != nil {
		return sesh, true, nil
	} else {
		if !u.bypass {
			ainfo := usermanager.AuthorisationInfo{NumExistingSessions: len(u.sessions)}
			err := u.panel.Manager.AuthoriseNewSession(u.arrUID[:], ainfo)
			if err != nil {
				return nil, false, err
			}
		}
		config.Valve = u.valve
		sesh = mux.MakeSession(sessionID, config)
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
		sesh.Close()
	}
	u.sessionsM.Unlock()
	u.panel.DeleteActiveUser(u)
}

func (u *ActiveUser) NumSession() int {
	u.sessionsM.RLock()
	defer u.sessionsM.RUnlock()
	return len(u.sessions)
}
