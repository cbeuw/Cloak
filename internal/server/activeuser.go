package server

import (
	"sync"

	"github.com/cbeuw/Cloak/internal/server/usermanager"

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

// CloseSession closes a session and removes its reference from the user
func (u *ActiveUser) CloseSession(sessionID uint32, reason string) {
	u.sessionsM.Lock()
	sesh, existing := u.sessions[sessionID]
	if existing {
		delete(u.sessions, sessionID)
		sesh.SetTerminalMsg(reason)
		sesh.Close()
	}
	remaining := len(u.sessions)
	u.sessionsM.Unlock()
	if remaining == 0 {
		u.panel.TerminateActiveUser(u, "no session left")
	}
}

// GetSession returns the reference to an existing session, or if one such session doesn't exist, it queries
// the UserManager for the authorisation for a new session. If a new session is allowed, it creates this new session
// and returns its reference
func (u *ActiveUser) GetSession(sessionID uint32, config mux.SessionConfig) (sesh *mux.Session, existing bool, err error) {
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

// closeAllSessions closes all sessions of this active user
func (u *ActiveUser) closeAllSessions(reason string) {
	u.sessionsM.Lock()
	for sessionID, sesh := range u.sessions {
		sesh.SetTerminalMsg(reason)
		sesh.Close()
		delete(u.sessions, sessionID)
	}
	u.sessionsM.Unlock()
}

// NumSession returns the number of active sessions
func (u *ActiveUser) NumSession() int {
	u.sessionsM.RLock()
	defer u.sessionsM.RUnlock()
	return len(u.sessions)
}
