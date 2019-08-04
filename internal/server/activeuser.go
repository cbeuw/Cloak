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

func (u *ActiveUser) GetSession(sessionID uint32, obfuscator *mux.Obfuscator, unitReader func(net.Conn, []byte) (int, error)) (sesh *mux.Session, existing bool, err error) {
	u.sessionsM.Lock()
	defer u.sessionsM.Unlock()
	if sesh = u.sessions[sessionID]; sesh != nil {
		return sesh, true, nil
	} else {
		if !u.bypass {
			err := u.panel.Manager.AuthoriseNewSession(u.arrUID[:], len(u.sessions))
			if err != nil {
				return nil, false, err
			}
		}
		sesh = mux.MakeSession(sessionID, u.valve, obfuscator, unitReader)
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
