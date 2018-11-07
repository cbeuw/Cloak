package usermanager

import (
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

/*
type userParams struct {
	sessionsCap uint32
	upRate      int64
	downRate    int64
	upCredit    int64
	downCredit  int64
}
*/

type user struct {
	up *Userpanel

	uid [32]byte

	sessionsCap uint32 //userParams

	valve *mux.Valve

	sessionsM sync.RWMutex
	sessions  map[uint32]*mux.Session
}

func MakeUser(up *Userpanel, uid [32]byte, sessionsCap uint32, upRate, downRate, upCredit, downCredit int64) *user {
	valve := mux.MakeValve(upRate, downRate, upCredit, downCredit)
	u := &user{
		up:          up,
		uid:         uid,
		valve:       valve,
		sessionsCap: sessionsCap,
		sessions:    make(map[uint32]*mux.Session),
	}
	return u
}

func (u *user) setSessionsCap(cap uint32) {
	atomic.StoreUint32(&u.sessionsCap, cap)
}

func (u *user) GetSession(sessionID uint32) *mux.Session {
	u.sessionsM.RLock()
	defer u.sessionsM.RUnlock()
	if sesh, ok := u.sessions[sessionID]; ok {
		return sesh
	} else {
		return nil
	}
}

func (u *user) PutSession(sessionID uint32, sesh *mux.Session) {
	u.sessionsM.Lock()
	u.sessions[sessionID] = sesh
	u.sessionsM.Unlock()
}

func (u *user) DelSession(sessionID uint32) {
	u.sessionsM.Lock()
	delete(u.sessions, sessionID)
	if len(u.sessions) == 0 {
		u.sessionsM.Unlock()
		u.up.delActiveUser(u.uid)
		return
	}
	u.sessionsM.Unlock()
}

func (u *user) GetOrCreateSession(sessionID uint32, obfs func(*mux.Frame) []byte, deobfs func([]byte) *mux.Frame, obfsedRead func(net.Conn, []byte) (int, error)) (sesh *mux.Session) {
	log.Printf("getting sessionID %v\n", sessionID)
	if sesh = u.GetSession(sessionID); sesh != nil {
		return
	} else {
		sesh = mux.MakeSession(sessionID, u.valve, obfs, deobfs, obfsedRead)
		u.PutSession(sessionID, sesh)
		return
	}
}
