package usermanager

import (
	"log"
	"net"
	"sync"
	"sync/atomic"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
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

type User struct {
	up *Userpanel

	uid [32]byte

	sessionsCap uint32 //userParams

	valve *mux.Valve

	sessionsM sync.RWMutex
	sessions  map[uint32]*mux.Session
}

func MakeUser(up *Userpanel, uid [32]byte, sessionsCap uint32, upRate, downRate, upCredit, downCredit int64) *User {
	valve := mux.MakeValve(upRate, downRate, upCredit, downCredit)
	u := &User{
		up:          up,
		uid:         uid,
		valve:       valve,
		sessionsCap: sessionsCap,
		sessions:    make(map[uint32]*mux.Session),
	}
	return u
}

func (u *User) setSessionsCap(cap uint32) {
	atomic.StoreUint32(&u.sessionsCap, cap)
}

func (u *User) GetSession(sessionID uint32) *mux.Session {
	u.sessionsM.RLock()
	defer u.sessionsM.RUnlock()
	return u.sessions[sessionID]
}

func (u *User) PutSession(sessionID uint32, sesh *mux.Session) {
	u.sessionsM.Lock()
	u.sessions[sessionID] = sesh
	u.sessionsM.Unlock()
}

func (u *User) DelSession(sessionID uint32) {
	u.sessionsM.Lock()
	delete(u.sessions, sessionID)
	if len(u.sessions) == 0 {
		u.sessionsM.Unlock()
		u.up.delActiveUser(u.uid)
		return
	}
	u.sessionsM.Unlock()
}

func (u *User) GetOrCreateSession(sessionID uint32, obfs func(*mux.Frame) []byte, deobfs func([]byte) *mux.Frame, obfsedRead func(net.Conn, []byte) (int, error)) (sesh *mux.Session, existing bool) {
	u.sessionsM.Lock()
	defer u.sessionsM.Unlock()
	if sesh = u.sessions[sessionID]; sesh != nil {
		return sesh, true
	} else {
		log.Printf("Creating session %v\n", sessionID)
		sesh = mux.MakeSession(sessionID, u.valve, obfs, deobfs, obfsedRead)
		u.sessions[sessionID] = sesh
		return sesh, false
	}
}
