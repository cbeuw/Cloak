package usermanager

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

// for the ease of using json package
type UserInfo struct {
	UID []byte
	// ALL of the following fields have to be accessed atomically
	SessionsCap uint32
	UpRate      int64
	DownRate    int64
	UpCredit    int64
	DownCredit  int64
	ExpiryTime  int64
}

type User struct {
	up *Userpanel

	arrUID [16]byte

	*UserInfo

	valve *mux.Valve

	sessionsM sync.RWMutex
	sessions  map[uint32]*mux.Session
}

func MakeUser(up *Userpanel, uinfo *UserInfo) *User {
	// this instance of valve is shared across ALL sessions of a user
	valve := mux.MakeValve(uinfo.UpRate, uinfo.DownRate, &uinfo.UpCredit, &uinfo.DownCredit)
	u := &User{
		up:       up,
		UserInfo: uinfo,
		valve:    valve,
		sessions: make(map[uint32]*mux.Session),
	}
	copy(u.arrUID[:], uinfo.UID)
	return u
}

func (u *User) addUpCredit(delta int64)   { u.valve.AddRxCredit(delta) }
func (u *User) addDownCredit(delta int64) { u.valve.AddTxCredit(delta) }
func (u *User) setSessionsCap(cap uint32) { atomic.StoreUint32(&u.SessionsCap, cap) }
func (u *User) setUpRate(rate int64)      { u.valve.SetRxRate(rate) }
func (u *User) setDownRate(rate int64)    { u.valve.SetTxRate(rate) }
func (u *User) setUpCredit(n int64)       { u.valve.SetRxCredit(n) }
func (u *User) setDownCredit(n int64)     { u.valve.SetTxCredit(n) }
func (u *User) setExpiryTime(time int64)  { atomic.StoreInt64(&u.ExpiryTime, time) }

func (u *User) updateInfo(uinfo UserInfo) {
	u.setSessionsCap(uinfo.SessionsCap)
	u.setUpCredit(uinfo.UpCredit)
	u.setDownCredit(uinfo.DownCredit)
	u.setUpRate(uinfo.UpRate)
	u.setDownRate(uinfo.DownRate)
	u.setExpiryTime(uinfo.ExpiryTime)
}

func (u *User) DelSession(sessionID uint32) {
	u.sessionsM.Lock()
	delete(u.sessions, sessionID)
	if len(u.sessions) == 0 {
		u.sessionsM.Unlock()
		u.up.delActiveUser(u.UID)
		return
	}
	u.sessionsM.Unlock()
}

func (u *User) GetSession(sessionID uint32, obfs mux.Obfser, deobfs mux.Deobfser, obfsedRead func(net.Conn, []byte) (int, error)) (sesh *mux.Session, existing bool, err error) {
	if time.Now().Unix() > u.ExpiryTime {
		return nil, false, errors.New("Expiry time passed")
	}
	u.sessionsM.Lock()
	if sesh = u.sessions[sessionID]; sesh != nil {
		u.sessionsM.Unlock()
		return sesh, true, nil
	} else {
		if len(u.sessions) >= int(u.SessionsCap) {
			u.sessionsM.Unlock()
			return nil, false, errors.New("SessionsCap reached")
		}
		sesh = mux.MakeSession(sessionID, u.valve, obfs, deobfs, obfsedRead)
		u.sessions[sessionID] = sesh
		u.sessionsM.Unlock()
		return sesh, false, nil
	}
}
