package usermanager

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/boltdb/bolt"
)

var Uint32 = binary.BigEndian.Uint32
var Uint64 = binary.BigEndian.Uint64
var PutUint16 = binary.BigEndian.PutUint16
var PutUint32 = binary.BigEndian.PutUint32
var PutUint64 = binary.BigEndian.PutUint64

type Userpanel struct {
	db *bolt.DB

	activeUsersM sync.RWMutex
	activeUsers  map[[32]byte]*User
}

func MakeUserpanel(dbPath string) (*Userpanel, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	up := &Userpanel{
		db:          db,
		activeUsers: make(map[[32]byte]*User),
	}
	go func() {
		for {
			time.Sleep(time.Second * 10)
			up.updateCredits()
		}
	}()
	return up, nil
}

// credits of all users are updated together so that there is only 1 goroutine managing it
func (up *Userpanel) updateCredits() {
	up.activeUsersM.RLock()
	for _, u := range up.activeUsers {
		up.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(u.arrUID[:])
			if b == nil {
				return ErrUserNotFound
			}
			if err := b.Put([]byte("UpCredit"), i64ToB(u.valve.GetRxCredit())); err != nil {
				return err
			}
			if err := b.Put([]byte("DownCredit"), i64ToB(u.valve.GetTxCredit())); err != nil {
				return err
			}
			return nil

		})
	}
	up.activeUsersM.RUnlock()

}

// TODO: prefixed backup path
func (up *Userpanel) backupDB(bakPath string) error {
	_, err := os.Stat(bakPath)
	if err == nil {
		return errors.New("Attempting to overwrite a file during backup!")
	}
	var bak *os.File
	if os.IsNotExist(err) {
		bak, err = os.Create(bakPath)
		if err != nil {
			return err
		}
	}
	err = up.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(bak)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

var ErrUserNotFound = errors.New("User does not exist in db")
var ErrUserNotActive = errors.New("User is not active")

// TODO: expiry check

// GetUser is used to retrieve a user if s/he is active, or to retrieve the user's infor
// from the db and mark it as an active user
func (up *Userpanel) GetAndActivateUser(UID []byte) (*User, error) {
	up.activeUsersM.Lock()
	var arrUID [32]byte
	copy(arrUID[:], UID)
	if user, ok := up.activeUsers[arrUID]; ok {
		up.activeUsersM.Unlock()
		return user, nil
	}

	var uinfo UserInfo
	uinfo.UID = UID
	err := up.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID[:])
		if b == nil {
			return ErrUserNotFound
		}
		uinfo.SessionsCap = Uint32(b.Get([]byte("SessionsCap")))
		uinfo.UpRate = int64(Uint64(b.Get([]byte("UpRate"))))
		uinfo.DownRate = int64(Uint64(b.Get([]byte("DownRate"))))
		uinfo.UpCredit = int64(Uint64(b.Get([]byte("UpCredit")))) // reee brackets
		uinfo.DownCredit = int64(Uint64(b.Get([]byte("DownCredit"))))
		uinfo.ExpiryTime = int64(Uint64(b.Get([]byte("ExpiryTime"))))
		return nil
	})
	if err != nil {
		up.activeUsersM.Unlock()
		return nil, err
	}
	u := MakeUser(up, &uinfo)
	up.activeUsers[arrUID] = u
	up.activeUsersM.Unlock()
	return u, nil
}

func (up *Userpanel) updateDBEntryUint32(UID []byte, key string, value uint32) error {
	err := up.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID)
		if b == nil {
			return ErrUserNotFound
		}
		if err := b.Put([]byte(key), u32ToB(value)); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (up *Userpanel) updateDBEntryInt64(UID []byte, key string, value int64) error {
	err := up.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID)
		if b == nil {
			return ErrUserNotFound
		}
		if err := b.Put([]byte(key), i64ToB(value)); err != nil {
			return err
		}
		return nil
	})
	return err
}

// This is used when all sessions of a user close
func (up *Userpanel) delActiveUser(UID []byte) {
	var arrUID [32]byte
	copy(arrUID[:], UID)
	up.activeUsersM.Lock()
	delete(up.activeUsers, arrUID)
	up.activeUsersM.Unlock()
}

func (up *Userpanel) getActiveUser(UID []byte) *User {
	var arrUID [32]byte
	copy(arrUID[:], UID)
	up.activeUsersM.RLock()
	ret := up.activeUsers[arrUID]
	up.activeUsersM.RUnlock()
	return ret
}

// below are remote control utilised functions

func (up *Userpanel) listActiveUsers() [][]byte {
	var ret [][]byte
	up.activeUsersM.RLock()
	for _, u := range up.activeUsers {
		ret = append(ret, u.UID)
	}
	up.activeUsersM.RUnlock()
	return ret
}

func (up *Userpanel) listAllUsers() []UserInfo {
	var ret []UserInfo
	up.db.View(func(tx *bolt.Tx) error {
		tx.ForEach(func(UID []byte, b *bolt.Bucket) error {
			// if we want to avoid writing every single key out,
			// we would have to either make UserInfo a map,
			// or use reflect.
			// neither is convinient
			var uinfo UserInfo
			uinfo.UID = UID
			uinfo.SessionsCap = Uint32(b.Get([]byte("SessionsCap")))
			uinfo.UpRate = int64(Uint64(b.Get([]byte("UpRate"))))
			uinfo.DownRate = int64(Uint64(b.Get([]byte("DownRate"))))
			uinfo.UpCredit = int64(Uint64(b.Get([]byte("UpCredit"))))
			uinfo.DownCredit = int64(Uint64(b.Get([]byte("DownCredit"))))
			uinfo.ExpiryTime = int64(Uint64(b.Get([]byte("ExpiryTime"))))
			ret = append(ret, uinfo)
			return nil
		})
		return nil
	})
	return ret
}

func (up *Userpanel) getUserInfo(UID []byte) (UserInfo, error) {
	var uinfo UserInfo
	err := up.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID)
		if b == nil {
			return ErrUserNotFound
		}
		uinfo.UID = UID
		uinfo.SessionsCap = Uint32(b.Get([]byte("SessionsCap")))
		uinfo.UpRate = int64(Uint64(b.Get([]byte("UpRate"))))
		uinfo.DownRate = int64(Uint64(b.Get([]byte("DownRate"))))
		uinfo.UpCredit = int64(Uint64(b.Get([]byte("UpCredit"))))
		uinfo.DownCredit = int64(Uint64(b.Get([]byte("DownCredit"))))
		uinfo.ExpiryTime = int64(Uint64(b.Get([]byte("ExpiryTime"))))
		return nil
	})
	return uinfo, err
}

// In boltdb, the value argument for bucket.Put has to be valid for the duration
// of the transaction.
// This basically means that you cannot reuse a byte slice for two different keys
// in a transaction. So we need to allocate a fresh byte slice for each value
func u32ToB(value uint32) []byte {
	quad := make([]byte, 4)
	PutUint32(quad, value)
	return quad
}

func i64ToB(value int64) []byte {
	oct := make([]byte, 8)
	PutUint64(oct, uint64(value))
	return oct
}

func (up *Userpanel) addNewUser(uinfo UserInfo) error {
	err := up.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(uinfo.UID[:])
		if err != nil {
			return err
		}
		// FIXME: obnoxious code
		if err = b.Put([]byte("SessionsCap"), u32ToB(uinfo.SessionsCap)); err != nil {
			return err
		}
		if err = b.Put([]byte("UpRate"), i64ToB(uinfo.UpRate)); err != nil {
			return err
		}
		if err = b.Put([]byte("DownRate"), i64ToB(uinfo.DownRate)); err != nil {
			return err
		}
		if err = b.Put([]byte("UpCredit"), i64ToB(uinfo.UpCredit)); err != nil {
			return err
		}
		if err = b.Put([]byte("DownCredit"), i64ToB(uinfo.DownCredit)); err != nil {
			return err
		}
		if err = b.Put([]byte("ExpiryTime"), i64ToB(uinfo.ExpiryTime)); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (up *Userpanel) delUser(UID []byte) error {
	err := up.backupDB(strconv.FormatInt(time.Now().Unix(), 10) + "_pre_del_" + hex.EncodeToString(UID) + ".bak")
	if err != nil {
		return err
	}
	err = up.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(UID)
	})
	return err
}

func (up *Userpanel) syncMemFromDB(UID []byte) error {
	var uinfo UserInfo
	err := up.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID)
		if b == nil {
			return ErrUserNotFound
		}
		uinfo.UID = UID
		uinfo.SessionsCap = Uint32(b.Get([]byte("SessionsCap")))
		uinfo.UpRate = int64(Uint64(b.Get([]byte("UpRate"))))
		uinfo.DownRate = int64(Uint64(b.Get([]byte("DownRate"))))
		uinfo.UpCredit = int64(Uint64(b.Get([]byte("UpCredit"))))
		uinfo.DownCredit = int64(Uint64(b.Get([]byte("DownCredit"))))
		uinfo.ExpiryTime = int64(Uint64(b.Get([]byte("ExpiryTime"))))
		return nil
	})
	if err != nil {
		return err
	}

	u := up.getActiveUser(UID)
	if u == nil {
		return ErrUserNotActive
	}
	u.updateInfo(uinfo)
	return nil
}

// the following functions will return err==nil if user is not active

func (up *Userpanel) setSessionsCap(UID []byte, cap uint32) error {
	err := up.updateDBEntryUint32(UID, "SessionsCap", cap)
	if err != nil {
		return err
	}
	u := up.getActiveUser(UID)
	if u == nil {
		return nil
	}
	u.setSessionsCap(cap)
	return nil
}

func (up *Userpanel) setUpRate(UID []byte, rate int64) error {
	err := up.updateDBEntryInt64(UID, "UpRate", rate)
	if err != nil {
		return err
	}
	u := up.getActiveUser(UID)
	if u == nil {
		return nil
	}
	u.setUpRate(rate)
	return nil
}
func (up *Userpanel) setDownRate(UID []byte, rate int64) error {
	err := up.updateDBEntryInt64(UID, "DownRate", rate)
	if err != nil {
		return err
	}
	u := up.getActiveUser(UID)
	if u == nil {
		return nil
	}
	u.setDownRate(rate)
	return nil
}
func (up *Userpanel) setUpCredit(UID []byte, n int64) error {
	err := up.updateDBEntryInt64(UID, "UpCredit", n)
	if err != nil {
		return err
	}
	u := up.getActiveUser(UID)
	if u == nil {
		return nil
	}
	u.setUpCredit(n)
	return nil
}
func (up *Userpanel) setDownCredit(UID []byte, n int64) error {
	err := up.updateDBEntryInt64(UID, "DownCredit", n)
	if err != nil {
		return err
	}
	u := up.getActiveUser(UID)
	if u == nil {
		return nil
	}
	u.setDownCredit(n)
	return nil
}

func (up *Userpanel) setExpiryTime(UID []byte, time int64) error {
	err := up.updateDBEntryInt64(UID, "ExpiryTime", time)
	if err != nil {
		return err
	}
	u := up.getActiveUser(UID)
	if u == nil {
		return nil
	}
	u.setExpiryTime(time)
	return nil
}
