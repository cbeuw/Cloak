package usermanager

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/boltdb/bolt"
)

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
		time.Sleep(time.Second * 10)
		up.updateCredits()
	}()
	return up, nil
}

var ErrUserNotFound = errors.New("User does not exist in memory or db")

// GetUser is used to retrieve a user if s/he is active, or to retrieve the user's infor
// from the db and mark it as an active user
func (up *Userpanel) GetAndActivateUser(UID [32]byte) (*User, error) {
	up.activeUsersM.Lock()
	defer up.activeUsersM.Unlock()
	if user, ok := up.activeUsers[UID]; ok {
		return user, nil
	}

	var sessionsCap uint32
	var upRate, downRate, upCredit, downCredit int64
	err := up.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID[:])
		if b == nil {
			return ErrUserNotFound
		}
		sessionsCap = binary.BigEndian.Uint32(b.Get([]byte("sessionsCap")))
		upRate = int64(binary.BigEndian.Uint64(b.Get([]byte("upRate"))))
		downRate = int64(binary.BigEndian.Uint64(b.Get([]byte("downRate"))))
		upCredit = int64(binary.BigEndian.Uint64(b.Get([]byte("upCredit")))) // reee brackets
		downCredit = int64(binary.BigEndian.Uint64(b.Get([]byte("downCredit"))))
		return nil
	})
	if err != nil {
		return nil, err
	}
	// TODO: put all of these parameters in a struct instead
	u := MakeUser(up, UID, sessionsCap, upRate, downRate, upCredit, downCredit)
	up.activeUsers[UID] = u
	return u, nil
}

func (up *Userpanel) AddNewUser(UID [32]byte, sessionsCap uint32, upRate, downRate, upCredit, downCredit int64) error {
	err := up.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(UID[:])
		if err != nil {
			return err
		}
		// FIXME: obnoxious code
		quad := make([]byte, 4)
		binary.BigEndian.PutUint32(quad, sessionsCap)
		if err = b.Put([]byte("sessionsCap"), quad); err != nil {
			return err
		}
		oct := make([]byte, 8)
		binary.BigEndian.PutUint64(oct, uint64(upRate))
		if err = b.Put([]byte("upRate"), oct); err != nil {
			return err
		}
		binary.BigEndian.PutUint64(oct, uint64(downRate))
		if err = b.Put([]byte("downRate"), oct); err != nil {
			return err
		}
		binary.BigEndian.PutUint64(oct, uint64(upCredit))
		if err = b.Put([]byte("upCredit"), oct); err != nil {
			return err
		}
		binary.BigEndian.PutUint64(oct, uint64(downCredit))
		if err = b.Put([]byte("downCredit"), oct); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (up *Userpanel) updateDBEntryUint32(UID [32]byte, key string, value uint32) error {
	err := up.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID[:])
		if b == nil {
			return ErrUserNotFound
		}
		quad := make([]byte, 4)
		binary.BigEndian.PutUint32(quad, value)
		if err := b.Put([]byte(key), quad); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (up *Userpanel) updateDBEntryInt64(UID [32]byte, key string, value int64) error {
	err := up.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(UID[:])
		if b == nil {
			return ErrUserNotFound
		}
		oct := make([]byte, 8)
		binary.BigEndian.PutUint64(oct, uint64(value))
		if err := b.Put([]byte(key), oct); err != nil {
			return err
		}
		return nil
	})
	return err
}

// This is used when all sessions of a user close
func (up *Userpanel) delActiveUser(UID [32]byte) {
	up.activeUsersM.Lock()
	delete(up.activeUsers, UID)
	up.activeUsersM.Unlock()
}

func (up *Userpanel) getActiveUser(UID [32]byte) *User {
	up.activeUsersM.RLock()
	defer up.activeUsersM.RUnlock()
	return up.activeUsers[UID]
}

func (up *Userpanel) SetSessionsCap(UID [32]byte, newSessionsCap uint32) error {
	if u := up.getActiveUser(UID); u != nil {
		u.setSessionsCap(newSessionsCap)
	}
	err := up.updateDBEntryUint32(UID, "sessionsCap", newSessionsCap)
	return err
}

func (up *Userpanel) updateCredits() {
	up.activeUsersM.RLock()
	defer u.activeUsersM.RUnlock()
	for _, user := range up.activeUsers {
		up.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(u.uid[:])
			if b == nil {
				return ErrUserNotFound
			}
			oct := make([]byte, 8)
			binary.BigEndian.PutUint64(oct, uint64(u.valve.GetRxCredit()))
			if err := b.Put([]byte("rxCredit"), oct); err != nil {
				return err
			}
			binary.BigEndian.PutUint64(oct, uint64(u.valve.GetTxCredit()))
			if err := b.Put([]byte("txCredit"), oct); err != nil {
				return err
			}
			return nil

		})
	}
}
