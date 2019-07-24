package server

import (
	"encoding/binary"
	"log"
	"time"

	"github.com/boltdb/bolt"
)

var Uint32 = binary.BigEndian.Uint32
var Uint64 = binary.BigEndian.Uint64
var PutUint32 = binary.BigEndian.PutUint32
var PutUint64 = binary.BigEndian.PutUint64

type localManager struct {
	db *bolt.DB
}

func MakeLocalManager(dbPath string) (*localManager, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	return &localManager{db}, nil
}

func (manager *localManager) authenticateUser(UID []byte) (int64, int64, error) {
	var upRate, downRate, upCredit, downCredit, expiryTime int64
	err := manager.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(UID)
		if bucket == nil {
			return ErrUserNotFound
		}
		upRate = int64(Uint64(bucket.Get([]byte("UpRate"))))
		downRate = int64(Uint64(bucket.Get([]byte("DownRate"))))
		upCredit = int64(Uint64(bucket.Get([]byte("UpCredit"))))
		downCredit = int64(Uint64(bucket.Get([]byte("DownCredit"))))
		expiryTime = int64(Uint64(bucket.Get([]byte("ExpiryTime"))))
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	if upCredit <= 0 {
		return 0, 0, ErrNoUpCredit
	}
	if downCredit <= 0 {
		return 0, 0, ErrNoDownCredit
	}
	if expiryTime < time.Now().Unix() {
		return 0, 0, ErrUserExpired
	}

	return upRate, downRate, nil
}

func (manager *localManager) authoriseNewSession(user *ActiveUser) error {
	var sessionsCap int
	var upCredit, downCredit, expiryTime int64
	err := manager.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(user.arrUID[:])
		if bucket == nil {
			return ErrUserNotFound
		}
		sessionsCap = int(Uint32(bucket.Get([]byte("SessionsCap"))))
		upCredit = int64(Uint64(bucket.Get([]byte("UpCredit"))))
		downCredit = int64(Uint64(bucket.Get([]byte("DownCredit"))))
		expiryTime = int64(Uint64(bucket.Get([]byte("ExpiryTime"))))
		return nil
	})
	if err != nil {
		return err
	}
	if upCredit <= 0 {
		return ErrNoUpCredit
	}
	if downCredit <= 0 {
		return ErrNoDownCredit
	}
	if expiryTime < time.Now().Unix() {
		return ErrUserExpired
	}
	//user.sessionsM.RLock()
	if len(user.sessions) >= sessionsCap {
		//user.sessionsM.RUnlock()
		return ErrSessionsCapReached
	}
	//user.sessionsM.RUnlock()
	return nil
}

func i64ToB(value int64) []byte {
	oct := make([]byte, 8)
	PutUint64(oct, uint64(value))
	return oct
}

func (manager *localManager) uploadStatus(uploads []statusUpdate) ([]statusResponse, error) {
	var responses []statusResponse
	err := manager.db.Update(func(tx *bolt.Tx) error {
		for _, status := range uploads {
			var resp statusResponse
			bucket := tx.Bucket(status.UID)
			if bucket == nil {
				log.Printf("%x doesn't exist\n", status.UID)
				continue
			}

			oldUp := int64(Uint64(bucket.Get([]byte("UpCredit"))))
			newUp := oldUp - status.upUsage
			if newUp <= 0 {
				resp = statusResponse{
					status.UID,
					TERMINATE,
					"No upload credit left",
				}
			}
			bucket.Put([]byte("UpCredit"), i64ToB(newUp))

			oldDown := int64(Uint64(bucket.Get([]byte("DownCredit"))))
			newDown := oldDown - status.downUsage
			if newDown <= 0 {
				resp = statusResponse{
					status.UID,
					TERMINATE,
					"No download credit left",
				}
			}
			bucket.Put([]byte("DownCredit"), i64ToB(newDown))

			expiry := int64(Uint64(bucket.Get([]byte("ExpiryTime"))))
			if time.Now().Unix()>expiry{
				resp = statusResponse{
					status.UID,
					TERMINATE,
					"User has expired",
				}
			}

			if resp.UID != nil {
				responses = append(responses, resp)
			}
		}
		return nil
	})
	return responses, err
}
