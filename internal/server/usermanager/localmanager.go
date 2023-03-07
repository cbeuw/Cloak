package usermanager

import (
	"encoding/binary"

	"github.com/cbeuw/Cloak/internal/common"
	log "github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
)

var u32 = binary.BigEndian.Uint32
var u64 = binary.BigEndian.Uint64

func i64ToB(value int64) []byte {
	oct := make([]byte, 8)
	binary.BigEndian.PutUint64(oct, uint64(value))
	return oct
}
func i32ToB(value int32) []byte {
	nib := make([]byte, 4)
	binary.BigEndian.PutUint32(nib, uint32(value))
	return nib
}

// localManager is responsible for managing the local user database
type localManager struct {
	db    *bolt.DB
	world common.WorldState
}

func MakeLocalManager(dbPath string, worldState common.WorldState) (*localManager, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	ret := &localManager{
		db:    db,
		world: worldState,
	}
	return ret, nil
}

// Authenticate user returns err==nil along with the users' up and down bandwidths if the UID is allowed to connect
// More specifically it checks that the user exists, that it has positive credit and that it hasn't expired
func (manager *localManager) AuthenticateUser(UID []byte) (int64, int64, error) {
	var upRate, downRate, upCredit, downCredit, expiryTime int64
	err := manager.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(UID)
		if bucket == nil {
			return ErrUserNotFound
		}
		upRate = int64(u64(bucket.Get([]byte("UpRate"))))
		downRate = int64(u64(bucket.Get([]byte("DownRate"))))
		upCredit = int64(u64(bucket.Get([]byte("UpCredit"))))
		downCredit = int64(u64(bucket.Get([]byte("DownCredit"))))
		expiryTime = int64(u64(bucket.Get([]byte("ExpiryTime"))))
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
	if expiryTime < manager.world.Now().Unix() {
		return 0, 0, ErrUserExpired
	}

	return upRate, downRate, nil
}

// AuthoriseNewSession returns err==nil when the user is allowed to make a new session
// More specifically it checks that the user exists, has credit, hasn't expired and hasn't reached sessionsCap
func (manager *localManager) AuthoriseNewSession(UID []byte, ainfo AuthorisationInfo) error {
	var arrUID [16]byte
	copy(arrUID[:], UID)
	var sessionsCap int
	var upCredit, downCredit, expiryTime int64
	err := manager.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(arrUID[:])
		if bucket == nil {
			return ErrUserNotFound
		}
		sessionsCap = int(u32(bucket.Get([]byte("SessionsCap"))))
		upCredit = int64(u64(bucket.Get([]byte("UpCredit"))))
		downCredit = int64(u64(bucket.Get([]byte("DownCredit"))))
		expiryTime = int64(u64(bucket.Get([]byte("ExpiryTime"))))
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
	if expiryTime < manager.world.Now().Unix() {
		return ErrUserExpired
	}

	if ainfo.NumExistingSessions >= sessionsCap {
		return ErrSessionsCapReached
	}
	return nil
}

// UploadStatus gets StatusUpdates representing the recent status of each user, and update them in the database
// it returns a slice of StatusResponse, which represents actions need to be taken for specific users.
// If no action is needed, there won't be a StatusResponse entry for that user
func (manager *localManager) UploadStatus(uploads []StatusUpdate) ([]StatusResponse, error) {
	var responses []StatusResponse
	if len(uploads) == 0 {
		return responses, nil
	}
	err := manager.db.Update(func(tx *bolt.Tx) error {
		for _, status := range uploads {
			var resp StatusResponse
			bucket := tx.Bucket(status.UID)
			if bucket == nil {
				resp = StatusResponse{
					status.UID,
					TERMINATE,
					"User no longer exists",
				}
				responses = append(responses, resp)
				continue
			}

			oldUp := int64(u64(bucket.Get([]byte("UpCredit"))))
			newUp := oldUp - status.UpUsage
			if newUp <= 0 {
				resp = StatusResponse{
					status.UID,
					TERMINATE,
					"No upload credit left",
				}
				responses = append(responses, resp)
			}
			err := bucket.Put([]byte("UpCredit"), i64ToB(newUp))
			if err != nil {
				log.Error(err)
			}

			oldDown := int64(u64(bucket.Get([]byte("DownCredit"))))
			newDown := oldDown - status.DownUsage
			if newDown <= 0 {
				resp = StatusResponse{
					status.UID,
					TERMINATE,
					"No download credit left",
				}
				responses = append(responses, resp)
			}
			err = bucket.Put([]byte("DownCredit"), i64ToB(newDown))
			if err != nil {
				log.Error(err)
			}

			expiry := int64(u64(bucket.Get([]byte("ExpiryTime"))))
			if manager.world.Now().Unix() > expiry {
				resp = StatusResponse{
					status.UID,
					TERMINATE,
					"User has expired",
				}
				responses = append(responses, resp)
			}
		}
		return nil
	})
	return responses, err
}

func (manager *localManager) ListAllUsers() (infos []UserInfo, err error) {
	err = manager.db.View(func(tx *bolt.Tx) error {
		err = tx.ForEach(func(UID []byte, bucket *bolt.Bucket) error {
			var uinfo UserInfo
			uinfo.UID = UID
			uinfo.SessionsCap = JustInt32(int32(u32(bucket.Get([]byte("SessionsCap")))))
			uinfo.UpRate = JustInt64(int64(u64(bucket.Get([]byte("UpRate")))))
			uinfo.DownRate = JustInt64(int64(u64(bucket.Get([]byte("DownRate")))))
			uinfo.UpCredit = JustInt64(int64(u64(bucket.Get([]byte("UpCredit")))))
			uinfo.DownCredit = JustInt64(int64(u64(bucket.Get([]byte("DownCredit")))))
			uinfo.ExpiryTime = JustInt64(int64(u64(bucket.Get([]byte("ExpiryTime")))))
			infos = append(infos, uinfo)
			return nil
		})
		return err
	})
	if infos == nil {
		infos = []UserInfo{}
	}
	return
}

func (manager *localManager) GetUserInfo(UID []byte) (uinfo UserInfo, err error) {
	err = manager.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(UID)
		if bucket == nil {
			return ErrUserNotFound
		}
		uinfo.UID = UID
		uinfo.SessionsCap = JustInt32(int32(u32(bucket.Get([]byte("SessionsCap")))))
		uinfo.UpRate = JustInt64(int64(u64(bucket.Get([]byte("UpRate")))))
		uinfo.DownRate = JustInt64(int64(u64(bucket.Get([]byte("DownRate")))))
		uinfo.UpCredit = JustInt64(int64(u64(bucket.Get([]byte("UpCredit")))))
		uinfo.DownCredit = JustInt64(int64(u64(bucket.Get([]byte("DownCredit")))))
		uinfo.ExpiryTime = JustInt64(int64(u64(bucket.Get([]byte("ExpiryTime")))))
		return nil
	})
	return
}

func (manager *localManager) WriteUserInfo(u UserInfo) (err error) {
	err = manager.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(u.UID)
		if err != nil {
			return err
		}
		if u.SessionsCap != nil {
			if err = bucket.Put([]byte("SessionsCap"), i32ToB(*u.SessionsCap)); err != nil {
				return err
			}
		}
		if u.UpRate != nil {
			if err = bucket.Put([]byte("UpRate"), i64ToB(*u.UpRate)); err != nil {
				return err
			}
		}
		if u.DownRate != nil {
			if err = bucket.Put([]byte("DownRate"), i64ToB(*u.DownRate)); err != nil {
				return err
			}
		}
		if u.UpCredit != nil {
			if err = bucket.Put([]byte("UpCredit"), i64ToB(*u.UpCredit)); err != nil {
				return err
			}
		}
		if u.DownCredit != nil {
			if err = bucket.Put([]byte("DownCredit"), i64ToB(*u.DownCredit)); err != nil {
				return err
			}
		}
		if u.ExpiryTime != nil {
			if err = bucket.Put([]byte("ExpiryTime"), i64ToB(*u.ExpiryTime)); err != nil {
				return err
			}
		}
		return nil
	})
	return
}

func (manager *localManager) DeleteUser(UID []byte) (err error) {
	err = manager.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(UID)
	})
	return
}

func (manager *localManager) Close() error {
	return manager.db.Close()
}
