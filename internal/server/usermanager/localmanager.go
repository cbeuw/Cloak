package usermanager

import (
	"encoding/binary"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"

	gmux "github.com/gorilla/mux"
	bolt "go.etcd.io/bbolt"
)

var Uint32 = binary.BigEndian.Uint32
var Uint64 = binary.BigEndian.Uint64
var PutUint32 = binary.BigEndian.PutUint32
var PutUint64 = binary.BigEndian.PutUint64

func i64ToB(value int64) []byte {
	oct := make([]byte, 8)
	PutUint64(oct, uint64(value))
	return oct
}
func i32ToB(value int32) []byte {
	nib := make([]byte, 4)
	PutUint32(nib, uint32(value))
	return nib
}

// localManager is responsible for routing API calls to appropriate handlers and manage the local user database accordingly
type localManager struct {
	db     *bolt.DB
	Router *gmux.Router
}

func MakeLocalManager(dbPath string) (*localManager, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}
	ret := &localManager{
		db: db,
	}
	ret.Router = ret.registerMux()
	return ret, nil
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

func (manager *localManager) registerMux() *gmux.Router {
	r := gmux.NewRouter()
	r.HandleFunc("/admin/users", manager.listAllUsersHlr).Methods("GET")
	r.HandleFunc("/admin/users/{UID}", manager.getUserInfoHlr).Methods("GET")
	r.HandleFunc("/admin/users/{UID}", manager.writeUserInfoHlr).Methods("POST")
	r.HandleFunc("/admin/users/{UID}", manager.deleteUserHlr).Methods("DELETE")
	r.Methods("OPTIONS").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
	})
	r.Use(corsMiddleware)
	return r
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

			oldUp := int64(Uint64(bucket.Get([]byte("UpCredit"))))
			newUp := oldUp - status.UpUsage
			if newUp <= 0 {
				resp = StatusResponse{
					status.UID,
					TERMINATE,
					"No upload credit left",
				}
				responses = append(responses, resp)
				continue
			}
			err := bucket.Put([]byte("UpCredit"), i64ToB(newUp))
			if err != nil {
				log.Error(err)
				continue
			}

			oldDown := int64(Uint64(bucket.Get([]byte("DownCredit"))))
			newDown := oldDown - status.DownUsage
			if newDown <= 0 {
				resp = StatusResponse{
					status.UID,
					TERMINATE,
					"No download credit left",
				}
				responses = append(responses, resp)
				continue
			}
			err = bucket.Put([]byte("DownCredit"), i64ToB(newDown))
			if err != nil {
				log.Error(err)
				continue
			}

			expiry := int64(Uint64(bucket.Get([]byte("ExpiryTime"))))
			if time.Now().Unix() > expiry {
				resp = StatusResponse{
					status.UID,
					TERMINATE,
					"User has expired",
				}
				responses = append(responses, resp)
				continue
			}
		}
		return nil
	})
	return responses, err
}

func (manager *localManager) Close() error {
	return manager.db.Close()
}
