package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/boltdb/bolt"
	"net/http"

	gmux "github.com/gorilla/mux"
)

type UserInfo struct {
	UID         []byte
	SessionsCap int
	UpRate      int64
	DownRate    int64
	UpCredit    int64
	DownCredit  int64
	ExpiryTime  int64
}

func (manager *localManager) listAllUsersHlr(w http.ResponseWriter, r *http.Request) {
	var infos []UserInfo
	_ = manager.db.View(func(tx *bolt.Tx) error {
		err := tx.ForEach(func(UID []byte, bucket *bolt.Bucket) error {
			var uinfo UserInfo
			uinfo.UID = UID
			uinfo.SessionsCap = int(Uint32(bucket.Get([]byte("SessionsCap"))))
			uinfo.UpRate = int64(Uint64(bucket.Get([]byte("UpRate"))))
			uinfo.DownRate = int64(Uint64(bucket.Get([]byte("DownRate"))))
			uinfo.UpCredit = int64(Uint64(bucket.Get([]byte("UpCredit"))))
			uinfo.DownCredit = int64(Uint64(bucket.Get([]byte("DownCredit"))))
			uinfo.ExpiryTime = int64(Uint64(bucket.Get([]byte("ExpiryTime"))))
			infos = append(infos, uinfo)
			return nil
		})
		return err
	})
	resp, err := json.Marshal(infos)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(resp)
}

func (manager *localManager) getUserInfoHlr(w http.ResponseWriter, r *http.Request) {
	b64UID := gmux.Vars(r)["UID"]
	if b64UID == "" {
		http.Error(w, "UID cannot be empty", http.StatusBadRequest)
	}

	UID, err := base64.URLEncoding.DecodeString(b64UID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var uinfo UserInfo
	err = manager.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(UID))
		if bucket == nil {
			return ErrUserNotFound
		}
		uinfo.UID = UID
		uinfo.SessionsCap = int(Uint32(bucket.Get([]byte("SessionsCap"))))
		uinfo.UpRate = int64(Uint64(bucket.Get([]byte("UpRate"))))
		uinfo.DownRate = int64(Uint64(bucket.Get([]byte("DownRate"))))
		uinfo.UpCredit = int64(Uint64(bucket.Get([]byte("UpCredit"))))
		uinfo.DownCredit = int64(Uint64(bucket.Get([]byte("DownCredit"))))
		uinfo.ExpiryTime = int64(Uint64(bucket.Get([]byte("ExpiryTime"))))
		return nil
	})
	if err == ErrUserNotFound {
		http.Error(w, ErrUserNotFound.Error(), http.StatusNotFound)
		return
	}
	resp, err := json.Marshal(uinfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(resp)
}

func (manager *localManager) writeUserInfoHlr(w http.ResponseWriter, r *http.Request) {
	b64UID := gmux.Vars(r)["UID"]
	if b64UID == "" {
		http.Error(w, "UID cannot be empty", http.StatusBadRequest)
		return
	}
	UID, err := base64.URLEncoding.DecodeString(b64UID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonUinfo := r.FormValue("UserInfo")
	if jsonUinfo == "" {
		http.Error(w, "UserInfo cannot be empty", http.StatusBadRequest)
		return
	}
	var uinfo UserInfo
	err = json.Unmarshal([]byte(jsonUinfo), &uinfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !bytes.Equal(UID, uinfo.UID) {
		http.Error(w, "UID mismatch", http.StatusBadRequest)
	}

	err = manager.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(uinfo.UID)
		if err != nil {
			return err
		}
		if err = bucket.Put([]byte("SessionsCap"), i32ToB(int32(uinfo.SessionsCap))); err != nil {
			return err
		}
		if err = bucket.Put([]byte("UpRate"), i64ToB(uinfo.UpRate)); err != nil {
			return err
		}
		if err = bucket.Put([]byte("DownRate"), i64ToB(uinfo.DownRate)); err != nil {
			return err
		}
		if err = bucket.Put([]byte("UpCredit"), i64ToB(uinfo.UpCredit)); err != nil {
			return err
		}
		if err = bucket.Put([]byte("DownCredit"), i64ToB(uinfo.DownCredit)); err != nil {
			return err
		}
		if err = bucket.Put([]byte("ExpiryTime"), i64ToB(uinfo.ExpiryTime)); err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusCreated)
}

func (manager *localManager) deleteUserHlr(w http.ResponseWriter, r *http.Request) {
	b64UID := gmux.Vars(r)["UID"]
	if b64UID == "" {
		http.Error(w, "UID cannot be empty", http.StatusBadRequest)
		return
	}
	UID, err := base64.URLEncoding.DecodeString(b64UID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = manager.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket(UID)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusOK)
}
