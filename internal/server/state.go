package server

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"io/ioutil"
	"sync"
	"time"

	gmux "github.com/gorilla/mux"
)

type rawConfig struct {
	ProxyBook    map[string]string
	BypassUID    [][]byte
	RedirAddr    string
	PrivateKey   string
	AdminUID     string
	DatabasePath string
	CncMode      bool
}

// State type stores the global state of the program
type State struct {
	ProxyBook map[string]string

	BindHost string
	BindPort string

	Now      func() time.Time
	AdminUID []byte

	BypassUID map[[16]byte]struct{}
	staticPv  crypto.PrivateKey

	RedirAddr string

	usedRandomM sync.RWMutex
	usedRandom  map[[32]byte]int64

	Panel          *userPanel
	LocalAPIRouter *gmux.Router
}

func InitState(bindHost, bindPort string, nowFunc func() time.Time) (*State, error) {
	ret := &State{
		BindHost:  bindHost,
		BindPort:  bindPort,
		Now:       nowFunc,
		BypassUID: make(map[[16]byte]struct{}),
	}
	ret.usedRandom = make(map[[32]byte]int64)
	go ret.UsedRandomCleaner()
	return ret, nil
}

// ParseConfig parses the config (either a path to json or in-line ssv config) into a State variable
func (sta *State) ParseConfig(conf string) (err error) {
	var content []byte
	var preParse rawConfig

	content, errPath := ioutil.ReadFile(conf)
	if errPath != nil {
		errJson := json.Unmarshal(content, &preParse)
		if errJson != nil {
			return errors.New("Failed to read/unmarshal configuration, path is invalid or " + errJson.Error())
		}
	} else {
		errJson := json.Unmarshal(content, &preParse)
		if errJson != nil {
			return errors.New("Failed to read configuration file: " + errJson.Error())
		}
	}

	if preParse.CncMode {
		//TODO: implement command & control mode

	} else {
		manager, err := usermanager.MakeLocalManager(preParse.DatabasePath)
		if err != nil {
			return err
		}
		sta.Panel = MakeUserPanel(manager)
		sta.LocalAPIRouter = manager.Router
	}

	sta.RedirAddr = preParse.RedirAddr
	sta.ProxyBook = preParse.ProxyBook

	pvBytes, err := base64.StdEncoding.DecodeString(preParse.PrivateKey)
	if err != nil {
		return errors.New("Failed to decode private key: " + err.Error())
	}
	var pv [32]byte
	copy(pv[:], pvBytes)
	sta.staticPv = &pv

	adminUID, err := base64.StdEncoding.DecodeString(preParse.AdminUID)
	if err != nil {
		return errors.New("Failed to decode AdminUID: " + err.Error())
	}
	sta.AdminUID = adminUID

	var arrUID [16]byte
	for _, UID := range preParse.BypassUID {
		copy(arrUID[:], UID)
		sta.BypassUID[arrUID] = struct{}{}
	}
	copy(arrUID[:], adminUID)
	sta.BypassUID[arrUID] = struct{}{}
	return nil
}

func (sta *State) IsBypass(UID []byte) bool {
	var arrUID [16]byte
	copy(arrUID[:], UID)
	_, exist := sta.BypassUID[arrUID]
	return exist
}

const TIMESTAMP_TOLERANCE = 180 * time.Second

const CACHE_CLEAN_INTERVAL = 12 * time.Hour

// UsedRandomCleaner clears the cache of used random fields every 12 hours
func (sta *State) UsedRandomCleaner() {
	for {
		time.Sleep(CACHE_CLEAN_INTERVAL)
		now := sta.Now()
		sta.usedRandomM.Lock()
		for key, t := range sta.usedRandom {
			if time.Unix(t, 0).Before(now.Add(TIMESTAMP_TOLERANCE)) {
				delete(sta.usedRandom, key)
			}
		}
		sta.usedRandomM.Unlock()
	}
}

func (sta *State) registerRandom(r []byte) bool {
	var random [32]byte
	copy(random[:], r)
	sta.usedRandomM.Lock()
	_, used := sta.usedRandom[random]
	sta.usedRandom[random] = sta.Now().Unix()
	sta.usedRandomM.Unlock()
	return used
}
