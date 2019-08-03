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
	staticPv crypto.PrivateKey

	RedirAddr string

	usedRandomM sync.RWMutex
	usedRandom  map[[32]byte]int

	Panel          *userPanel
	LocalAPIRouter *gmux.Router
}

func InitState(bindHost, bindPort string, nowFunc func() time.Time) (*State, error) {
	ret := &State{
		BindHost: bindHost,
		BindPort: bindPort,
		Now:      nowFunc,
	}
	ret.usedRandom = make(map[[32]byte]int)
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
	return nil
}

// This is the accepting window of the encrypted timestamp from client
// we reject the client if the timestamp is outside of this window.
// This is for replay prevention so that we don't have to save unlimited amount of
// random
const TIMESTAMP_WINDOW = 12 * time.Hour

// UsedRandomCleaner clears the cache of used random fields every 12 hours
func (sta *State) UsedRandomCleaner() {
	for {
		time.Sleep(TIMESTAMP_WINDOW)
		now := int(sta.Now().Unix())
		sta.usedRandomM.Lock()
		for key, t := range sta.usedRandom {
			if now-t > int(TIMESTAMP_WINDOW.Seconds()) {
				delete(sta.usedRandom, key)
			}
		}
		sta.usedRandomM.Unlock()
	}
}
