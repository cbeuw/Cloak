package server

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	gmux "github.com/gorilla/mux"
)

type rawConfig struct {
	ProxyBook     map[string][]string
	BindAddr      []string
	BypassUID     [][]byte
	RedirAddr     string
	PrivateKey    string
	AdminUID      string
	DatabasePath  string
	StreamTimeout int
	CncMode       bool
}

// State type stores the global state of the program
type State struct {
	BindAddr  []net.Addr
	ProxyBook map[string]net.Addr

	Now      func() time.Time
	AdminUID []byte
	Timeout  time.Duration

	BypassUID map[[16]byte]struct{}
	staticPv  crypto.PrivateKey

	RedirAddr net.Addr

	usedRandomM sync.RWMutex
	usedRandom  map[[32]byte]int64

	Panel          *userPanel
	LocalAPIRouter *gmux.Router
}

func InitState(nowFunc func() time.Time) (*State, error) {
	ret := &State{
		Now:        nowFunc,
		BypassUID:  make(map[[16]byte]struct{}),
		ProxyBook:  map[string]net.Addr{},
		usedRandom: map[[32]byte]int64{},
	}
	go ret.UsedRandomCleaner()
	return ret, nil
}

// ParseConfig parses the config (either a path to json or the json itself as argument) into a State variable
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

	sta.Timeout = time.Duration(preParse.StreamTimeout) * time.Second

	sta.RedirAddr, err = net.ResolveIPAddr("ip", preParse.RedirAddr)
	if err != nil {
		logrus.Error("If RedirAddr contains a port number, please remove it.")
		return fmt.Errorf("unable to resolve RedirAddr: %v. ", err)
	}

	for _, addr := range preParse.BindAddr {
		bindAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return err
		}
		sta.BindAddr = append(sta.BindAddr, bindAddr)
	}

	for name, pair := range preParse.ProxyBook {
		name = strings.ToLower(name)
		if len(pair) != 2 {
			return fmt.Errorf("invalid proxy endpoint and address pair for %v: %v", name, pair)
		}
		network := strings.ToLower(pair[0])
		switch network {
		case "tcp":
			addr, err := net.ResolveTCPAddr("tcp", pair[1])
			if err != nil {
				return err
			}
			sta.ProxyBook[name] = addr
			continue
		case "udp":
			addr, err := net.ResolveUDPAddr("udp", pair[1])
			if err != nil {
				return err
			}
			sta.ProxyBook[name] = addr
			continue
		}
	}

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

// IsBypass checks if a UID is a bypass user
func (sta *State) IsBypass(UID []byte) bool {
	var arrUID [16]byte
	copy(arrUID[:], UID)
	_, exist := sta.BypassUID[arrUID]
	return exist
}

const TIMESTAMP_TOLERANCE = 180 * time.Second

const CACHE_CLEAN_INTERVAL = 12 * time.Hour

// UsedRandomCleaner clears the cache of used random fields every CACHE_CLEAN_INTERVAL
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
