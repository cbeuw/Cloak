package server

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
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
	PrivateKey    []byte
	AdminUID      []byte
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

	RedirHost net.Addr
	RedirPort string

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

func parseRedirAddr(redirAddr string) (net.Addr, string, error) {
	var host string
	var port string
	colonSep := strings.Split(redirAddr, ":")
	if len(colonSep) > 1 {
		if len(colonSep) == 2 {
			// domain or ipv4 with port
			host = colonSep[0]
			port = colonSep[1]
		} else {
			if strings.Contains(redirAddr, "[") {
				// ipv6 with port
				port = colonSep[len(colonSep)-1]
				host = strings.TrimSuffix(redirAddr, "]:"+port)
				host = strings.TrimPrefix(host, "[")
			} else {
				// ipv6 without port
				host = redirAddr
			}
		}
	} else {
		// domain or ipv4 without port
		host = redirAddr
	}

	redirHost, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, "", fmt.Errorf("unable to resolve RedirAddr: %v. ", err)
	}
	return redirHost, port, nil
}

func parseLocalPanel(databasePath string) (*userPanel, *gmux.Router, error) {
	manager, err := usermanager.MakeLocalManager(databasePath)
	if err != nil {
		return nil, nil, err
	}
	panel := MakeUserPanel(manager)
	router := manager.Router
	return panel, router, nil

}

func parseBindAddr(bindAddrs []string) ([]net.Addr, error) {
	var addrs []net.Addr
	for _, addr := range bindAddrs {
		bindAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, bindAddr)
	}
	return addrs, nil
}

func parseProxyBook(bookEntries map[string][]string) (map[string]net.Addr, error) {
	proxyBook := map[string]net.Addr{}
	for name, pair := range bookEntries {
		name = strings.ToLower(name)
		if len(pair) != 2 {
			return nil, fmt.Errorf("invalid proxy endpoint and address pair for %v: %v", name, pair)
		}
		network := strings.ToLower(pair[0])
		switch network {
		case "tcp":
			addr, err := net.ResolveTCPAddr("tcp", pair[1])
			if err != nil {
				return nil, err
			}
			proxyBook[name] = addr
			continue
		case "udp":
			addr, err := net.ResolveUDPAddr("udp", pair[1])
			if err != nil {
				return nil, err
			}
			proxyBook[name] = addr
			continue
		}
	}
	return proxyBook, nil
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
		return errors.New("command & control mode not implemented")
	} else {
		sta.Panel, sta.LocalAPIRouter, err = parseLocalPanel(preParse.DatabasePath)
	}

	if preParse.StreamTimeout == 0 {
		sta.Timeout = time.Duration(300) * time.Second
	} else {
		sta.Timeout = time.Duration(preParse.StreamTimeout) * time.Second
	}

	sta.RedirHost, sta.RedirPort, err = parseRedirAddr(preParse.RedirAddr)
	if err != nil {
		return fmt.Errorf("unable to parse RedirAddr: %v", err)
	}

	sta.BindAddr, err = parseBindAddr(preParse.BindAddr)
	if err != nil {
		return fmt.Errorf("unable to parse BindAddr: %v", err)
	}

	sta.ProxyBook, err = parseProxyBook(preParse.ProxyBook)
	if err != nil {
		return fmt.Errorf("unable to parse ProxyBook: %v", err)
	}

	var pv [32]byte
	copy(pv[:], preParse.PrivateKey)
	sta.staticPv = &pv

	sta.AdminUID = preParse.AdminUID

	var arrUID [16]byte
	for _, UID := range preParse.BypassUID {
		copy(arrUID[:], UID)
		sta.BypassUID[arrUID] = struct{}{}
	}
	copy(arrUID[:], sta.AdminUID)
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

func (sta *State) registerRandom(r [32]byte) bool {
	sta.usedRandomM.Lock()
	_, used := sta.usedRandom[r]
	sta.usedRandom[r] = sta.Now().Unix()
	sta.usedRandomM.Unlock()
	return used
}
