package server

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
)

type RawConfig struct {
	ProxyBook    map[string][]string
	BindAddr     []string
	BypassUID    [][]byte
	RedirAddr    string
	PrivateKey   []byte
	AdminUID     []byte
	DatabasePath string
	KeepAlive    int
	CncMode      bool
}

// State type stores the global state of the program
type State struct {
	ProxyBook   map[string]net.Addr
	ProxyDialer common.Dialer

	WorldState common.WorldState
	AdminUID   []byte

	BypassUID map[[16]byte]struct{}
	StaticPv  crypto.PrivateKey

	// TODO: this doesn't have to be a net.Addr; resolution is done in Dial automatically
	RedirHost   net.Addr
	RedirPort   string
	RedirDialer common.Dialer

	usedRandomM sync.RWMutex
	UsedRandom  map[[32]byte]int64

	Panel *userPanel
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

// ParseConfig reads the config file or semicolon-separated options and parse them into a RawConfig
func ParseConfig(conf string) (raw RawConfig, err error) {
	content, errPath := ioutil.ReadFile(conf)
	if errPath != nil {
		errJson := json.Unmarshal(content, &raw)
		if errJson != nil {
			err = fmt.Errorf("failed to read/unmarshal configuration, path is invalid or %v", errJson)
			return
		}
	} else {
		errJson := json.Unmarshal(content, &raw)
		if errJson != nil {
			err = fmt.Errorf("failed to read configuration file: %v", errJson)
			return
		}
	}
	if raw.ProxyBook == nil {
		raw.ProxyBook = make(map[string][]string)
	}
	return
}

// InitState process the RawConfig and initialises a server State accordingly
func InitState(preParse RawConfig, worldState common.WorldState) (sta *State, err error) {
	sta = &State{
		BypassUID:   make(map[[16]byte]struct{}),
		ProxyBook:   map[string]net.Addr{},
		UsedRandom:  map[[32]byte]int64{},
		RedirDialer: &net.Dialer{},
		WorldState:  worldState,
	}
	if preParse.CncMode {
		err = errors.New("command & control mode not implemented")
		return
	} else {
		var manager usermanager.UserManager
		if len(preParse.AdminUID) == 0 || preParse.DatabasePath == "" {
			manager = &usermanager.Voidmanager{}
		} else {
			manager, err = usermanager.MakeLocalManager(preParse.DatabasePath, worldState)
			if err != nil {
				return sta, err
			}
		}
		sta.Panel = MakeUserPanel(manager)
	}

	if preParse.KeepAlive <= 0 {
		sta.ProxyDialer = &net.Dialer{KeepAlive: -1}
	} else {
		sta.ProxyDialer = &net.Dialer{KeepAlive: time.Duration(preParse.KeepAlive) * time.Second}
	}

	sta.RedirHost, sta.RedirPort, err = parseRedirAddr(preParse.RedirAddr)
	if err != nil {
		err = fmt.Errorf("unable to parse RedirAddr: %v", err)
		return
	}

	sta.ProxyBook, err = parseProxyBook(preParse.ProxyBook)
	if err != nil {
		err = fmt.Errorf("unable to parse ProxyBook: %v", err)
		return
	}

	if len(preParse.PrivateKey) == 0 {
		err = fmt.Errorf("must have a valid private key. Run `ck-server -key` to generate one")
		return
	}
	var pv [32]byte
	copy(pv[:], preParse.PrivateKey)
	sta.StaticPv = &pv

	sta.AdminUID = preParse.AdminUID

	var arrUID [16]byte
	for _, UID := range preParse.BypassUID {
		copy(arrUID[:], UID)
		sta.BypassUID[arrUID] = struct{}{}
	}
	if len(sta.AdminUID) != 0 {
		copy(arrUID[:], sta.AdminUID)
		sta.BypassUID[arrUID] = struct{}{}
	}

	go sta.UsedRandomCleaner()
	return sta, nil
}

// IsBypass checks if a UID is a bypass user
func (sta *State) IsBypass(UID []byte) bool {
	var arrUID [16]byte
	copy(arrUID[:], UID)
	_, exist := sta.BypassUID[arrUID]
	return exist
}

const timestampTolerance = 180 * time.Second

const replayCacheAgeLimit = 12 * time.Hour

// UsedRandomCleaner clears the cache of used random fields every replayCacheAgeLimit
func (sta *State) UsedRandomCleaner() {
	for {
		time.Sleep(replayCacheAgeLimit)
		sta.usedRandomM.Lock()
		for key, t := range sta.UsedRandom {
			if time.Unix(t, 0).Before(sta.WorldState.Now().Add(timestampTolerance)) {
				delete(sta.UsedRandom, key)
			}
		}
		sta.usedRandomM.Unlock()
	}
}

func (sta *State) registerRandom(r [32]byte) bool {
	sta.usedRandomM.Lock()
	_, used := sta.UsedRandom[r]
	sta.UsedRandom[r] = sta.WorldState.Now().Unix()
	sta.usedRandomM.Unlock()
	return used
}
