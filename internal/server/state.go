package server

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

type rawConfig struct {
	WebServerAddr string
	Key           string
}
type stateManager interface {
	ParseConfig(string) error
	SetAESKey(string)
	PutUsedRandom([32]byte)
}

// State type stores the global state of the program
type State struct {
	SS_LOCAL_HOST  string
	SS_LOCAL_PORT  string
	SS_REMOTE_HOST string
	SS_REMOTE_PORT string

	Now         func() time.Time
	staticPv    crypto.PrivateKey
	usedRandomM sync.RWMutex
	usedRandom  map[[32]byte]int
	sessionsM   sync.RWMutex
	sessions    map[[32]byte]*mux.Session

	WebServerAddr string
}

func InitState(localHost, localPort, remoteHost, remotePort string, nowFunc func() time.Time) *State {
	ret := &State{
		SS_LOCAL_HOST:  localHost,
		SS_LOCAL_PORT:  localPort,
		SS_REMOTE_HOST: remoteHost,
		SS_REMOTE_PORT: remotePort,
		Now:            nowFunc,
	}
	ret.usedRandom = make(map[[32]byte]int)
	ret.sessions = make(map[[32]byte]*mux.Session)
	return ret
}

// semi-colon separated value.
func ssvToJson(ssv string) (ret []byte) {
	unescape := func(s string) string {
		r := strings.Replace(s, "\\\\", "\\", -1)
		r = strings.Replace(r, "\\=", "=", -1)
		r = strings.Replace(r, "\\;", ";", -1)
		return r
	}
	lines := strings.Split(unescape(ssv), ";")
	ret = []byte("{")
	for _, ln := range lines {
		if ln == "" {
			break
		}
		sp := strings.SplitN(ln, "=", 2)
		key := sp[0]
		value := sp[1]
		ret = append(ret, []byte("\""+key+"\":\""+value+"\",")...)

	}
	ret = ret[:len(ret)-1] // remove the last comma
	ret = append(ret, '}')
	return ret
}

// base64 encoded 32 byte private key
func parseKey(b64 string) (crypto.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	var pv [32]byte
	copy(pv[:], b)
	return &pv, nil
}

// ParseConfig parses the config (either a path to json or in-line ssv config) into a State variable
func (sta *State) ParseConfig(conf string) (err error) {
	var content []byte
	if strings.Contains(conf, ";") && strings.Contains(conf, "=") {
		content = ssvToJson(conf)
	} else {
		content, err = ioutil.ReadFile(conf)
		if err != nil {
			return err
		}
	}

	var preParse rawConfig
	err = json.Unmarshal(content, &preParse)
	if err != nil {
		return err
	}

	sta.WebServerAddr = preParse.WebServerAddr
	pv, err := parseKey(preParse.Key)
	if err != nil {
		return err
	}
	sta.staticPv = pv
	return nil
}

func (sta *State) GetSession(SID [32]byte) *mux.Session {
	sta.sessionsM.RLock()
	defer sta.sessionsM.RUnlock()
	if sesh, ok := sta.sessions[SID]; ok {
		return sesh
	} else {
		return nil
	}
}

func (sta *State) PutSession(SID [32]byte, sesh *mux.Session) {
	sta.sessionsM.Lock()
	sta.sessions[SID] = sesh
	sta.sessionsM.Unlock()
}

func (sta *State) DelSession(SID [32]byte) {
	sta.sessionsM.Lock()
	delete(sta.sessions, SID)
	sta.sessionsM.Unlock()
}

func (sta *State) getUsedRandom(random [32]byte) int {
	sta.usedRandomM.Lock()
	defer sta.usedRandomM.Unlock()
	return sta.usedRandom[random]

}

// PutUsedRandom adds a random field into map usedRandom
func (sta *State) putUsedRandom(random [32]byte) {
	sta.usedRandomM.Lock()
	sta.usedRandom[random] = int(sta.Now().Unix())
	sta.usedRandomM.Unlock()
}

// UsedRandomCleaner clears the cache of used random fields every 12 hours
func (sta *State) UsedRandomCleaner() {
	for {
		time.Sleep(12 * time.Hour)
		now := int(sta.Now().Unix())
		sta.usedRandomM.Lock()
		for key, t := range sta.usedRandom {
			if now-t > 12*3600 {
				delete(sta.usedRandom, key)
			}
		}
		sta.usedRandomM.Unlock()
	}
}
