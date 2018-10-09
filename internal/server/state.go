package server

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"strings"
	"sync"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/ecies"
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
	WebServerAddr  string
	Now            func() time.Time
	SS_LOCAL_HOST  string
	SS_LOCAL_PORT  string
	SS_REMOTE_HOST string
	SS_REMOTE_PORT string
	UsedRandomM    sync.RWMutex
	UsedRandom     map[[32]byte]int
	pv             *ecies.PrivateKey

	SessionsM sync.RWMutex
	Sessions  map[[32]byte]*mux.Session
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

// Structue: [D 32 bytes][marshalled public key]
func parseKey(b64 string) (*ecies.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	d := b[0:32]
	marshalled := b[32:]
	x, y := elliptic.Unmarshal(ecies.DefaultCurve, marshalled)
	pub := ecies.PublicKey{
		X:      x,
		Y:      y,
		Curve:  ecies.DefaultCurve,
		Params: ecies.ParamsFromCurve(ecies.DefaultCurve),
	}

	pv := &ecies.PrivateKey{
		PublicKey: pub,
		D:         new(big.Int).SetBytes(d),
	}
	return pv, nil
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
	sta.pv = pv
	return nil
}

func (sta *State) GetSession(SID [32]byte) *mux.Session {
	sta.SessionsM.Lock()
	defer sta.SessionsM.Unlock()
	if sesh, ok := sta.Sessions[SID]; ok {
		return sesh
	} else {
		return nil
	}
}

func (sta *State) PutSession(SID [32]byte, sesh *mux.Session) {
	sta.SessionsM.Lock()
	sta.Sessions[SID] = sesh
	sta.SessionsM.Unlock()
}

func (sta *State) getUsedRandom(random [32]byte) int {
	sta.UsedRandomM.Lock()
	defer sta.UsedRandomM.Unlock()
	return sta.UsedRandom[random]

}

// PutUsedRandom adds a random field into map UsedRandom
func (sta *State) putUsedRandom(random [32]byte) {
	sta.UsedRandomM.Lock()
	sta.UsedRandom[random] = int(sta.Now().Unix())
	sta.UsedRandomM.Unlock()
}

// UsedRandomCleaner clears the cache of used random fields every 12 hours
func (sta *State) UsedRandomCleaner() {
	for {
		time.Sleep(12 * time.Hour)
		now := int(sta.Now().Unix())
		sta.UsedRandomM.Lock()
		for key, t := range sta.UsedRandom {
			if now-t > 12*3600 {
				delete(sta.UsedRandom, key)
			}
		}
		sta.UsedRandomM.Unlock()
	}
}
