package client

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	ecdh "github.com/cbeuw/go-ecdh"
)

type rawConfig struct {
	ServerName     string
	Key            string
	TicketTimeHint int
	MaskBrowser    string
	NumConn        int
}

// State stores global variables
type State struct {
	SS_LOCAL_HOST  string
	SS_LOCAL_PORT  string
	SS_REMOTE_HOST string
	SS_REMOTE_PORT string

	Now       func() time.Time
	SID       []byte
	staticPub crypto.PublicKey
	keyPairsM sync.RWMutex
	keyPairs  map[int64]*keyPair

	TicketTimeHint int
	ServerName     string
	MaskBrowser    string
	NumConn        int
}

func InitState(localHost, localPort, remoteHost, remotePort string, nowFunc func() time.Time) *State {
	ret := &State{
		SS_LOCAL_HOST:  localHost,
		SS_LOCAL_PORT:  localPort,
		SS_REMOTE_HOST: remoteHost,
		SS_REMOTE_PORT: remotePort,
		Now:            nowFunc,
	}
	ret.keyPairs = make(map[int64]*keyPair)
	return ret
}

// semi-colon separated value. This is for Android plugin options
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
		// JSON doesn't like quotation marks around int
		// Yes this is extremely ugly but it's still better than writing a tokeniser
		if key == "TicketTimeHint" || key == "NumConn" {
			ret = append(ret, []byte("\""+key+"\":"+value+",")...)
		} else {
			ret = append(ret, []byte("\""+key+"\":\""+value+"\",")...)
		}
	}
	ret = ret[:len(ret)-1] // remove the last comma
	ret = append(ret, '}')
	return ret
}

// ParseConfig parses the config (either a path to json or Android config) into a State variable
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
	sta.ServerName = preParse.ServerName
	sta.TicketTimeHint = preParse.TicketTimeHint
	sta.MaskBrowser = preParse.MaskBrowser
	sta.NumConn = preParse.NumConn
	sid, pub, err := parseKey(preParse.Key)
	if err != nil {
		return errors.New("Failed to parse Key: " + err.Error())
	}
	sta.SID = sid
	sta.staticPub = pub
	return nil
}

// Structure: [SID 32 bytes][marshalled public key 32 bytes]
func parseKey(b64 string) ([]byte, crypto.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, err
	}
	ec := ecdh.NewCurve25519ECDH()
	pub, _ := ec.Unmarshal(b[32:64])
	return b[0:32], pub, nil
}

func (sta *State) getKeyPair(tthInterval int64) *keyPair {
	sta.keyPairsM.Lock()
	defer sta.keyPairsM.Unlock()
	return sta.keyPairs[tthInterval]
}

func (sta *State) putKeyPair(tthInterval int64, kp *keyPair) {
	sta.keyPairsM.Lock()
	sta.keyPairs[tthInterval] = kp
	sta.keyPairsM.Unlock()
}
