package client

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/cbeuw/Cloak/internal/ecdh"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

type rawConfig struct {
	ServerName       string
	ProxyMethod      string
	EncryptionMethod string
	UID              string
	PublicKey        string
	TicketTimeHint   int
	BrowserSig       string
	NumConn          int
}

type tthIntervalKeys struct {
	interval    int64
	ephPv       crypto.PrivateKey
	ephPub      crypto.PublicKey
	intervalKey []byte
	seed        int64
}

// State stores global variables
type State struct {
	LocalHost  string
	LocalPort  string
	RemoteHost string
	RemotePort string

	Now       func() time.Time
	SessionID uint32
	UID       []byte
	staticPub crypto.PublicKey

	intervalDataM sync.Mutex
	intervalData  *tthIntervalKeys

	ProxyMethod      string
	EncryptionMethod byte
	Cipher           mux.Crypto
	TicketTimeHint   int
	ServerName       string
	BrowserSig       string
	NumConn          int
}

func InitState(localHost, localPort, remoteHost, remotePort string, nowFunc func() time.Time) *State {
	ret := &State{
		LocalHost:    localHost,
		LocalPort:    localPort,
		RemoteHost:   remoteHost,
		RemotePort:   remotePort,
		Now:          nowFunc,
		intervalData: &tthIntervalKeys{},
	}
	return ret
}

func (sta *State) UpdateIntervalKeys() {
	sta.intervalDataM.Lock()
	currentInterval := sta.Now().Unix() / int64(sta.TicketTimeHint)
	if currentInterval == sta.intervalData.interval {
		sta.intervalDataM.Unlock()
		return
	}
	sta.intervalData.interval = currentInterval
	ephPv, ephPub, _ := ecdh.GenerateKey(rand.Reader)
	intervalKey := ecdh.GenerateSharedSecret(ephPv, sta.staticPub)
	seed := int64(binary.BigEndian.Uint64(ephPv.(*[32]byte)[0:8]))
	sta.intervalData.ephPv, sta.intervalData.ephPub, sta.intervalData.intervalKey, sta.intervalData.seed = ephPv, ephPub, intervalKey, seed
	sta.intervalDataM.Unlock()
}

func (sta *State) GetIntervalKeys() (crypto.PublicKey, []byte, int64) {
	sta.intervalDataM.Lock()
	defer sta.intervalDataM.Unlock()
	return sta.intervalData.ephPub, sta.intervalData.intervalKey, sta.intervalData.seed
}

// semi-colon separated value. This is for Android plugin options
func ssvToJson(ssv string) (ret []byte) {
	unescape := func(s string) string {
		r := strings.Replace(s, `\\`, `\`, -1)
		r = strings.Replace(r, `\=`, `=`, -1)
		r = strings.Replace(r, `\;`, `;`, -1)
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
			ret = append(ret, []byte(`"`+key+`":`+value+`,`)...)
		} else {
			ret = append(ret, []byte(`"`+key+`":"`+value+`",`)...)
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

	switch preParse.EncryptionMethod {
	case "plain":
		sta.EncryptionMethod = 0x00
		sta.Cipher = &mux.Plain{}
	case "aes-gcm":
		sta.EncryptionMethod = 0x01
		sta.Cipher, err = mux.MakeAESGCMCipher(sta.UID)
		if err != nil {
			return err
		}
	case "chacha20-poly1305":
		sta.EncryptionMethod = 0x02
		sta.Cipher, err = mux.MakeCPCipher(sta.UID)
		if err != nil {
			return err
		}
	default:
		return errors.New("Unknown encryption method")
	}

	sta.ProxyMethod = preParse.ProxyMethod
	sta.ServerName = preParse.ServerName
	sta.TicketTimeHint = preParse.TicketTimeHint
	sta.BrowserSig = preParse.BrowserSig
	sta.NumConn = preParse.NumConn

	uid, err := base64.StdEncoding.DecodeString(preParse.UID)
	if err != nil {
		return errors.New("Failed to parse UID: " + err.Error())
	}
	sta.UID = uid

	pubBytes, err := base64.StdEncoding.DecodeString(preParse.PublicKey)
	if err != nil {
		return errors.New("Failed to parse Public key: " + err.Error())
	}
	pub, ok := ecdh.Unmarshal(pubBytes)
	if !ok {
		return errors.New("Failed to unmarshal Public key")
	}
	sta.staticPub = pub
	return nil
}
