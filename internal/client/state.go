package client

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	"github.com/cbeuw/Cloak/internal/ecdh"
)

type rawConfig struct {
	ServerName       string
	ProxyMethod      string
	EncryptionMethod string
	UID              string
	PublicKey        string
	BrowserSig       string
	NumConn          int
}

// State stores global variables
type State struct {
	LocalHost  string
	LocalPort  string
	RemoteHost string
	RemotePort string
	Unordered  bool

	SessionID uint32
	UID       []byte

	staticPub crypto.PublicKey
	now       func() time.Time
	browser   browser

	ProxyMethod      string
	EncryptionMethod byte
	ServerName       string
	NumConn          int
}

func InitState(localHost, localPort, remoteHost, remotePort string, nowFunc func() time.Time) *State {
	ret := &State{
		LocalHost:  localHost,
		LocalPort:  localPort,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
		now:        nowFunc,
	}
	return ret
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
		if key == "NumConn" || key == "Unordered" {
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

	switch strings.ToLower(preParse.EncryptionMethod) {
	case "plain":
		sta.EncryptionMethod = 0x00
	case "aes-gcm":
		sta.EncryptionMethod = 0x01
	case "chacha20-poly1305":
		sta.EncryptionMethod = 0x02
	default:
		return errors.New("Unknown encryption method")
	}

	switch strings.ToLower(preParse.BrowserSig) {
	case "chrome":
		sta.browser = &Chrome{}
	case "firefox":
		sta.browser = &Firefox{}
	default:
		return errors.New("unsupported browser signature")
	}

	sta.ProxyMethod = preParse.ProxyMethod
	sta.ServerName = preParse.ServerName
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
