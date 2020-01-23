package client

import (
	"crypto"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	"github.com/cbeuw/Cloak/internal/ecdh"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

// rawConfig represents the fields in the config json file
type rawConfig struct {
	ServerName       string
	ProxyMethod      string
	EncryptionMethod string
	UID              []byte
	PublicKey        []byte
	BrowserSig       string
	Transport        string
	NumConn          int
	StreamTimeout    int
}

// State stores the parsed configuration fields
type State struct {
	LocalHost  string
	LocalPort  string
	RemoteHost string
	RemotePort string
	Unordered  bool

	Transport Transport

	SessionID uint32
	UID       []byte

	staticPub crypto.PublicKey
	Now       func() time.Time // for easier testing
	browser   browser

	ProxyMethod      string
	EncryptionMethod byte
	ServerName       string
	NumConn          int
	Timeout          time.Duration
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
		// JSON doesn't like quotation marks around int and bool
		// This is extremely ugly but it's still better than writing a tokeniser
		if key == "NumConn" || key == "Unordered" || key == "StreamTimeout" {
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
	// Checking if it's a path to json or a ssv string
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
		sta.EncryptionMethod = mux.E_METHOD_PLAIN
	case "aes-gcm":
		sta.EncryptionMethod = mux.E_METHOD_AES_GCM
	case "chacha20-poly1305":
		sta.EncryptionMethod = mux.E_METHOD_CHACHA20_POLY1305
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

	switch strings.ToLower(preParse.Transport) {
	case "direct":
		sta.Transport = DirectTLS{}
	case "cdn":
		sta.Transport = WSOverTLS{}
	default:
		sta.Transport = DirectTLS{}
	}

	sta.ProxyMethod = preParse.ProxyMethod
	sta.ServerName = preParse.ServerName
	sta.NumConn = preParse.NumConn
	if preParse.StreamTimeout == 0 {
		sta.Timeout = 300 * time.Second
	} else {
		sta.Timeout = time.Duration(preParse.StreamTimeout) * time.Second
	}
	sta.UID = preParse.UID

	pub, ok := ecdh.Unmarshal(preParse.PublicKey)
	if !ok {
		return errors.New("Failed to unmarshal Public key")
	}
	sta.staticPub = pub

	return nil
}
