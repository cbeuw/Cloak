package client

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/cbeuw/ecies"
	"io/ioutil"
	"strings"
	"time"
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
	Now            func() time.Time
	SID            []byte
	pub            *ecies.PublicKey
	TicketTimeHint int
	ServerName     string
	MaskBrowser    string
	NumConn        int
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
	sta.pub = pub
	return nil
}

// Structure: [SID 32 bytes][marshalled public key]
func parseKey(b64 string) ([]byte, *ecies.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, err
	}
	sid := b[0:32]
	marshalled := b[32:]
	x, y := elliptic.Unmarshal(ecies.DefaultCurve, marshalled)
	pub := &ecies.PublicKey{
		X:      x,
		Y:      y,
		Curve:  ecies.DefaultCurve,
		Params: ecies.ParamsFromCurve(ecies.DefaultCurve),
	}
	return sid, pub, nil
}
