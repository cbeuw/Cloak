package cli_client

import (
	"encoding/json"
	"fmt"
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/libcloak/client"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

type CLIConfig struct {
	client.Config

	// LocalHost is the hostname or IP address to listen for incoming proxy client connections
	LocalHost string // jsonOptional
	// LocalPort is the port to listen for incomig proxy client connections
	LocalPort string // jsonOptional
	// AlternativeNames is a list of ServerName Cloak may randomly pick from for different sessions
	AlternativeNames []string
	// StreamTimeout is the duration, in seconds, for an incoming connection to be automatically closed after the last
	// piece of incoming data .
	// Defaults to 300
	StreamTimeout int
}

// semi-colon separated value. This is for Android plugin options
func ssvToJson(ssv string) (ret []byte) {
	elem := func(val string, lst []string) bool {
		for _, v := range lst {
			if val == v {
				return true
			}
		}
		return false
	}
	unescape := func(s string) string {
		r := strings.Replace(s, `\\`, `\`, -1)
		r = strings.Replace(r, `\=`, `=`, -1)
		r = strings.Replace(r, `\;`, `;`, -1)
		return r
	}
	unquoted := []string{"NumConn", "StreamTimeout", "KeepAlive", "UDP"}
	lines := strings.Split(unescape(ssv), ";")
	ret = []byte("{")
	for _, ln := range lines {
		if ln == "" {
			break
		}
		sp := strings.SplitN(ln, "=", 2)
		if len(sp) < 2 {
			log.Errorf("Malformed config option: %v", ln)
			continue
		}
		key := sp[0]
		value := sp[1]
		if strings.HasPrefix(key, "AlternativeNames") {
			switch strings.Contains(value, ",") {
			case true:
				domains := strings.Split(value, ",")
				for index, domain := range domains {
					domains[index] = `"` + domain + `"`
				}
				value = strings.Join(domains, ",")
				ret = append(ret, []byte(`"`+key+`":[`+value+`],`)...)
			case false:
				ret = append(ret, []byte(`"`+key+`":["`+value+`"],`)...)
			}
			continue
		}
		// JSON doesn't like quotation marks around int and bool
		// This is extremely ugly but it's still better than writing a tokeniser
		if elem(key, unquoted) {
			ret = append(ret, []byte(`"`+key+`":`+value+`,`)...)
		} else {
			ret = append(ret, []byte(`"`+key+`":"`+value+`",`)...)
		}
	}
	ret = ret[:len(ret)-1] // remove the last comma
	ret = append(ret, '}')
	return ret
}

func ParseConfig(conf string) (raw *CLIConfig, err error) {
	var content []byte
	// Checking if it's a path to json or a ssv string
	if strings.Contains(conf, ";") && strings.Contains(conf, "=") {
		content = ssvToJson(conf)
	} else {
		content, err = ioutil.ReadFile(conf)
		if err != nil {
			return
		}
	}

	raw = new(CLIConfig)
	err = json.Unmarshal(content, &raw)
	if err != nil {
		return
	}
	return
}

type LocalConnConfig struct {
	LocalAddr      string
	Timeout        time.Duration
	MockDomainList []string
}

func (raw *CLIConfig) ProcessCLIConfig(worldState common.WorldState) (local LocalConnConfig, remote client.RemoteConnConfig, auth client.AuthInfo, err error) {
	remote, auth, err = raw.Config.Process(worldState)
	if err != nil {
		return
	}

	var filteredAlternativeNames []string
	for _, alternativeName := range raw.AlternativeNames {
		if len(alternativeName) > 0 {
			filteredAlternativeNames = append(filteredAlternativeNames, alternativeName)
		}
	}
	raw.AlternativeNames = filteredAlternativeNames

	local.MockDomainList = raw.AlternativeNames
	local.MockDomainList = append(local.MockDomainList, auth.MockDomain)

	if raw.LocalHost == "" {
		err = fmt.Errorf("LocalHost cannot be empty")
		return
	}
	if raw.LocalPort == "" {
		err = fmt.Errorf("LocalPort cannot be empty")
		return
	}
	local.LocalAddr = net.JoinHostPort(raw.LocalHost, raw.LocalPort)
	// stream no write timeout
	if raw.StreamTimeout == 0 {
		local.Timeout = 300 * time.Second
	} else {
		local.Timeout = time.Duration(raw.StreamTimeout) * time.Second
	}

	return
}
