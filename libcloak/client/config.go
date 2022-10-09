package client

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/libcloak/client/browsers"
	"github.com/cbeuw/Cloak/libcloak/client/transports"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/cbeuw/Cloak/internal/common"
	log "github.com/sirupsen/logrus"

	"github.com/cbeuw/Cloak/internal/ecdh"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

// Config contains the configuration parameter fields for a Cloak client
type Config struct {
	// Required fields
	// ServerName is the domain you appear to be visiting
	// to your Firewall or ISP
	ServerName string
	// ProxyMethod is the name of the underlying proxy you wish
	// to connect to, as determined by your server. The value can
	// be any string whose UTF-8 ENCODED byte length is no greater than
	// 12 bytes
	ProxyMethod string
	// UID is a 16-byte secret string unique to an authorised user
	// The same UID can be used by the same user for multiple Cloak connections
	UID []byte
	// PublicKey is the 32-byte public Curve25519 ECDH key of your server
	PublicKey []byte
	// RemoteHost is the Cloak server's hostname or IP address
	RemoteHost string

	// Optional Fields
	// EncryptionMethod is the cryptographic algorithm used to
	// encrypt data on the wire.
	// Valid values are `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, and `plain`
	// Defaults to `aes-256-gcm`
	EncryptionMethod string
	// NumConn is the amount of underlying TLS connections to establish with Cloak server.
	// Cloak multiplexes any number of incoming connections to a fixed number of underlying TLS connections.
	// If set to 0, a special singleplex mode is enabled: each incoming connection will correspond to exactly one
	// TLS connection
	// Defaults to 4
	NumConn *int
	// UDP enables UDP semantics, where packets must fit into one unit of message (below 16000 bytes by default),
	// and packets can be received out of order. Though reliable delivery is still guaranteed.
	UDP bool
	// BrowserSig is the browser signature to be used. Options are `chrome` and `firefox`
	// Defaults to `chrome`
	BrowserSig string
	// Transport is either `direct` or `cdn`. Under `direct`, the client connects to a Cloak server directly.
	// Under `cdn`, the client connects to a CDN provider such as Amazon Cloudfront, which in turn connects
	// to a Cloak server.
	// Defaults to `direct`
	Transport string
	// CDNOriginHost is the CDN Origin's (i.e. Cloak server) real hostname or IP address, which is encrypted between
	// the client and the CDN server, and therefore hidden to ISP or firewalls. This only has effect when Transport
	// is set to `cdn`
	// Defaults to RemoteHost
	CDNOriginHost string
	// KeepAlive is the interval between TCP KeepAlive packets to be sent over the underlying TLS connections
	// Defaults to -1, which means no TCP KeepAlive is ever sent
	KeepAlive int
	// RemotePort is the port Cloak server is listening to
	// Defaults to 443
	RemotePort string
	// InactivityTimeout is the number of seconds the client keeps the underlying connections to the server
	// after the last proxy connection is disconnected.
	// Defaults to 30. Always set to 0 under Singleplex mode (NumConn == 0)
	InactivityTimeout *int
}

type RemoteConnConfig struct {
	NumConn           int
	KeepAlive         time.Duration
	RemoteAddr        string
	TransportMaker    func() transports.Transport
	InactivityTimeout time.Duration
}

type AuthInfo = transports.AuthInfo

func (raw *Config) Process(worldState common.WorldState) (remote RemoteConnConfig, auth AuthInfo, err error) {
	if raw.ServerName == "" {
		err = fmt.Errorf("ServerName cannot be empty")
		return
	}
	if raw.ProxyMethod == "" {
		err = fmt.Errorf("ProxyMethod cannot be empty")
		return
	}
	if len(raw.UID) == 0 {
		err = fmt.Errorf("UID cannot be empty")
		return
	}
	if len(raw.PublicKey) == 0 {
		err = fmt.Errorf("PublicKey cannot be empty")
		return
	}
	if raw.RemoteHost == "" {
		err = fmt.Errorf("RemoteHost cannot be empty")
		return
	}

	auth.UID = raw.UID
	auth.Unordered = raw.UDP
	auth.MockDomain = raw.ServerName
	auth.ProxyMethod = raw.ProxyMethod
	auth.WorldState = worldState

	// static public key
	pub, ok := ecdh.Unmarshal(raw.PublicKey)
	if !ok {
		err = fmt.Errorf("failed to unmarshal Public key")
		return
	}
	auth.ServerPubKey = pub

	// Encryption method
	switch strings.ToLower(raw.EncryptionMethod) {
	case "plain":
		auth.EncryptionMethod = mux.EncryptionMethodPlain
	case "aes-gcm", "aes-256-gcm", "":
		auth.EncryptionMethod = mux.EncryptionMethodAES256GCM
	case "aes-128-gcm":
		auth.EncryptionMethod = mux.EncryptionMethodAES128GCM
	case "chacha20-poly1305":
		auth.EncryptionMethod = mux.EncryptionMethodChaha20Poly1305
	default:
		err = fmt.Errorf("unknown encryption method %v", raw.EncryptionMethod)
		return
	}

	var remotePort string
	if raw.RemotePort == "" {
		remotePort = "443"
	} else {
		remotePort = raw.RemotePort
	}
	remote.RemoteAddr = net.JoinHostPort(raw.RemoteHost, remotePort)

	if raw.InactivityTimeout == nil {
		remote.InactivityTimeout = 30 * time.Second
	} else {
		remote.InactivityTimeout = time.Duration(*raw.InactivityTimeout) * time.Second
	}

	if raw.NumConn == nil {
		remote.NumConn = 4
	} else if *raw.NumConn <= 0 {
		remote.NumConn = 1
		remote.InactivityTimeout = 0
	} else {
		remote.NumConn = *raw.NumConn
	}

	// Transport and (if TLS mode), browser
	switch strings.ToLower(raw.Transport) {
	case "cdn":
		cdnPort := raw.RemotePort
		var cdnHost string
		if raw.CDNOriginHost == "" {
			cdnHost = raw.RemoteHost
		} else {
			cdnHost = raw.CDNOriginHost
		}

		remote.TransportMaker = func() transports.Transport {
			return &transports.WSOverTLS{
				CDNHost: cdnHost,
				CDNPort: cdnPort,
			}
		}
	case "direct":
		var browser browser
		switch strings.ToLower(raw.BrowserSig) {
		case "firefox":
			browser = firefox
		case "safari":
			browser = safari
		case "chrome":
			fallthrough
		default:
			browser = chrome
		}
		remote.TransportMaker = func() transports.Transport {
			return &transports.DirectTLS{
				Browser: browser,
			}
		}
	default:
		err = fmt.Errorf("unknown transport %v", raw.Transport)
		return
	}

	// KeepAlive
	if raw.KeepAlive <= 0 {
		remote.KeepAlive = -1
	} else {
		remote.KeepAlive = remote.KeepAlive * time.Second
	}

	return
}
