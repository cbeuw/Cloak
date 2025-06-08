package client

import (
	"net"
)

type Transport interface {
	Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error)
	net.Conn
}

type TransportConfig struct {
	mode string

	wsUrl string

	browser browser
}

func (t TransportConfig) CreateTransport() Transport {
	switch t.mode {
	case "cdn":
		return &WSOverTLS{
			wsUrl: t.wsUrl,
		}
	case "direct":
		return &DirectTLS{
			browser: t.browser,
		}
	default:
		return nil
	}
}
