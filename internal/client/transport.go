package client

import (
	"net"
)

type Transport interface {
	Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error)
	net.Conn
}
