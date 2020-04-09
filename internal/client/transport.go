package client

import (
	"net"
)

type Transport interface {
	Handshake(rawConn net.Conn, authInfo authInfo) (sessionKey [32]byte, err error)
	net.Conn
}
