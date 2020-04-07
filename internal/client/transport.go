package client

import "net"

type Transport interface {
	PrepareConnection(*authInfo, net.Conn) (net.Conn, [32]byte, error)
	HasRecordLayer() bool
	UnitReadFunc() func(net.Conn, []byte) (int, error)
}
