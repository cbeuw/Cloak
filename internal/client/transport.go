package client

import "net"

type Transport interface {
	PrepareConnection(*State, net.Conn) (net.Conn, []byte, error)
	HasRecordLayer() bool
	UnitReadFunc() func(net.Conn, []byte) (int, error)
}
