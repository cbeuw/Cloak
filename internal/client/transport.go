package client

import "net"

type Transport interface {
	PrepareConnection(*State, net.Conn) ([]byte, error)
}
