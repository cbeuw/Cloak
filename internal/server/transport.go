package server

import (
	"github.com/cbeuw/Cloak/internal/util"
	"net"
)

type Transport interface {
	HasRecordLayer() bool
	UnitReadFunc() func(net.Conn, []byte) (int, error)
}

type TLS struct{}

func (*TLS) HasRecordLayer() bool                              { return true }
func (*TLS) UnitReadFunc() func(net.Conn, []byte) (int, error) { return util.ReadTLS }

type WebSocket struct{}

func (*WebSocket) HasRecordLayer() bool                              { return false }
func (*WebSocket) UnitReadFunc() func(net.Conn, []byte) (int, error) { return util.ReadWebSocket }
