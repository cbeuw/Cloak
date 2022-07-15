package transports

import (
	"crypto"
	"github.com/cbeuw/Cloak/internal/common"
	"net"
)

type Transport interface {
	Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error)
	net.Conn
}

type AuthInfo struct {
	UID              []byte
	SessionId        uint32
	ProxyMethod      string
	EncryptionMethod byte
	Unordered        bool
	ServerPubKey     crypto.PublicKey
	MockDomain       string
	WorldState       common.WorldState
}
