package server

import (
	"crypto"
	"errors"
	"net"
)

type Transport interface {
	HasRecordLayer() bool
	UnitReadFunc() func(net.Conn, []byte) (int, error)
	handshake(reqPacket []byte, privateKey crypto.PrivateKey, originalConn net.Conn) (authFragments, func([]byte) (net.Conn, error), error)
}

var ErrInvalidPubKey = errors.New("public key has invalid format")
var ErrCiphertextLength = errors.New("ciphertext has the wrong length")
