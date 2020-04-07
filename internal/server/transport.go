package server

import (
	"crypto"
	"errors"
	"net"
)

type Responder = func(originalConn net.Conn, sessionKey [32]byte) (preparedConn net.Conn, err error)
type Transport interface {
	HasRecordLayer() bool
	UnitReadFunc() func(net.Conn, []byte) (int, error)
	processFirstPacket(reqPacket []byte, privateKey crypto.PrivateKey) (authFragments, Responder, error)
}

var ErrInvalidPubKey = errors.New("public key has invalid format")
var ErrCiphertextLength = errors.New("ciphertext has the wrong length")
