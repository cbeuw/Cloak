package server

import (
	"crypto"
	"errors"
	"io"
	"net"
)

type Responder = func(originalConn net.Conn, sessionKey [32]byte, randSource io.Reader) (preparedConn net.Conn, err error)
type Transport interface {
	processFirstPacket(reqPacket []byte, privateKey crypto.PrivateKey) (authFragments, Responder, error)
}

var ErrInvalidPubKey = errors.New("public key has invalid format")
var ErrCiphertextLength = errors.New("ciphertext has the wrong length")
