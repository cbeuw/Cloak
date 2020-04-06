package server

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
	"net"

	log "github.com/sirupsen/logrus"
)

type TLS struct{}

var ErrBadClientHello = errors.New("non (or malformed) ClientHello")

func (TLS) String() string                                    { return "TLS" }
func (TLS) HasRecordLayer() bool                              { return true }
func (TLS) UnitReadFunc() func(net.Conn, []byte) (int, error) { return util.ReadTLS }

func (TLS) handshake(clientHello []byte, privateKey crypto.PrivateKey, originalConn net.Conn) (fragments authFragments, finisher func([]byte) (net.Conn, error), err error) {
	var ch *ClientHello
	ch, err = parseClientHello(clientHello)
	if err != nil {
		log.Debug(err)
		err = ErrBadClientHello
		return
	}

	fragments, err = unmarshalClientHello(ch, privateKey)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal ClientHello into authFragments: %v", err)
		return
	}

	finisher = func(sessionKey []byte) (preparedConn net.Conn, err error) {
		preparedConn = originalConn
		reply, err := composeReply(ch, fragments.sharedSecret[:], sessionKey)
		if err != nil {
			err = fmt.Errorf("failed to compose TLS reply: %v", err)
			return
		}
		_, err = preparedConn.Write(reply)
		if err != nil {
			err = fmt.Errorf("failed to write TLS reply: %v", err)
			go preparedConn.Close()
			return
		}
		return
	}

	return
}

func unmarshalClientHello(ch *ClientHello, staticPv crypto.PrivateKey) (fragments authFragments, err error) {
	copy(fragments.randPubKey[:], ch.random)
	ephPub, ok := ecdh.Unmarshal(fragments.randPubKey[:])
	if !ok {
		err = ErrInvalidPubKey
		return
	}

	copy(fragments.sharedSecret[:], ecdh.GenerateSharedSecret(staticPv, ephPub))
	var keyShare []byte
	keyShare, err = parseKeyShare(ch.extensions[[2]byte{0x00, 0x33}])
	if err != nil {
		return
	}

	ctxTag := append(ch.sessionId, keyShare...)
	if len(ctxTag) != 64 {
		err = fmt.Errorf("%v: %v", ErrCiphertextLength, len(ctxTag))
		return
	}
	copy(fragments.ciphertextWithTag[:], ctxTag)
	return
}
