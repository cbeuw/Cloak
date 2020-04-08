package server

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"net"

	log "github.com/sirupsen/logrus"
)

type TLS struct{}

var ErrBadClientHello = errors.New("non (or malformed) ClientHello")

func (TLS) String() string { return "TLS" }

func (TLS) processFirstPacket(clientHello []byte, privateKey crypto.PrivateKey) (fragments authFragments, respond Responder, err error) {
	ch, err := parseClientHello(clientHello)
	if err != nil {
		log.Debug(err)
		err = ErrBadClientHello
		return
	}

	fragments, err = TLS{}.unmarshalClientHello(ch, privateKey)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal ClientHello into authFragments: %v", err)
		return
	}

	respond = TLS{}.makeResponder(ch.sessionId, fragments.sharedSecret)

	return
}

func (TLS) makeResponder(clientHelloSessionId []byte, sharedSecret [32]byte) Responder {
	respond := func(originalConn net.Conn, sessionKey [32]byte) (preparedConn net.Conn, err error) {
		reply, err := composeReply(clientHelloSessionId, sharedSecret, sessionKey)
		if err != nil {
			err = fmt.Errorf("failed to compose TLS reply: %v", err)
			return
		}
		_, err = originalConn.Write(reply)
		if err != nil {
			err = fmt.Errorf("failed to write TLS reply: %v", err)
			go originalConn.Close()
			return
		}
		preparedConn = &common.TLSConn{Conn: originalConn}
		return
	}
	return respond
}

func (TLS) unmarshalClientHello(ch *ClientHello, staticPv crypto.PrivateKey) (fragments authFragments, err error) {
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
