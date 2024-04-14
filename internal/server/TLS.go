package server

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/ecdh"

	log "github.com/sirupsen/logrus"
)

const appDataMaxLength = 16401

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
	respond := func(originalConn net.Conn, sessionKey [32]byte, randSource io.Reader) (preparedConn net.Conn, err error) {
		// the cert length needs to be the same for all handshakes belonging to the same session
		// we can use sessionKey as a seed here to ensure consistency
		possibleCertLengths := []int{42, 27, 68, 59, 36, 44, 46}
		cert := make([]byte, possibleCertLengths[common.RandInt(len(possibleCertLengths))])
		common.RandRead(randSource, cert)

		var nonce [12]byte
		common.RandRead(randSource, nonce[:])
		encryptedSessionKey, err := common.AESGCMEncrypt(nonce[:], sharedSecret[:], sessionKey[:])
		if err != nil {
			return
		}
		var encryptedSessionKeyArr [48]byte
		copy(encryptedSessionKeyArr[:], encryptedSessionKey)

		reply := composeReply(clientHelloSessionId, nonce, encryptedSessionKeyArr, cert)
		_, err = originalConn.Write(reply)
		if err != nil {
			err = fmt.Errorf("failed to write TLS reply: %v", err)
			originalConn.Close()
			return
		}
		preparedConn = common.NewTLSConn(originalConn)
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

	var sharedSecret []byte
	sharedSecret, err = ecdh.GenerateSharedSecret(staticPv, ephPub)
	if err != nil {
		return
	}

	copy(fragments.sharedSecret[:], sharedSecret)
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
