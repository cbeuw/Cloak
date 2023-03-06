package server

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/ecdh"
)

type WebSocket struct{}

func (WebSocket) String() string { return "WebSocket" }

func (WebSocket) processFirstPacket(reqPacket []byte, privateKey crypto.PrivateKey) (fragments authFragments, respond Responder, err error) {
	var req *http.Request
	req, err = http.ReadRequest(bufio.NewReader(bytes.NewBuffer(reqPacket)))
	if err != nil {
		err = fmt.Errorf("failed to parse first HTTP GET: %v", err)
		return
	}
	var hiddenData []byte
	hiddenData, err = base64.StdEncoding.DecodeString(req.Header.Get("hidden"))

	fragments, err = WebSocket{}.unmarshalHidden(hiddenData, privateKey)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal hidden data from WS into authFragments: %v", err)
		return
	}

	respond = WebSocket{}.makeResponder(reqPacket, fragments.sharedSecret)

	return
}

func (WebSocket) makeResponder(reqPacket []byte, sharedSecret [32]byte) Responder {
	respond := func(originalConn net.Conn, sessionKey [32]byte, randSource io.Reader) (preparedConn net.Conn, err error) {
		handler := newWsHandshakeHandler()

		// For an explanation of the following 3 lines, see the comments in websocketAux.go
		http.Serve(newWsAcceptor(originalConn, reqPacket), handler)

		<-handler.finished
		preparedConn = handler.conn
		nonce := make([]byte, 12)
		common.RandRead(randSource, nonce)

		// reply: [12 bytes nonce][32 bytes encrypted session key][16 bytes authentication tag]
		encryptedKey, err := common.AESGCMEncrypt(nonce, sharedSecret[:], sessionKey[:]) // 32 + 16 = 48 bytes
		if err != nil {
			err = fmt.Errorf("failed to encrypt reply: %v", err)
			return
		}
		reply := append(nonce, encryptedKey...)
		_, err = preparedConn.Write(reply)
		if err != nil {
			err = fmt.Errorf("failed to write reply: %v", err)
			preparedConn.Close()
			return
		}
		return
	}
	return respond
}

var ErrBadGET = errors.New("non (or malformed) HTTP GET")

func (WebSocket) unmarshalHidden(hidden []byte, staticPv crypto.PrivateKey) (fragments authFragments, err error) {
	if len(hidden) < 96 {
		err = ErrBadGET
		return
	}

	copy(fragments.randPubKey[:], hidden[0:32])
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

	if len(hidden[32:]) != 64 {
		err = fmt.Errorf("%v: %v", ErrCiphertextLength, len(hidden[32:]))
		return
	}

	copy(fragments.ciphertextWithTag[:], hidden[32:])
	return
}
