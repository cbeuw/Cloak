package server

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
	"github.com/gorilla/websocket"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type firstBuffedConn struct {
	net.Conn
	firstRead   bool
	firstPacket []byte
}

func (c *firstBuffedConn) Read(buf []byte) (int, error) {
	if !c.firstRead {
		copy(buf, c.firstPacket)
		n := len(c.firstPacket)
		c.firstPacket = []byte{}
		return n, nil
	}
	return c.Read(buf)
}

type wsAcceptor struct {
	done bool
	c    *firstBuffedConn
}

func newWsAcceptor(conn net.Conn, first []byte) *wsAcceptor {
	f := make([]byte, len(first))
	copy(f, first)
	return &wsAcceptor{
		c: &firstBuffedConn{Conn: conn, firstPacket: first},
	}
}

func (w *wsAcceptor) Accept() (net.Conn, error) {
	if w.done {
		return nil, errors.New("already accepted")
	}
	w.done = true
	return w.c, nil
}

func (w *wsAcceptor) Close() error {
	w.done = true
	return nil
}

func (w *wsAcceptor) Addr() net.Addr {
	return w.c.LocalAddr()
}

type wsHandshakeHandler struct {
	conn     net.Conn
	finished chan struct{}
}

func newWsHandshakeHandler() *wsHandshakeHandler {
	return &wsHandshakeHandler{finished: make(chan struct{})}
}

func (ws *wsHandshakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  16380,
		WriteBufferSize: 16380,
	}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("failed to upgrade connection to ws: %v", err)
		return
	}
	ws.conn = &util.WebSocketConn{c}
	ws.finished <- struct{}{}
}

var ErrBadGET = errors.New("non (or malformed) HTTP GET")

func unmarshalHidden(hidden []byte, staticPv crypto.PrivateKey) (ai authenticationInfo, err error) {
	if len(hidden) < 96 {
		err = ErrBadGET
		return
	}
	ephPub, ok := ecdh.Unmarshal(hidden[0:32])
	if !ok {
		err = ErrInvalidPubKey
		return
	}

	ai.nonce = hidden[:12]

	ai.sharedSecret = ecdh.GenerateSharedSecret(staticPv, ephPub)

	ai.ciphertextWithTag = hidden[32:]
	if len(ai.ciphertextWithTag) != 64 {
		err = fmt.Errorf("%v: %v", ErrCiphertextLength, len(ai.ciphertextWithTag))
		return
	}
	return
}
