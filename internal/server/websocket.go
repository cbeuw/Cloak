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

// since we need to read the first packet from the client to identify its protocol, the first packet will no longer
// be in Conn's buffer. However, websocket.Upgrade relies on reading the first packet for handshake, so we must
// fake a conn that returns the first packet on first read
type firstBuffedConn struct {
	net.Conn
	firstRead   bool
	firstPacket []byte
}

func (c *firstBuffedConn) Read(buf []byte) (int, error) {
	if !c.firstRead {
		c.firstRead = true
		copy(buf, c.firstPacket)
		n := len(c.firstPacket)
		c.firstPacket = []byte{}
		return n, nil
	}
	return c.Conn.Read(buf)
}

type wsAcceptor struct {
	done bool
	c    *firstBuffedConn
}

// net/http provides no method to serve an existing connection, we must feed in a net.Accept interface to get an
// http.Server. This is an acceptor that accepts only one Conn
func newWsAcceptor(conn net.Conn, first []byte) *wsAcceptor {
	f := make([]byte, len(first))
	copy(f, first)
	return &wsAcceptor{
		c: &firstBuffedConn{Conn: conn, firstPacket: f},
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

// the handler to turn a net.Conn into a websocket.Conn
func newWsHandshakeHandler() *wsHandshakeHandler {
	return &wsHandshakeHandler{finished: make(chan struct{})}
}

func (ws *wsHandshakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("failed to upgrade connection to ws: %v", err)
		return
	}
	ws.conn = &util.WebSocketConn{Conn: c}
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
