package server

import (
	"errors"
	"net"
	"net/http"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/gorilla/websocket"

	log "github.com/sirupsen/logrus"
)

// The code in this file is mostly to obtain a binary-oriented, net.Conn analogous
// util.WebSocketConn from the awkward APIs of gorilla/websocket and net/http
//
// The flow of our process is: accept a Conn from remote, read the first packet remote sent us. If it's in the format
// of a TLS handshake, we hand it over to the TLS part; if it's in the format of a HTTP request, we process it as a
// websocket and eventually wrap the remote Conn as util.WebSocketConn,
//
// To get a util.WebSocketConn, we need a gorilla/websocket.Conn. This is obtained by using upgrader.Upgrade method
// inside a HTTP request handler function (which is defined by us). The HTTP request handler function is invoked by
// net/http package upon receiving a request from a Conn.
//
// Ideally we want to give net/http the connection we got from remote, then it can read the first packet (which should
// be an HTTP request) from that Conn and call the handler function, which can then be upgraded to obtain a
// gorilla/websocket.Conn. But this won't work for two reasons: one is that we have ALREADY READ the request packet
// from the remote Conn to determine if it's TLS or HTTP. When net/http reads from the Conn, it will not receive that
// request packet. The second reason is that there is no API in net/http that accepts a Conn at all. Instead, the
// closest we can get is http.Serve which takes in a net.Listener and a http.Handler which implements the ServeHTTP
// function.
//
// Recall that net.Listener has a method Accept which blocks until the Listener receives a connection, then
// it returns a net.Conn. net/http calls Listener.Accept repeatedly and creates a new goroutine handling each Conn
// accepted.
//
// So here is what we need to do: we need to create a type WsAcceptor that implements net.Listener interface.
// the first time WsAcceptor.Accept is called, it will return something that implements net.Conn, subsequent calls to
// Accept will return error (so that the caller won't call again)
//
// The "something that implements net.Conn" needs to do the following: the first time Read is called, it returns the
// request packet we got from the remote Conn which we have already read, so that the packet, which is an HTTP request
// will be processed by the handling function. Subsequent calls to Read will read directly from the remote Conn. To do
// this we create a type firstBuffedConn that implements net.Conn. When we instantiate a firstBuffedConn object, we
// give it the request packet we have already read from the remote Conn, as well as the reference to the remote Conn.
//
// So now we call http.Serve(WsAcceptor, [some handler]), net/http will call WsAcceptor.Accept, which returns a
// firstBuffedConn. net/http will call WsAcceptor.Accept again but this time it returns error so net/http will stop.
// firstBuffedConn.Read will then be called, which returns the request packet from remote Conn. Then
// [some handler].ServeHTTP will be called, in which websocket.upgrader.Upgrade will be called to obtain a
// websocket.Conn
//
// One problem remains: websocket.upgrader.Upgrade is called inside the handling function. The websocket.Conn it
// returned needs to be somehow preserved so we can keep using it. To do this, we define a type WsHandshakeHandler
// which implements http.Handler. WsHandshakeHandler has a struct field of type net.Conn that can be set. Inside
// WsHandshakeHandler.ServeHTTP, the returned websocket.Conn from upgrader.Upgrade will be converted into a
// util.WebSocketConn, whose reference will be kept in the struct field. Whoever has the reference to the instance of
// WsHandshakeHandler can get the reference to the established util.WebSocketConn.
//
// There is another problem: the call of http.Serve(WsAcceptor, WsHandshakeHandler) is async. We don't know when
// the instance of WsHandshakeHandler will have the util.WebSocketConn ready. We synchronise this using a channel.
// A channel called finished will be provided to an instance of WsHandshakeHandler upon its creation. Once
// WsHandshakeHandler.ServeHTTP has the reference to util.WebSocketConn ready, it will write to finished.
// Outside, immediately after the call to http.Serve(WsAcceptor, WsHandshakeHandler), we read from finished so that the
// execution will block until the reference to util.WebSocketConn is ready.

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

type wsOnceListener struct {
	done bool
	c    *firstBuffedConn
}

// net/http provides no method to serve an existing connection, we must feed in a net.Accept interface to get an
// http.Server. This is an acceptor that accepts only one Conn
func newWsAcceptor(conn net.Conn, first []byte) *wsOnceListener {
	f := make([]byte, len(first))
	copy(f, first)
	return &wsOnceListener{
		c: &firstBuffedConn{Conn: conn, firstPacket: f},
	}
}

func (w *wsOnceListener) Accept() (net.Conn, error) {
	if w.done {
		return nil, errors.New("already accepted")
	}
	w.done = true
	return w.c, nil
}

func (w *wsOnceListener) Close() error {
	w.done = true
	return nil
}

func (w *wsOnceListener) Addr() net.Addr {
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
	ws.conn = &common.WebSocketConn{Conn: c}
	ws.finished <- struct{}{}
}
