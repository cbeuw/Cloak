package client

import (
	"encoding/base64"
	"errors"
	"github.com/cbeuw/Cloak/internal/util"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

type WebSocketConn struct {
	c *websocket.Conn
}

func (ws *WebSocketConn) Write(data []byte) (int, error) {
	err := ws.c.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return 0, err
	} else {
		return len(data), nil
	}
}

func (ws *WebSocketConn) Read(buf []byte) (int, error) {
	_, r, err := ws.c.NextReader()
	if err != nil {
		return 0, err
	}
	return r.Read(buf)
}

func (ws *WebSocketConn) Close() error         { return ws.c.Close() }
func (ws *WebSocketConn) LocalAddr() net.Addr  { return ws.c.LocalAddr() }
func (ws *WebSocketConn) RemoteAddr() net.Addr { return ws.c.RemoteAddr() }
func (ws *WebSocketConn) SetDeadline(t time.Time) error {
	err := ws.c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	err = ws.c.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return nil
}
func (ws *WebSocketConn) SetReadDeadline(t time.Time) error  { return ws.c.SetReadDeadline(t) }
func (ws *WebSocketConn) SetWriteDeadline(t time.Time) error { return ws.c.SetWriteDeadline(t) }

type WebSocket struct {
	Transport
}

func (WebSocket) PrepareConnection(sta *State, conn net.Conn) (sessionKey []byte, err error) {
	u, err := url.Parse("ws://" + sta.RemoteHost + ":" + sta.RemotePort) //TODO IPv6
	if err != nil {
		return nil, err
	}

	hd, sharedSecret := makeHiddenData(sta)
	header := http.Header{}
	header.Add("hidden", base64.StdEncoding.EncodeToString(hd.rawCiphertextWithTag))
	c, resp, err := websocket.NewClient(conn, u, header, 16480, 16480)
	if err != nil {
		return nil, err
	}

	reply, err := base64.StdEncoding.DecodeString(resp.Header.Get("reply"))
	if err != nil {
		return nil, err
	}

	if len(reply) != 60 {
		return nil, errors.New("reply must be 60 bytes")
	}
	sessionKey, err = util.AESGCMDecrypt(reply[:12], sharedSecret, reply[12:])

	conn = &WebSocketConn{c: c}
	return
}
