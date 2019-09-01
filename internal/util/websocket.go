package util

import (
	"github.com/gorilla/websocket"
	"time"
)

type WebSocketConn struct {
	*websocket.Conn
}

func (ws *WebSocketConn) Write(data []byte) (int, error) {
	err := ws.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return 0, err
	} else {
		return len(data), nil
	}
}

func (ws *WebSocketConn) Read(buf []byte) (int, error) {
	_, r, err := ws.NextReader()
	if err != nil {
		return 0, err
	}
	return r.Read(buf)
}

func (ws *WebSocketConn) SetDeadline(t time.Time) error {
	err := ws.SetReadDeadline(t)
	if err != nil {
		return err
	}
	err = ws.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return nil
}
