package common

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConn implements io.ReadWriteCloser
// it makes websocket.Conn binary-oriented
type WebSocketConn struct {
	*websocket.Conn
	writeM sync.Mutex
}

func (ws *WebSocketConn) Write(data []byte) (int, error) {
	ws.writeM.Lock()
	err := ws.WriteMessage(websocket.BinaryMessage, data)
	ws.writeM.Unlock()
	if err != nil {
		return 0, err
	} else {
		return len(data), nil
	}
}

func (ws *WebSocketConn) Read(buf []byte) (n int, err error) {
	t, r, err := ws.NextReader()
	if err != nil {
		return 0, err
	}
	if t != websocket.BinaryMessage {
		return 0, nil
	}

	// Read until io.EOL for one full message
	for {
		var read int
		read, err = r.Read(buf[n:])
		if err != nil {
			if err == io.EOF {
				err = nil
				break
			} else {
				break
			}
		} else {
			// There may be data available to read but n == len(buf)-1, read==0 because buffer is full
			if read == 0 {
				err = errors.New("nothing more is read. message may be larger than buffer")
				break
			}
		}
		n += read
	}
	return
}
func (ws *WebSocketConn) Close() error {
	ws.writeM.Lock()
	defer ws.writeM.Unlock()
	return ws.Conn.Close()
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
