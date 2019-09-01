package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/util"
	"github.com/gorilla/websocket"
	"net"
	"net/http"
	"net/url"
)

type WebSocket struct {
	Transport
}

func (WebSocket) PrepareConnection(sta *State, conn net.Conn) (sessionKey []byte, err error) {
	u, err := url.Parse("ws://" + sta.RemoteHost + ":" + sta.RemotePort) //TODO IPv6
	if err != nil {
		return nil, fmt.Errorf("failed to parse ws url: %v")
	}

	hd, sharedSecret := makeHiddenData(sta)
	header := http.Header{}
	header.Add("hidden", base64.StdEncoding.EncodeToString(hd.fullRaw))
	c, _, err := websocket.NewClient(conn, u, header, 16480, 16480)
	if err != nil {
		return nil, fmt.Errorf("failed to handshake: %v", err)
	}

	conn = &util.WebSocketConn{c}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read reply: %v", err)
	}

	if n != 60 {
		return nil, errors.New("reply must be 60 bytes")
	}

	reply := buf[:60]
	sessionKey, err = util.AESGCMDecrypt(reply[:12], sharedSecret, reply[12:])

	return
}
