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

	utls "github.com/refraction-networking/utls"
)

type WSOverTLS struct {
	Transport
}

func (WSOverTLS) HasRecordLayer() bool                              { return false }
func (WSOverTLS) UnitReadFunc() func(net.Conn, []byte) (int, error) { return util.ReadWebSocket }

func (WSOverTLS) PrepareConnection(sta *State, conn net.Conn) (preparedConn net.Conn, sessionKey []byte, err error) {
	utlsConfig := &utls.Config{
		ServerName:         sta.ServerName,
		InsecureSkipVerify: true,
	}
	uconn := utls.UClient(conn, utlsConfig, utls.HelloChrome_Auto)
	err = uconn.Handshake()
	preparedConn = uconn
	if err != nil {
		return
	}

	u, err := url.Parse("ws://" + sta.RemoteHost + ":" + sta.RemotePort) //TODO IPv6
	if err != nil {
		return preparedConn, nil, fmt.Errorf("failed to parse ws url: %v", err)
	}

	hd, sharedSecret := makeHiddenData(sta)
	header := http.Header{}
	header.Add("hidden", base64.StdEncoding.EncodeToString(hd.fullRaw))
	c, _, err := websocket.NewClient(preparedConn, u, header, 16480, 16480)
	if err != nil {
		return preparedConn, nil, fmt.Errorf("failed to handshake: %v", err)
	}

	preparedConn = &util.WebSocketConn{Conn: c}

	buf := make([]byte, 128)
	n, err := preparedConn.Read(buf)
	if err != nil {
		return preparedConn, nil, fmt.Errorf("failed to read reply: %v", err)
	}

	if n != 60 {
		return preparedConn, nil, errors.New("reply must be 60 bytes")
	}

	reply := buf[:60]
	sessionKey, err = util.AESGCMDecrypt(reply[:12], sharedSecret, reply[12:])

	return
}
