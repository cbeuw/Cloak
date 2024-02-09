package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

type WSOverTLS struct {
	*common.WebSocketConn
	wsUrl string
}

func (ws *WSOverTLS) Handshake(rawConn net.Conn, authInfo AuthInfo) (sessionKey [32]byte, err error) {
	utlsConfig := &utls.Config{
		ServerName:         authInfo.MockDomain,
		InsecureSkipVerify: true,
	}
	uconn := utls.UClient(rawConn, utlsConfig, utls.HelloChrome_Auto)
	err = uconn.BuildHandshakeState()
	if err != nil {
		return
	}
	for i, extension := range uconn.Extensions {
		_, ok := extension.(*utls.ALPNExtension)
		if ok {
			uconn.Extensions = append(uconn.Extensions[:i], uconn.Extensions[i+1:]...)
			break
		}
	}

	err = uconn.Handshake()
	if err != nil {
		return
	}

	u, err := url.Parse(ws.wsUrl)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to parse ws url: %v", err)
	}

	payload, sharedSecret := makeAuthenticationPayload(authInfo)
	header := http.Header{}
	header.Add("hidden", base64.StdEncoding.EncodeToString(append(payload.randPubKey[:], payload.ciphertextWithTag[:]...)))
	c, _, err := websocket.NewClient(uconn, u, header, 16480, 16480)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to handshake: %v", err)
	}

	ws.WebSocketConn = &common.WebSocketConn{Conn: c}

	buf := make([]byte, 128)
	n, err := ws.Read(buf)
	if err != nil {
		return sessionKey, fmt.Errorf("failed to read reply: %v", err)
	}

	if n != 60 {
		return sessionKey, errors.New("reply must be 60 bytes")
	}

	reply := buf[:60]
	sessionKeySlice, err := common.AESGCMDecrypt(reply[:12], sharedSecret[:], reply[12:])
	if err != nil {
		return
	}
	copy(sessionKey[:], sessionKeySlice)

	return
}

func (ws *WSOverTLS) Close() error {
	if ws.WebSocketConn != nil {
		return ws.WebSocketConn.Close()
	}
	return nil
}
