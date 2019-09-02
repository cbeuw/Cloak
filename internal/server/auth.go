package server

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/util"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type ClientInfo struct {
	UID              []byte
	SessionId        uint32
	ProxyMethod      string
	EncryptionMethod byte
	Unordered        bool
	Transport        Transport
}

type authenticationInfo struct {
	sharedSecret      []byte
	nonce             []byte
	ciphertextWithTag []byte
}

const (
	UNORDERED_FLAG = 0x01 // 0000 0001
)

var ErrInvalidPubKey = errors.New("public key has invalid format")
var ErrCiphertextLength = errors.New("ciphertext has the wrong length")
var ErrTimestampOutOfWindow = errors.New("timestamp is outside of the accepting window")
var ErrUnreconisedProtocol = errors.New("unreconised protocol")

// touchStone checks if a the authenticationInfo are valid. It doesn't check if the UID is authorised
func touchStone(ai authenticationInfo, now func() time.Time) (info ClientInfo, err error) {
	var plaintext []byte
	plaintext, err = util.AESGCMDecrypt(ai.nonce, ai.sharedSecret, ai.ciphertextWithTag)
	if err != nil {
		return
	}

	info = ClientInfo{
		UID:              plaintext[0:16],
		SessionId:        0,
		ProxyMethod:      string(bytes.Trim(plaintext[16:28], "\x00")),
		EncryptionMethod: plaintext[28],
		Unordered:        plaintext[41]&UNORDERED_FLAG != 0,
	}

	timestamp := int64(binary.BigEndian.Uint64(plaintext[29:37]))
	clientTime := time.Unix(timestamp, 0)
	serverTime := now()
	if !(clientTime.After(serverTime.Truncate(TIMESTAMP_TOLERANCE)) && clientTime.Before(serverTime.Add(TIMESTAMP_TOLERANCE))) {
		err = fmt.Errorf("%v: received timestamp %v", ErrTimestampOutOfWindow, timestamp)
		return
	}
	info.SessionId = binary.BigEndian.Uint32(plaintext[37:41])
	return
}

var ErrBadClientHello = errors.New("non (or malformed) ClientHello")
var ErrReplay = errors.New("duplicate random")
var ErrBadProxyMethod = errors.New("invalid proxy method")

// PrepareConnection checks if the first packet of data is ClientHello or HTTP GET, and checks if it was from a Cloak client
// if it is from a Cloak client, it returns the ClientInfo with the decrypted fields. It doesn't check if the user
// is authorised. It also returns a finisher callback function to be called when the caller wishes to proceed with
// the handshake
func PrepareConnection(firstPacket []byte, sta *State, conn net.Conn) (info ClientInfo, finisher func([]byte) (net.Conn, error), err error) {
	var transport Transport
	var ai authenticationInfo
	switch firstPacket[0] {
	case 0x47:
		transport = WebSocket{}
		var req *http.Request
		req, err = http.ReadRequest(bufio.NewReader(bytes.NewBuffer(firstPacket)))
		if err != nil {
			err = fmt.Errorf("failed to parse first HTTP GET: %v", err)
			return
		}
		var hiddenData []byte
		hiddenData, err = base64.StdEncoding.DecodeString(req.Header.Get("hidden"))

		ai, err = unmarshalHidden(hiddenData, sta.staticPv)
		if err != nil {
			err = fmt.Errorf("failed to unmarshal hidden data from WS into authenticationInfo: %v", err)
			return
		}

		finisher = func(sessionKey []byte) (preparedConn net.Conn, err error) {
			handler := newWsHandshakeHandler()

			http.Serve(newWsAcceptor(conn, firstPacket), handler)

			<-handler.finished
			preparedConn = handler.conn
			nonce := make([]byte, 12)
			rand.Read(nonce)

			// reply: [12 bytes nonce][32 bytes encrypted session key][16 bytes authentication tag]
			encryptedKey, err := util.AESGCMEncrypt(nonce, ai.sharedSecret, sessionKey) // 32 + 16 = 48 bytes
			if err != nil {
				err = fmt.Errorf("failed to encrypt reply: %v", err)
				return
			}
			reply := append(nonce, encryptedKey...)
			_, err = preparedConn.Write(reply)
			if err != nil {
				err = fmt.Errorf("failed to write reply: %v", err)
				go preparedConn.Close()
				return
			}
			return
		}
	case 0x16:
		transport = TLS{}
		var ch *ClientHello
		ch, err = parseClientHello(firstPacket)
		if err != nil {
			log.Debug(err)
			err = ErrBadClientHello
			return
		}

		if sta.registerRandom(ch.random) {
			err = ErrReplay
			return
		}

		ai, err = unmarshalClientHello(ch, sta.staticPv)
		if err != nil {
			err = fmt.Errorf("failed to unmarshal ClientHello into authenticationInfo: %v", err)
			return
		}

		finisher = func(sessionKey []byte) (preparedConn net.Conn, err error) {
			preparedConn = conn
			reply, err := composeReply(ch, ai.sharedSecret, sessionKey)
			if err != nil {
				err = fmt.Errorf("failed to compose TLS reply: %v", err)
				return
			}
			_, err = preparedConn.Write(reply)
			if err != nil {
				err = fmt.Errorf("failed to write TLS reply: %v", err)
				go preparedConn.Close()
				return
			}
			return
		}
	default:
		err = ErrUnreconisedProtocol
		return
	}

	info, err = touchStone(ai, sta.Now)
	if err != nil {
		log.Debug(err)
		err = fmt.Errorf("transport %v in correct format but not Cloak: %v", transport, err)
		return
	}
	info.Transport = transport
	if _, ok := sta.ProxyBook[info.ProxyMethod]; !ok {
		err = ErrBadProxyMethod
		return
	}

	return
}
