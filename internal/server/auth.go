package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/util"
	"net"
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

var ErrReplay = errors.New("duplicate random")
var ErrBadProxyMethod = errors.New("invalid proxy method")

// PrepareConnection checks if the first packet of data is ClientHello or HTTP GET, and checks if it was from a Cloak client
// if it is from a Cloak client, it returns the ClientInfo with the decrypted fields. It doesn't check if the user
// is authorised. It also returns a finisher callback function to be called when the caller wishes to proceed with
// the handshake
func PrepareConnection(firstPacket []byte, sta *State, conn net.Conn) (info ClientInfo, finisher func([]byte) (net.Conn, error), err error) {
	var transport Transport
	switch firstPacket[0] {
	case 0x47:
		transport = WebSocket{}
	case 0x16:
		transport = TLS{}
	default:
		err = ErrUnreconisedProtocol
		return
	}

	var ai authenticationInfo
	ai, finisher, err = transport.handshake(firstPacket, sta.staticPv, conn)

	if err != nil {
		return
	}

	if sta.registerRandom(ai.nonce) {
		err = ErrReplay
		return
	}

	info, err = touchStone(ai, sta.Now)
	if err != nil {
		log.Debug(err)
		err = fmt.Errorf("transport %v in correct format but not Cloak: %v", info.Transport, err)
		return
	}
	if _, ok := sta.ProxyBook[info.ProxyMethod]; !ok {
		err = ErrBadProxyMethod
		return
	}
	info.Transport = transport
	return
}
