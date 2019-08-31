package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/util"
	"time"
)

type ClientInfo struct {
	UID              []byte
	SessionId        uint32
	ProxyMethod      string
	EncryptionMethod byte
	Unordered        bool
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

// touchStone checks if a ClientHello came from a Cloak client by checking and decrypting the fields Cloak hides data in
// It returns the ClientInfo, but it doesn't check if the UID is authorised
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
