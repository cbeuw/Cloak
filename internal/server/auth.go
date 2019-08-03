package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
)

var ErrReplay = errors.New("duplicate random")
var ErrInvalidPubKey = errors.New("public key has invalid format")
var ErrCiphertextLength = errors.New("ciphertext has the wrong length")
var ErrTimestampOutOfWindow = errors.New("timestamp is outside of the accepting window")

func TouchStone(ch *ClientHello, sta *State) (UID []byte, sessionID uint32, proxyMethod string, encryptionMethod byte, sharedSecret []byte, err error) {

	if sta.registerRandom(ch.random) {
		err = ErrReplay
		return
	}

	ephPub, ok := ecdh.Unmarshal(ch.random)
	if !ok {
		err = ErrInvalidPubKey
		return
	}

	sharedSecret = ecdh.GenerateSharedSecret(sta.staticPv, ephPub)
	var keyShare []byte
	keyShare, err = parseKeyShare(ch.extensions[[2]byte{0x00, 0x33}])
	if err != nil {
		return
	}

	ciphertext := append(ch.sessionId, keyShare...)
	if len(ciphertext) != 64 {
		err = fmt.Errorf("%v: %v", ErrCiphertextLength, len(ciphertext))
		return
	}

	var plaintext []byte
	plaintext, err = util.AESGCMDecrypt(ch.random[0:12], sharedSecret, ciphertext)
	if err != nil {
		return
	}

	UID = plaintext[0:16]
	proxyMethod = string(bytes.Trim(plaintext[16:28], "\x00"))
	encryptionMethod = plaintext[28]
	timestamp := int64(binary.BigEndian.Uint64(plaintext[29:37]))
	if timestamp/int64(TIMESTAMP_WINDOW.Seconds()) != sta.Now().Unix()/int64(TIMESTAMP_WINDOW.Seconds()) {
		err = fmt.Errorf("%v: received timestamp %v", ErrTimestampOutOfWindow, timestamp)
		return
	}
	sessionID = binary.BigEndian.Uint32(plaintext[37:41])
	return
}
