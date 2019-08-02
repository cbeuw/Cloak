package server

import (
	"bytes"
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
	"log"
)

func TouchStone(ch *ClientHello, sta *State) (isCK bool, UID []byte, sessionID uint32, proxyMethod string, encryptionMethod byte, sharedSecret []byte) {
	var random [32]byte
	copy(random[:], ch.random)

	sta.usedRandomM.Lock()
	used := sta.usedRandom[random]
	sta.usedRandom[random] = int(sta.Now().Unix())
	sta.usedRandomM.Unlock()

	if used != 0 {
		log.Println("Replay! Duplicate random")
		return
	}

	ephPub, ok := ecdh.Unmarshal(random[:])
	if !ok {
		return
	}

	sharedSecret = ecdh.GenerateSharedSecret(sta.staticPv, ephPub)
	keyShare, err := parseKeyShare(ch.extensions[[2]byte{0x00, 0x33}])
	if err != nil {
		return
	}
	ciphertext := append(ch.sessionId, keyShare...)

	if len(ciphertext) != 64 {
		return
	}

	plaintext, err := util.AESGCMDecrypt(random[0:12], sharedSecret, ciphertext)
	if err != nil {
		return
	}

	UID = plaintext[0:16]
	proxyMethod = string(bytes.Trim(plaintext[16:28], "\x00"))
	encryptionMethod = plaintext[28]
	timestamp := int64(binary.BigEndian.Uint64(plaintext[29:37]))
	if timestamp/int64(TIMESTAMP_WINDOW.Seconds()) != sta.Now().Unix()/int64(TIMESTAMP_WINDOW.Seconds()) {
		isCK = false
		return
	}
	sessionID = binary.BigEndian.Uint32(plaintext[37:41])

	isCK = true
	return
}
