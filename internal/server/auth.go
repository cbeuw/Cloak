package server

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
	"log"
)

const SESSION_TICKET_LEN = 192
const PUB_KEY_LEN = 32
const AUTH_TAG_LEN = 16
const USED_STAGNO_LEN = 16 + 16 + 1

func decryptSessionTicket(staticPv crypto.PrivateKey, ticket []byte) (UID []byte, proxyMethod string, encryptionMethod byte, tthKey []byte) {
	// sessionTicket: [marshalled ephemeral pub key 32 bytes][encrypted UID 16 bytes, proxy method 16 bytes, encryption method 1 byte][reserved 111 bytes][padding 111 bytes]
	ephPub, _ := ecdh.Unmarshal(ticket[0:PUB_KEY_LEN])
	tthKey = ecdh.GenerateSharedSecret(staticPv, ephPub)
	plain, err := util.AESGCMDecrypt(ticket[0:12], tthKey, ticket[PUB_KEY_LEN:])
	if err != nil {
		return
	}
	return plain[0:16], string(bytes.Trim(plain[16:32], "\x00")), plain[32], tthKey
}

func validateRandom(random []byte, UID []byte, time int64) (bool, uint32) {
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(time/(12*60*60)))
	front := random[0:16]
	preHash := make([]byte, 56)
	copy(preHash[0:32], UID)
	copy(preHash[32:40], t)
	copy(preHash[40:56], front)
	h := sha256.New()
	h.Write(preHash)

	sessionID := binary.BigEndian.Uint32(front[0:4])
	return bytes.Equal(h.Sum(nil)[0:16], random[16:32]), sessionID
}
func TouchStone(ch *ClientHello, sta *State) (isCK bool, UID []byte, sessionID uint32, proxyMethod string, encryptionMethod byte, tthKey []byte) {
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

	ticket := ch.extensions[[2]byte{0x00, 0x23}]

	if len(ticket) < PUB_KEY_LEN+USED_STAGNO_LEN+AUTH_TAG_LEN {
		return
	}

	UID, proxyMethod, encryptionMethod, tthKey = decryptSessionTicket(sta.staticPv, ticket)

	if len(UID) < 16 {
		return
	}
	isCK, sessionID = validateRandom(ch.random, UID, sta.Now().Unix())
	if !isCK {
		return
	}

	return
}
