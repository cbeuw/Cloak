package server

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"log"

	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
)

// input ticket, return UID
func decryptSessionTicket(staticPv crypto.PrivateKey, ticket []byte) ([]byte, uint32, string) {
	ephPub, _ := ecdh.Unmarshal(ticket[0:32])
	key := ecdh.GenerateSharedSecret(staticPv, ephPub)
	plain := util.AESDecrypt(ticket[0:16], key, ticket[32:84])
	sessionID := binary.BigEndian.Uint32(plain[32:36])
	return plain[0:32], sessionID, string(bytes.Trim(plain[36:52], "\x00"))
}

func validateRandom(random []byte, UID []byte, time int64) bool {
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(time/(12*60*60)))
	rdm := random[0:16]
	preHash := make([]byte, 56)
	copy(preHash[0:32], UID)
	copy(preHash[32:40], t)
	copy(preHash[40:56], rdm)
	h := sha256.New()
	h.Write(preHash)
	return bytes.Equal(h.Sum(nil)[0:16], random[16:32])
}
func TouchStone(ch *ClientHello, sta *State) (isCK bool, UID []byte, sessionID uint32, proxyMethod string) {
	var random [32]byte
	copy(random[:], ch.random)

	sta.usedRandomM.Lock()
	used := sta.usedRandom[random]
	sta.usedRandom[random] = int(sta.Now().Unix())
	sta.usedRandomM.Unlock()

	if used != 0 {
		log.Println("Replay! Duplicate random")
		return false, nil, 0, ""
	}

	ticket := ch.extensions[[2]byte{0x00, 0x23}]
	if len(ticket) < 68 {
		return false, nil, 0, ""
	}
	UID, sessionID, proxyMethod = decryptSessionTicket(sta.staticPv, ticket)
	isCK = validateRandom(ch.random, UID, sta.Now().Unix())
	if !isCK {
		return false, nil, 0, ""
	}

	return
}
