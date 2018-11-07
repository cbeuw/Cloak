package server

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"log"

	"github.com/cbeuw/Cloak/internal/util"
	ecdh "github.com/cbeuw/go-ecdh"
)

// input ticket, return UID
func decryptSessionTicket(staticPv crypto.PrivateKey, ticket []byte) ([]byte, uint32, error) {
	ec := ecdh.NewCurve25519ECDH()
	ephPub, _ := ec.Unmarshal(ticket[0:32])
	key, err := ec.GenerateSharedSecret(staticPv, ephPub)
	if err != nil {
		return nil, 0, err
	}
	UIDsID := util.AESDecrypt(ticket[0:16], key, ticket[32:68])
	sessionID := binary.BigEndian.Uint32(UIDsID[32:36])
	return UIDsID[0:32], sessionID, nil
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
func TouchStone(ch *ClientHello, sta *State) (isSS bool, UID []byte, sessionID uint32) {
	var random [32]byte
	copy(random[:], ch.random)
	used := sta.getUsedRandom(random)
	if used != 0 {
		log.Println("Replay! Duplicate random")
		return false, nil, 0
	}
	sta.putUsedRandom(random)

	ticket := ch.extensions[[2]byte{0x00, 0x23}]
	if len(ticket) < 64 {
		return false, nil, 0
	}
	UID, sessionID, err := decryptSessionTicket(sta.staticPv, ticket)
	if err != nil {
		log.Printf("ts: %v\n", err)
		return false, nil, 0
	}
	isSS = validateRandom(ch.random, UID, sta.Now().Unix())
	if !isSS {
		return false, nil, 0
	}

	return
}
