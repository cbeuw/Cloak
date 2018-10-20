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

// input ticket, return SID
func decryptSessionTicket(staticPv crypto.PrivateKey, ticket []byte) ([]byte, error) {
	ec := ecdh.NewCurve25519ECDH()
	ephPub, _ := ec.Unmarshal(ticket[0:32])
	key, err := ec.GenerateSharedSecret(staticPv, ephPub)
	if err != nil {
		return nil, err
	}
	SID := util.AESDecrypt(ticket[0:16], key, ticket[32:64])
	return SID, nil
}

func validateRandom(random []byte, SID []byte, time int64) bool {
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(time/(12*60*60)))
	rdm := random[0:16]
	preHash := make([]byte, 56)
	copy(preHash[0:32], SID)
	copy(preHash[32:40], t)
	copy(preHash[40:56], rdm)
	h := sha256.New()
	h.Write(preHash)
	return bytes.Equal(h.Sum(nil)[0:16], random[16:32])
}
func TouchStone(ch *ClientHello, sta *State) (bool, []byte) {
	var random [32]byte
	copy(random[:], ch.random)
	used := sta.getUsedRandom(random)
	if used != 0 {
		log.Println("Replay! Duplicate random")
		return false, nil
	}
	sta.putUsedRandom(random)

	ticket := ch.extensions[[2]byte{0x00, 0x23}]
	if len(ticket) < 64 {
		return false, nil
	}
	SID, err := decryptSessionTicket(sta.staticPv, ticket)
	if err != nil {
		log.Printf("ts: %v\n", err)
		return false, nil
	}
	log.Printf("SID: %x\n", SID)
	isSS := validateRandom(ch.random, SID, sta.Now().Unix())
	if !isSS {
		return false, nil
	}

	return true, SID
}
