package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/cbeuw/ecies"
	"log"
)

// input ticket, return SID
func decryptSessionTicket(pv *ecies.PrivateKey, ticket []byte) ([]byte, error) {
	ciphertext := make([]byte, 153)
	ciphertext[0] = 0x04
	copy(ciphertext[1:], ticket)
	plaintext, err := pv.Decrypt(ciphertext, nil, nil)
	if err != nil {
		return nil, err
	}
	return plaintext[0:32], nil
}

func validateRandom(random []byte, SID []byte, time int64) bool {
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(time/12*60*60))
	rand := random[0:16]
	preHash := make([]byte, 56)
	copy(preHash[0:32], SID)
	copy(preHash[32:40], t)
	copy(preHash[40:56], rand)
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

	SID, err := decryptSessionTicket(sta.pv, ch.extensions[[2]byte{0x00, 0x23}])
	if err != nil {
		return false, nil
	}
	isSS := validateRandom(ch.random, SID, sta.Now().Unix())
	if !isSS {
		return false, nil
	}

	return true, SID
}
