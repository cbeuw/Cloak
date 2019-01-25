package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	prand "math/rand"
	"testing"
	"time"

	"github.com/cbeuw/Cloak/internal/ecdh"
)

func TestMakeSessionTicket(t *testing.T) {
	UID, _ := hex.DecodeString("26a8e88bcd7c64a69ca051740851d22a6818de2fddafc00882331f1c5a8b866c")
	staticPv, staticPub, _ := ecdh.GenerateKey(rand.Reader)
	mockSta := &State{
		Now:            time.Now,
		sessionID:      42,
		UID:            UID,
		staticPub:      staticPub,
		keyPairs:       make(map[int64]*keyPair),
		TicketTimeHint: 3600,
	}

	ticket := MakeSessionTicket(mockSta)

	// verification
	ephPub, _ := ecdh.Unmarshal(ticket[0:32])
	key := ecdh.GenerateSharedSecret(staticPv, ephPub)

	// aes decrypt
	UIDsID := make([]byte, len(ticket[32:68]))
	copy(UIDsID, ticket[32:68]) // Because XORKeyStream is inplace, but we don't want the input to be changed
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, ticket[0:16])
	stream.XORKeyStream(UIDsID, UIDsID)

	decryUID := UIDsID[0:32]
	decrySessionID := binary.BigEndian.Uint32(UIDsID[32:36])

	// check padding
	tthInterval := mockSta.Now().Unix() / int64(mockSta.TicketTimeHint)
	r := prand.New(prand.NewSource(tthInterval + int64(mockSta.sessionID)))
	pad := make([]byte, 124)
	r.Read(pad)

	if !bytes.Equal(mockSta.UID, decryUID) {
		t.Error(
			"For", "UID",
			"expecting", fmt.Sprintf("%x", mockSta.UID),
			"got", fmt.Sprintf("%x", decryUID),
		)
	}
	if mockSta.sessionID != decrySessionID {
		t.Error(
			"For", "sessionID",
			"expecting", mockSta.sessionID,
			"got", decrySessionID,
		)
	}
	if !bytes.Equal(pad, ticket[68:]) {
		t.Error(
			"For", "Padding",
			"expecting", fmt.Sprintf("%x", pad),
			"got", fmt.Sprintf("%x", ticket[68:]),
		)
	}
}

func TestMakeRandomField(t *testing.T) {
	UID, _ := hex.DecodeString("26a8e88bcd7c64a69ca051740851d22a6818de2fddafc00882331f1c5a8b866c")
	mockSta := &State{
		Now: time.Now,
		UID: UID,
	}
	random := MakeRandomField(mockSta)

	// verification
	tb := make([]byte, 8)
	binary.BigEndian.PutUint64(tb, uint64(time.Now().Unix()/(12*60*60)))
	rdm := random[0:16]
	preHash := make([]byte, 56)
	copy(preHash[0:32], UID)
	copy(preHash[32:40], tb)
	copy(preHash[40:56], rdm)
	h := sha256.New()
	h.Write(preHash)
	exp := h.Sum(nil)[0:16]
	if !bytes.Equal(exp, random[16:32]) {
		t.Error(
			"For", "Random",
			"expecting", fmt.Sprintf("%x", exp),
			"got", fmt.Sprintf("%x", random[16:32]),
		)
	}
}
