package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
)

func MakeRandomField(sta *State) []byte {
	// [4 bytes sessionId] [12 bytes random] [16 bytes hash]
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(sta.Now().Unix()/(12*60*60)))

	front := make([]byte, 16)
	binary.BigEndian.PutUint32(front[0:4], sta.SessionID)
	rand.Read(front[4:])
	preHash := make([]byte, 56)
	copy(preHash[0:32], sta.UID)
	copy(preHash[32:40], t)
	copy(preHash[40:56], front)
	h := sha256.New()
	h.Write(preHash)

	ret := make([]byte, 32)
	copy(ret[0:16], front)
	copy(ret[16:32], h.Sum(nil)[0:16])
	return ret
}

const SESSION_TICKET_LEN = 192
const PUB_KEY_LEN = 32
const AUTH_TAG_LEN = 16
const STEGANO_LEN = SESSION_TICKET_LEN - PUB_KEY_LEN - AUTH_TAG_LEN

func MakeSessionTicket(sta *State) []byte {
	// sessionTicket: [marshalled ephemeral pub key 32 bytes][encrypted UID 16 bytes, proxy method 16 bytes, encryption method 1 byte][reserved 111 bytes][16 bytes authentication tag]
	// The first 12 bytes of the marshalled ephemeral public key is used as the nonce
	// for encrypting the UID

	ticket := make([]byte, SESSION_TICKET_LEN)

	//TODO: error when the interval has expired
	ephPub, intervalKey := sta.GetIntervalKeys()
	copy(ticket[0:PUB_KEY_LEN], ecdh.Marshal(ephPub))

	plain := make([]byte, STEGANO_LEN)
	copy(plain, sta.UID)
	copy(plain[16:32], sta.ProxyMethod)
	plain[32] = sta.EncryptionMethod

	cipher, _ := util.AESGCMEncrypt(ticket[0:12], intervalKey, plain)
	copy(ticket[PUB_KEY_LEN:], cipher)
	return ticket
}
