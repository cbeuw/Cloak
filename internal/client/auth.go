package client

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
	"sync/atomic"
)

func makeHiddenData(sta *State) (random, TLSsessionID, keyShare, sharedSecret []byte) {
	// random is marshalled ephemeral pub key 32 bytes
	// TLSsessionID || keyShare is [encrypted UID 16 bytes, proxy method 12 bytes, encryption method 1 byte, timestamp 8 bytes, sessionID 4 bytes] [unused data] [16 bytes authentication tag]
	ephPv, ephPub, _ := ecdh.GenerateKey(rand.Reader)
	random = ecdh.Marshal(ephPub)

	plaintext := make([]byte, 48)
	copy(plaintext, sta.UID)
	copy(plaintext[16:28], sta.ProxyMethod)
	plaintext[28] = sta.EncryptionMethod
	binary.BigEndian.PutUint64(plaintext[29:37], uint64(sta.Now().Unix()))
	binary.BigEndian.PutUint32(plaintext[37:41], atomic.LoadUint32(&sta.SessionID))

	sharedSecret = ecdh.GenerateSharedSecret(ephPv, sta.staticPub)
	nonce := random[0:12]
	ciphertext, _ := util.AESGCMEncrypt(nonce, sharedSecret, plaintext)
	TLSsessionID = ciphertext[0:32]
	keyShare = ciphertext[32:64]
	return
}

func xor(a []byte, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

func decryptSessionKey(serverRandom []byte, sharedSecret []byte) []byte {
	xor(serverRandom, sharedSecret)
	return serverRandom
}
