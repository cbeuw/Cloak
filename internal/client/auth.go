package client

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/ecdh"
	"github.com/cbeuw/Cloak/internal/util"
	"sync/atomic"
)

const (
	UNORDERED_FLAG = 0x01 // 0000 0001
)

type chHiddenData struct {
	chRandom         []byte
	chSessionId      []byte
	chX25519KeyShare []byte
	chExtSNI         []byte
}

func makeHiddenData(sta *State) (ret chHiddenData, sharedSecret []byte) {
	// random is marshalled ephemeral pub key 32 bytes
	// TLSsessionID || keyShare is [encrypted UID 16 bytes, proxy method 12 bytes, encryption method 1 byte, timestamp 8 bytes, sessionID 4 bytes] [1 byte flag] [6 bytes reserved] [16 bytes authentication tag]
	ephPv, ephPub, _ := ecdh.GenerateKey(rand.Reader)
	ret.chRandom = ecdh.Marshal(ephPub)

	plaintext := make([]byte, 48)
	copy(plaintext, sta.UID)
	copy(plaintext[16:28], sta.ProxyMethod)
	plaintext[28] = sta.EncryptionMethod
	binary.BigEndian.PutUint64(plaintext[29:37], uint64(sta.Now().Unix()))
	binary.BigEndian.PutUint32(plaintext[37:41], atomic.LoadUint32(&sta.SessionID))

	if sta.Unordered {
		plaintext[41] |= UNORDERED_FLAG
	}

	sharedSecret = ecdh.GenerateSharedSecret(ephPv, sta.staticPub)
	nonce := ret.chRandom[0:12]
	ciphertext, _ := util.AESGCMEncrypt(nonce, sharedSecret, plaintext)
	ret.chSessionId = ciphertext[0:32]
	ret.chX25519KeyShare = ciphertext[32:64]
	ret.chExtSNI = makeServerName(sta.ServerName)
	return
}
