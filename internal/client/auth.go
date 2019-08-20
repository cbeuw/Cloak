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

// makeHiddenData generates the ephemeral key pair, calculates the shared secret, and then compose and
// encrypt the Authentication data. It also composes SNI extension.
func makeHiddenData(sta *State) (ret chHiddenData, sharedSecret []byte) {
	// random is marshalled ephemeral pub key 32 bytes
	/*
		Authentication data:
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
		|  _UID_   | _Proxy Method_ | _Encryption Method_ | _Timestamp_ | _Session Id_ | _Flag_ | _reserved_ |
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
		| 16 bytes | 12 bytes       | 1 byte              | 8 bytes     | 4 bytes      | 1 byte | 6 bytes    |
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
	*/
	// The authentication ciphertext and its tag are then distributed among SessionId and X25519KeyShare
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
	ciphertextWithTag, _ := util.AESGCMEncrypt(nonce, sharedSecret, plaintext)
	ret.chSessionId = ciphertextWithTag[0:32]
	ret.chX25519KeyShare = ciphertextWithTag[32:64]
	ret.chExtSNI = makeServerName(sta.ServerName)
	return
}
