package client

import (
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/ecdh"
)

const (
	UNORDERED_FLAG = 0x01 // 0000 0001
)

type authenticationPayload struct {
	randPubKey        [32]byte
	ciphertextWithTag [64]byte
}

// makeAuthenticationPayload generates the ephemeral key pair, calculates the shared secret, and then compose and
// encrypt the authenticationPayload
func makeAuthenticationPayload(authInfo AuthInfo) (ret authenticationPayload, sharedSecret [32]byte) {
	/*
		Authentication data:
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
		|  _UID_   | _Proxy Method_ | _Encryption Method_ | _Timestamp_ | _Session Id_ | _Flag_ | _reserved_ |
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
		| 16 bytes | 12 bytes       | 1 byte              | 8 bytes     | 4 bytes      | 1 byte | 6 bytes    |
		+----------+----------------+---------------------+-------------+--------------+--------+------------+
	*/
	ephPv, ephPub, _ := ecdh.GenerateKey(authInfo.WorldState.Rand)
	copy(ret.randPubKey[:], ecdh.Marshal(ephPub))

	plaintext := make([]byte, 48)
	copy(plaintext, authInfo.UID)
	copy(plaintext[16:28], authInfo.ProxyMethod)
	plaintext[28] = authInfo.EncryptionMethod
	binary.BigEndian.PutUint64(plaintext[29:37], uint64(authInfo.WorldState.Now().Unix()))
	binary.BigEndian.PutUint32(plaintext[37:41], authInfo.SessionId)

	if authInfo.Unordered {
		plaintext[41] |= UNORDERED_FLAG
	}

	copy(sharedSecret[:], ecdh.GenerateSharedSecret(ephPv, authInfo.ServerPubKey))
	ciphertextWithTag, _ := common.AESGCMEncrypt(ret.randPubKey[:12], sharedSecret[:], plaintext)
	copy(ret.ciphertextWithTag[:], ciphertextWithTag[:])
	return
}
