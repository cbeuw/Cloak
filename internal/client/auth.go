package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/util"
	"github.com/cbeuw/ecies"
)

func MakeRandomField(sta *State) []byte {

	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(sta.Now().Unix()/12*60*60))
	rand := util.PsudoRandBytes(16, sta.Now().UnixNano())
	preHash := make([]byte, 56)
	copy(preHash[0:32], sta.SID)
	copy(preHash[32:40], t)
	copy(preHash[40:56], rand)
	h := sha256.New()
	h.Write(preHash)
	ret := make([]byte, 32)
	copy(ret[0:16], rand)
	copy(ret[16:32], h.Sum(nil)[0:16])
	return ret
}

func MakeSessionTicket(sta *State) []byte {
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(sta.Now().Unix()/int64(sta.TicketTimeHint)))
	plain := make([]byte, 40)
	copy(plain, sta.SID)
	copy(plain[32:], t)
	// With the default settings (P256, AES128, SHA256) of the ecies package, len(ct)==153.
	//
	// ciphertext is composed of 3 parts: marshalled X and Y coordinates on the curve,
	// iv+ciphertext of the block cipher (aes128 in this case),
	// and the hmac which is 32 bytes because it's sha256
	//
	// The marshalling is done by crypto/elliptic.Marshal. According to the code,
	// the size after marshall is 65
	//
	// IV is 16 bytes. The size of ciphertext is equal to the plaintext, which is 40,
	// that is 32 bytes of SID + 8 bytes of timestamp/tickettimehint.
	// 16+40 = 56
	//
	// Then the hmac is 32 bytes
	//
	// 65+56+32=153
	ct, _ := ecies.Encrypt(rand.Reader, sta.Pub, plain, nil, nil)
	sessionTicket := make([]byte, 192)
	// The reason for ct[1:] is that, the first byte of ct is always 0x04
	// This is specified in the section 4.3.6 of ANSI X9.62 (the uncompressed form).
	// This is a flag that is useless to us and it will expose our pattern
	// (because the sessionTicket isn't fully random anymore). Therefore we drop it.
	copy(sessionTicket, ct[1:])
	copy(sessionTicket[152:], util.PsudoRandBytes(40, sta.Now().UnixNano()))
	return sessionTicket
}
