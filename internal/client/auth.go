package client

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/util"
	ecdh "github.com/cbeuw/go-ecdh"
	"io"
)

type keyPair struct {
	crypto.PrivateKey
	crypto.PublicKey
}

func MakeRandomField(sta *State) []byte {
	t := make([]byte, 8)
	binary.BigEndian.PutUint64(t, uint64(sta.Now().Unix()/(12*60*60)))
	rdm := make([]byte, 16)
	io.ReadFull(rand.Reader, rdm)
	preHash := make([]byte, 56)
	copy(preHash[0:32], sta.SID)
	copy(preHash[32:40], t)
	copy(preHash[40:56], rdm)
	h := sha256.New()
	h.Write(preHash)
	ret := make([]byte, 32)
	copy(ret[0:16], rdm)
	copy(ret[16:32], h.Sum(nil)[0:16])
	return ret
}

func MakeSessionTicket(sta *State) []byte {
	// sessionTicket: [marshalled ephemeral pub key 32 bytes][encrypted SID 32 bytes][padding 128 bytes]
	// The first 16 bytes of the marshalled ephemeral public key is used as the IV
	// for encrypting the SID
	tthInterval := sta.Now().Unix() / int64(sta.TicketTimeHint)
	ec := ecdh.NewCurve25519ECDH()
	ephKP := sta.getKeyPair(tthInterval)
	if ephKP == nil {
		ephPv, ephPub, _ := ec.GenerateKey(rand.Reader)
		ephKP = &keyPair{
			ephPv,
			ephPub,
		}
		sta.putKeyPair(tthInterval, ephKP)
	}
	ticket := make([]byte, 192)
	copy(ticket[0:32], ec.Marshal(ephKP.PublicKey))
	key, _ := ec.GenerateSharedSecret(ephKP.PrivateKey, sta.staticPub)
	cipherSID := util.AESEncrypt(ticket[0:16], key, sta.SID)
	copy(ticket[32:64], cipherSID)
	io.ReadFull(rand.Reader, ticket[64:192])
	return ticket
}
