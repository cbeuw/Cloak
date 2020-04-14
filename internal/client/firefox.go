// Fingerprint of Firefox 68

package client

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/cbeuw/Cloak/internal/common"
)

type Firefox struct{}

func (f *Firefox) composeExtensions(SNI []byte, keyShare []byte) []byte {
	composeKeyShare := func(hidden []byte) []byte {
		ret := make([]byte, 107)
		ret[0], ret[1] = 0x00, 0x69 // length 105
		ret[2], ret[3] = 0x00, 0x1d // group x25519
		ret[4], ret[5] = 0x00, 0x20 // length 32
		copy(ret[6:38], hidden)
		ret[38], ret[39] = 0x00, 0x17 // group secp256r1
		ret[40], ret[41] = 0x00, 0x41 // length 65
		common.CryptoRandRead(ret[42:107])
		return ret
	}
	// extension length is always 399, and server name length is variable
	var ext [14][]byte
	ext[0] = addExtRec([]byte{0x00, 0x00}, SNI)          // server name indication
	ext[1] = addExtRec([]byte{0x00, 0x17}, nil)          // extended_master_secret
	ext[2] = addExtRec([]byte{0xff, 0x01}, []byte{0x00}) // renegotiation_info
	suppGroup, _ := hex.DecodeString("000c001d00170018001901000101")
	ext[3] = addExtRec([]byte{0x00, 0x0a}, suppGroup)          // supported groups
	ext[4] = addExtRec([]byte{0x00, 0x0b}, []byte{0x01, 0x00}) // ec point formats
	ext[5] = addExtRec([]byte{0x00, 0x23}, []byte{})           // Session tickets
	APLN, _ := hex.DecodeString("000c02683208687474702f312e31")
	ext[6] = addExtRec([]byte{0x00, 0x10}, APLN)                                 // app layer proto negotiation
	ext[7] = addExtRec([]byte{0x00, 0x05}, []byte{0x01, 0x00, 0x00, 0x00, 0x00}) // status request
	ext[8] = addExtRec([]byte{0x00, 0x33}, composeKeyShare(keyShare))            // key share
	suppVersions, _ := hex.DecodeString("080304030303020301")
	ext[9] = addExtRec([]byte{0x00, 0x2b}, suppVersions) // supported versions
	sigAlgo, _ := hex.DecodeString("001604030503060308040805080604010501060102030201")
	ext[10] = addExtRec([]byte{0x00, 0x0d}, sigAlgo)            // Signature Algorithms
	ext[11] = addExtRec([]byte{0x00, 0x2d}, []byte{0x01, 0x01}) // psk key exchange modes
	ext[12] = addExtRec([]byte{0x00, 0x1c}, []byte{0x40, 0x01}) // record size limit
	// len(ext[0]) + 237 + 4 + len(padding) = 399
	// len(padding) = 158 - len(ext[0])
	ext[13] = addExtRec([]byte{0x00, 0x15}, make([]byte, 163-len(SNI))) // padding
	var ret []byte
	for _, e := range ext {
		ret = append(ret, e...)
	}
	return ret
}

func (f *Firefox) composeClientHello(hd clientHelloFields) (ch []byte) {
	var clientHello [12][]byte
	clientHello[0] = []byte{0x01}             // handshake type
	clientHello[1] = []byte{0x00, 0x01, 0xfc} // length 508
	clientHello[2] = []byte{0x03, 0x03}       // client version
	clientHello[3] = hd.random                // random
	clientHello[4] = []byte{0x20}             // session id length 32
	clientHello[5] = hd.sessionId             // session id
	clientHello[6] = []byte{0x00, 0x24}       // cipher suites length 36
	cipherSuites, _ := hex.DecodeString("130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a")
	clientHello[7] = cipherSuites // cipher suites
	clientHello[8] = []byte{0x01} // compression methods length 1
	clientHello[9] = []byte{0x00} // compression methods

	clientHello[11] = f.composeExtensions(hd.sni, hd.x25519KeyShare)
	clientHello[10] = []byte{0x00, 0x00} // extensions length
	binary.BigEndian.PutUint16(clientHello[10], uint16(len(clientHello[11])))

	var ret []byte
	for _, c := range clientHello {
		ret = append(ret, c...)
	}
	return ret
}
