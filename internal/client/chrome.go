// Fingerprint of Chrome 85

package client

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/cbeuw/Cloak/internal/common"
)

type Chrome struct{}

func makeGREASE() []byte {
	// see https://tools.ietf.org/html/draft-davidben-tls-grease-01
	// This is exclusive to Chrome.
	var one [1]byte
	common.CryptoRandRead(one[:])
	sixteenth := one[0] % 16
	monoGREASE := sixteenth*16 + 0xA
	doubleGREASE := []byte{monoGREASE, monoGREASE}
	return doubleGREASE
}

func (c *Chrome) composeExtensions(sni []byte, keyShare []byte) []byte {

	makeSupportedGroups := func() []byte {
		suppGroupListLen := []byte{0x00, 0x08}
		ret := make([]byte, 2+8)
		copy(ret[0:2], suppGroupListLen)
		copy(ret[2:4], makeGREASE())
		copy(ret[4:], []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})
		return ret
	}

	makeKeyShare := func(hidden []byte) []byte {
		ret := make([]byte, 43)
		ret[0], ret[1] = 0x00, 0x29 // length 41
		copy(ret[2:4], makeGREASE())
		ret[4], ret[5] = 0x00, 0x01 // length 1
		ret[6] = 0x00
		ret[7], ret[8] = 0x00, 0x1d  // group x25519
		ret[9], ret[10] = 0x00, 0x20 // length 32
		copy(ret[11:43], hidden)
		return ret
	}

	// extension length is always 403, and server name length is variable

	var ext [17][]byte
	ext[0] = addExtRec(makeGREASE(), nil)                         // First GREASE
	ext[1] = addExtRec([]byte{0x00, 0x00}, sni)                   // server name indication
	ext[2] = addExtRec([]byte{0x00, 0x17}, nil)                   // extended_master_secret
	ext[3] = addExtRec([]byte{0xff, 0x01}, []byte{0x00})          // renegotiation_info
	ext[4] = addExtRec([]byte{0x00, 0x0a}, makeSupportedGroups()) // supported groups
	ext[5] = addExtRec([]byte{0x00, 0x0b}, []byte{0x01, 0x00})    // ec point formats
	ext[6] = addExtRec([]byte{0x00, 0x23}, nil)                   // Session tickets
	APLN, _ := hex.DecodeString("000c02683208687474702f312e31")
	ext[7] = addExtRec([]byte{0x00, 0x10}, APLN)                                 // app layer proto negotiation
	ext[8] = addExtRec([]byte{0x00, 0x05}, []byte{0x01, 0x00, 0x00, 0x00, 0x00}) // status request
	sigAlgo, _ := hex.DecodeString("001004030804040105030805050108060601")
	ext[9] = addExtRec([]byte{0x00, 0x0d}, sigAlgo)                 // Signature Algorithms
	ext[10] = addExtRec([]byte{0x00, 0x12}, nil)                    // signed cert timestamp
	ext[11] = addExtRec([]byte{0x00, 0x33}, makeKeyShare(keyShare)) // key share
	ext[12] = addExtRec([]byte{0x00, 0x2d}, []byte{0x01, 0x01})     // psk key exchange modes
	suppVersions, _ := hex.DecodeString("0a9A9A0304030303020301")   // 9A9A needs to be a GREASE
	copy(suppVersions[1:3], makeGREASE())
	ext[13] = addExtRec([]byte{0x00, 0x2b}, suppVersions)             // supported versions
	ext[14] = addExtRec([]byte{0x00, 0x1b}, []byte{0x02, 0x00, 0x02}) // compress certificate
	ext[15] = addExtRec(makeGREASE(), []byte{0x00})                   // Last GREASE
	// len(ext[1]) + 170 + len(ext[16]) = 403
	// len(ext[16]) = 233 - len(ext[1])
	// 2+2+len(padding) = 233 - len(ext[1])
	// len(padding) = 229 - len(ext[1])
	ext[16] = addExtRec([]byte{0x00, 0x15}, make([]byte, 229-len(ext[1]))) // padding
	var ret []byte
	for _, e := range ext {
		ret = append(ret, e...)
	}
	return ret
}

func (c *Chrome) composeClientHello(hd clientHelloFields) (ch []byte) {
	var clientHello [12][]byte
	clientHello[0] = []byte{0x01}             // handshake type
	clientHello[1] = []byte{0x00, 0x01, 0xfc} // length 508
	clientHello[2] = []byte{0x03, 0x03}       // client version
	clientHello[3] = hd.random                // random
	clientHello[4] = []byte{0x20}             // session id length 32
	clientHello[5] = hd.sessionId             // session id
	clientHello[6] = []byte{0x00, 0x20}       // cipher suites length 34
	cipherSuites, _ := hex.DecodeString("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")
	clientHello[7] = append(makeGREASE(), cipherSuites...) // cipher suites
	clientHello[8] = []byte{0x01}                          // compression methods length 1
	clientHello[9] = []byte{0x00}                          // compression methods
	clientHello[11] = c.composeExtensions(hd.sni, hd.x25519KeyShare)
	clientHello[10] = []byte{0x00, 0x00} // extensions length 403
	binary.BigEndian.PutUint16(clientHello[10], uint16(len(clientHello[11])))
	var ret []byte
	for _, c := range clientHello {
		ret = append(ret, c...)
	}
	return ret
}
