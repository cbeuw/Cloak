// Fingerprint of Safari 16.4

package client

import (
	"encoding/binary"
)

type Safari struct{}

func (s *Safari) composeExtensions(serverName string, keyShare []byte) []byte {
	makeSupportedGroups := func() []byte {
		suppGroupListLen := []byte{0x00, 0x0a}
		ret := make([]byte, 2+2+8)
		copy(ret[0:2], suppGroupListLen)
		copy(ret[2:4], makeGREASE())
		copy(ret[4:], []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19})
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

	// extension length is always 393, and server name length is variable
	var ext [16][]byte
	ext[0] = addExtRec(makeGREASE(), nil)                                                                 // First GREASE
	ext[1] = addExtRec([]byte{0x00, 0x00}, generateSNI(serverName))                                       // server name indication
	ext[2] = addExtRec([]byte{0x00, 0x17}, nil)                                                           // extended_master_secret
	ext[3] = addExtRec([]byte{0xff, 0x01}, []byte{0x00})                                                  // renegotiation_info
	ext[4] = addExtRec([]byte{0x00, 0x0a}, makeSupportedGroups())                                         // supported groups
	ext[5] = addExtRec([]byte{0x00, 0x0b}, []byte{0x01, 0x00})                                            // ec point formats
	ext[6] = addExtRec([]byte{0x00, 0x10}, decodeHex("000c02683208687474702f312e31"))                     // app layer proto negotiation
	ext[7] = addExtRec([]byte{0x00, 0x05}, []byte{0x01, 0x00, 0x00, 0x00, 0x00})                          // status request
	ext[8] = addExtRec([]byte{0x00, 0x0d}, decodeHex("001604030804040105030203080508050501080606010201")) // Signature Algorithms
	ext[9] = addExtRec([]byte{0x00, 0x12}, nil)                                                           // signed cert timestamp
	ext[10] = addExtRec([]byte{0x00, 0x33}, makeKeyShare(keyShare))                                       // key share
	ext[11] = addExtRec([]byte{0x00, 0x2d}, []byte{0x01, 0x01})                                           // psk key exchange modes
	suppVersions := decodeHex("0a5a5a0304030303020301")                                                   // 5a5a needs to be a GREASE
	copy(suppVersions[1:3], makeGREASE())
	ext[12] = addExtRec([]byte{0x00, 0x2b}, suppVersions)             // supported versions
	ext[13] = addExtRec([]byte{0x00, 0x1b}, []byte{0x02, 0x00, 0x01}) // compress certificate
	ext[14] = addExtRec(makeGREASE(), []byte{0x00})                   // Last GREASE
	// len(ext[1]) + len(all other ext) + len(ext[15]) = 393
	// len(all other ext) = 174
	// len(ext[15]) = 219 - len(ext[1])
	// 2+2+len(padding) = 219 - len(ext[1])
	// len(padding) = 215 - len(ext[1])
	ext[15] = addExtRec([]byte{0x00, 0x15}, make([]byte, 215-len(ext[1]))) // padding
	var ret []byte
	for _, e := range ext {
		ret = append(ret, e...)
	}
	return ret
}

func (s *Safari) composeClientHello(hd clientHelloFields) (ch []byte) {
	var clientHello [12][]byte
	clientHello[0] = []byte{0x01}                                                                                                           // handshake type
	clientHello[1] = []byte{0x00, 0x01, 0xfc}                                                                                               // length 508
	clientHello[2] = []byte{0x03, 0x03}                                                                                                     // client version
	clientHello[3] = hd.random                                                                                                              // random
	clientHello[4] = []byte{0x20}                                                                                                           // session id length 32
	clientHello[5] = hd.sessionId                                                                                                           // session id
	clientHello[6] = []byte{0x00, 0x2a}                                                                                                     // cipher suites length 42
	clientHello[7] = append(makeGREASE(), decodeHex("130113021303c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002fc008c012000a")...) // cipher suites
	clientHello[8] = []byte{0x01}                                                                                                           // compression methods length 1
	clientHello[9] = []byte{0x00}                                                                                                           // compression methods

	extensions := s.composeExtensions(hd.serverName, hd.x25519KeyShare)
	clientHello[10] = []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(clientHello[10], uint16(len(extensions))) // extension length
	clientHello[11] = extensions

	var ret []byte
	for _, c := range clientHello {
		ret = append(ret, c...)
	}
	return ret
}
