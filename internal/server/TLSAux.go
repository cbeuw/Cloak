package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cbeuw/Cloak/internal/common"
)

// ClientHello contains every field in a ClientHello message
type ClientHello struct {
	handshakeType         byte
	length                int
	clientVersion         []byte
	random                []byte
	sessionIdLen          int
	sessionId             []byte
	cipherSuitesLen       int
	cipherSuites          []byte
	compressionMethodsLen int
	compressionMethods    []byte
	extensionsLen         int
	extensions            map[[2]byte][]byte
}

var u16 = binary.BigEndian.Uint16
var u32 = binary.BigEndian.Uint32

func parseExtensions(input []byte) (ret map[[2]byte][]byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Malformed Extensions")
		}
	}()
	pointer := 0
	totalLen := len(input)
	ret = make(map[[2]byte][]byte)
	for pointer < totalLen {
		var typ [2]byte
		copy(typ[:], input[pointer:pointer+2])
		pointer += 2
		length := int(u16(input[pointer : pointer+2]))
		pointer += 2
		data := input[pointer : pointer+length]
		pointer += length
		ret[typ] = data
	}
	return ret, err
}

func parseKeyShare(input []byte) (ret []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("malformed key_share")
		}
	}()
	totalLen := int(u16(input[0:2]))
	// 2 bytes "client key share length"
	pointer := 2
	for pointer < totalLen {
		if bytes.Equal([]byte{0x00, 0x1d}, input[pointer:pointer+2]) {
			// skip "key exchange length"
			pointer += 2
			length := int(u16(input[pointer : pointer+2]))
			pointer += 2
			if length != 32 {
				return nil, fmt.Errorf("key share length should be 32, instead of %v", length)
			}
			return input[pointer : pointer+length], nil
		}
		pointer += 2
		length := int(u16(input[pointer : pointer+2]))
		pointer += 2
		_ = input[pointer : pointer+length]
		pointer += length
	}
	return nil, errors.New("x25519 does not exist")
}

// addRecordLayer adds record layer to data
func addRecordLayer(input []byte, typ []byte, ver []byte) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(input)))
	ret := make([]byte, 5+len(input))
	copy(ret[0:1], typ)
	copy(ret[1:3], ver)
	copy(ret[3:5], length)
	copy(ret[5:], input)
	return ret
}

// parseClientHello parses everything on top of the TLS layer
// (including the record layer) into ClientHello type
func parseClientHello(data []byte) (ret *ClientHello, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Malformed ClientHello")
		}
	}()

	if !bytes.Equal(data[0:3], []byte{0x16, 0x03, 0x01}) {
		return ret, errors.New("wrong TLS1.3 handshake magic bytes")
	}

	peeled := make([]byte, len(data)-5)
	copy(peeled, data[5:])
	pointer := 0
	// Handshake Type
	handshakeType := peeled[pointer]
	if handshakeType != 0x01 {
		return ret, errors.New("Not a ClientHello")
	}
	pointer += 1
	// Length
	length := int(u32(append([]byte{0x00}, peeled[pointer:pointer+3]...)))
	pointer += 3
	if length != len(peeled[pointer:]) {
		return ret, errors.New("Hello length doesn't match")
	}
	// Client Version
	clientVersion := peeled[pointer : pointer+2]
	pointer += 2
	// Random
	random := peeled[pointer : pointer+32]
	pointer += 32
	// Session ID
	sessionIdLen := int(peeled[pointer])
	pointer += 1
	sessionId := peeled[pointer : pointer+sessionIdLen]
	pointer += sessionIdLen
	// Cipher Suites
	cipherSuitesLen := int(u16(peeled[pointer : pointer+2]))
	pointer += 2
	cipherSuites := peeled[pointer : pointer+cipherSuitesLen]
	pointer += cipherSuitesLen
	// Compression Methods
	compressionMethodsLen := int(peeled[pointer])
	pointer += 1
	compressionMethods := peeled[pointer : pointer+compressionMethodsLen]
	pointer += compressionMethodsLen
	// Extensions
	extensionsLen := int(u16(peeled[pointer : pointer+2]))
	pointer += 2
	extensions, err := parseExtensions(peeled[pointer:])
	ret = &ClientHello{
		handshakeType,
		length,
		clientVersion,
		random,
		sessionIdLen,
		sessionId,
		cipherSuitesLen,
		cipherSuites,
		compressionMethodsLen,
		compressionMethods,
		extensionsLen,
		extensions,
	}
	return
}

func composeServerHello(sessionId []byte, nonce [12]byte, encryptedSessionKeyWithTag [48]byte) []byte {
	var serverHello [11][]byte
	serverHello[0] = []byte{0x02}                                             // handshake type
	serverHello[1] = []byte{0x00, 0x00, 0x76}                                 // length 118
	serverHello[2] = []byte{0x03, 0x03}                                       // server version
	serverHello[3] = append(nonce[0:12], encryptedSessionKeyWithTag[0:20]...) // random 32 bytes
	serverHello[4] = []byte{0x20}                                             // session id length 32
	serverHello[5] = sessionId                                                // session id
	serverHello[6] = []byte{0x13, 0x02}                                       // cipher suite TLS_AES_256_GCM_SHA384
	serverHello[7] = []byte{0x00}                                             // compression method null
	serverHello[8] = []byte{0x00, 0x2e}                                       // extensions length 46

	keyShare := []byte{0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}
	keyExchange := make([]byte, 32)
	copy(keyExchange, encryptedSessionKeyWithTag[20:48])
	common.CryptoRandRead(keyExchange[28:32])
	serverHello[9] = append(keyShare, keyExchange...)

	serverHello[10] = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04} // supported versions
	var ret []byte
	for _, s := range serverHello {
		ret = append(ret, s...)
	}
	return ret
}

// composeReply composes the ServerHello, ChangeCipherSpec and an ApplicationData messages
// together with their respective record layers into one byte slice.
func composeReply(clientHelloSessionId []byte, nonce [12]byte, encryptedSessionKeyWithTag [48]byte, cert []byte) []byte {
	TLS12 := []byte{0x03, 0x03}
	sh := composeServerHello(clientHelloSessionId, nonce, encryptedSessionKeyWithTag)
	shBytes := addRecordLayer(sh, []byte{0x16}, TLS12)
	ccsBytes := addRecordLayer([]byte{0x01}, []byte{0x14}, TLS12)

	encryptedCertBytes := addRecordLayer(cert, []byte{0x17}, TLS12)
	ret := append(shBytes, ccsBytes...)
	ret = append(ret, encryptedCertBytes...)
	return ret
}
