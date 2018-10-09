package server

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/cbeuw/Cloak/internal/util"
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
		length := util.BtoInt(input[pointer : pointer+2])
		pointer += 2
		data := input[pointer : pointer+length]
		pointer += length
		ret[typ] = data
	}
	return ret, err
}

// AddRecordLayer adds record layer to data
func AddRecordLayer(input []byte, typ []byte, ver []byte) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(input)))
	ret := make([]byte, 5+len(input))
	copy(ret[0:1], typ)
	copy(ret[1:3], ver)
	copy(ret[3:5], length)
	copy(ret[5:], input)
	return ret
}

// PeelRecordLayer peels off the record layer
func PeelRecordLayer(data []byte) []byte {
	ret := data[5:]
	return ret
}

// ParseClientHello parses everything on top of the TLS layer
// (including the record layer) into ClientHello type
func ParseClientHello(data []byte) (ret *ClientHello, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("Malformed ClientHello")
		}
	}()
	data = PeelRecordLayer(data)
	pointer := 0
	// Handshake Type
	handshakeType := data[pointer]
	if handshakeType != 0x01 {
		return ret, errors.New("Not a ClientHello")
	}
	pointer += 1
	// Length
	length := util.BtoInt(data[pointer : pointer+3])
	pointer += 3
	if length != len(data[pointer:]) {
		return ret, errors.New("Hello length doesn't match")
	}
	// Client Version
	clientVersion := data[pointer : pointer+2]
	pointer += 2
	// Random
	random := data[pointer : pointer+32]
	pointer += 32
	// Session ID
	sessionIdLen := int(data[pointer])
	pointer += 1
	sessionId := data[pointer : pointer+sessionIdLen]
	pointer += sessionIdLen
	// Cipher Suites
	cipherSuitesLen := util.BtoInt(data[pointer : pointer+2])
	pointer += 2
	cipherSuites := data[pointer : pointer+cipherSuitesLen]
	pointer += cipherSuitesLen
	// Compression Methods
	compressionMethodsLen := int(data[pointer])
	pointer += 1
	compressionMethods := data[pointer : pointer+compressionMethodsLen]
	pointer += compressionMethodsLen
	// Extensions
	extensionsLen := util.BtoInt(data[pointer : pointer+2])
	pointer += 2
	extensions, err := parseExtensions(data[pointer:])
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

func composeServerHello(ch *ClientHello) []byte {
	var serverHello [10][]byte
	serverHello[0] = []byte{0x02}                                   // handshake type
	serverHello[1] = []byte{0x00, 0x00, 0x4d}                       // length 77
	serverHello[2] = []byte{0x03, 0x03}                             // server version
	serverHello[3] = util.PsudoRandBytes(32, time.Now().UnixNano()) // random
	serverHello[4] = []byte{0x20}                                   // session id length 32
	serverHello[5] = ch.sessionId                                   // session id
	serverHello[6] = []byte{0xc0, 0x30}                             // cipher suite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	serverHello[7] = []byte{0x00}                                   // compression method null
	serverHello[8] = []byte{0x00, 0x05}                             // extensions length 5
	serverHello[9] = []byte{0xff, 0x01, 0x00, 0x01, 0x00}           // extensions renegotiation_info
	ret := []byte{}
	for i := 0; i < 10; i++ {
		ret = append(ret, serverHello[i]...)
	}
	return ret
}

// ComposeReply composes the ServerHello, ChangeCipherSpec and Finished messages
// together with their respective record layers into one byte slice. The content
// of these messages are random and useless for this plugin
func ComposeReply(ch *ClientHello) []byte {
	TLS12 := []byte{0x03, 0x03}
	shBytes := AddRecordLayer(composeServerHello(ch), []byte{0x16}, TLS12)
	ccsBytes := AddRecordLayer([]byte{0x01}, []byte{0x14}, TLS12)
	finished := make([]byte, 64)
	finished = util.PsudoRandBytes(40, time.Now().UnixNano())
	fBytes := AddRecordLayer(finished, []byte{0x16}, TLS12)
	ret := append(shBytes, ccsBytes...)
	ret = append(ret, fBytes...)
	return ret
}
