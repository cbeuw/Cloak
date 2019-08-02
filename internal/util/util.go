package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"net"
	"strconv"
)

func AESGCMEncrypt(nonce []byte, key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce, plaintext, nil), nil
}

func AESGCMDecrypt(nonce []byte, key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// ReadTLS reads TLS data according to its record layer
func ReadTLS(conn net.Conn, buffer []byte) (n int, err error) {
	// TCP is a stream. Multiple TLS messages can arrive at the same time,
	// a single message can also be segmented due to MTU of the IP layer.
	// This function guareentees a single TLS message to be read and everything
	// else is left in the buffer.
	i, err := io.ReadFull(conn, buffer[:5])
	if err != nil {
		return
	}

	dataLength := int(binary.BigEndian.Uint16(buffer[3:5]))
	if dataLength > len(buffer) {
		err = errors.New("Reading TLS message: message size greater than buffer. message size: " + strconv.Itoa(dataLength))
		return
	}
	left := dataLength
	readPtr := 5

	for left != 0 {
		// If left > buffer size (i.e. our message got segmented), the entire MTU is read
		// if left = buffer size, the entire buffer is all there left to read
		// if left < buffer size (i.e. multiple messages came together),
		// only the message we want is read
		i, err = io.ReadFull(conn, buffer[readPtr:readPtr+left])
		if err != nil {
			return
		}
		left -= i
		readPtr += i
	}

	n = 5 + dataLength
	return
}

func GenerateObfs(encryptionMethod byte, sessionKey []byte) (obfuscator *mux.Obfuscator, err error) {
	var payloadCipher cipher.AEAD
	switch encryptionMethod {
	case 0x00:
		payloadCipher = nil
	case 0x01:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey)
		if err != nil {
			return
		}
		payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
	case 0x02:
		payloadCipher, err = chacha20poly1305.New(sessionKey)
		if err != nil {
			return
		}
	default:
		return nil, errors.New("Unknown encryption method")
	}

	headerCipher, err := aes.NewCipher(sessionKey)
	if err != nil {
		return
	}

	obfuscator = &mux.Obfuscator{
		mux.MakeObfs(headerCipher, payloadCipher),
		mux.MakeDeobfs(headerCipher, payloadCipher),
		sessionKey,
	}
	return
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
