package multiplex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/salsa20"

	prand "math/rand"
)

type Obfser func(*Frame, []byte) (int, error)
type Deobfser func([]byte) (*Frame, error)

var u32 = binary.BigEndian.Uint32
var putU32 = binary.BigEndian.PutUint32

const HEADER_LEN = 12

func MakeObfs(salsaKey [32]byte, payloadCipher cipher.AEAD) Obfser {
	obfs := func(f *Frame, buf []byte) (int, error) {
		var extraLen uint8
		if payloadCipher == nil {
			if len(f.Payload) < 8 {
				extraLen = uint8(8 - len(f.Payload))
			}
		} else {
			extraLen = uint8(payloadCipher.Overhead())
		}

		usefulLen := 5 + HEADER_LEN + len(f.Payload) + int(extraLen)
		if len(buf) < usefulLen {
			return 0, errors.New("buffer is too small")
		}
		used := buf[:usefulLen]
		recordLayer := used[0:5]
		header := used[5 : 5+HEADER_LEN]
		encryptedPayload := used[5+HEADER_LEN:]

		// header: [StreamID 4 bytes][Seq 4 bytes][Closing 1 byte][extraLen 1 bytes][random 2 bytes]
		putU32(header[0:4], f.StreamID)
		putU32(header[4:8], f.Seq)
		header[8] = f.Closing
		header[9] = extraLen
		prand.Read(header[10:12])

		if payloadCipher == nil {
			copy(encryptedPayload, f.Payload)
			if extraLen != 0 {
				rand.Read(encryptedPayload[len(encryptedPayload)-int(extraLen):])
			}
		} else {
			ciphertext := payloadCipher.Seal(nil, header, f.Payload, nil)
			copy(encryptedPayload, ciphertext)
		}

		nonce := encryptedPayload[len(encryptedPayload)-8:]
		salsa20.XORKeyStream(header, header, nonce, &salsaKey)

		// Composing final obfsed message
		// We don't use util.AddRecordLayer here to avoid unnecessary malloc
		recordLayer[0] = 0x17
		recordLayer[1] = 0x03
		recordLayer[2] = 0x03
		binary.BigEndian.PutUint16(recordLayer[3:5], uint16(HEADER_LEN+len(encryptedPayload)))
		return usefulLen, nil
	}
	return obfs
}

func MakeDeobfs(salsaKey [32]byte, payloadCipher cipher.AEAD) Deobfser {
	deobfs := func(in []byte) (*Frame, error) {
		if len(in) < 5+HEADER_LEN+8 {
			return nil, errors.New("Input cannot be shorter than 33 bytes")
		}
		peeled := in[5:]

		header := peeled[0:12]
		payload := peeled[12:]

		nonce := peeled[len(peeled)-8:]
		salsa20.XORKeyStream(header, header, nonce, &salsaKey)

		streamID := u32(header[0:4])
		seq := u32(header[4:8])
		closing := header[8]
		extraLen := header[9]

		outputLen := len(payload) - int(extraLen)
		if outputLen < 0 {
			return nil, errors.New("extra length is greater than total payload length")
		}
		outputPayload := make([]byte, outputLen)

		if payloadCipher == nil {
			copy(outputPayload, payload)
		} else {
			plaintext, err := payloadCipher.Open(nil, header, payload, nil)
			if err != nil {
				return nil, err
			}
			copy(outputPayload, plaintext)
		}

		ret := &Frame{
			StreamID: streamID,
			Seq:      seq,
			Closing:  closing,
			Payload:  outputPayload,
		}
		return ret, nil
	}
	return deobfs
}

func GenerateObfs(encryptionMethod byte, sessionKey []byte) (obfuscator *Obfuscator, err error) {
	if len(sessionKey) != 32 {
		err = errors.New("sessionKey size must be 32 bytes")
	}

	var salsaKey [32]byte
	copy(salsaKey[:], sessionKey)

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

	obfuscator = &Obfuscator{
		MakeObfs(salsaKey, payloadCipher),
		MakeDeobfs(salsaKey, payloadCipher),
		sessionKey,
	}
	return
}
