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

const (
	E_METHOD_PLAIN = iota
	E_METHOD_AES_GCM
	E_METHOD_CHACHA20_POLY1305
)

func MakeObfs(salsaKey [32]byte, payloadCipher cipher.AEAD) Obfser {
	obfs := func(f *Frame, buf []byte) (int, error) {
		// we need the encrypted data to be at least 8 bytes to be used as nonce for salsa20 stream header encryption
		// this will be the case if the encryption method is an AEAD cipher, however for plain, it's well possible
		// that the frame payload is smaller than 8 bytes, so we need to add on the difference
		var extraLen uint8
		if payloadCipher == nil {
			if len(f.Payload) < 8 {
				extraLen = uint8(8 - len(f.Payload))
			}
		} else {
			extraLen = uint8(payloadCipher.Overhead())
		}

		// usefulLen is the amount of bytes that will be eventually sent off
		usefulLen := 5 + HEADER_LEN + len(f.Payload) + int(extraLen)
		if len(buf) < usefulLen {
			return 0, errors.New("buffer is too small")

		}
		// we do as much in-place as possible to save allocation
		useful := buf[:usefulLen] // tls header + payload + potential overhead
		recordLayer := useful[0:5]
		header := useful[5 : 5+HEADER_LEN]
		encryptedPayloadWithExtra := useful[5+HEADER_LEN:]

		// TODO: Once Seq wraps around, the chance of a nonce reuse will be 1/65536 which is unacceptably low
		// prohibit Seq wrap around? simple solution : 2^32 messages per stream may be too little
		//
		// use uint64 Seq? Vastly reduces the complexity of frameSorter : concern with 64 bit number performance on
		// embedded systems (frameSorter already has a non-trivial performance impact on RPi2B, can only be worse on
		// mipsle). HOWEVER since frameSorter already deals with uint64, prehaps changing it totally wouldn't matter much?
		//
		// regular rekey? Improves security in general : when to rekey? Not easy to synchronise, also will add a decent
		// amount of complexity
		//
		// LEANING TOWARDS uint64 Seq. Adds extra 2 bytes of overhead but shouldn't really matter that much

		// header: [StreamID 4 bytes][Seq 4 bytes][Closing 1 byte][extraLen 1 bytes][random 2 bytes]
		putU32(header[0:4], f.StreamID)
		putU32(header[4:8], f.Seq)
		header[8] = f.Closing
		header[9] = extraLen
		prand.Read(header[10:12])

		if payloadCipher == nil {
			copy(encryptedPayloadWithExtra, f.Payload)
			if extraLen != 0 {
				rand.Read(encryptedPayloadWithExtra[len(encryptedPayloadWithExtra)-int(extraLen):])
			}
		} else {
			ciphertext := payloadCipher.Seal(nil, header, f.Payload, nil)
			copy(encryptedPayloadWithExtra, ciphertext)
		}

		nonce := encryptedPayloadWithExtra[len(encryptedPayloadWithExtra)-8:]
		salsa20.XORKeyStream(header, header, nonce, &salsaKey)

		// Composing final obfsed message
		// We don't use util.AddRecordLayer here to avoid unnecessary malloc
		recordLayer[0] = 0x17
		recordLayer[1] = 0x03
		recordLayer[2] = 0x03
		binary.BigEndian.PutUint16(recordLayer[3:5], uint16(HEADER_LEN+len(encryptedPayloadWithExtra)))
		return usefulLen, nil
	}
	return obfs
}

func MakeDeobfs(salsaKey [32]byte, payloadCipher cipher.AEAD) Deobfser {
	deobfs := func(in []byte) (*Frame, error) {
		if len(in) < 5+HEADER_LEN+8 {
			return nil, errors.New("Input cannot be shorter than 25 bytes")
		}

		peeled := make([]byte, len(in)-5)
		copy(peeled, in[5:])

		header := peeled[:12]
		pldWithOverHead := peeled[12:] // payload + potential overhead

		nonce := peeled[len(peeled)-8:]
		salsa20.XORKeyStream(header, header, nonce, &salsaKey)

		streamID := u32(header[0:4])
		seq := u32(header[4:8])
		closing := header[8]
		extraLen := header[9]

		usefulPayloadLen := len(pldWithOverHead) - int(extraLen)
		if usefulPayloadLen < 0 {
			return nil, errors.New("extra length is greater than total pldWithOverHead length")
		}

		var outputPayload []byte

		if payloadCipher == nil {
			if extraLen == 0 {
				outputPayload = pldWithOverHead
			} else {
				outputPayload = pldWithOverHead[:usefulPayloadLen]
			}
		} else {
			_, err := payloadCipher.Open(pldWithOverHead[:0], header, pldWithOverHead, nil)
			if err != nil {
				return nil, err
			}
			outputPayload = pldWithOverHead[:usefulPayloadLen]
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
	case E_METHOD_PLAIN:
		payloadCipher = nil
	case E_METHOD_AES_GCM:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey)
		if err != nil {
			return
		}
		payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
	case E_METHOD_CHACHA20_POLY1305:
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
