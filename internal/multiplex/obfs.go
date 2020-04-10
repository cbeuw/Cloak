package multiplex

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/util"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/salsa20"
	"io"
)

type Obfser func(*Frame, []byte) (int, error)
type Deobfser func([]byte) (*Frame, error)

var u32 = binary.BigEndian.Uint32
var u64 = binary.BigEndian.Uint64
var putU32 = binary.BigEndian.PutUint32
var putU64 = binary.BigEndian.PutUint64

const HEADER_LEN = 14

const (
	E_METHOD_PLAIN = iota
	E_METHOD_AES_GCM
	E_METHOD_CHACHA20_POLY1305
)

// Obfuscator is responsible for the obfuscation and deobfuscation of frames
type Obfuscator struct {
	// Used in Stream.Write. Add multiplexing headers, encrypt and add TLS header
	Obfs Obfser
	// Remove TLS header, decrypt and unmarshall frames
	Deobfs      Deobfser
	SessionKey  [32]byte
	minOverhead int
}

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
		usefulLen := HEADER_LEN + len(f.Payload) + int(extraLen)
		if len(buf) < usefulLen {
			return 0, io.ErrShortBuffer

		}
		// we do as much in-place as possible to save allocation
		useful := buf[:usefulLen] // stream header + payload + potential overhead
		header := useful[:HEADER_LEN]
		encryptedPayloadWithExtra := useful[HEADER_LEN:]

		putU32(header[0:4], f.StreamID)
		putU64(header[4:12], f.Seq)
		header[12] = f.Closing
		header[13] = extraLen

		if payloadCipher == nil {
			copy(encryptedPayloadWithExtra, f.Payload)
			if extraLen != 0 {
				util.CryptoRandRead(encryptedPayloadWithExtra[len(encryptedPayloadWithExtra)-int(extraLen):])
			}
		} else {
			ciphertext := payloadCipher.Seal(nil, header[:12], f.Payload, nil)
			copy(encryptedPayloadWithExtra, ciphertext)
		}

		nonce := encryptedPayloadWithExtra[len(encryptedPayloadWithExtra)-8:]
		salsa20.XORKeyStream(header, header, nonce, &salsaKey)

		return usefulLen, nil
	}
	return obfs
}

func MakeDeobfs(salsaKey [32]byte, payloadCipher cipher.AEAD) Deobfser {
	// stream header length + minimum data size (i.e. nonce size of salsa20)
	minInputLen := HEADER_LEN + 8
	deobfs := func(in []byte) (*Frame, error) {
		if len(in) < minInputLen {
			return nil, fmt.Errorf("input size %v, but it cannot be shorter than %v bytes", len(in), minInputLen)
		}

		header := in[:HEADER_LEN]
		pldWithOverHead := in[HEADER_LEN:] // payload + potential overhead

		nonce := in[len(in)-8:]
		salsa20.XORKeyStream(header, header, nonce, &salsaKey)

		streamID := u32(header[0:4])
		seq := u64(header[4:12])
		closing := header[12]
		extraLen := header[13]

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
			_, err := payloadCipher.Open(pldWithOverHead[:0], header[:12], pldWithOverHead, nil)
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

func MakeObfuscator(encryptionMethod byte, sessionKey [32]byte) (obfuscator Obfuscator, err error) {
	obfuscator = Obfuscator{
		SessionKey: sessionKey,
	}
	var payloadCipher cipher.AEAD
	switch encryptionMethod {
	case E_METHOD_PLAIN:
		payloadCipher = nil
		obfuscator.minOverhead = 0
	case E_METHOD_AES_GCM:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey[:])
		if err != nil {
			return
		}
		payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
		obfuscator.minOverhead = payloadCipher.Overhead()
	case E_METHOD_CHACHA20_POLY1305:
		payloadCipher, err = chacha20poly1305.New(sessionKey[:])
		if err != nil {
			return
		}
		obfuscator.minOverhead = payloadCipher.Overhead()
	default:
		return obfuscator, errors.New("Unknown encryption method")
	}

	obfuscator.Obfs = MakeObfs(sessionKey, payloadCipher)
	obfuscator.Deobfs = MakeDeobfs(sessionKey, payloadCipher)
	return
}
