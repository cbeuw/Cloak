package multiplex

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cbeuw/Cloak/internal/common"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/salsa20"
)

type Obfser func(*Frame, []byte, int) (int, error)
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
	obfs := func(f *Frame, buf []byte, payloadOffsetInBuf int) (int, error) {
		// we need the encrypted data to be at least 8 bytes to be used as nonce for salsa20 stream header encryption
		// this will be the case if the encryption method is an AEAD cipher, however for plain, it's well possible
		// that the frame payload is smaller than 8 bytes, so we need to add on the difference
		payloadLen := len(f.Payload)
		if payloadLen == 0 {
			return 0, errors.New("payload cannot be empty")
		}
		var extraLen int
		if payloadCipher == nil {
			if extraLen = 8 - payloadLen; extraLen < 0 {
				extraLen = 0
			}
		} else {
			extraLen = payloadCipher.Overhead()
			if extraLen < 8 {
				return 0, errors.New("AEAD's Overhead cannot be fewer than 8 bytes")
			}
		}

		usefulLen := HEADER_LEN + payloadLen + extraLen
		if len(buf) < usefulLen {
			return 0, errors.New("obfs buffer too small")
		}
		// we do as much in-place as possible to save allocation
		payload := buf[HEADER_LEN : HEADER_LEN+payloadLen]
		if payloadOffsetInBuf != HEADER_LEN {
			// if payload is not at the correct location in buffer
			copy(payload, f.Payload)
		}

		header := buf[:HEADER_LEN]
		putU32(header[0:4], f.StreamID)
		putU64(header[4:12], f.Seq)
		header[12] = f.Closing
		header[13] = byte(extraLen)

		if payloadCipher == nil {
			if extraLen != 0 { // read nonce
				extra := buf[usefulLen-extraLen : usefulLen]
				common.CryptoRandRead(extra)
			}
		} else {
			payloadCipher.Seal(payload[:0], header[:12], payload, nil)
		}

		nonce := buf[usefulLen-8 : usefulLen]
		salsa20.XORKeyStream(header, header, nonce, &salsaKey)

		return usefulLen, nil
	}
	return obfs
}

func MakeDeobfs(salsaKey [32]byte, payloadCipher cipher.AEAD) Deobfser {
	// stream header length + minimum data size (i.e. nonce size of salsa20)
	const minInputLen = HEADER_LEN + 8
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
		if usefulPayloadLen < 0 || usefulPayloadLen > len(pldWithOverHead) {
			return nil, errors.New("extra length is negative or extra length is greater than total pldWithOverHead length")
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
