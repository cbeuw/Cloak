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

const frameHeaderLength = 14
const salsa20NonceSize = 8

const (
	EncryptionMethodPlain = iota
	EncryptionMethodAES256GCM
	EncryptionMethodChaha20Poly1305
	EncryptionMethodAES128GCM
)

// Obfuscator is responsible for serialisation, obfuscation, and optional encryption of data frames.
type Obfuscator struct {
	payloadCipher cipher.AEAD

	sessionKey [32]byte

	maxOverhead int
}

// obfuscate adds multiplexing headers, encrypt and add TLS header
func (o *Obfuscator) obfuscate(f *Frame, buf []byte, payloadOffsetInBuf int) (int, error) {
	// The method here is to use the first payloadCipher.NonceSize() bytes of the serialised frame header
	// as iv/nonce for the AEAD cipher to encrypt the frame payload. Then we use
	// the authentication tag produced appended to the end of the ciphertext (of size payloadCipher.Overhead())
	// as nonce for Salsa20 to encrypt the frame header. Both with sessionKey as keys.
	//
	// Several cryptographic guarantees we have made here: that payloadCipher, as an AEAD, is given a unique
	// iv/nonce each time, relative to its key; that the frame header encryptor Salsa20 is given a unique
	// nonce each time, relative to its key; and that the authenticity of frame header is checked.
	//
	// The payloadCipher is given a unique iv/nonce each time because it is derived from the frame header, which
	// contains the monotonically increasing stream id (uint32) and frame sequence (uint64). There will be a nonce
	// reuse after 2^64-1 frames sent (sent, not received because frames going different ways are sequenced
	// independently) by a stream, or after 2^32-1 streams created in a single session. We consider these number
	// to be large enough that they may never happen in reasonable time frames. Of course, different sessions
	// will produce the same combination of stream id and frame sequence, but they will have different session keys.
	//
	// Salsa20 is assumed to be given a unique nonce each time because we assume the tags produced by payloadCipher
	// AEAD is unique each time, as payloadCipher itself is given a unique iv/nonce each time due to points made above.
	// This is relatively a weak guarantee as we are assuming AEADs to produce different tags given different iv/nonces.
	// This is almost certainly true but I cannot find a source that outright states this.
	//
	// Because the frame header, before it being encrypted, is fed into the AEAD, it is also authenticated.
	// (rfc5116 s.2.1 "The nonce is authenticated internally to the algorithm").
	//
	// In case the user chooses to not encrypt the frame payload, payloadCipher will be nil. In this scenario,
	// we pad the frame payload with random bytes until it reaches Salsa20's nonce size (8 bytes). Then we simply
	// encrypt the frame header with the last 8 bytes of frame payload as nonce.
	// If the payload provided by the user is greater than 8 bytes, then we use entirely the user input as nonce.
	// We can't ensure its uniqueness ourselves, which is why plaintext mode must only be used when the user input
	// is already random-like. For Cloak it would normally mean that the user is using a proxy protocol that sends
	// encrypted data.
	payloadLen := len(f.Payload)
	if payloadLen == 0 {
		return 0, errors.New("payload cannot be empty")
	}
	var extraLen int
	if o.payloadCipher == nil {
		extraLen = salsa20NonceSize - payloadLen
		if extraLen < 0 {
			// if our payload is already greater than 8 bytes
			extraLen = 0
		}
	} else {
		extraLen = o.payloadCipher.Overhead()
		if extraLen < salsa20NonceSize {
			return 0, errors.New("AEAD's Overhead cannot be fewer than 8 bytes")
		}
	}

	usefulLen := frameHeaderLength + payloadLen + extraLen
	if len(buf) < usefulLen {
		return 0, errors.New("obfs buffer too small")
	}
	// we do as much in-place as possible to save allocation
	payload := buf[frameHeaderLength : frameHeaderLength+payloadLen]
	if payloadOffsetInBuf != frameHeaderLength {
		// if payload is not at the correct location in buffer
		copy(payload, f.Payload)
	}

	header := buf[:frameHeaderLength]
	binary.BigEndian.PutUint32(header[0:4], f.StreamID)
	binary.BigEndian.PutUint64(header[4:12], f.Seq)
	header[12] = f.Closing
	header[13] = byte(extraLen)

	if o.payloadCipher == nil {
		if extraLen != 0 { // read nonce
			extra := buf[usefulLen-extraLen : usefulLen]
			common.CryptoRandRead(extra)
		}
	} else {
		o.payloadCipher.Seal(payload[:0], header[:o.payloadCipher.NonceSize()], payload, nil)
	}

	nonce := buf[usefulLen-salsa20NonceSize : usefulLen]
	salsa20.XORKeyStream(header, header, nonce, &o.sessionKey)

	return usefulLen, nil
}

// deobfuscate removes TLS header, decrypt and unmarshall frames
func (o *Obfuscator) deobfuscate(f *Frame, in []byte) error {
	if len(in) < frameHeaderLength+salsa20NonceSize {
		return fmt.Errorf("input size %v, but it cannot be shorter than %v bytes", len(in), frameHeaderLength+salsa20NonceSize)
	}

	header := in[:frameHeaderLength]
	pldWithOverHead := in[frameHeaderLength:] // payload + potential overhead

	nonce := in[len(in)-salsa20NonceSize:]
	salsa20.XORKeyStream(header, header, nonce, &o.sessionKey)

	streamID := binary.BigEndian.Uint32(header[0:4])
	seq := binary.BigEndian.Uint64(header[4:12])
	closing := header[12]
	extraLen := header[13]

	usefulPayloadLen := len(pldWithOverHead) - int(extraLen)
	if usefulPayloadLen < 0 || usefulPayloadLen > len(pldWithOverHead) {
		return errors.New("extra length is negative or extra length is greater than total pldWithOverHead length")
	}

	var outputPayload []byte

	if o.payloadCipher == nil {
		if extraLen == 0 {
			outputPayload = pldWithOverHead
		} else {
			outputPayload = pldWithOverHead[:usefulPayloadLen]
		}
	} else {
		_, err := o.payloadCipher.Open(pldWithOverHead[:0], header[:o.payloadCipher.NonceSize()], pldWithOverHead, nil)
		if err != nil {
			return err
		}
		outputPayload = pldWithOverHead[:usefulPayloadLen]
	}

	f.StreamID = streamID
	f.Seq = seq
	f.Closing = closing
	f.Payload = outputPayload
	return nil
}

func MakeObfuscator(encryptionMethod byte, sessionKey [32]byte) (o Obfuscator, err error) {
	o = Obfuscator{
		sessionKey: sessionKey,
	}
	switch encryptionMethod {
	case EncryptionMethodPlain:
		o.payloadCipher = nil
		o.maxOverhead = salsa20NonceSize
	case EncryptionMethodAES256GCM:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey[:])
		if err != nil {
			return
		}
		o.payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
		o.maxOverhead = o.payloadCipher.Overhead()
	case EncryptionMethodAES128GCM:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey[:16])
		if err != nil {
			return
		}
		o.payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
		o.maxOverhead = o.payloadCipher.Overhead()
	case EncryptionMethodChaha20Poly1305:
		o.payloadCipher, err = chacha20poly1305.New(sessionKey[:])
		if err != nil {
			return
		}
		o.maxOverhead = o.payloadCipher.Overhead()
	default:
		return o, fmt.Errorf("unknown encryption method valued %v", encryptionMethod)
	}

	if o.payloadCipher != nil {
		if o.payloadCipher.NonceSize() > frameHeaderLength {
			return o, errors.New("payload AEAD's nonce size cannot be greater than size of frame header")
		}
	}

	return
}
