package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

func encrypt(iv []byte, key []byte, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func decrypt(iv []byte, key []byte, ciphertext []byte) []byte {
	ret := make([]byte, len(ciphertext))
	copy(ret, ciphertext) // Because XORKeyStream is inplace, but we don't want the input to be changed
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ret, ret)
	// ret is now plaintext
	return ret
}

func MakeObfs(key []byte) func(*mux.Frame) []byte {
	obfs := func(f *mux.Frame) []byte {
		header := make([]byte, 12)
		binary.BigEndian.PutUint32(header[0:4], f.StreamID)
		binary.BigEndian.PutUint32(header[4:8], f.Seq)
		binary.BigEndian.PutUint32(header[8:12], f.ClosingStreamID)
		// header: [StreamID 4 bytes][Seq 4 bytes][ClosingStreamID 4 bytes]
		plaintext := make([]byte, 12+len(f.Payload)-16)
		copy(plaintext[0:12], header)
		copy(plaintext[12:], f.Payload[16:])
		// plaintext: [header 12 bytes][Payload[16:]]
		iv := f.Payload[0:16]
		ciphertext := encrypt(iv, key, plaintext)
		obfsed := make([]byte, 16+len(ciphertext))
		copy(obfsed[0:16], iv)
		copy(obfsed[16:], ciphertext)
		// obfsed: [iv 16 bytes][ciphertext]
		ret := AddRecordLayer(obfsed, []byte{0x17}, []byte{0x03, 0x03})
		return ret
	}
	return obfs
}

func MakeDeobfs(key []byte) func([]byte) *mux.Frame {
	deobfs := func(in []byte) *mux.Frame {
		peeled := PeelRecordLayer(in)
		plaintext := decrypt(peeled[0:16], key, peeled[16:])
		// plaintext: [header 12 bytes][Payload[16:]]
		streamID := binary.BigEndian.Uint32(plaintext[0:4])
		seq := binary.BigEndian.Uint32(plaintext[4:8])
		closingStreamID := binary.BigEndian.Uint32(plaintext[8:12])
		payload := make([]byte, len(plaintext)-12)
		copy(payload[0:16], peeled[0:16])
		copy(payload[16:], plaintext[12:])
		ret := &mux.Frame{
			StreamID:        streamID,
			Seq:             seq,
			ClosingStreamID: closingStreamID,
			Payload:         payload,
		}
		return ret
	}
	return deobfs
}
