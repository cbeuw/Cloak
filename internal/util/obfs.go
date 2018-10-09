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
		plainheader := make([]byte, 16)
		copy(plainheader[0:12], header)
		copy(plainheader[12:], []byte{0x00, 0x00, 0x00, 0x00})
		// plainheader: [header 12 bytes][0x00,0x00,0x00,0x00]
		iv := f.Payload[0:16]
		cipherheader := encrypt(iv, key, plainheader)
		obfsed := make([]byte, len(f.Payload)+12+4)
		copy(obfsed[0:16], iv)
		copy(obfsed[16:32], cipherheader)
		copy(obfsed[32:], f.Payload[16:])
		// obfsed: [iv 16 bytes][cipherheader 16 bytes][payload w/o iv]
		ret := AddRecordLayer(obfsed, []byte{0x17}, []byte{0x03, 0x03})
		return ret
	}
	return obfs
}

func MakeDeobfs(key []byte) func([]byte) *mux.Frame {
	deobfs := func(in []byte) *mux.Frame {
		peeled := PeelRecordLayer(in)
		plainheader := decrypt(peeled[0:16], key, peeled[16:32])
		// plainheader: [header 12 bytes][0x00,0x00,0x00,0x00]
		streamID := binary.BigEndian.Uint32(plainheader[0:4])
		seq := binary.BigEndian.Uint32(plainheader[4:8])
		closingStreamID := binary.BigEndian.Uint32(plainheader[8:12])
		payload := make([]byte, len(peeled)-12-4)
		copy(payload[0:16], peeled[0:16])
		copy(payload[16:], peeled[32:])
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
