package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
)

func AESEncrypt(iv []byte, key []byte, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func AESDecrypt(iv []byte, key []byte, ciphertext []byte) []byte {
	ret := make([]byte, len(ciphertext))
	copy(ret, ciphertext) // Because XORKeyStream is inplace, but we don't want the input to be changed
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ret, ret)
	return ret
}

func MakeObfs(key []byte) func(*mux.Frame) []byte {
	obfs := func(f *mux.Frame) []byte {
		header := make([]byte, 12)
		binary.BigEndian.PutUint32(header[0:4], f.StreamID)
		binary.BigEndian.PutUint32(header[4:8], f.Seq)
		binary.BigEndian.PutUint32(header[8:12], f.ClosingStreamID)
		// header: [StreamID 4 bytes][Seq 4 bytes][ClosingStreamID 4 bytes]
		iv := make([]byte, 16)
		io.ReadFull(rand.Reader, iv)
		cipherheader := AESEncrypt(iv, key, header)

		// Composing final obfsed message
		// We don't use util.AddRecordLayer here to avoid unnecessary malloc
		obfsed := make([]byte, 5+16+12+len(f.Payload))
		obfsed[0] = 0x17
		obfsed[1] = 0x03
		obfsed[2] = 0x03
		binary.BigEndian.PutUint16(obfsed[3:5], uint16(16+12+len(f.Payload)))
		copy(obfsed[5:21], iv)
		copy(obfsed[21:33], cipherheader)
		copy(obfsed[33:], f.Payload)
		// obfsed: [record layer 5 bytes][iv 16 bytes][cipherheader 12 bytes][payload]
		return obfsed
	}
	return obfs
}

func MakeDeobfs(key []byte) func([]byte) *mux.Frame {
	deobfs := func(in []byte) *mux.Frame {
		peeled := in[5:]
		header := AESDecrypt(peeled[0:16], key, peeled[16:28])
		streamID := binary.BigEndian.Uint32(header[0:4])
		seq := binary.BigEndian.Uint32(header[4:8])
		closingStreamID := binary.BigEndian.Uint32(header[8:12])
		payload := make([]byte, len(peeled)-12-16)
		//log.Printf("Payload: %x\n", payload)
		copy(payload, peeled[28:])
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
