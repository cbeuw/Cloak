package multiplex

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

type Obfser func(*Frame) ([]byte, error)
type Deobfser func([]byte) (*Frame, error)

var u32 = binary.BigEndian.Uint32
var putU32 = binary.BigEndian.PutUint32

const headerLen = 12

func genXorKey(key, salt []byte) []byte {
	h := sha1.New()
	h.Write(append(key, salt...))
	return h.Sum(nil)[:12]
}

func xor(a []byte, b []byte) {
	for i := range a {
		a[i] ^= b[i]
	}
}

func MakeObfs(key []byte, algo Crypto) Obfser {
	obfs := func(f *Frame) ([]byte, error) {
		// header: [StreamID 4 bytes][Seq 4 bytes][Closing 1 byte][random 3 bytes]
		header := make([]byte, headerLen)
		putU32(header[0:4], f.StreamID)
		putU32(header[4:8], f.Seq)
		header[8] = f.Closing
		rand.Read(header[9:12])

		encryptedPayload, err := algo.encrypt(f.Payload, header)
		if err != nil {
			return nil, err
		}

		salt := encryptedPayload[len(encryptedPayload)-16:]
		xorKey := genXorKey(key, salt)
		xor(header, xorKey)

		// Composing final obfsed message
		// We don't use util.AddRecordLayer here to avoid unnecessary malloc
		// TODO: allocate this in the beginning and do everything in place
		obfsed := make([]byte, 5+headerLen+len(encryptedPayload))
		obfsed[0] = 0x17
		obfsed[1] = 0x03
		obfsed[2] = 0x03
		binary.BigEndian.PutUint16(obfsed[3:5], uint16(headerLen+len(encryptedPayload)))
		copy(obfsed[5:5+headerLen], header)
		copy(obfsed[5+headerLen:], encryptedPayload)
		// obfsed: [record layer 5 bytes][obfsedheader 12 bytes][payload]
		return obfsed, nil
	}
	return obfs
}

func MakeDeobfs(key []byte, algo Crypto) Deobfser {
	deobfs := func(in []byte) (*Frame, error) {
		if len(in) < 5+headerLen+16 {
			return nil, errors.New("Input cannot be shorter than 33 bytes")
		}
		peeled := in[5:]

		header := peeled[0:12]
		payload := peeled[12:]
		salt := peeled[len(peeled)-16:]

		xorKey := genXorKey(key, salt)
		xor(header, xorKey)

		streamID := u32(header[0:4])
		seq := u32(header[4:8])
		closing := header[8]

		decryptedPayload, err := algo.decrypt(payload, header)
		if err != nil {
			return nil, err
		}

		outputPayload := make([]byte, len(decryptedPayload))
		copy(outputPayload, decryptedPayload)

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
