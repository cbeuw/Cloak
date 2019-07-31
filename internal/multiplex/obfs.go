package multiplex

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

type Obfser func(*Frame) ([]byte, error)
type Deobfser func([]byte) (*Frame, error)

var u32 = binary.BigEndian.Uint32
var putU32 = binary.BigEndian.PutUint32

const HEADER_LEN = 12

func MakeObfs(headerCipher cipher.Block, algo Crypto) Obfser {
	obfs := func(f *Frame) ([]byte, error) {
		ret := make([]byte, 5+HEADER_LEN+len(f.Payload)+16)
		recordLayer := ret[0:5]
		header := ret[5 : 5+HEADER_LEN]
		encryptedPayload := ret[5+HEADER_LEN:]

		// header: [StreamID 4 bytes][Seq 4 bytes][Closing 1 byte][random 3 bytes]
		putU32(header[0:4], f.StreamID)
		putU32(header[4:8], f.Seq)
		header[8] = f.Closing
		rand.Read(header[9:12])

		ciphertext, err := algo.encrypt(f.Payload, header)
		if err != nil {
			return nil, err
		}
		copy(encryptedPayload, ciphertext)

		iv := encryptedPayload[len(encryptedPayload)-16:]
		cipher.NewCTR(headerCipher, iv).XORKeyStream(header, header)

		// Composing final obfsed message
		// We don't use util.AddRecordLayer here to avoid unnecessary malloc
		recordLayer[0] = 0x17
		recordLayer[1] = 0x03
		recordLayer[2] = 0x03
		binary.BigEndian.PutUint16(recordLayer[3:5], uint16(HEADER_LEN+len(encryptedPayload)))
		return ret, nil
	}
	return obfs
}

func MakeDeobfs(headerCipher cipher.Block, algo Crypto) Deobfser {
	deobfs := func(in []byte) (*Frame, error) {
		if len(in) < 5+HEADER_LEN+16 {
			return nil, errors.New("Input cannot be shorter than 33 bytes")
		}
		peeled := in[5:]

		header := peeled[0:12]
		payload := peeled[12:]
		iv := peeled[len(peeled)-16:]

		cipher.NewCTR(headerCipher, iv).XORKeyStream(header, header)

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
