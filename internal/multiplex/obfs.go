package multiplex

import (
	"encoding/binary"
	"errors"

	xxhash "github.com/OneOfOne/xxhash"
)

type Obfser func(*Frame) ([]byte, error)
type Deobfser func([]byte) (*Frame, error)

// For each frame, the three parts of the header is xored with three keys.
// The keys are generated from the SID and the payload of the frame.
// FIXME: this code will panic if len(data)<18.
func genXorKeys(secret []byte, data []byte) (i uint32, ii uint32, iii uint32) {
	h := xxhash.New32()
	ret := make([]uint32, 3)
	preHash := make([]byte, 16)
	for j := 0; j < 3; j++ {
		copy(preHash[0:10], secret[j*10:j*10+10])
		copy(preHash[10:16], data[j*6:j*6+6])
		h.Write(preHash)
		ret[j] = h.Sum32()
	}
	return ret[0], ret[1], ret[2]
}

func MakeObfs(key []byte) Obfser {
	obfs := func(f *Frame) ([]byte, error) {
		if len(f.Payload) < 18 {
			return nil, errors.New("Payload cannot be shorter than 18 bytes")
		}
		obfsedHeader := make([]byte, 12)
		// header: [StreamID 4 bytes][Seq 4 bytes][Closing 4 bytes]
		i, ii, iii := genXorKeys(key, f.Payload[0:18])
		binary.BigEndian.PutUint32(obfsedHeader[0:4], f.StreamID^i)
		binary.BigEndian.PutUint32(obfsedHeader[4:8], f.Seq^ii)
		binary.BigEndian.PutUint32(obfsedHeader[8:12], f.Closing^iii)

		// Composing final obfsed message
		// We don't use util.AddRecordLayer here to avoid unnecessary malloc
		obfsed := make([]byte, 5+12+len(f.Payload))
		obfsed[0] = 0x17
		obfsed[1] = 0x03
		obfsed[2] = 0x03
		binary.BigEndian.PutUint16(obfsed[3:5], uint16(12+len(f.Payload)))
		copy(obfsed[5:17], obfsedHeader)
		copy(obfsed[17:], f.Payload)
		// obfsed: [record layer 5 bytes][cipherheader 12 bytes][payload]
		return obfsed, nil
	}
	return obfs
}

func MakeDeobfs(key []byte) Deobfser {
	deobfs := func(in []byte) (*Frame, error) {
		if len(in) < 30 {
			return nil, errors.New("Input cannot be shorter than 30 bytes")
		}
		peeled := in[5:]
		i, ii, iii := genXorKeys(key, peeled[12:30])
		streamID := binary.BigEndian.Uint32(peeled[0:4]) ^ i
		seq := binary.BigEndian.Uint32(peeled[4:8]) ^ ii
		closing := binary.BigEndian.Uint32(peeled[8:12]) ^ iii
		payload := make([]byte, len(peeled)-12)
		copy(payload, peeled[12:])
		ret := &Frame{
			StreamID: streamID,
			Seq:      seq,
			Closing:  closing,
			Payload:  payload,
		}
		return ret, nil
	}
	return deobfs
}
