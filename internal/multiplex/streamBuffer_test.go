package multiplex

import (
	"encoding/binary"
	"io"

	//"log"
	"sort"
	"testing"
)

func TestRecvNewFrame(t *testing.T) {
	inOrder := []uint64{5, 6, 7, 8, 9, 10, 11}
	outOfOrder0 := []uint64{5, 7, 8, 6, 11, 10, 9}
	outOfOrder1 := []uint64{1, 96, 47, 2, 29, 18, 60, 8, 74, 22, 82, 58, 44, 51, 57, 71, 90, 94, 68, 83, 61, 91, 39, 97, 85, 63, 46, 73, 54, 84, 76, 98, 93, 79, 75, 50, 67, 37, 92, 99, 42, 77, 17, 16, 38, 3, 100, 24, 31, 7, 36, 40, 86, 64, 34, 45, 12, 5, 9, 27, 21, 26, 35, 6, 65, 69, 53, 4, 48, 28, 30, 56, 32, 11, 80, 66, 25, 41, 78, 13, 88, 62, 15, 70, 49, 43, 72, 23, 10, 55, 52, 95, 14, 59, 87, 33, 19, 20, 81, 89}
	outOfOrder2 := []uint64{1<<32 - 5, 1<<32 + 3, 1 << 32, 1<<32 - 3, 1<<32 - 4, 1<<32 + 2, 1<<32 - 2, 1<<32 - 1, 1<<32 + 1}

	test := func(set []uint64, ct *testing.T) {
		sb := NewStreamBuffer()
		sb.nextRecvSeq = set[0]
		for _, n := range set {
			bu64 := make([]byte, 8)
			binary.BigEndian.PutUint64(bu64, n)
			sb.Write(&Frame{
				Seq:     n,
				Payload: bu64,
			})
		}

		var sortedResult []uint64
		for x := 0; x < len(set); x++ {
			oct := make([]byte, 8)
			n, err := sb.Read(oct)
			if n != 8 || err != nil {
				ct.Error("failed to read from sorted Buf", n, err)
				return
			}
			//log.Print(p)
			sortedResult = append(sortedResult, binary.BigEndian.Uint64(oct))
		}
		targetSorted := make([]uint64, len(set))
		copy(targetSorted, set)
		sort.Slice(targetSorted, func(i, j int) bool { return targetSorted[i] < targetSorted[j] })

		for i := range targetSorted {
			if sortedResult[i] != targetSorted[i] {
				goto fail
			}
		}
		sb.Close()
		return
	fail:
		ct.Error(
			"expecting", targetSorted,
			"got", sortedResult,
		)
	}

	t.Run("in order", func(t *testing.T) {
		test(inOrder, t)
	})
	t.Run("out of order0", func(t *testing.T) {
		test(outOfOrder0, t)
	})
	t.Run("out of order1", func(t *testing.T) {
		test(outOfOrder1, t)
	})
	t.Run("out of order wrap", func(t *testing.T) {
		test(outOfOrder2, t)
	})
}

func TestStreamBuffer_RecvThenClose(t *testing.T) {
	const testDataLen = 128
	sb := NewStreamBuffer()
	testData := make([]byte, testDataLen)
	testFrame := Frame{
		StreamID: 0,
		Seq:      0,
		Closing:  0,
		Payload:  testData,
	}
	sb.Write(&testFrame)
	sb.Close()

	readBuf := make([]byte, testDataLen)
	_, err := io.ReadFull(sb, readBuf)
	if err != nil {
		t.Error(err)
	}
}
