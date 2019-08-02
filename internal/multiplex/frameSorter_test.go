package multiplex

import (
	"encoding/binary"
	//"log"
	"sort"
	"testing"
)

func TestRecvNewFrame(t *testing.T) {
	inOrder := []uint64{5, 6, 7, 8, 9, 10, 11}
	outOfOrder0 := []uint64{5, 7, 8, 6, 11, 10, 9}
	outOfOrder1 := []uint64{1, 96, 47, 2, 29, 18, 60, 8, 74, 22, 82, 58, 44, 51, 57, 71, 90, 94, 68, 83, 61, 91, 39, 97, 85, 63, 46, 73, 54, 84, 76, 98, 93, 79, 75, 50, 67, 37, 92, 99, 42, 77, 17, 16, 38, 3, 100, 24, 31, 7, 36, 40, 86, 64, 34, 45, 12, 5, 9, 27, 21, 26, 35, 6, 65, 69, 53, 4, 48, 28, 30, 56, 32, 11, 80, 66, 25, 41, 78, 13, 88, 62, 15, 70, 49, 43, 72, 23, 10, 55, 52, 95, 14, 59, 87, 33, 19, 20, 81, 89}
	outOfOrderWrap0 := []uint64{1<<32 - 5, 1<<32 + 3, 1 << 32, 1<<32 - 3, 1<<32 - 4, 1<<32 + 2, 1<<32 - 2, 1<<32 - 1, 1<<32 + 1}
	sets := [][]uint64{inOrder, outOfOrder0, outOfOrder1, outOfOrderWrap0}
	for _, set := range sets {
		stream := makeStream(1, &Session{})
		stream.nextRecvSeq = uint32(set[0])
		for _, n := range set {
			bu64 := make([]byte, 8)
			binary.BigEndian.PutUint64(bu64, n)
			frame := &Frame{
				Seq:     uint32(n),
				Payload: bu64,
			}
			stream.writeNewFrame(frame)
		}

		var testSorted []uint32
		for x := 0; x < len(set); x++ {
			oct := make([]byte, 8)
			stream.sortedBuf.Read(oct)
			//log.Print(p)
			testSorted = append(testSorted, uint32(binary.BigEndian.Uint64(oct)))
		}
		sorted64 := make([]uint64, len(set))
		copy(sorted64, set)
		sort.Slice(sorted64, func(i, j int) bool { return sorted64[i] < sorted64[j] })
		sorted32 := make([]uint32, len(set))
		for i, _ := range sorted64 {
			sorted32[i] = uint32(sorted64[i])
		}

		for i, _ := range sorted32 {
			if sorted32[i] != testSorted[i] {
				t.Error(
					"For", set,
					"expecting", sorted32,
					"got", testSorted,
				)
			}
		}
		stream.newFrameCh <- nil
	}
}
