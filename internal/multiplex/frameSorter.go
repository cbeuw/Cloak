package multiplex

import (
	"container/heap"
)

// The data is multiplexed through several TCP connections, therefore the
// order of arrival is not guaranteed. A stream's first packet may be sent through
// connection0 and its second packet may be sent through connection1. Although both
// packets are transmitted reliably (as TCP is reliable), packet1 may arrive to the
// remote side before packet0.
//
// However, shadowsocks' protocol does not provide sequence control. We must therefore
// make sure packets arrive in order.
//
// Cloak packets will have a 32-bit sequence number on them, so we know in which order
// they should be sent to shadowsocks. In the case that the packets arrive out-of-order,
// the code in this file provides buffering and sorting.
//
// Similar to TCP, the next seq number after 2^32-1 is 0. This is called wrap around.
//
// Note that in golang, integer overflow results in wrap around
//
// Stream.nextRecvSeq is the expected sequence number of the next packet
// Stream.rev counts the amount of time the sequence number gets wrapped

type frameNode struct {
	seq     uint32
	trueSeq uint64
	frame   *Frame
}
type sorterHeap []*frameNode

func (sh sorterHeap) Less(i, j int) bool {
	return sh[i].trueSeq < sh[j].trueSeq
}
func (sh sorterHeap) Len() int {
	return len(sh)
}
func (sh sorterHeap) Swap(i, j int) {
	sh[i], sh[j] = sh[j], sh[i]
}

func (sh *sorterHeap) Push(x interface{}) {
	*sh = append(*sh, x.(*frameNode))
}

func (sh *sorterHeap) Pop() interface{} {
	old := *sh
	n := len(old)
	x := old[n-1]
	*sh = old[0 : n-1]
	return x
}

func (s *Stream) recvNewFrame() {
	for {
		f := <-s.newFrameCh
		if f == nil {
			continue
		}
		// For the ease of demonstration, assume seq is uint8, i.e. it wraps around after 255
		fs := &frameNode{
			f.Seq,
			0,
			f,
		}

		// TODO: if a malicious client resend a previously sent seq number, what will happen?
		if fs.seq < s.nextRecvSeq {
			// e.g. we are on rev=0 (wrap has not happened yet)
			// and we get the order of recv as 253 254 0 1
			// after 254, nextN should be 255, but 0 is received and 0 < 255
			// now 0 should have a trueSeq of 256
			if !s.wrapMode {
				// wrapMode is true when the latest seq is wrapped but nextN is not
				s.wrapMode = true
			}
			fs.trueSeq = uint64(2<<16*(s.rev+1)) + uint64(fs.seq) + 1
			// +1 because wrapped 0 should have trueSeq of 256 instead of 255
			// when this bit was run on 1, the trueSeq of 1 would become 256
		} else {
			fs.trueSeq = uint64(2<<16*s.rev) + uint64(fs.seq)
			// when this bit was run on 255, the trueSeq of 255 would be 255
		}
		heap.Push(&s.sh, fs)

		// Keep popping from the heap until empty or to the point that the wanted seq was not received
		for len(s.sh) > 0 && s.sh[0].seq == s.nextRecvSeq {

			s.sortedBufCh <- heap.Pop(&s.sh).(*frameNode).frame.Payload

			s.nextRecvSeq += 1
			if s.nextRecvSeq == 0 {
				// when nextN is wrapped, wrapMode becomes false and rev+1
				s.rev += 1
				s.wrapMode = false
			}
		}
	}

}
