package multiplex

import (
	"container/heap"
	//"log"
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
// they should be sent to shadowsocks. The code in this file provides buffering and sorting.
//
// Similar to TCP, the next seq number after 2^32-1 is 0. This is called wrap around.
//
// Note that in golang, integer overflow results in wrap around
//
// Stream.nextRecvSeq is the expected sequence number of the next packet
// Stream.rev counts the amount of time the sequence number gets wrapped

type frameNode struct {
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

func (s *Stream) writeNewFrame(f *Frame) {
	s.newFrameCh <- f
}

// recvNewFrame is a forever running loop which receives frames unordered,
// cache and order them and send them into sortedBufCh
func (s *Stream) recvNewFrame() {
	for {
		var f *Frame
		select {
		case <-s.die:
			return
		case f = <-s.newFrameCh:
		}
		if f == nil { // This shouldn't happen
			//log.Println("nil frame")
			continue
		}

		// when there's no ooo packages in heap and we receive the next package in order
		if len(s.sh) == 0 && f.Seq == s.nextRecvSeq {
			s.pushFrame(f)
			if f.Closing == 1 {
				// empty data indicates closing signal
				s.sortedBufCh <- []byte{}
				return
			}
			continue
		}

		fs := &frameNode{
			trueSeq: 0,
			frame:   f,
		}

		if f.Seq < s.nextRecvSeq {
			// For the ease of demonstration, assume seq is uint8, i.e. it wraps around after 255
			// e.g. we are on rev=0 (wrap has not happened yet)
			// and we get the order of recv as 253 254 0 1
			// after 254, nextN should be 255, but 0 is received and 0 < 255
			// now 0 should have a trueSeq of 256
			if !s.wrapMode {
				// wrapMode is true when the latest seq is wrapped but nextN is not
				s.wrapMode = true
			}
			fs.trueSeq = uint64(1<<32)*uint64(s.rev+1) + uint64(f.Seq) + 1
			// +1 because wrapped 0 should have trueSeq of 256 instead of 255
			// when this bit was run on 1, the trueSeq of 1 would become 256
		} else {
			fs.trueSeq = uint64(1<<32)*uint64(s.rev) + uint64(f.Seq)
			// when this bit was run on 255, the trueSeq of 255 would be 255
		}

		heap.Push(&s.sh, fs)
		// Keep popping from the heap until empty or to the point that the wanted seq was not received
		for len(s.sh) > 0 && s.sh[0].frame.Seq == s.nextRecvSeq {
			frame := heap.Pop(&s.sh).(*frameNode).frame
			if frame.Closing == 1 {
				// empty data indicates closing signal
				s.sortedBufCh <- []byte{}
				return
			}
			s.pushFrame(frame)
		}
	}

}

func (s *Stream) pushFrame(f *Frame) {
	s.sortedBufCh <- f.Payload
	s.nextRecvSeq += 1
	if s.nextRecvSeq == 0 { // getting wrapped
		s.rev += 1
		s.wrapMode = false
	}
}
