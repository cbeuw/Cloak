package multiplex

// The data is multiplexed through several TCP connections, therefore the
// order of arrival is not guaranteed. A stream's first packet may be sent through
// connection0 and its second packet may be sent through connection1. Although both
// packets are transmitted reliably (as TCP is reliable), packet1 may arrive to the
// remote side before packet0. Cloak have to therefore sequence the packets so that they
// arrive in order as they were sent by the proxy software
//
// Cloak packets will have a 32-bit sequence number on them, so we know in which order
// they should be sent to the proxy software. The code in this file provides buffering and sorting.

import (
	"container/heap"
	"errors"
	"sync"
)

type frameNode struct {
	trueSeq uint64
	frame   Frame
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

type streamBuffer struct {
	recvM sync.Mutex

	nextRecvSeq uint32
	rev         int
	sh          sorterHeap
	wrapMode    bool

	buf *bufferedPipe
}

func NewStreamBuffer() *streamBuffer {
	sb := &streamBuffer{
		sh:  []*frameNode{},
		rev: 0,
		buf: NewBufferedPipe(),
	}
	return sb
}

var ClosingFrameReceived = errors.New("closed by closing frame")

// recvNewFrame is a forever running loop which receives frames unordered,
// cache and order them and send them into sortedBufCh
func (sb *streamBuffer) Write(f Frame) error {
	sb.recvM.Lock()
	defer sb.recvM.Unlock()
	// when there'fs no ooo packages in heap and we receive the next package in order
	if len(sb.sh) == 0 && f.Seq == sb.nextRecvSeq {
		if f.Closing == 1 {
			// empty data indicates closing signal
			sb.buf.Close()
			return ClosingFrameReceived
		} else {
			sb.buf.Write(f.Payload)
			sb.nextRecvSeq += 1
			if sb.nextRecvSeq == 0 { // getting wrapped
				sb.rev += 1
				sb.wrapMode = false
			}
		}
		return nil
	}

	node := &frameNode{
		trueSeq: 0,
		frame:   f,
	}

	if f.Seq < sb.nextRecvSeq {
		// For the ease of demonstration, assume seq is uint8, i.e. it wraps around after 255
		// e.g. we are on rev=0 (wrap has not happened yet)
		// and we get the order of recv as 253 254 0 1
		// after 254, nextN should be 255, but 0 is received and 0 < 255
		// now 0 should have a trueSeq of 256
		if !sb.wrapMode {
			// wrapMode is true when the latest seq is wrapped but nextN is not
			sb.wrapMode = true
		}
		node.trueSeq = uint64(1<<32)*uint64(sb.rev+1) + uint64(f.Seq) + 1
		// +1 because wrapped 0 should have trueSeq of 256 instead of 255
		// when this bit was run on 1, the trueSeq of 1 would become 256
	} else {
		node.trueSeq = uint64(1<<32)*uint64(sb.rev) + uint64(f.Seq)
		// when this bit was run on 255, the trueSeq of 255 would be 255
	}

	heap.Push(&sb.sh, node)
	// Keep popping from the heap until empty or to the point that the wanted seq was not received
	for len(sb.sh) > 0 && sb.sh[0].frame.Seq == sb.nextRecvSeq {
		f = heap.Pop(&sb.sh).(*frameNode).frame
		if f.Closing == 1 {
			// empty data indicates closing signal
			sb.buf.Close()
			return ClosingFrameReceived
		} else {
			sb.buf.Write(f.Payload)
			sb.nextRecvSeq += 1
			if sb.nextRecvSeq == 0 { // getting wrapped
				sb.rev += 1
				sb.wrapMode = false
			}
		}
	}
	return nil
}

func (sb *streamBuffer) Read(buf []byte) (int, error) {
	return sb.buf.Read(buf)
}

func (sb *streamBuffer) Close() error {
	return sb.buf.Close()
}

func (sb *streamBuffer) Len() int {
	return sb.buf.Len()
}
