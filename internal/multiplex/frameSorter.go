package multiplex

import (
	"container/heap"
	"io"

	log "github.com/sirupsen/logrus"
)

// The data is multiplexed through several TCP connections, therefore the
// order of arrival is not guaranteed. A stream's first packet may be sent through
// connection0 and its second packet may be sent through connection1. Although both
// packets are transmitted reliably (as TCP is reliable), packet1 may arrive to the
// remote side before packet0. Cloak have to therefore sequence the packets so that they
// arrive in order as they were sent by the proxy software
//
// Cloak packets will have a 32-bit sequence number on them, so we know in which order
// they should be sent to the proxy software. The code in this file provides buffering and sorting.
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

type frameSorter struct {
	nextRecvSeq uint32
	rev         int
	sh          sorterHeap
	wrapMode    bool

	// New frames are received through newFrameCh by frameSorter
	newFrameCh chan *Frame

	output io.WriteCloser
}

func NewFrameSorter(output io.WriteCloser) *frameSorter {
	fs := &frameSorter{
		sh:         []*frameNode{},
		newFrameCh: make(chan *Frame, 1024),
		rev:        0,
		output:     output,
	}
	go fs.recvNewFrame()
	return fs
}

func (fs *frameSorter) writeNewFrame(f *Frame) {
	fs.newFrameCh <- f
}
func (fs *frameSorter) Close() error {
	fs.newFrameCh <- nil
	return nil
}

// recvNewFrame is a forever running loop which receives frames unordered,
// cache and order them and send them into sortedBufCh
func (fs *frameSorter) recvNewFrame() {
	defer log.Tracef("a recvNewFrame has returned gracefully")
	for {
		f := <-fs.newFrameCh
		if f == nil {
			return
		}

		// when there'fs no ooo packages in heap and we receive the next package in order
		if len(fs.sh) == 0 && f.Seq == fs.nextRecvSeq {
			if f.Closing == 1 {
				// empty data indicates closing signal
				fs.output.Close()
				return
			} else {
				fs.output.Write(f.Payload)
				fs.nextRecvSeq += 1
				if fs.nextRecvSeq == 0 { // getting wrapped
					fs.rev += 1
					fs.wrapMode = false
				}
			}
			continue
		}

		node := &frameNode{
			trueSeq: 0,
			frame:   f,
		}

		if f.Seq < fs.nextRecvSeq {
			// For the ease of demonstration, assume seq is uint8, i.e. it wraps around after 255
			// e.g. we are on rev=0 (wrap has not happened yet)
			// and we get the order of recv as 253 254 0 1
			// after 254, nextN should be 255, but 0 is received and 0 < 255
			// now 0 should have a trueSeq of 256
			if !fs.wrapMode {
				// wrapMode is true when the latest seq is wrapped but nextN is not
				fs.wrapMode = true
			}
			node.trueSeq = uint64(1<<32)*uint64(fs.rev+1) + uint64(f.Seq) + 1
			// +1 because wrapped 0 should have trueSeq of 256 instead of 255
			// when this bit was run on 1, the trueSeq of 1 would become 256
		} else {
			node.trueSeq = uint64(1<<32)*uint64(fs.rev) + uint64(f.Seq)
			// when this bit was run on 255, the trueSeq of 255 would be 255
		}

		heap.Push(&fs.sh, node)
		// Keep popping from the heap until empty or to the point that the wanted seq was not received
		for len(fs.sh) > 0 && fs.sh[0].frame.Seq == fs.nextRecvSeq {
			f = heap.Pop(&fs.sh).(*frameNode).frame
			if f.Closing == 1 {
				// empty data indicates closing signal
				fs.output.Close()
				return
			} else {
				fs.output.Write(f.Payload)
				fs.nextRecvSeq += 1
				if fs.nextRecvSeq == 0 { // getting wrapped
					fs.rev += 1
					fs.wrapMode = false
				}
			}
		}
	}

}
