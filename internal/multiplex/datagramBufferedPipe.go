// This is base on https://github.com/golang/go/blob/0436b162397018c45068b47ca1b5924a3eafdee0/src/net/net_fake.go#L173

package multiplex

import (
	"bytes"
	"io"
	"sync"
	"time"
)

// datagramBufferedPipe is the same as streamBufferedPipe with the exception that it's message-oriented,
// instead of byte-oriented. The integrity of datagrams written into this buffer is preserved.
// it won't get chopped up into individual bytes
type datagramBufferedPipe struct {
	pLens     []int
	buf       *bytes.Buffer
	closed    bool
	rwCond    *sync.Cond
	wtTimeout time.Duration
	rDeadline time.Time

	timeoutTimer *time.Timer
}

func NewDatagramBufferedPipe() *datagramBufferedPipe {
	d := &datagramBufferedPipe{
		rwCond: sync.NewCond(&sync.Mutex{}),
		buf:    new(bytes.Buffer),
	}
	return d
}

func (d *datagramBufferedPipe) Read(target []byte) (int, error) {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()
	for {
		if d.closed && len(d.pLens) == 0 {
			return 0, io.EOF
		}

		hasRDeadline := !d.rDeadline.IsZero()
		if hasRDeadline {
			if time.Until(d.rDeadline) <= 0 {
				return 0, ErrTimeout
			}
		}

		if len(d.pLens) > 0 {
			break
		}

		if hasRDeadline {
			d.broadcastAfter(time.Until(d.rDeadline))
		}
		d.rwCond.Wait()
	}
	dataLen := d.pLens[0]
	if len(target) < dataLen {
		return 0, io.ErrShortBuffer
	}
	d.pLens = d.pLens[1:]
	d.buf.Read(target[:dataLen])
	// err will always be nil because we have already verified that buf.Len() != 0
	d.rwCond.Broadcast()
	return dataLen, nil
}

func (d *datagramBufferedPipe) Write(f *Frame) (toBeClosed bool, err error) {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()
	for {
		if d.closed {
			return true, io.ErrClosedPipe
		}
		if d.buf.Len() <= recvBufferSizeLimit {
			// if d.buf gets too large, write() will panic. We don't want this to happen
			break
		}
		d.rwCond.Wait()
	}

	if f.Closing != closingNothing {
		d.closed = true
		d.rwCond.Broadcast()
		return true, nil
	}

	dataLen := len(f.Payload)
	d.pLens = append(d.pLens, dataLen)
	d.buf.Write(f.Payload)
	// err will always be nil
	d.rwCond.Broadcast()
	return false, nil
}

func (d *datagramBufferedPipe) Close() error {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()

	d.closed = true
	d.rwCond.Broadcast()
	return nil
}

func (d *datagramBufferedPipe) SetReadDeadline(t time.Time) {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()

	d.rDeadline = t
	d.rwCond.Broadcast()
}

func (d *datagramBufferedPipe) broadcastAfter(t time.Duration) {
	if d.timeoutTimer != nil {
		d.timeoutTimer.Stop()
	}
	d.timeoutTimer = time.AfterFunc(t, d.rwCond.Broadcast)
}
