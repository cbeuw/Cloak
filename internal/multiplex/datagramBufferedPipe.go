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
	pLens []int
	// lazily allocated
	buf       *bytes.Buffer
	closed    bool
	rwCond    *sync.Cond
	wtTimeout time.Duration
	rDeadline time.Time
}

func NewDatagramBufferedPipe() *datagramBufferedPipe {
	d := &datagramBufferedPipe{
		rwCond: sync.NewCond(&sync.Mutex{}),
	}
	return d
}

func (d *datagramBufferedPipe) Read(target []byte) (int, error) {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()
	if d.buf == nil {
		d.buf = new(bytes.Buffer)
	}
	for {
		if d.closed && len(d.pLens) == 0 {
			return 0, io.EOF
		}

		if !d.rDeadline.IsZero() {
			delta := time.Until(d.rDeadline)
			if delta <= 0 {
				return 0, ErrTimeout
			}
			time.AfterFunc(delta, d.rwCond.Broadcast)
		}

		if len(d.pLens) > 0 {
			break
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

func (d *datagramBufferedPipe) WriteTo(w io.Writer) (n int64, err error) {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()
	if d.buf == nil {
		d.buf = new(bytes.Buffer)
	}
	for {
		if d.closed && len(d.pLens) == 0 {
			return 0, io.EOF
		}
		if !d.rDeadline.IsZero() {
			delta := time.Until(d.rDeadline)
			if delta <= 0 {
				return 0, ErrTimeout
			}
			if d.wtTimeout == 0 {
				// if there hasn't been a scheduled broadcast
				time.AfterFunc(delta, d.rwCond.Broadcast)
			}
		}
		if d.wtTimeout != 0 {
			d.rDeadline = time.Now().Add(d.wtTimeout)
			time.AfterFunc(d.wtTimeout, d.rwCond.Broadcast)
		}

		if len(d.pLens) > 0 {
			var dataLen int
			dataLen, d.pLens = d.pLens[0], d.pLens[1:]
			written, er := w.Write(d.buf.Next(dataLen))
			n += int64(written)
			if er != nil {
				d.rwCond.Broadcast()
				return n, er
			}
			d.rwCond.Broadcast()
		} else {
			d.rwCond.Wait()
		}
	}
}

func (d *datagramBufferedPipe) Write(f Frame) (toBeClosed bool, err error) {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()
	if d.buf == nil {
		d.buf = new(bytes.Buffer)
	}
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

	if f.Closing != C_NOOP {
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

func (d *datagramBufferedPipe) SetWriteToTimeout(t time.Duration) {
	d.rwCond.L.Lock()
	defer d.rwCond.L.Unlock()

	d.wtTimeout = t
	d.rwCond.Broadcast()
}
