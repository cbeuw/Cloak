// This is base on https://github.com/golang/go/blob/0436b162397018c45068b47ca1b5924a3eafdee0/src/net/net_fake.go#L173

package multiplex

import (
	"bytes"
	"io"
	"sync"
	"time"
)

// The point of a streamBufferedPipe is that Read() will block until data is available
type streamBufferedPipe struct {
	// only alloc when on first Read or Write
	buf *bytes.Buffer

	closed    bool
	rwCond    *sync.Cond
	rDeadline time.Time
	wtTimeout time.Duration

	timeoutTimer *time.Timer
}

func NewStreamBufferedPipe() *streamBufferedPipe {
	p := &streamBufferedPipe{
		rwCond: sync.NewCond(&sync.Mutex{}),
	}
	return p
}

func (p *streamBufferedPipe) Read(target []byte) (int, error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	if p.buf == nil {
		p.buf = new(bytes.Buffer)
	}
	for {
		if p.closed && p.buf.Len() == 0 {
			return 0, io.EOF
		}

		hasRDeadline := !p.rDeadline.IsZero()
		if hasRDeadline {
			if time.Until(p.rDeadline) <= 0 {
				return 0, ErrTimeout
			}
		}
		if p.buf.Len() > 0 {
			break
		}

		if hasRDeadline {
			p.broadcastAfter(time.Until(p.rDeadline))
		}
		p.rwCond.Wait()
	}
	n, err := p.buf.Read(target)
	// err will always be nil because we have already verified that buf.Len() != 0
	p.rwCond.Broadcast()
	return n, err
}

func (p *streamBufferedPipe) WriteTo(w io.Writer) (n int64, err error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	if p.buf == nil {
		p.buf = new(bytes.Buffer)
	}
	for {
		if p.closed && p.buf.Len() == 0 {
			return 0, io.EOF
		}

		hasRDeadline := !p.rDeadline.IsZero()
		if hasRDeadline {
			if time.Until(p.rDeadline) <= 0 {
				return 0, ErrTimeout
			}
		}
		if p.buf.Len() > 0 {
			written, er := p.buf.WriteTo(w)
			n += written
			if er != nil {
				p.rwCond.Broadcast()
				return n, er
			}
			p.rwCond.Broadcast()
		} else {
			if p.wtTimeout == 0 {
				if hasRDeadline {
					p.broadcastAfter(time.Until(p.rDeadline))
				}
			} else {
				p.rDeadline = time.Now().Add(p.wtTimeout)
				p.broadcastAfter(p.wtTimeout)
			}

			p.rwCond.Wait()
		}
	}
}

func (p *streamBufferedPipe) Write(input []byte) (int, error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	if p.buf == nil {
		p.buf = new(bytes.Buffer)
	}
	for {
		if p.closed {
			return 0, io.ErrClosedPipe
		}
		if p.buf.Len() <= recvBufferSizeLimit {
			// if p.buf gets too large, write() will panic. We don't want this to happen
			break
		}
		p.rwCond.Wait()
	}
	n, err := p.buf.Write(input)
	// err will always be nil
	p.rwCond.Broadcast()
	return n, err
}

func (p *streamBufferedPipe) Close() error {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()

	p.closed = true
	p.rwCond.Broadcast()
	return nil
}

func (p *streamBufferedPipe) SetReadDeadline(t time.Time) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()

	p.rDeadline = t
	p.rwCond.Broadcast()
}

func (p *streamBufferedPipe) SetWriteToTimeout(d time.Duration) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()

	p.wtTimeout = d
	p.rwCond.Broadcast()
}

func (p *streamBufferedPipe) broadcastAfter(d time.Duration) {
	if p.timeoutTimer != nil {
		p.timeoutTimer.Stop()
	}
	p.timeoutTimer = time.AfterFunc(d, p.rwCond.Broadcast)
}
