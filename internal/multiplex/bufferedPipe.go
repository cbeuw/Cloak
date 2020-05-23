// This is base on https://github.com/golang/go/blob/0436b162397018c45068b47ca1b5924a3eafdee0/src/net/net_fake.go#L173

package multiplex

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"
)

const BUF_SIZE_LIMIT = 1 << 20 * 500

var ErrTimeout = errors.New("deadline exceeded")

// The point of a bufferedPipe is that Read() will block until data is available
type bufferedPipe struct {
	// only alloc when on first Read or Write
	buf *bytes.Buffer

	closed    bool
	rwCond    *sync.Cond
	rDeadline time.Time
	wtTimeout time.Duration
}

func NewBufferedPipe() *bufferedPipe {
	p := &bufferedPipe{
		rwCond: sync.NewCond(&sync.Mutex{}),
	}
	return p
}

func (p *bufferedPipe) Read(target []byte) (int, error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	if p.buf == nil {
		p.buf = new(bytes.Buffer)
	}
	for {
		if p.closed && p.buf.Len() == 0 {
			return 0, io.EOF
		}
		if !p.rDeadline.IsZero() {
			d := time.Until(p.rDeadline)
			if d <= 0 {
				return 0, ErrTimeout
			}
			time.AfterFunc(d, p.rwCond.Broadcast)
		}
		if p.buf.Len() > 0 {
			break
		}
		p.rwCond.Wait()
	}
	n, err := p.buf.Read(target)
	// err will always be nil because we have already verified that buf.Len() != 0
	p.rwCond.Broadcast()
	return n, err
}

func (p *bufferedPipe) WriteTo(w io.Writer) (n int64, err error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	if p.buf == nil {
		p.buf = new(bytes.Buffer)
	}
	for {
		if p.closed && p.buf.Len() == 0 {
			return 0, io.EOF
		}
		if !p.rDeadline.IsZero() {
			d := time.Until(p.rDeadline)
			if d <= 0 {
				return 0, ErrTimeout
			}
			if p.wtTimeout == 0 {
				// if there hasn't been a scheduled broadcast
				time.AfterFunc(d, p.rwCond.Broadcast)
			}
		}
		if p.wtTimeout != 0 {
			p.rDeadline = time.Now().Add(p.wtTimeout)
			time.AfterFunc(p.wtTimeout, p.rwCond.Broadcast)
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
			p.rwCond.Wait()
		}
	}
}

func (p *bufferedPipe) Write(input []byte) (int, error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	if p.buf == nil {
		p.buf = new(bytes.Buffer)
	}
	for {
		if p.closed {
			return 0, io.ErrClosedPipe
		}
		if p.buf.Len() <= BUF_SIZE_LIMIT {
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

func (p *bufferedPipe) Close() error {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()

	p.closed = true
	p.rwCond.Broadcast()
	return nil
}

func (p *bufferedPipe) SetReadDeadline(t time.Time) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()

	p.rDeadline = t
	p.rwCond.Broadcast()
}

func (p *bufferedPipe) SetWriteToTimeout(d time.Duration) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()

	p.wtTimeout = d
	p.rwCond.Broadcast()
}
