// This is base on https://github.com/golang/go/blob/0436b162397018c45068b47ca1b5924a3eafdee0/src/net/net_fake.go#L173

package multiplex

import (
	"bytes"
	"io"
	"sync"
)

const BUF_SIZE_LIMIT = 1 << 20 * 500

type bufferedPipe struct {
	buf    *bytes.Buffer
	closed bool
	rwCond *sync.Cond
}

func NewBufferedPipe() *bufferedPipe {
	p := &bufferedPipe{
		buf:    new(bytes.Buffer),
		rwCond: sync.NewCond(&sync.Mutex{}),
	}
	return p
}

func (p *bufferedPipe) Read(target []byte) (int, error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	for {
		if p.closed && p.buf.Len() == 0 {
			return 0, io.EOF
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

func (p *bufferedPipe) Write(input []byte) (int, error) {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
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

func (p *bufferedPipe) Len() int {
	p.rwCond.L.Lock()
	defer p.rwCond.L.Unlock()
	return p.buf.Len()
}
