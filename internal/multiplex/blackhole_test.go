package multiplex

import (
	"bufio"
	"io"
	"io/ioutil"
	"net"
	"time"
)

type blackhole struct {
	hole   *bufio.Writer
	closer chan int
}

func newBlackHole() *blackhole {
	return &blackhole{
		hole:   bufio.NewWriter(ioutil.Discard),
		closer: make(chan int),
	}
}
func (b *blackhole) Read([]byte) (int, error) {
	<-b.closer
	return 0, io.EOF
}
func (b *blackhole) Write(in []byte) (int, error) { return b.hole.Write(in) }
func (b *blackhole) Close() error {
	b.closer <- 1
	return nil
}
func (b *blackhole) LocalAddr() net.Addr {
	ret, _ := net.ResolveTCPAddr("tcp", "127.0.0.1")
	return ret
}
func (b *blackhole) RemoteAddr() net.Addr {
	ret, _ := net.ResolveTCPAddr("tcp", "127.0.0.1")
	return ret
}
func (b *blackhole) SetDeadline(t time.Time) error      { return nil }
func (b *blackhole) SetReadDeadline(t time.Time) error  { return nil }
func (b *blackhole) SetWriteDeadline(t time.Time) error { return nil }
