package multiplex

import (
	"bufio"
	"github.com/cbeuw/Cloak/internal/util"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"
	"time"
)

func setupSesh() *Session {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	obfuscator, _ := util.GenerateObfs(0x00, sessionKey)
	return MakeSession(0, UNLIMITED_VALVE, obfuscator, util.ReadTLS)
}

type blackhole struct {
	hole *bufio.Writer
}

func newBlackHole() *blackhole { return &blackhole{hole: bufio.NewWriter(ioutil.Discard)} }
func (b *blackhole) Read([]byte) (int, error) {
	time.Sleep(1 * time.Hour)
	return 0, nil
}
func (b *blackhole) Write(in []byte) (int, error) { return b.hole.Write(in) }
func (b *blackhole) Close() error                 { return nil }
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

const PAYLOAD_LEN = 1 << 20 * 100

func BenchmarkStream_Write(b *testing.B) {
	hole := newBlackHole()
	sesh := setupSesh()
	sesh.AddConnection(hole)
	testData := make([]byte, PAYLOAD_LEN)
	rand.Read(testData)

	stream, _ := sesh.OpenStream()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := stream.Write(testData)
		if err != nil {
			b.Error(
				"For", "stream write",
				"got", err,
			)
		}
		b.SetBytes(PAYLOAD_LEN)
	}
}
