package multiplex

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"strconv"
	"testing"
	"time"
)

// ReadTLS reads TLS data according to its record layer
func ReadTLS(conn net.Conn, buffer []byte) (n int, err error) {
	// TCP is a stream. Multiple TLS messages can arrive at the same time,
	// a single message can also be segmented due to MTU of the IP layer.
	// This function guareentees a single TLS message to be read and everything
	// else is left in the buffer.
	i, err := io.ReadFull(conn, buffer[:5])
	if err != nil {
		return
	}

	dataLength := int(binary.BigEndian.Uint16(buffer[3:5]))
	if dataLength > len(buffer) {
		err = errors.New("Reading TLS message: message size greater than buffer. message size: " + strconv.Itoa(dataLength))
		return
	}
	left := dataLength
	readPtr := 5

	for left != 0 {
		// If left > buffer size (i.e. our message got segmented), the entire MTU is read
		// if left = buffer size, the entire buffer is all there left to read
		// if left < buffer size (i.e. multiple messages came together),
		// only the message we want is read
		i, err = io.ReadFull(conn, buffer[readPtr:readPtr+left])
		if err != nil {
			return
		}
		left -= i
		readPtr += i
	}

	n = 5 + dataLength
	return
}

func GenerateObfs(encryptionMethod byte, sessionKey []byte) (obfuscator *Obfuscator, err error) {
	var payloadCipher cipher.AEAD
	switch encryptionMethod {
	case 0x00:
		payloadCipher = nil
	case 0x01:
		var c cipher.Block
		c, err = aes.NewCipher(sessionKey)
		if err != nil {
			return
		}
		payloadCipher, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
	case 0x02:
		payloadCipher, err = chacha20poly1305.New(sessionKey)
		if err != nil {
			return
		}
	default:
		return nil, errors.New("Unknown encryption method")
	}

	headerCipher, err := aes.NewCipher(sessionKey)
	if err != nil {
		return
	}

	obfuscator = &Obfuscator{
		MakeObfs(headerCipher, payloadCipher),
		MakeDeobfs(headerCipher, payloadCipher),
		sessionKey,
	}
	return
}

func setupSesh() *Session {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	obfuscator, _ := GenerateObfs(0x00, sessionKey)
	return MakeSession(0, UNLIMITED_VALVE, obfuscator, ReadTLS)
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

func BenchmarkStream_Write(b *testing.B) {
	const PAYLOAD_LEN = 1 << 20 * 100
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

func TestStream_Read(t *testing.T) {
	sesh := setupSesh()
	testPayload := []byte{42, 42, 42}
	const PAYLOAD_LEN = 3

	f := &Frame{
		1,
		0,
		0,
		testPayload,
	}

	ch := make(chan []byte)
	l, _ := net.Listen("tcp", ":0")
	go func() {
		conn, _ := net.Dial("tcp", l.Addr().String())
		for {
			data := <-ch
			_, err := conn.Write(data)
			if err != nil {
				t.Error("cannot write to connection", err)
			}
		}
	}()
	conn, _ := l.Accept()
	sesh.AddConnection(conn)

	var streamID uint32
	buf := make([]byte, 10)
	t.Run("Plain read", func(t *testing.T) {
		f.StreamID = streamID
		obfsed, _ := sesh.Obfs(f)
		streamID++
		ch <- obfsed
		stream, err := sesh.Accept()
		if err != nil {
			t.Error("failed to accept stream", err)
		}
		i, err := stream.Read(buf)
		if err != nil {
			t.Error("failed to read", err)
		}
		if i != PAYLOAD_LEN {
			t.Errorf("expected read %v, got %v", PAYLOAD_LEN, i)
		}
		if !bytes.Equal(buf[:i], testPayload) {
			t.Error("expected", testPayload,
				"got", buf[:i])
		}
	})
	t.Run("Nil buf", func(t *testing.T) {
		f.StreamID = streamID
		obfsed, _ := sesh.Obfs(f)
		streamID++
		ch <- obfsed
		stream, _ := sesh.Accept()
		i, err := stream.Read(nil)
		if i != 0 || err != nil {
			t.Error("expecting", 0, nil,
				"got", i, err)
		}

		stream.Close()
		i, err = stream.Read(nil)
		if i != 0 || err != ErrBrokenStream {
			t.Error("expecting", 0, ErrBrokenStream,
				"got", i, err)
		}

	})
	t.Run("Read after stream close", func(t *testing.T) {
		f.StreamID = streamID
		obfsed, _ := sesh.Obfs(f)
		streamID++
		ch <- obfsed
		stream, _ := sesh.Accept()
		stream.Close()
		i, err := stream.Read(buf)
		if err != nil {
			t.Error("failed to read", err)
		}
		if i != PAYLOAD_LEN {
			t.Errorf("expected read %v, got %v", PAYLOAD_LEN, i)
		}
		if !bytes.Equal(buf[:i], testPayload) {
			t.Error("expected", testPayload,
				"got", buf[:i])
		}
		_, err = stream.Read(buf)
		if err == nil {
			t.Error("expecting error", ErrBrokenStream,
				"got nil error")
		}
	})
	t.Run("Read after session close", func(t *testing.T) {
		f.StreamID = streamID
		obfsed, _ := sesh.Obfs(f)
		streamID++
		ch <- obfsed
		stream, _ := sesh.Accept()
		sesh.Close()
		i, err := stream.Read(buf)
		if err != nil {
			t.Error("failed to read", err)
		}
		if i != PAYLOAD_LEN {
			t.Errorf("expected read %v, got %v", PAYLOAD_LEN, i)
		}
		if !bytes.Equal(buf[:i], testPayload) {
			t.Error("expected", testPayload,
				"got", buf[:i])
		}
		_, err = stream.Read(buf)
		if err == nil {
			t.Error("expecting error", ErrBrokenStream,
				"got nil error")
		}
	})

}
