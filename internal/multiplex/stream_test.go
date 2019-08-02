package multiplex

import (
	"bufio"
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
