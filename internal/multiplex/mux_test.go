package multiplex

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/connutil"
	"github.com/stretchr/testify/assert"
)

func serveEcho(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			// TODO: pass the error back
			return
		}
		go func(conn net.Conn) {
			_, err := io.Copy(conn, conn)
			if err != nil {
				// TODO: pass the error back
				return
			}
		}(conn)
	}
}

type connPair struct {
	clientConn net.Conn
	serverConn net.Conn
}

func makeSessionPair(numConn int) (*Session, *Session, []*connPair) {
	sessionKey := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	sessionId := 1
	obfuscator, _ := MakeObfuscator(EncryptionMethodChaha20Poly1305, sessionKey)
	clientConfig := SessionConfig{
		Obfuscator: obfuscator,
		Valve:      nil,
		Unordered:  false,
	}
	serverConfig := clientConfig

	clientSession := MakeSession(uint32(sessionId), clientConfig)
	serverSession := MakeSession(uint32(sessionId), serverConfig)

	paris := make([]*connPair, numConn)
	for i := 0; i < numConn; i++ {
		c, s := connutil.AsyncPipe()
		clientConn := common.NewTLSConn(c)
		serverConn := common.NewTLSConn(s)
		paris[i] = &connPair{
			clientConn: clientConn,
			serverConn: serverConn,
		}
		clientSession.AddConnection(clientConn)
		serverSession.AddConnection(serverConn)
	}
	return clientSession, serverSession, paris
}

func runEchoTest(t *testing.T, conns []net.Conn, msgLen int) {
	var wg sync.WaitGroup

	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()

			testData := make([]byte, msgLen)
			rand.Read(testData)

			// we cannot call t.Fatalf in concurrent contexts
			n, err := conn.Write(testData)
			if n != msgLen {
				t.Errorf("written only %v, err %v", n, err)
				return
			}

			recvBuf := make([]byte, msgLen)
			_, err = io.ReadFull(conn, recvBuf)
			if err != nil {
				t.Errorf("failed to read back: %v", err)
				return
			}

			if !bytes.Equal(testData, recvBuf) {
				t.Errorf("echoed data not correct")
				return
			}
		}(conn)
	}
	wg.Wait()
}

func TestMultiplex(t *testing.T) {
	const numStreams = 2000 // -race option limits the number of goroutines to 8192
	const numConns = 4
	const msgLen = 16384

	clientSession, serverSession, _ := makeSessionPair(numConns)
	go serveEcho(serverSession)

	streams := make([]net.Conn, numStreams)
	for i := 0; i < numStreams; i++ {
		stream, err := clientSession.OpenStream()
		assert.NoError(t, err)
		streams[i] = stream
	}

	//test echo
	runEchoTest(t, streams, msgLen)

	assert.EqualValues(t, numStreams, clientSession.streamCount(), "client stream count is wrong")
	assert.EqualValues(t, numStreams, serverSession.streamCount(), "server stream count is wrong")

	// close one stream
	closing, streams := streams[0], streams[1:]
	err := closing.Close()
	assert.NoError(t, err, "couldn't close a stream")
	_, err = closing.Write([]byte{0})
	assert.Equal(t, ErrBrokenStream, err)
	_, err = closing.Read(make([]byte, 1))
	assert.Equal(t, ErrBrokenStream, err)
}

func TestMux_StreamClosing(t *testing.T) {
	clientSession, serverSession, _ := makeSessionPair(1)
	go serveEcho(serverSession)

	// read after closing stream
	testData := make([]byte, 128)
	recvBuf := make([]byte, 128)
	toBeClosed, _ := clientSession.OpenStream()
	_, err := toBeClosed.Write(testData) // should be echoed back
	assert.NoError(t, err, "couldn't write to a stream")

	_, err = io.ReadFull(toBeClosed, recvBuf[:1])
	assert.NoError(t, err, "can't read anything before stream closed")

	_ = toBeClosed.Close()
	_, err = io.ReadFull(toBeClosed, recvBuf[1:])
	assert.NoError(t, err, "can't read residual data on stream")
	assert.Equal(t, testData, recvBuf, "incorrect data read back")
}
