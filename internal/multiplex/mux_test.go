package multiplex

import (
	"bytes"
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/connutil"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func serveEcho(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			// TODO: pass the error back
			return
		}
		go func() {
			_, err := io.Copy(conn, conn)
			if err != nil {
				// TODO: pass the error back
				return
			}
		}()
	}
}

type connPair struct {
	clientConn net.Conn
	serverConn net.Conn
}

func makeSessionPair(numConn int) (*Session, *Session, []*connPair) {
	sessionKey := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	sessionId := 1
	obfuscator, _ := MakeObfuscator(E_METHOD_CHACHA20_POLY1305, sessionKey)
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

func runEchoTest(t *testing.T, streams []*Stream) {
	const testDataLen = 16384
	var wg sync.WaitGroup
	for _, stream := range streams {
		wg.Add(1)
		go func(stream *Stream) {
			testData := make([]byte, testDataLen)
			rand.Read(testData)

			n, err := stream.Write(testData)
			if n != testDataLen {
				t.Fatalf("written only %v, err %v", n, err)
			}

			recvBuf := make([]byte, testDataLen)
			_, err = io.ReadFull(stream, recvBuf)
			if err != nil {
				t.Fatalf("failed to read back: %v", err)
			}

			if !bytes.Equal(testData, recvBuf) {
				t.Fatalf("echoed data not correct")
			}
			wg.Done()
		}(stream)
	}
	wg.Wait()
}

func TestMultiplex(t *testing.T) {
	const numStreams = 2000 // -race option limits the number of goroutines to 8192
	const numConns = 4

	clientSession, serverSession, _ := makeSessionPair(numConns)
	go serveEcho(serverSession)

	streams := make([]*Stream, numStreams)
	for i := 0; i < numStreams; i++ {
		stream, err := clientSession.OpenStream()
		if err != nil {
			t.Fatalf("failed to open stream: %v", err)
		}
		streams[i] = stream
	}

	//test echo
	runEchoTest(t, streams)
	if clientSession.streamCount() != numStreams {
		t.Errorf("client stream count is wrong: %v", clientSession.streamCount())
	}
	if serverSession.streamCount() != numStreams {
		t.Errorf("server stream count is wrong: %v", serverSession.streamCount())
	}

	// close one stream
	closing, streams := streams[0], streams[1:]
	err := closing.Close()
	if err != nil {
		t.Errorf("couldn't close a stream")
	}
	_, err = closing.Write([]byte{0})
	if err != ErrBrokenStream {
		t.Errorf("expecting error %v, got %v", ErrBrokenStream, err)
	}
	_, err = closing.Read(make([]byte, 1))
	if err != ErrBrokenStream {
		t.Errorf("expecting error %v, got %v", ErrBrokenStream, err)
	}

}

func TestMux_StreamClosing(t *testing.T) {
	clientSession, serverSession, _ := makeSessionPair(1)
	go serveEcho(serverSession)

	// read after closing stream
	testData := make([]byte, 128)
	recvBuf := make([]byte, 128)
	toBeClosed, _ := clientSession.OpenStream()
	_, err := toBeClosed.Write(testData) // should be echoed back
	if err != nil {
		t.Errorf("can't write to stream: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	_ = toBeClosed.Close()
	_, err = io.ReadFull(toBeClosed, recvBuf)
	if err != nil {
		t.Errorf("can't read residual data on stream: %v", err)
	}
	if !bytes.Equal(testData, recvBuf) {
		t.Errorf("incorrect data read back")
	}
}
