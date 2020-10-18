package multiplex

import (
	"bytes"
	"github.com/cbeuw/Cloak/internal/common"
	"io"
	"io/ioutil"
	"math/rand"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
)

const payloadLen = 1000

var emptyKey [32]byte

func setupSesh(unordered bool, key [32]byte, encryptionMethod byte) *Session {
	obfuscator, _ := MakeObfuscator(encryptionMethod, key)

	seshConfig := SessionConfig{
		Obfuscator: obfuscator,
		Valve:      nil,
		Unordered:  unordered,
	}
	return MakeSession(0, seshConfig)
}

func BenchmarkStream_Write_Ordered(b *testing.B) {
	hole := connutil.Discard()
	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	const testDataLen = 65536
	testData := make([]byte, testDataLen)
	rand.Read(testData)
	eMethods := map[string]byte{
		"plain":             E_METHOD_PLAIN,
		"chacha20-poly1305": E_METHOD_CHACHA20_POLY1305,
		"aes-gcm":           E_METHOD_AES_GCM,
	}

	for name, method := range eMethods {
		b.Run(name, func(b *testing.B) {
			sesh := setupSesh(false, sessionKey, method)
			sesh.AddConnection(hole)
			stream, _ := sesh.OpenStream()
			b.SetBytes(testDataLen)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stream.Write(testData)
			}
		})
	}
}

/*
func BenchmarkStream_Read_Ordered(b *testing.B) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	sesh := setupSesh(false, sessionKey)
	testPayload := make([]byte, payloadLen)
	rand.Read(testPayload)

	f := &Frame{
		1,
		0,
		0,
		testPayload,
	}

	obfsBuf := make([]byte, 17000)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		// potentially bottlenecked here rather than the actual stream read throughput
		conn, _ := net.Dial("tcp", l.Addr().String())
		for {
			i, _ := sesh.Obfs(f, obfsBuf)
			f.Seq += 1
			_, err := conn.Write(obfsBuf[:i])
			if err != nil {
				b.Error("cannot write to connection", err)
			}
		}
	}()
	conn, _ := l.Accept()

	sesh.AddConnection(conn)
	stream, err := sesh.Accept()
	if err != nil {
		b.Error("failed to accept stream", err)
	}

	//time.Sleep(5*time.Second) // wait for buffer to fill up

	readBuf := make([]byte, payloadLen)
	b.SetBytes(payloadLen)
	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		stream.Read(readBuf)
	}

}

*/

func TestStream_Write(t *testing.T) {
	hole := connutil.Discard()
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	sesh := setupSesh(false, sessionKey, E_METHOD_PLAIN)
	sesh.AddConnection(hole)
	testData := make([]byte, payloadLen)
	rand.Read(testData)

	stream, _ := sesh.OpenStream()
	_, err := stream.Write(testData)
	if err != nil {
		t.Error(
			"For", "stream write",
			"got", err,
		)
	}
}

func TestStream_WriteSync(t *testing.T) {
	// Close calls made after write MUST have a higher seq
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	clientSesh := setupSesh(false, sessionKey, E_METHOD_PLAIN)
	serverSesh := setupSesh(false, sessionKey, E_METHOD_PLAIN)
	w, r := connutil.AsyncPipe()
	clientSesh.AddConnection(common.NewTLSConn(w))
	serverSesh.AddConnection(common.NewTLSConn(r))
	testData := make([]byte, payloadLen)
	rand.Read(testData)

	t.Run("test single", func(t *testing.T) {
		go func() {
			stream, _ := clientSesh.OpenStream()
			stream.Write(testData)
			stream.Close()
		}()

		recvBuf := make([]byte, payloadLen)
		serverStream, _ := serverSesh.Accept()
		_, err := io.ReadFull(serverStream, recvBuf)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("test multiple", func(t *testing.T) {
		const numStreams = 100
		for i := 0; i < numStreams; i++ {
			go func() {
				stream, _ := clientSesh.OpenStream()
				stream.Write(testData)
				stream.Close()
			}()
		}
		for i := 0; i < numStreams; i++ {
			recvBuf := make([]byte, payloadLen)
			serverStream, _ := serverSesh.Accept()
			_, err := io.ReadFull(serverStream, recvBuf)
			if err != nil {
				t.Error(err)
			}
		}
	})
}

func TestStream_Close(t *testing.T) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	testPayload := []byte{42, 42, 42}

	dataFrame := &Frame{
		1,
		0,
		0,
		testPayload,
	}

	t.Run("active closing", func(t *testing.T) {
		sesh := setupSesh(false, sessionKey, E_METHOD_PLAIN)
		rawConn, rawWritingEnd := connutil.AsyncPipe()
		sesh.AddConnection(common.NewTLSConn(rawConn))
		writingEnd := common.NewTLSConn(rawWritingEnd)

		obfsBuf := make([]byte, 512)
		i, _ := sesh.Obfs(dataFrame, obfsBuf, 0)
		_, err := writingEnd.Write(obfsBuf[:i])
		if err != nil {
			t.Error("failed to write from remote end")
		}
		stream, err := sesh.Accept()
		if err != nil {
			t.Error("failed to accept stream", err)
			return
		}
		err = stream.Close()
		if err != nil {
			t.Error("failed to actively close stream", err)
			return
		}

		if sI, _ := sesh.streams.Load(stream.(*Stream).id); sI != nil {
			t.Error("stream still exists")
			return
		}

		readBuf := make([]byte, len(testPayload))
		_, err = io.ReadFull(stream, readBuf)
		if err != nil {
			t.Errorf("can't read residual data %v", err)
		}
		if !bytes.Equal(readBuf, testPayload) {
			t.Errorf("read wrong data")
		}
	})

	t.Run("passive closing", func(t *testing.T) {
		sesh := setupSesh(false, sessionKey, E_METHOD_PLAIN)
		rawConn, rawWritingEnd := connutil.AsyncPipe()
		sesh.AddConnection(common.NewTLSConn(rawConn))
		writingEnd := common.NewTLSConn(rawWritingEnd)

		obfsBuf := make([]byte, 512)
		i, err := sesh.Obfs(dataFrame, obfsBuf, 0)
		if err != nil {
			t.Errorf("failed to obfuscate frame %v", err)
		}
		_, err = writingEnd.Write(obfsBuf[:i])
		if err != nil {
			t.Error("failed to write from remote end")
		}

		stream, err := sesh.Accept()
		if err != nil {
			t.Error("failed to accept stream", err)
			return
		}

		closingFrame := &Frame{
			1,
			dataFrame.Seq + 1,
			C_STREAM,
			testPayload,
		}

		i, err = sesh.Obfs(closingFrame, obfsBuf, 0)
		if err != nil {
			t.Errorf("failed to obfuscate frame %v", err)
		}
		_, err = writingEnd.Write(obfsBuf[:i])
		if err != nil {
			t.Errorf("failed to write from remote end %v", err)
		}

		closingFrameDup := &Frame{
			1,
			dataFrame.Seq + 2,
			C_STREAM,
			testPayload,
		}

		i, err = sesh.Obfs(closingFrameDup, obfsBuf, 0)
		if err != nil {
			t.Errorf("failed to obfuscate frame %v", err)
		}
		_, err = writingEnd.Write(obfsBuf[:i])
		if err != nil {
			t.Errorf("failed to write from remote end %v", err)
		}

		readBuf := make([]byte, len(testPayload))
		_, err = io.ReadFull(stream, readBuf)
		if err != nil {
			t.Errorf("can't read residual data %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		if sI, _ := sesh.streams.Load(stream.(*Stream).id); sI != nil {
			t.Error("stream still exists")
			return
		}

	})
}

func TestStream_Read(t *testing.T) {
	seshes := map[string]bool{
		"ordered":   false,
		"unordered": true,
	}
	testPayload := []byte{42, 42, 42}
	const smallPayloadLen = 3

	f := &Frame{
		1,
		0,
		0,
		testPayload,
	}

	var streamID uint32
	buf := make([]byte, 10)

	obfsBuf := make([]byte, 512)

	for name, unordered := range seshes {
		sesh := setupSesh(unordered, emptyKey, E_METHOD_PLAIN)
		rawConn, rawWritingEnd := connutil.AsyncPipe()
		sesh.AddConnection(common.NewTLSConn(rawConn))
		writingEnd := common.NewTLSConn(rawWritingEnd)
		t.Run(name, func(t *testing.T) {
			t.Run("Plain read", func(t *testing.T) {
				f.StreamID = streamID
				i, _ := sesh.Obfs(f, obfsBuf, 0)
				streamID++
				writingEnd.Write(obfsBuf[:i])
				stream, err := sesh.Accept()
				if err != nil {
					t.Error("failed to accept stream", err)
					return
				}
				i, err = stream.Read(buf)
				if err != nil {
					t.Error("failed to read", err)
					return
				}
				if i != smallPayloadLen {
					t.Errorf("expected read %v, got %v", smallPayloadLen, i)
					return
				}
				if !bytes.Equal(buf[:i], testPayload) {
					t.Error("expected", testPayload,
						"got", buf[:i])
					return
				}
			})
			t.Run("Nil buf", func(t *testing.T) {
				f.StreamID = streamID
				i, _ := sesh.Obfs(f, obfsBuf, 0)
				streamID++
				writingEnd.Write(obfsBuf[:i])
				stream, _ := sesh.Accept()
				i, err := stream.Read(nil)
				if i != 0 || err != nil {
					t.Error("expecting", 0, nil,
						"got", i, err)
				}
			})
			t.Run("Read after stream close", func(t *testing.T) {
				f.StreamID = streamID
				i, _ := sesh.Obfs(f, obfsBuf, 0)
				streamID++
				writingEnd.Write(obfsBuf[:i])
				stream, _ := sesh.Accept()
				stream.Close()
				i, err := stream.Read(buf)
				if err != nil {
					t.Error("failed to read", err)
				}
				if i != smallPayloadLen {
					t.Errorf("expected read %v, got %v", smallPayloadLen, i)
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
				i, _ := sesh.Obfs(f, obfsBuf, 0)
				streamID++
				writingEnd.Write(obfsBuf[:i])
				stream, _ := sesh.Accept()
				sesh.Close()
				i, err := stream.Read(buf)
				if err != nil {
					t.Error("failed to read", err)
				}
				if i != smallPayloadLen {
					t.Errorf("expected read %v, got %v", smallPayloadLen, i)
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
		})
	}
}

func TestStream_SetWriteToTimeout(t *testing.T) {
	seshes := map[string]*Session{
		"ordered":   setupSesh(false, emptyKey, E_METHOD_PLAIN),
		"unordered": setupSesh(true, emptyKey, E_METHOD_PLAIN),
	}
	for name, sesh := range seshes {
		t.Run(name, func(t *testing.T) {
			stream, _ := sesh.OpenStream()
			stream.SetWriteToTimeout(100 * time.Millisecond)
			done := make(chan struct{})
			go func() {
				stream.WriteTo(ioutil.Discard)
				done <- struct{}{}
			}()

			select {
			case <-done:
				return
			case <-time.After(500 * time.Millisecond):
				t.Error("didn't timeout")
			}
		})
	}
}

func TestStream_SetReadFromTimeout(t *testing.T) {
	seshes := map[string]*Session{
		"ordered":   setupSesh(false, emptyKey, E_METHOD_PLAIN),
		"unordered": setupSesh(true, emptyKey, E_METHOD_PLAIN),
	}
	for name, sesh := range seshes {
		t.Run(name, func(t *testing.T) {
			stream, _ := sesh.OpenStream()
			stream.SetReadFromTimeout(100 * time.Millisecond)
			done := make(chan struct{})
			go func() {
				stream.ReadFrom(connutil.Discard())
				done <- struct{}{}
			}()
			select {
			case <-done:
				return
			case <-time.After(500 * time.Millisecond):
				t.Error("didn't timeout")
			}
		})
	}
}
