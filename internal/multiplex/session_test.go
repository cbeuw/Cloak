package multiplex

import (
	"bytes"
	"github.com/cbeuw/connutil"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var seshConfigs = map[string]SessionConfig{
	"ordered":   {},
	"unordered": {Unordered: true},
}

const testPayloadLen = 1024
const obfsBufLen = testPayloadLen * 2

func TestRecvDataFromRemote(t *testing.T) {
	testPayload := make([]byte, testPayloadLen)
	rand.Read(testPayload)
	f := &Frame{
		1,
		0,
		0,
		testPayload,
	}
	obfsBuf := make([]byte, obfsBufLen)

	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	MakeObfuscatorUnwrap := func(method byte, sessionKey [32]byte) Obfuscator {
		ret, err := MakeObfuscator(method, sessionKey)
		if err != nil {
			t.Fatalf("failed to make an obfuscator: %v", err)
		}
		return ret
	}

	encryptionMethods := map[string]Obfuscator{
		"plain":             MakeObfuscatorUnwrap(EncryptionMethodPlain, sessionKey),
		"aes-gcm":           MakeObfuscatorUnwrap(EncryptionMethodAESGCM, sessionKey),
		"chacha20-poly1305": MakeObfuscatorUnwrap(EncryptionMethodChaha20Poly1305, sessionKey),
	}

	for seshType, seshConfig := range seshConfigs {
		seshConfig := seshConfig
		t.Run(seshType, func(t *testing.T) {
			for method, obfuscator := range encryptionMethods {
				obfuscator := obfuscator
				t.Run(method, func(t *testing.T) {
					seshConfig.Obfuscator = obfuscator
					sesh := MakeSession(0, seshConfig)
					n, err := sesh.Obfs(f, obfsBuf, 0)
					if err != nil {
						t.Error(err)
						return
					}
					err = sesh.recvDataFromRemote(obfsBuf[:n])
					if err != nil {
						t.Error(err)
						return
					}
					stream, err := sesh.Accept()
					if err != nil {
						t.Error(err)
						return
					}

					resultPayload := make([]byte, testPayloadLen)
					_, err = stream.Read(resultPayload)
					if err != nil {
						t.Error(err)
						return
					}
					if !bytes.Equal(testPayload, resultPayload) {
						t.Errorf("Expecting %x, got %x", testPayload, resultPayload)
					}
				})
			}
		})
	}
}

func TestRecvDataFromRemote_Closing_InOrder(t *testing.T) {
	testPayload := make([]byte, testPayloadLen)
	rand.Read(testPayload)
	obfsBuf := make([]byte, obfsBufLen)

	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	obfuscator, _ := MakeObfuscator(EncryptionMethodPlain, sessionKey)

	seshConfig := seshConfigs["ordered"]
	seshConfig.Obfuscator = obfuscator
	sesh := MakeSession(0, seshConfig)

	f1 := &Frame{
		1,
		0,
		closingNothing,
		testPayload,
	}
	// create stream 1
	n, _ := sesh.Obfs(f1, obfsBuf, 0)
	err := sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving normal frame for stream 1: %v", err)
	}
	sesh.streamsM.Lock()
	_, ok := sesh.streams[f1.StreamID]
	sesh.streamsM.Unlock()
	if !ok {
		t.Fatal("failed to fetch stream 1 after receiving it")
	}
	if sesh.streamCount() != 1 {
		t.Error("stream count isn't 1")
	}

	// create stream 2
	f2 := &Frame{
		2,
		0,
		closingNothing,
		testPayload,
	}
	n, _ = sesh.Obfs(f2, obfsBuf, 0)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving normal frame for stream 2: %v", err)
	}
	sesh.streamsM.Lock()
	s2M, ok := sesh.streams[f2.StreamID]
	sesh.streamsM.Unlock()
	if s2M == nil || !ok {
		t.Fatal("failed to fetch stream 2 after receiving it")
	}
	if sesh.streamCount() != 2 {
		t.Error("stream count isn't 2")
	}

	// close stream 1
	f1CloseStream := &Frame{
		1,
		1,
		closingStream,
		testPayload,
	}
	n, _ = sesh.Obfs(f1CloseStream, obfsBuf, 0)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving stream closing frame for stream 1: %v", err)
	}
	sesh.streamsM.Lock()
	s1M, _ := sesh.streams[f1.StreamID]
	sesh.streamsM.Unlock()
	if s1M != nil {
		t.Fatal("stream 1 still exist after receiving stream close")
	}
	s1, _ := sesh.Accept()
	if !s1.(*Stream).isClosed() {
		t.Fatal("stream 1 not marked as closed")
	}
	payloadBuf := make([]byte, testPayloadLen)
	_, err = s1.Read(payloadBuf)
	if err != nil || !bytes.Equal(payloadBuf, testPayload) {
		t.Fatalf("failed to read from stream 1 after closing: %v", err)
	}
	s2, _ := sesh.Accept()
	if s2.(*Stream).isClosed() {
		t.Fatal("stream 2 shouldn't be closed")
	}
	if sesh.streamCount() != 1 {
		t.Error("stream count isn't 1 after stream 1 closed")
	}

	// close stream 1 again
	n, _ = sesh.Obfs(f1CloseStream, obfsBuf, 0)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving stream closing frame for stream 1 %v", err)
	}
	sesh.streamsM.Lock()
	s1M, _ = sesh.streams[f1.StreamID]
	sesh.streamsM.Unlock()
	if s1M != nil {
		t.Error("stream 1 exists after receiving stream close for the second time")
	}
	streamCount := sesh.streamCount()
	if streamCount != 1 {
		t.Errorf("stream count is %v after stream 1 closed twice, expected 1", streamCount)
	}

	// close session
	fCloseSession := &Frame{
		StreamID: 0xffffffff,
		Seq:      0,
		Closing:  closingSession,
		Payload:  testPayload,
	}
	n, _ = sesh.Obfs(fCloseSession, obfsBuf, 0)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving session closing frame: %v", err)
	}
	if !sesh.IsClosed() {
		t.Error("session not closed after receiving signal")
	}
	if !s2.(*Stream).isClosed() {
		t.Error("stream 2 isn't closed after session closed")
	}
	if _, err := s2.Read(payloadBuf); err != nil || !bytes.Equal(payloadBuf, testPayload) {
		t.Error("failed to read from stream 2 after session closed")
	}
	if _, err := s2.Write(testPayload); err == nil {
		t.Error("can still write to stream 2 after session closed")
	}
	if sesh.streamCount() != 0 {
		t.Error("stream count isn't 0 after session closed")
	}
}

func TestRecvDataFromRemote_Closing_OutOfOrder(t *testing.T) {
	// Tests for when the closing frame of a stream is received first before any data frame
	testPayload := make([]byte, testPayloadLen)
	rand.Read(testPayload)
	obfsBuf := make([]byte, obfsBufLen)

	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	obfuscator, _ := MakeObfuscator(EncryptionMethodPlain, sessionKey)

	seshConfig := seshConfigs["ordered"]
	seshConfig.Obfuscator = obfuscator
	sesh := MakeSession(0, seshConfig)

	// receive stream 1 closing first
	f1CloseStream := &Frame{
		1,
		1,
		closingStream,
		testPayload,
	}
	n, _ := sesh.Obfs(f1CloseStream, obfsBuf, 0)
	err := sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving out of order stream closing frame for stream 1: %v", err)
	}
	sesh.streamsM.Lock()
	_, ok := sesh.streams[f1CloseStream.StreamID]
	sesh.streamsM.Unlock()
	if !ok {
		t.Fatal("stream 1 doesn't exist")
	}
	if sesh.streamCount() != 1 {
		t.Error("stream count isn't 1 after stream 1 received")
	}

	// receive data frame of stream 1 after receiving the closing frame
	f1 := &Frame{
		1,
		0,
		closingNothing,
		testPayload,
	}
	n, _ = sesh.Obfs(f1, obfsBuf, 0)
	err = sesh.recvDataFromRemote(obfsBuf[:n])
	if err != nil {
		t.Fatalf("receiving normal frame for stream 1: %v", err)
	}
	s1, err := sesh.Accept()
	if err != nil {
		t.Fatal("failed to accept stream 1 after receiving it")
	}
	payloadBuf := make([]byte, testPayloadLen)
	if _, err := s1.Read(payloadBuf); err != nil || !bytes.Equal(payloadBuf, testPayload) {
		t.Error("failed to read from steam 1")
	}
	if !s1.(*Stream).isClosed() {
		t.Error("s1 isn't closed")
	}
	if sesh.streamCount() != 0 {
		t.Error("stream count isn't 0 after stream 1 closed")
	}
}

func TestParallelStreams(t *testing.T) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	obfuscator, _ := MakeObfuscator(EncryptionMethodPlain, sessionKey)

	for seshType, seshConfig := range seshConfigs {
		seshConfig := seshConfig
		t.Run(seshType, func(t *testing.T) {
			seshConfig.Obfuscator = obfuscator
			sesh := MakeSession(0, seshConfig)

			numStreams := acceptBacklog
			seqs := make([]*uint64, numStreams)
			for i := range seqs {
				seqs[i] = new(uint64)
			}
			randFrame := func() *Frame {
				id := rand.Intn(numStreams)
				return &Frame{
					uint32(id),
					atomic.AddUint64(seqs[id], 1) - 1,
					uint8(rand.Intn(2)),
					[]byte{1, 2, 3, 4},
				}
			}

			const numOfTests = 5000
			tests := make([]struct {
				name  string
				frame *Frame
			}, numOfTests)
			for i := range tests {
				tests[i].name = strconv.Itoa(i)
				tests[i].frame = randFrame()
			}

			var wg sync.WaitGroup
			for _, tc := range tests {
				wg.Add(1)
				go func(frame *Frame) {
					obfsBuf := make([]byte, obfsBufLen)
					n, _ := sesh.Obfs(frame, obfsBuf, 0)
					obfsBuf = obfsBuf[0:n]

					err := sesh.recvDataFromRemote(obfsBuf)
					if err != nil {
						t.Error(err)
					}
					wg.Done()
				}(tc.frame)
			}

			wg.Wait()
			sc := int(sesh.streamCount())
			var count int
			sesh.streamsM.Lock()
			for _, s := range sesh.streams {
				if s != nil {
					count++
				}
			}
			sesh.streamsM.Unlock()
			if sc != count {
				t.Errorf("broken referential integrety: actual %v, reference count: %v", count, sc)
			}
		})
	}
}

func TestStream_SetReadDeadline(t *testing.T) {
	for seshType, seshConfig := range seshConfigs {
		seshConfig := seshConfig
		t.Run(seshType, func(t *testing.T) {
			sesh := MakeSession(0, seshConfig)
			sesh.AddConnection(connutil.Discard())

			t.Run("read after deadline set", func(t *testing.T) {
				stream, _ := sesh.OpenStream()
				_ = stream.SetReadDeadline(time.Now().Add(-1 * time.Second))
				_, err := stream.Read(make([]byte, 1))
				if err != ErrTimeout {
					t.Errorf("expecting error %v, got %v", ErrTimeout, err)
				}
			})

			t.Run("unblock when deadline passed", func(t *testing.T) {
				stream, _ := sesh.OpenStream()

				done := make(chan struct{})
				go func() {
					_, _ = stream.Read(make([]byte, 1))
					done <- struct{}{}
				}()

				_ = stream.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

				select {
				case <-done:
					return
				case <-time.After(500 * time.Millisecond):
					t.Error("Read did not unblock after deadline has passed")
				}
			})
		})
	}
}

func TestSession_timeoutAfter(t *testing.T) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])
	obfuscator, _ := MakeObfuscator(EncryptionMethodPlain, sessionKey)

	for seshType, seshConfig := range seshConfigs {
		seshConfig := seshConfig
		t.Run(seshType, func(t *testing.T) {
			seshConfig.Obfuscator = obfuscator
			seshConfig.InactivityTimeout = 100 * time.Millisecond
			sesh := MakeSession(0, seshConfig)

			assert.Eventually(t, func() bool {
				return sesh.IsClosed()
			}, 5*seshConfig.InactivityTimeout, seshConfig.InactivityTimeout, "session should have timed out")
		})
	}
}

func BenchmarkRecvDataFromRemote_Ordered(b *testing.B) {
	testPayload := make([]byte, testPayloadLen)
	rand.Read(testPayload)
	f := &Frame{
		1,
		0,
		0,
		testPayload,
	}

	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	table := map[string]byte{
		"plain":            EncryptionMethodPlain,
		"aes-gcm":          EncryptionMethodAESGCM,
		"chacha20poly1305": EncryptionMethodChaha20Poly1305,
	}

	const maxIter = 100_000 // run with -benchtime 100000x to avoid index out of bounds panic
	for name, ep := range table {
		ep := ep
		b.Run(name, func(b *testing.B) {
			seshConfig := seshConfigs["ordered"]
			obfuscator, _ := MakeObfuscator(ep, sessionKey)
			seshConfig.Obfuscator = obfuscator
			sesh := MakeSession(0, seshConfig)

			binaryFrames := [maxIter][]byte{}
			for i := 0; i < maxIter; i++ {
				obfsBuf := make([]byte, obfsBufLen)
				n, _ := sesh.Obfs(f, obfsBuf, 0)
				binaryFrames[i] = obfsBuf[:n]
				f.Seq++
			}

			b.SetBytes(int64(len(f.Payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sesh.recvDataFromRemote(binaryFrames[i])
			}
		})
	}
}

func BenchmarkMultiStreamWrite(b *testing.B) {
	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	table := map[string]byte{
		"plain":            EncryptionMethodPlain,
		"aes-gcm":          EncryptionMethodAESGCM,
		"chacha20poly1305": EncryptionMethodChaha20Poly1305,
	}

	testPayload := make([]byte, testPayloadLen)

	for name, ep := range table {
		b.Run(name, func(b *testing.B) {
			for seshType, seshConfig := range seshConfigs {
				seshConfig := seshConfig
				b.Run(seshType, func(b *testing.B) {
					obfuscator, _ := MakeObfuscator(ep, sessionKey)
					seshConfig.Obfuscator = obfuscator
					sesh := MakeSession(0, seshConfig)
					sesh.AddConnection(connutil.Discard())
					b.ResetTimer()
					b.SetBytes(testPayloadLen)
					b.RunParallel(func(pb *testing.PB) {
						stream, _ := sesh.OpenStream()
						for pb.Next() {
							stream.Write(testPayload)
						}
					})
				})
			}
		})
	}
}
