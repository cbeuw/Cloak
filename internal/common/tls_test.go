package common

import (
	"net"
	"testing"
)

func BenchmarkTLSConn_Write(b *testing.B) {
	const bufSize = 16 * 1024
	addrCh := make(chan string, 1)
	go func() {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		addrCh <- listener.Addr().String()
		conn, err := listener.Accept()
		if err != nil {
			b.Fatal(err)
		}
		readBuf := make([]byte, bufSize*2)
		for {
			_, err = conn.Read(readBuf)
			if err != nil {
				return
			}
		}
	}()
	data := make([]byte, bufSize)
	discardConn, _ := net.Dial("tcp", <-addrCh)
	tlsConn := NewTLSConn(discardConn)
	defer tlsConn.Close()
	b.SetBytes(bufSize)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tlsConn.Write(data)
		}
	})
}
