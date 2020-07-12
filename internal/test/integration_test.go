package test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/common"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server"
	"github.com/cbeuw/connutil"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

const numConns = 200 // -race option limits the number of goroutines to 8192

func serveTCPEcho(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Error(err)
			return
		}
		go func() {
			conn := conn
			_, err := io.Copy(conn, conn)
			if err != nil {
				conn.Close()
				log.Error(err)
				return
			}
		}()
	}
}

func serveUDPEcho(listener *connutil.PipeListener) {
	for {
		conn, err := listener.ListenPacket("udp", "")
		if err != nil {
			log.Error(err)
			return
		}
		const bufSize = 32 * 1024
		go func() {
			conn := conn
			defer conn.Close()
			buf := make([]byte, bufSize)
			for {
				r, _, err := conn.ReadFrom(buf)
				if err != nil {
					log.Error(err)
					return
				}
				w, err := conn.WriteTo(buf[:r], nil)
				if err != nil {
					log.Error(err)
					return
				}
				if r != w {
					log.Error("written not eqal to read")
					return
				}
			}
		}()
	}
}

var bypassUID = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var publicKey, _ = base64.StdEncoding.DecodeString("7f7TuKrs264VNSgMno8PkDlyhGhVuOSR8JHLE6H4Ljc=")
var privateKey, _ = base64.StdEncoding.DecodeString("SMWeC6VuZF8S/id65VuFQFlfa7hTEJBpL6wWhqPP100=")

func basicClientConfigs(state common.WorldState) (client.LocalConnConfig, client.RemoteConnConfig, client.AuthInfo) {
	var clientConfig = client.RawConfig{
		ServerName:       "www.example.com",
		ProxyMethod:      "tcp",
		EncryptionMethod: "plain",
		UID:              bypassUID[:],
		PublicKey:        publicKey,
		NumConn:          4,
		UDP:              false,
		Transport:        "direct",
		RemoteHost:       "fake.com",
		RemotePort:       "9999",
		LocalHost:        "127.0.0.1",
		LocalPort:        "9999",
	}
	lcl, rmt, auth, err := clientConfig.SplitConfigs(state)
	if err != nil {
		log.Fatal(err)
	}
	return lcl, rmt, auth
}

func basicServerState(ws common.WorldState, db *os.File) *server.State {
	var serverConfig = server.RawConfig{
		ProxyBook:     map[string][]string{"tcp": {"tcp", "fake.com:9999"}, "udp": {"udp", "fake.com:9999"}},
		BindAddr:      []string{"fake.com:9999"},
		BypassUID:     [][]byte{bypassUID[:]},
		RedirAddr:     "fake.com:9999",
		PrivateKey:    privateKey,
		AdminUID:      nil,
		DatabasePath:  db.Name(),
		StreamTimeout: 300,
		KeepAlive:     15,
		CncMode:       false,
	}
	state, err := server.InitState(serverConfig, ws)
	if err != nil {
		log.Fatal(err)
	}
	return state
}

type mockUDPDialer struct {
	addrCh chan *net.UDPAddr
	raddr  *net.UDPAddr
}

func (m *mockUDPDialer) Dial(network, address string) (net.Conn, error) {
	if m.raddr == nil {
		m.raddr = <-m.addrCh
	}
	return net.DialUDP("udp", nil, m.raddr)
}

func establishSession(lcc client.LocalConnConfig, rcc client.RemoteConnConfig, ai client.AuthInfo, serverState *server.State) (common.Dialer, *connutil.PipeListener, common.Dialer, net.Listener, error) {
	// transport
	ckClientDialer, ckServerListener := connutil.DialerListener(10 * 1024)
	clientSeshMaker := func() *mux.Session {
		return client.MakeSession(rcc, ai, ckClientDialer, false)
	}

	useSessionPerConnection := rcc.NumConn == 0
	var proxyToCkClientD common.Dialer
	if ai.Unordered {
		addrCh := make(chan *net.UDPAddr, 1)
		mDialer := &mockUDPDialer{
			addrCh: addrCh,
		}
		acceptor := func() (*net.UDPConn, error) {
			laddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
			conn, err := net.ListenUDP("udp", laddr)
			addrCh <- conn.LocalAddr().(*net.UDPAddr)
			return conn, err
		}
		go client.RouteUDP(acceptor, lcc.Timeout, clientSeshMaker, useSessionPerConnection)
		proxyToCkClientD = mDialer
	} else {
		var proxyToCkClientL *connutil.PipeListener
		proxyToCkClientD, proxyToCkClientL = connutil.DialerListener(10 * 1024)
		go client.RouteTCP(proxyToCkClientL, lcc.Timeout, clientSeshMaker, useSessionPerConnection)
	}

	// set up server
	ckServerToProxyD, ckServerToProxyL := connutil.DialerListener(10 * 1024)
	ckServerToWebD, ckServerToWebL := connutil.DialerListener(10 * 1024)
	serverState.ProxyDialer = ckServerToProxyD
	serverState.RedirDialer = ckServerToWebD

	go server.Serve(ckServerListener, serverState)

	return proxyToCkClientD, ckServerToProxyL, ckClientDialer, ckServerToWebL, nil
}

func runEchoTest(t *testing.T, conns []net.Conn, maxMsgLen int) {
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
			testDataLen := rand.Intn(maxMsgLen)
			testData := make([]byte, testDataLen)
			rand.Read(testData)

			n, err := conn.Write(testData)
			if n != testDataLen {
				t.Fatalf("written only %v, err %v", n, err)
			}

			recvBuf := make([]byte, testDataLen)
			_, err = io.ReadFull(conn, recvBuf)
			if err != nil {
				t.Fatalf("failed to read back: %v", err)
			}

			if !bytes.Equal(testData, recvBuf) {
				t.Fatalf("echoed data not correct")
			}
			wg.Done()
		}(conn)
	}
	wg.Wait()
}

func TestUDP(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	log.SetLevel(log.TraceLevel)

	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := basicClientConfigs(worldState)
	ai.ProxyMethod = "udp"
	ai.Unordered = true
	sta := basicServerState(worldState, tmpDB)

	pxyClientD, pxyServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("simple send", func(t *testing.T) {
		pxyClientConn, err := pxyClientD.Dial("udp", "")
		if err != nil {
			t.Error(err)
		}

		const testDataLen = 1500
		testData := make([]byte, testDataLen)
		rand.Read(testData)
		n, err := pxyClientConn.Write(testData)
		if n != testDataLen {
			t.Errorf("wrong length sent: %v", n)
		}
		if err != nil {
			t.Error(err)
		}

		pxyServerConn, err := pxyServerL.ListenPacket("", "")
		if err != nil {
			t.Error(err)
		}
		recvBuf := make([]byte, testDataLen+100)
		r, _, err := pxyServerConn.ReadFrom(recvBuf)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(testData, recvBuf[:r]) {
			t.Error("read wrong data")
		}
	})

	t.Run("user echo", func(t *testing.T) {
		go serveUDPEcho(pxyServerL)
		var conn [1]net.Conn
		conn[0], err = pxyClientD.Dial("udp", "")
		if err != nil {
			t.Error(err)
		}

		runEchoTest(t, conn[:], 1024)
	})

}

func TestTCP(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	log.SetLevel(log.ErrorLevel)

	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := basicClientConfigs(worldState)
	sta := basicServerState(worldState, tmpDB)

	pxyClientD, pxyServerL, dialerToCkServer, rdirServerL, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("user echo single", func(t *testing.T) {
		for i := 0; i < 18; i += 2 {
			dataLen := 1 << i
			writeData := make([]byte, dataLen)
			rand.Read(writeData)
			t.Run(fmt.Sprintf("data length %v", dataLen), func(t *testing.T) {
				go serveTCPEcho(pxyServerL)
				conn, err := pxyClientD.Dial("", "")
				if err != nil {
					t.Error(err)
				}
				n, err := conn.Write(writeData)
				if err != nil {
					t.Error(err)
				}
				if n != dataLen {
					t.Errorf("write length doesn't match up: %v, expected %v", n, dataLen)
				}

				recvBuf := make([]byte, dataLen)
				_, err = io.ReadFull(conn, recvBuf)
				if err != nil {
					t.Error(err)
				}
				if !bytes.Equal(writeData, recvBuf) {
					t.Error("echoed data incorrect")
				}

			})
		}
	})

	t.Run("user echo", func(t *testing.T) {
		go serveTCPEcho(pxyServerL)
		var conns [numConns]net.Conn
		for i := 0; i < numConns; i++ {
			conns[i], err = pxyClientD.Dial("", "")
			if err != nil {
				t.Error(err)
			}
		}

		runEchoTest(t, conns[:], 65536)
	})

	t.Run("redir echo", func(t *testing.T) {
		go serveTCPEcho(rdirServerL)
		var conns [numConns]net.Conn
		for i := 0; i < numConns; i++ {
			conns[i], err = dialerToCkServer.Dial("", "")
			if err != nil {
				t.Error(err)
			}
		}
		runEchoTest(t, conns[:], 65536)
	})
}

func TestClosingStreamsFromProxy(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	log.SetLevel(log.ErrorLevel)
	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := basicClientConfigs(worldState)
	sta := basicServerState(worldState, tmpDB)
	pxyClientD, pxyServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("closing from server", func(t *testing.T) {
		clientConn, _ := pxyClientD.Dial("", "")
		clientConn.Write(make([]byte, 16))
		serverConn, _ := pxyServerL.Accept()
		serverConn.Close()

		time.Sleep(500 * time.Millisecond)
		if _, err := clientConn.Read(make([]byte, 16)); err == nil {
			t.Errorf("closing stream on server side is not reflected to the client: %v", err)
		}
	})

	t.Run("closing from client", func(t *testing.T) {
		// closing stream on client side
		clientConn, _ := pxyClientD.Dial("", "")
		clientConn.Write(make([]byte, 16))
		serverConn, _ := pxyServerL.Accept()
		clientConn.Close()

		time.Sleep(500 * time.Millisecond)
		if _, err := serverConn.Read(make([]byte, 16)); err == nil {
			t.Errorf("closing stream on client side is not reflected to the server: %v", err)
		}
	})

	t.Run("send then close", func(t *testing.T) {
		testData := make([]byte, 24*1024)
		rand.Read(testData)
		clientConn, _ := pxyClientD.Dial("", "")
		go func() {
			clientConn.Write(testData)
			// TODO: this is time dependent. It could be due to the time it took for this
			// connutil.StreamPipe's Close to be reflected on the copy function, instead of inherent bad sync
			// in multiplexer
			time.Sleep(10 * time.Millisecond)
			clientConn.Close()
		}()

		readBuf := make([]byte, len(testData))
		serverConn, _ := pxyServerL.Accept()
		_, err := io.ReadFull(serverConn, readBuf)
		if err != nil {
			t.Errorf("failed to read data sent before closing: %v", err)
		}
	})
}

func BenchmarkThroughput(b *testing.B) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	log.SetLevel(log.ErrorLevel)
	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := basicClientConfigs(worldState)
	sta := basicServerState(worldState, tmpDB)
	const bufSize = 16 * 1024

	encryptionMethods := map[string]byte{
		"plain":             mux.E_METHOD_PLAIN,
		"chacha20-poly1305": mux.E_METHOD_CHACHA20_POLY1305,
		"aes-gcm":           mux.E_METHOD_AES_GCM,
	}

	for name, method := range encryptionMethods {
		b.Run(name, func(b *testing.B) {
			ai.EncryptionMethod = method
			pxyClientD, pxyServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("single conn", func(b *testing.B) {
				more := make(chan int, 10)
				go func() {
					writeBuf := make([]byte, bufSize+100)
					serverConn, _ := pxyServerL.Accept()
					for {
						serverConn.Write(writeBuf)
						<-more
					}
				}()
				clientConn, _ := pxyClientD.Dial("", "")
				readBuf := make([]byte, bufSize)
				clientConn.Write([]byte{1}) // to make server accept
				b.SetBytes(bufSize)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					io.ReadFull(clientConn, readBuf)
					more <- 0
				}
			})

			/*
				b.Run("multiconn", func(b *testing.B) {
					writeBuf := make([]byte, bufSize)
					b.SetBytes(bufSize)
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						ready := make(chan int, 10)
						go func() {
							serverConn, _ := pxyServerL.Accept()
							for {
								serverConn.Write(writeBuf)
								<-ready
							}
						}()
						readBuf := make([]byte, bufSize)
						clientConn, _ := pxyClientD.Dial("", "")
						clientConn.Write([]byte{1}) // to make server accept
						for pb.Next() {
							io.ReadFull(clientConn,readBuf)
							ready <- 0
						}
					})
				})

			*/

		})
	}

}
