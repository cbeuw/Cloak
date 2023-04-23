package test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/common"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server"
	"github.com/cbeuw/connutil"
	"github.com/stretchr/testify/assert"

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
		go func(conn net.Conn) {
			_, err := io.Copy(conn, conn)
			if err != nil {
				conn.Close()
				log.Error(err)
				return
			}
		}(conn)
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
		go func(conn net.PacketConn) {
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
		}(conn)
	}
}

var bypassUID = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var publicKey, _ = base64.StdEncoding.DecodeString("7f7TuKrs264VNSgMno8PkDlyhGhVuOSR8JHLE6H4Ljc=")
var privateKey, _ = base64.StdEncoding.DecodeString("SMWeC6VuZF8S/id65VuFQFlfa7hTEJBpL6wWhqPP100=")

var basicUDPConfig = client.RawConfig{
	ServerName:       "www.example.com",
	ProxyMethod:      "openvpn",
	EncryptionMethod: "plain",
	UID:              bypassUID[:],
	PublicKey:        publicKey,
	NumConn:          4,
	UDP:              true,
	Transport:        "direct",
	RemoteHost:       "fake.com",
	RemotePort:       "9999",
	LocalHost:        "127.0.0.1",
	LocalPort:        "9999",
}

var basicTCPConfig = client.RawConfig{
	ServerName:       "www.example.com",
	ProxyMethod:      "shadowsocks",
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
	BrowserSig:       "firefox",
}

var singleplexTCPConfig = client.RawConfig{
	ServerName:       "www.example.com",
	ProxyMethod:      "shadowsocks",
	EncryptionMethod: "plain",
	UID:              bypassUID[:],
	PublicKey:        publicKey,
	NumConn:          0,
	UDP:              false,
	Transport:        "direct",
	RemoteHost:       "fake.com",
	RemotePort:       "9999",
	LocalHost:        "127.0.0.1",
	LocalPort:        "9999",
	BrowserSig:       "safari",
}

func generateClientConfigs(rawConfig client.RawConfig, state common.WorldState) (client.LocalConnConfig, client.RemoteConnConfig, client.AuthInfo) {
	lcl, rmt, auth, err := rawConfig.ProcessRawConfig(state)
	if err != nil {
		log.Fatal(err)
	}
	return lcl, rmt, auth
}

func basicServerState(ws common.WorldState) *server.State {
	var serverConfig = server.RawConfig{
		ProxyBook:  map[string][]string{"shadowsocks": {"tcp", "fake.com:9999"}, "openvpn": {"udp", "fake.com:9999"}},
		BindAddr:   []string{"fake.com:9999"},
		BypassUID:  [][]byte{bypassUID[:]},
		RedirAddr:  "fake.com:9999",
		PrivateKey: privateKey,
		KeepAlive:  15,
		CncMode:    false,
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
	//													 redirecting web server
	//																^
	//																|
	//																|
	//														redirFromCkServerL
	//																|
	//															    |
	// proxy client ----proxyToCkClientD----> ck-client ------> ck-server ----proxyFromCkServerL----> proxy server
	//																^
	//																|
	//																|
	//														 netToCkServerD
	//																|
	//															    |
	//									whatever connection initiator (including a proper ck-client)

	netToCkServerD, ckServerListener := connutil.DialerListener(10 * 1024)

	clientSeshMaker := func() *mux.Session {
		ai := ai
		quad := make([]byte, 4)
		common.RandRead(ai.WorldState.Rand, quad)
		ai.SessionId = binary.BigEndian.Uint32(quad)
		return client.MakeSession(rcc, ai, netToCkServerD)
	}

	var proxyToCkClientD common.Dialer
	if ai.Unordered {
		// We can only "dial" a single UDP connection as we can't send packets from different context
		// to a single UDP listener
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
		go client.RouteUDP(acceptor, lcc.Timeout, rcc.Singleplex, clientSeshMaker)
		proxyToCkClientD = mDialer
	} else {
		var proxyToCkClientL *connutil.PipeListener
		proxyToCkClientD, proxyToCkClientL = connutil.DialerListener(10 * 1024)
		go client.RouteTCP(proxyToCkClientL, lcc.Timeout, rcc.Singleplex, clientSeshMaker)
	}

	// set up server
	ckServerToProxyD, proxyFromCkServerL := connutil.DialerListener(10 * 1024)
	ckServerToWebD, redirFromCkServerL := connutil.DialerListener(10 * 1024)
	serverState.ProxyDialer = ckServerToProxyD
	serverState.RedirDialer = ckServerToWebD

	go server.Serve(ckServerListener, serverState)

	return proxyToCkClientD, proxyFromCkServerL, netToCkServerD, redirFromCkServerL, nil
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

func TestUDP(t *testing.T) {
	log.SetLevel(log.ErrorLevel)

	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := generateClientConfigs(basicUDPConfig, worldState)
	sta := basicServerState(worldState)

	proxyToCkClientD, proxyFromCkServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("simple send", func(t *testing.T) {
		pxyClientConn, err := proxyToCkClientD.Dial("udp", "")
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

		pxyServerConn, err := proxyFromCkServerL.ListenPacket("", "")
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

	const echoMsgLen = 1024
	t.Run("user echo", func(t *testing.T) {
		go serveUDPEcho(proxyFromCkServerL)
		var conn [1]net.Conn
		conn[0], err = proxyToCkClientD.Dial("udp", "")
		if err != nil {
			t.Error(err)
		}

		runEchoTest(t, conn[:], echoMsgLen)
	})

}

func TestTCPSingleplex(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := generateClientConfigs(singleplexTCPConfig, worldState)
	sta := basicServerState(worldState)
	proxyToCkClientD, proxyFromCkServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	const echoMsgLen = 1 << 16
	go serveTCPEcho(proxyFromCkServerL)

	proxyConn1, err := proxyToCkClientD.Dial("", "")
	if err != nil {
		t.Fatal(err)
	}
	runEchoTest(t, []net.Conn{proxyConn1}, echoMsgLen)
	user, err := sta.Panel.GetUser(ai.UID[:])
	if err != nil {
		t.Fatalf("failed to fetch user: %v", err)
	}

	if user.NumSession() != 1 {
		t.Error("no session were made on first connection establishment")
	}

	proxyConn2, err := proxyToCkClientD.Dial("", "")
	if err != nil {
		t.Fatal(err)
	}
	runEchoTest(t, []net.Conn{proxyConn2}, echoMsgLen)
	if user.NumSession() != 2 {
		t.Error("no extra session were made on second connection establishment")
	}

	// Both conns should work
	runEchoTest(t, []net.Conn{proxyConn1, proxyConn2}, echoMsgLen)

	proxyConn1.Close()

	assert.Eventually(t, func() bool {
		return user.NumSession() == 1
	}, time.Second, 10*time.Millisecond, "first session was not closed on connection close")

	// conn2 should still work
	runEchoTest(t, []net.Conn{proxyConn2}, echoMsgLen)

	var conns [numConns]net.Conn
	for i := 0; i < numConns; i++ {
		conns[i], err = proxyToCkClientD.Dial("", "")
		if err != nil {
			t.Fatal(err)
		}
	}

	runEchoTest(t, conns[:], echoMsgLen)

}

func TestTCPMultiplex(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	worldState := common.WorldOfTime(time.Unix(10, 0))

	lcc, rcc, ai := generateClientConfigs(basicTCPConfig, worldState)
	sta := basicServerState(worldState)

	proxyToCkClientD, proxyFromCkServerL, netToCkServerD, redirFromCkServerL, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("user echo single", func(t *testing.T) {
		for i := 0; i < 18; i += 2 {
			dataLen := 1 << i
			writeData := make([]byte, dataLen)
			rand.Read(writeData)
			t.Run(fmt.Sprintf("data length %v", dataLen), func(t *testing.T) {
				go serveTCPEcho(proxyFromCkServerL)
				conn, err := proxyToCkClientD.Dial("", "")
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

	const echoMsgLen = 16384
	t.Run("user echo", func(t *testing.T) {
		go serveTCPEcho(proxyFromCkServerL)
		var conns [numConns]net.Conn
		for i := 0; i < numConns; i++ {
			conns[i], err = proxyToCkClientD.Dial("", "")
			if err != nil {
				t.Error(err)
			}
		}

		runEchoTest(t, conns[:], echoMsgLen)
	})

	t.Run("redir echo", func(t *testing.T) {
		go serveTCPEcho(redirFromCkServerL)
		var conns [numConns]net.Conn
		for i := 0; i < numConns; i++ {
			conns[i], err = netToCkServerD.Dial("", "")
			if err != nil {
				t.Error(err)
			}
		}
		runEchoTest(t, conns[:], echoMsgLen)
	})
}

func TestClosingStreamsFromProxy(t *testing.T) {
	log.SetLevel(log.ErrorLevel)
	worldState := common.WorldOfTime(time.Unix(10, 0))

	for clientConfigName, clientConfig := range map[string]client.RawConfig{"basic": basicTCPConfig, "singleplex": singleplexTCPConfig} {
		clientConfig := clientConfig
		clientConfigName := clientConfigName
		t.Run(clientConfigName, func(t *testing.T) {
			lcc, rcc, ai := generateClientConfigs(clientConfig, worldState)
			sta := basicServerState(worldState)
			proxyToCkClientD, proxyFromCkServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("closing from server", func(t *testing.T) {
				clientConn, _ := proxyToCkClientD.Dial("", "")
				clientConn.Write(make([]byte, 16))
				serverConn, _ := proxyFromCkServerL.Accept()
				serverConn.Close()

				assert.Eventually(t, func() bool {
					_, err := clientConn.Read(make([]byte, 16))
					return err != nil
				}, time.Second, 10*time.Millisecond, "closing stream on server side is not reflected to the client")
			})

			t.Run("closing from client", func(t *testing.T) {
				// closing stream on client side
				clientConn, _ := proxyToCkClientD.Dial("", "")
				clientConn.Write(make([]byte, 16))
				serverConn, _ := proxyFromCkServerL.Accept()
				clientConn.Close()

				assert.Eventually(t, func() bool {
					_, err := serverConn.Read(make([]byte, 16))
					return err != nil
				}, time.Second, 10*time.Millisecond, "closing stream on client side is not reflected to the server")
			})

			t.Run("send then close", func(t *testing.T) {
				testData := make([]byte, 24*1024)
				rand.Read(testData)
				clientConn, _ := proxyToCkClientD.Dial("", "")
				go func() {
					clientConn.Write(testData)
					// it takes time for this written data to be copied asynchronously
					// into ck-server's domain. If the pipe is closed before that, read
					// by ck-client in RouteTCP will fail as we have closed it.
					time.Sleep(700 * time.Millisecond)
					clientConn.Close()
				}()

				readBuf := make([]byte, len(testData))
				serverConn, err := proxyFromCkServerL.Accept()
				if err != nil {
					t.Errorf("failed to accept a connection delievering data sent before closing: %v", err)
				}
				_, err = io.ReadFull(serverConn, readBuf)
				if err != nil {
					t.Errorf("failed to read data sent before closing: %v", err)
				}
			})
		})
	}
}

func BenchmarkIntegration(b *testing.B) {
	log.SetLevel(log.ErrorLevel)
	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := generateClientConfigs(basicTCPConfig, worldState)
	sta := basicServerState(worldState)
	const bufSize = 16 * 1024

	encryptionMethods := map[string]byte{
		"plain":             mux.EncryptionMethodPlain,
		"chacha20-poly1305": mux.EncryptionMethodChaha20Poly1305,
		"aes-256-gcm":       mux.EncryptionMethodAES256GCM,
		"aes-128-gcm":       mux.EncryptionMethodAES128GCM,
	}

	for name, method := range encryptionMethods {
		b.Run(name, func(b *testing.B) {
			ai.EncryptionMethod = method
			proxyToCkClientD, proxyFromCkServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("single stream bandwidth", func(b *testing.B) {
				more := make(chan int, 10)
				go func() {
					// sender
					writeBuf := make([]byte, bufSize+100)
					serverConn, _ := proxyFromCkServerL.Accept()
					for {
						serverConn.Write(writeBuf)
						<-more
					}
				}()
				// receiver
				clientConn, _ := proxyToCkClientD.Dial("", "")
				readBuf := make([]byte, bufSize)
				clientConn.Write([]byte{1}) // to make server accept
				b.SetBytes(bufSize)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					io.ReadFull(clientConn, readBuf)
					// ask for more
					more <- 0
				}
			})

			b.Run("single stream latency", func(b *testing.B) {
				clientConn, _ := proxyToCkClientD.Dial("", "")
				buf := []byte{1}
				clientConn.Write(buf)
				serverConn, _ := proxyFromCkServerL.Accept()
				serverConn.Read(buf)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					clientConn.Write(buf)
					serverConn.Read(buf)
				}
			})

		})
	}

}
