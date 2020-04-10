package test

import (
	"bytes"
	"encoding/base64"
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

var bypassUID = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var publicKey, _ = base64.StdEncoding.DecodeString("7f7TuKrs264VNSgMno8PkDlyhGhVuOSR8JHLE6H4Ljc=")
var privateKey, _ = base64.StdEncoding.DecodeString("SMWeC6VuZF8S/id65VuFQFlfa7hTEJBpL6wWhqPP100=")

func basicClientConfigs(state common.WorldState) (client.LocalConnConfig, client.RemoteConnConfig, client.AuthInfo) {
	var clientConfig = client.RawConfig{
		ServerName:       "www.example.com",
		ProxyMethod:      "test",
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
		ProxyBook:     map[string][]string{"test": {"tcp", "fake.com:9999"}},
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

func establishSession(lcc client.LocalConnConfig, rcc client.RemoteConnConfig, ai client.AuthInfo, serverState *server.State) (common.Dialer, net.Listener, common.Dialer, net.Listener, error) {
	// transport
	ckClientDialer, ckServerListener := connutil.DialerListener(128)

	clientSeshMaker := func() *mux.Session {
		return client.MakeSession(rcc, ai, ckClientDialer, false)
	}

	proxyToCkClientD, proxyToCkClientL := connutil.DialerListener(128)
	go client.RouteTCP(proxyToCkClientL, lcc.Timeout, clientSeshMaker)

	// set up server
	ckServerToProxyD, ckServerToProxyL := connutil.DialerListener(128)
	ckServerToWebD, ckServerToWebL := connutil.DialerListener(128)
	serverState.ProxyDialer = ckServerToProxyD
	serverState.RedirDialer = ckServerToWebD

	go server.Serve(ckServerListener, serverState)

	return proxyToCkClientD, ckServerToProxyL, ckClientDialer, ckServerToWebL, nil
}

func runEchoTest(t *testing.T, conns []net.Conn) {
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
			testDataLen := rand.Intn(65536)
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

func TestTCP(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	log.SetLevel(log.FatalLevel)

	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := basicClientConfigs(worldState)
	sta := basicServerState(worldState, tmpDB)

	pxyClientD, pxyServerL, dialerToCkServer, rdirServerL, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("user echo", func(t *testing.T) {
		go serveEcho(pxyServerL)
		const numConns = 2000 // -race option limits the number of goroutines to 8192
		var conns [numConns]net.Conn
		for i := 0; i < numConns; i++ {
			conns[i], err = pxyClientD.Dial("", "")
			if err != nil {
				t.Error(err)
			}
		}

		runEchoTest(t, conns[:])
	})

	t.Run("redir echo", func(t *testing.T) {
		go serveEcho(rdirServerL)
		const numConns = 2000 // -race option limits the number of goroutines to 8192
		var conns [numConns]net.Conn
		for i := 0; i < numConns; i++ {
			conns[i], err = dialerToCkServer.Dial("", "")
			if err != nil {
				t.Error(err)
			}
		}
		runEchoTest(t, conns[:])
	})
}

func TestClosingStreamsFromProxy(t *testing.T) {
	var tmpDB, _ = ioutil.TempFile("", "ck_user_info")
	defer os.Remove(tmpDB.Name())
	log.SetLevel(log.FatalLevel)
	worldState := common.WorldOfTime(time.Unix(10, 0))
	lcc, rcc, ai := basicClientConfigs(worldState)
	sta := basicServerState(worldState, tmpDB)
	pxyClientD, pxyServerL, _, _, err := establishSession(lcc, rcc, ai, sta)
	if err != nil {
		t.Fatal(err)
	}

	// closing stream on server side
	clientConn, _ := pxyClientD.Dial("", "")
	clientConn.Write(make([]byte, 16))
	serverConn, _ := pxyServerL.Accept()
	serverConn.Close()

	time.Sleep(100 * time.Millisecond)
	if _, err := clientConn.Read(make([]byte, 16)); err == nil {
		t.Errorf("closing stream on server side is not reflected to the client: %v", err)
	}

	// closing stream on client side
	clientConn, _ = pxyClientD.Dial("", "")
	clientConn.Write(make([]byte, 16))
	serverConn, _ = pxyServerL.Accept()
	clientConn.Close()

	time.Sleep(100 * time.Millisecond)
	if _, err := serverConn.Read(make([]byte, 16)); err == nil {
		t.Errorf("closing stream on client side is not reflected to the server: %v", err)
	}
}
