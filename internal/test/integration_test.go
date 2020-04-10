package test

import (
	"bytes"
	"encoding/base64"
	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/common"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
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
	lcl, rmt, auth, _ := clientConfig.SplitConfigs(state)
	return lcl, rmt, auth
}

func basicServerState(ws common.WorldState, db *os.File) *server.State {
	manager, _ := usermanager.MakeLocalManager(db.Name())
	var pv [32]byte
	copy(pv[:], privateKey)
	serverState := &server.State{
		ProxyBook:      map[string]net.Addr{"test": &net.TCPAddr{}},
		UsedRandom:     map[[32]byte]int64{},
		Timeout:        0,
		BypassUID:      map[[16]byte]struct{}{bypassUID: {}},
		RedirHost:      &net.TCPAddr{},
		RedirPort:      "9999",
		Panel:          server.MakeUserPanel(manager),
		LocalAPIRouter: nil,
		StaticPv:       &pv,
		WorldState:     ws,
	}
	return serverState
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
	const testDataLen = 16384
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func(conn net.Conn) {
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
	log.SetOutput(ioutil.Discard)

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
