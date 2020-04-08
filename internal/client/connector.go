package client

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/util"
	log "github.com/sirupsen/logrus"
)

type remoteConnConfig struct {
	NumConn    int
	KeepAlive  time.Duration
	Protector  func(string, string, syscall.RawConn) error
	RemoteAddr string
	Transport  Transport
}

func MakeSession(connConfig *remoteConnConfig, authInfo *authInfo, isAdmin bool) *mux.Session {
	log.Info("Attempting to start a new session")
	if !isAdmin {
		// sessionID is usergenerated. There shouldn't be a security concern because the scope of
		// sessionID is limited to its UID.
		quad := make([]byte, 4)
		util.CryptoRandRead(quad)
		authInfo.SessionId = binary.BigEndian.Uint32(quad)
	} else {
		authInfo.SessionId = 0
	}

	d := net.Dialer{Control: connConfig.Protector, KeepAlive: connConfig.KeepAlive}
	connsCh := make(chan net.Conn, connConfig.NumConn)
	var _sessionKey atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < connConfig.NumConn; i++ {
		wg.Add(1)
		go func() {
		makeconn:
			remoteConn, err := d.Dial("tcp", connConfig.RemoteAddr)
			if err != nil {
				log.Errorf("Failed to establish new connections to remote: %v", err)
				// TODO increase the interval if failed multiple times
				time.Sleep(time.Second * 3)
				goto makeconn
			}
			var sk [32]byte
			remoteConn, sk, err = connConfig.Transport.PrepareConnection(authInfo, remoteConn)
			if err != nil {
				remoteConn.Close()
				log.Errorf("Failed to prepare connection to remote: %v", err)
				time.Sleep(time.Second * 3)
				goto makeconn
			}
			_sessionKey.Store(sk)
			connsCh <- remoteConn
			wg.Done()
		}()
	}
	wg.Wait()
	log.Debug("All underlying connections established")

	sessionKey := _sessionKey.Load().([32]byte)
	obfuscator, err := mux.MakeObfuscator(authInfo.EncryptionMethod, sessionKey, connConfig.Transport.HasRecordLayer())
	if err != nil {
		log.Fatal(err)
	}

	seshConfig := &mux.SessionConfig{
		Obfuscator: obfuscator,
		Valve:      nil,
		UnitRead:   connConfig.Transport.UnitReadFunc(),
		Unordered:  authInfo.Unordered,
	}
	sesh := mux.MakeSession(authInfo.SessionId, seshConfig)

	for i := 0; i < connConfig.NumConn; i++ {
		conn := <-connsCh
		sesh.AddConnection(conn)
	}

	log.Infof("Session %v established", authInfo.SessionId)
	return sesh
}
