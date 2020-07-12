package client

import (
	"encoding/binary"
	"github.com/cbeuw/Cloak/internal/common"
	"net"
	"sync"
	"sync/atomic"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
)

func MakeSession(connConfig RemoteConnConfig, authInfo AuthInfo, dialer common.Dialer, isAdmin bool) *mux.Session {
	log.Info("Attempting to start a new session")
	//TODO: let caller set this
	if !isAdmin {
		// sessionID is usergenerated. There shouldn't be a security concern because the scope of
		// sessionID is limited to its UID.
		quad := make([]byte, 4)
		common.RandRead(authInfo.WorldState.Rand, quad)
		authInfo.SessionId = binary.BigEndian.Uint32(quad)
	} else {
		authInfo.SessionId = 0
	}

	numConn := connConfig.NumConn
	if numConn <= 0 {
		log.Infof("Using session per connection (no multiplexing)")
		numConn = 1
	}

	connsCh := make(chan net.Conn, numConn)
	var _sessionKey atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < numConn; i++ {
		wg.Add(1)
		go func() {
		makeconn:
			remoteConn, err := dialer.Dial("tcp", connConfig.RemoteAddr)
			if err != nil {
				log.Errorf("Failed to establish new connections to remote: %v", err)
				// TODO increase the interval if failed multiple times
				time.Sleep(time.Second * 3)
				goto makeconn
			}

			transportConn := connConfig.TransportMaker()
			sk, err := transportConn.Handshake(remoteConn, authInfo)
			if err != nil {
				transportConn.Close()
				log.Errorf("Failed to prepare connection to remote: %v", err)
				time.Sleep(time.Second * 3)
				goto makeconn
			}
			_sessionKey.Store(sk)
			connsCh <- transportConn
			wg.Done()
		}()
	}
	wg.Wait()
	log.Debug("All underlying connections established")

	sessionKey := _sessionKey.Load().([32]byte)
	obfuscator, err := mux.MakeObfuscator(authInfo.EncryptionMethod, sessionKey)
	if err != nil {
		log.Fatal(err)
	}

	seshConfig := mux.SessionConfig{
		Obfuscator:   obfuscator,
		Valve:        nil,
		Unordered:    authInfo.Unordered,
		MaxFrameSize: appDataMaxLength,
	}
	sesh := mux.MakeSession(authInfo.SessionId, seshConfig)

	for i := 0; i < numConn; i++ {
		conn := <-connsCh
		sesh.AddConnection(conn)
	}

	log.Infof("Session %v established", authInfo.SessionId)
	return sesh
}
