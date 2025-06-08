package client

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/Cloak/internal/common"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
)

// On different invocations to MakeSession, authInfo.SessionId MUST be different
func MakeSession(connConfig RemoteConnConfig, authInfo AuthInfo, dialer common.Dialer) *mux.Session {
	log.Info("Attempting to start a new session")

	connsCh := make(chan net.Conn, connConfig.NumConn)
	var _sessionKey atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < connConfig.NumConn; i++ {
		wg.Add(1)
		transportConfig := connConfig.Transport
		go func() {
		makeconn:
			transportConn := transportConfig.CreateTransport()
			remoteConn, err := dialer.Dial("tcp", connConfig.RemoteAddr)
			if err != nil {
				log.Errorf("Failed to establish new connections to remote: %v", err)
				// TODO increase the interval if failed multiple times
				time.Sleep(time.Second * 3)
				goto makeconn
			}

			sk, err := transportConn.Handshake(remoteConn, authInfo)
			if err != nil {
				log.Errorf("Failed to prepare connection to remote: %v", err)
				transportConn.Close()

				// In Cloak v2.11.0, we've updated uTLS version and subsequently increased the first packet size for chrome above 1500
				// https://github.com/cbeuw/Cloak/pull/306#issuecomment-2862728738. As a backwards compatibility feature, if we fail
				// to connect using chrome signature, retry with firefox which has a smaller packet size.
				if transportConfig.mode == "direct" && transportConfig.browser == chrome {
					transportConfig.browser = firefox
					log.Warnf("failed to connect with chrome signature, falling back to retry with firefox")
				}
				time.Sleep(time.Second * 3)

				goto makeconn
			}
			// sessionKey given by each connection should be identical
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
		Singleplex:         connConfig.Singleplex,
		Obfuscator:         obfuscator,
		Valve:              nil,
		Unordered:          authInfo.Unordered,
		MsgOnWireSizeLimit: appDataMaxLength,
	}
	sesh := mux.MakeSession(authInfo.SessionId, seshConfig)

	for i := 0; i < connConfig.NumConn; i++ {
		conn := <-connsCh
		sesh.AddConnection(conn)
	}

	log.Infof("Session %v established", authInfo.SessionId)
	return sesh
}
