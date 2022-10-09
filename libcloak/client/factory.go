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

type CloakClient struct {
	connConfig RemoteConnConfig
	authInfo   AuthInfo
	dialer     common.Dialer

	session *mux.Session
}

const appDataMaxLength = 16401

// On different invocations to NewCloakClient, authInfo.SessionId MUST be different
func NewCloakClient(connConfig RemoteConnConfig, authInfo AuthInfo, dialer common.Dialer) *CloakClient {
	log.Info("Attempting to start a new session")

	connsCh := make(chan net.Conn, connConfig.NumConn)
	var _sessionKey atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < connConfig.NumConn; i++ {
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
				log.Errorf("Failed to prepare connection to remote: %v", err)
				transportConn.Close()
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
		Obfuscator:         obfuscator,
		Valve:              nil,
		Unordered:          authInfo.Unordered,
		MsgOnWireSizeLimit: appDataMaxLength,
		InactivityTimeout:  connConfig.InactivityTimeout,
	}
	session := mux.MakeSession(authInfo.SessionId, seshConfig)

	for i := 0; i < connConfig.NumConn; i++ {
		conn := <-connsCh
		session.AddConnection(conn)
	}

	log.Infof("Session %v established", authInfo.SessionId)

	return &CloakClient{
		connConfig: connConfig,
		authInfo:   authInfo,
		dialer:     dialer,
		session:    session,
	}
}

func (client *CloakClient) Dial() (net.Conn, error) {
	return client.session.OpenStream()
}

func (client *CloakClient) Close() error {
	return client.session.Close()
}

func (client *CloakClient) IsClosed() bool {
	return client.session.IsClosed()
}
