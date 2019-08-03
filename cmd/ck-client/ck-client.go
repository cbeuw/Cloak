// +build go1.11

package main

import (
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/Cloak/internal/client"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/util"
	log "github.com/sirupsen/logrus"
)

var version string

// This establishes a connection with ckserver and performs a handshake
func makeRemoteConn(sta *client.State) (net.Conn, []byte, error) {

	// For android
	d := net.Dialer{Control: protector}

	clientHello, sharedSecret := client.ComposeClientHello(sta)
	connectingIP := sta.RemoteHost
	if net.ParseIP(connectingIP).To4() == nil {
		// IPv6 needs square brackets
		connectingIP = "[" + connectingIP + "]"
	}
	remoteConn, err := d.Dial("tcp", connectingIP+":"+sta.RemotePort)
	if err != nil {
		log.WithField("error", err).Error("Failed to connect to remote")
		return nil, nil, err
	}
	_, err = remoteConn.Write(clientHello)
	if err != nil {
		log.WithField("error", err).Error("Failed to send ClientHello")
		return nil, nil, err
	}

	buf := make([]byte, 1024)
	_, err = util.ReadTLS(remoteConn, buf)
	if err != nil {
		log.WithField("error", err).Error("Failed to read ServerHello")
	}
	serverRandom := buf[11:43]
	sessionKey := client.DecryptSessionKey(serverRandom, sharedSecret)
	_, err = util.ReadTLS(remoteConn, buf)
	if err != nil {
		log.WithField("error", err).Error("Failed to read ChangeCipherSpec")
		return nil, nil, err
	}

	return remoteConn, sessionKey, nil

}

func makeSession(sta *client.State) *mux.Session {
	log.Info("Attemtping to start a new session")
	if !sta.IsAdmin {
		// sessionID is usergenerated. There shouldn't be a security concern because the scope of
		// sessionID is limited to its UID.
		quad := make([]byte, 4)
		rand.Read(quad)
		atomic.StoreUint32(&sta.SessionID, binary.BigEndian.Uint32(quad))
	}

	connsCh := make(chan net.Conn, sta.NumConn)
	var _sessionKey atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < sta.NumConn; i++ {
		wg.Add(1)
		go func() {
		makeconn:
			conn, sk, err := makeRemoteConn(sta)
			_sessionKey.Store(sk)
			if err != nil {
				log.Errorf("Failed to establish new connections to remote: %v", err)
				// TODO increase the interval if failed multiple times
				time.Sleep(time.Second * 3)
				goto makeconn
			}
			connsCh <- conn
			wg.Done()
		}()
	}
	wg.Wait()

	sessionKey := _sessionKey.Load().([]byte)
	obfuscator, err := util.GenerateObfs(sta.EncryptionMethod, sessionKey)
	if err != nil {
		log.Fatal(err)
	}
	sesh := mux.MakeSession(sta.SessionID, mux.UNLIMITED_VALVE, obfuscator, util.ReadTLS)

	for i := 0; i < sta.NumConn; i++ {
		conn := <-connsCh
		sesh.AddConnection(conn)
	}

	log.Infof("Session %v established", sta.SessionID)
	return sesh
}

func main() {
	// Should be 127.0.0.1 to listen to a proxy client on this machine
	var localHost string
	// port used by proxy clients to communicate with cloak client
	var localPort string
	// The ip of the proxy server
	var remoteHost string
	// The proxy port,should be 443
	var remotePort string
	var config string
	var b64AdminUID string

	log_init()
	log.SetLevel(log.DebugLevel)

	if os.Getenv("SS_LOCAL_HOST") != "" {
		localHost = os.Getenv("SS_LOCAL_HOST")
		localPort = os.Getenv("SS_LOCAL_PORT")
		remoteHost = os.Getenv("SS_REMOTE_HOST")
		remotePort = os.Getenv("SS_REMOTE_PORT")
		config = os.Getenv("SS_PLUGIN_OPTIONS")
	} else {
		localHost = "127.0.0.1"
		flag.StringVar(&localPort, "l", "1984", "localPort: Cloak listens to proxy clients on this port")
		flag.StringVar(&remoteHost, "s", "", "remoteHost: IP of your proxy server")
		flag.StringVar(&remotePort, "p", "443", "remotePort: proxy port, should be 443")
		flag.StringVar(&config, "c", "ckclient.json", "config: path to the configuration file or options seperated with semicolons")
		flag.StringVar(&b64AdminUID, "a", "", "adminUID: enter the adminUID to serve the admin api")
		askVersion := flag.Bool("v", false, "Print the version number")
		printUsage := flag.Bool("h", false, "Print this message")
		flag.Parse()

		if *askVersion {
			fmt.Printf("ck-client %s", version)
			return
		}

		if *printUsage {
			flag.Usage()
			return
		}

		log.Info("Starting standalone mode")
	}

	sta := client.InitState(localHost, localPort, remoteHost, remotePort, time.Now)
	err := sta.ParseConfig(config)
	if err != nil {
		log.Fatal(err)
	}

	if os.Getenv("SS_LOCAL_HOST") != "" {
		sta.ProxyMethod = "shadowsocks"
	}

	if sta.LocalPort == "" {
		log.Fatal("Must specify localPort")
	}
	if sta.RemoteHost == "" {
		log.Fatal("Must specify remoteHost")
	}

	listeningIP := sta.LocalHost
	if net.ParseIP(listeningIP).To4() == nil {
		// IPv6 needs square brackets
		listeningIP = "[" + listeningIP + "]"
	}
	listener, err := net.Listen("tcp", listeningIP+":"+sta.LocalPort)
	if err != nil {
		log.Fatal(err)
	}

	var adminUID []byte
	if b64AdminUID != "" {
		adminUID, err = base64.StdEncoding.DecodeString(b64AdminUID)
		if err != nil {
			log.Fatal(err)
		}
	}

	if adminUID != nil {
		log.Infof("API base is %v:%v", listeningIP, sta.LocalPort)
		sta.IsAdmin = true
		sta.SessionID = 0
		sta.UID = adminUID
		sta.NumConn = 1
	} else {
		log.Infof("Listening on %v:%v for proxy clients", listeningIP, sta.LocalPort)
	}

	var sesh *mux.Session

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Error(err)
			continue
		}
		if sesh == nil || sesh.IsClosed() {
			sesh = makeSession(sta)
		}
		go func() {
			data := make([]byte, 10240)
			i, err := io.ReadAtLeast(localConn, data, 1)
			if err != nil {
				log.Errorf("Failed to read first packet from proxy client: %v", err)
				localConn.Close()
				return
			}
			stream, err := sesh.OpenStream()
			if err != nil {
				log.Errorf("Failed to open stream: %v", err)
				localConn.Close()
				return
			}
			_, err = stream.Write(data[:i])
			if err != nil {
				log.Errorf("Failed to write to stream: %v", err)
				localConn.Close()
				stream.Close()
				return
			}
			go util.Pipe(localConn, stream)
			util.Pipe(stream, localConn)
		}()
	}

}
