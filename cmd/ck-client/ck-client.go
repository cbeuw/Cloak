// +build go1.11

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
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

func makeSession(sta *client.State, isAdmin bool, unordered bool) *mux.Session {
	log.Info("Attemtping to start a new session")
	if !isAdmin {
		// sessionID is usergenerated. There shouldn't be a security concern because the scope of
		// sessionID is limited to its UID.
		quad := make([]byte, 4)
		rand.Read(quad)
		atomic.StoreUint32(&sta.SessionID, binary.BigEndian.Uint32(quad))
	}

	d := net.Dialer{Control: protector}
	connsCh := make(chan net.Conn, sta.NumConn)
	var _sessionKey atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < sta.NumConn; i++ {
		wg.Add(1)
		go func() {
		makeconn:
			connectingIP := sta.RemoteHost
			if net.ParseIP(connectingIP).To4() == nil {
				// IPv6 needs square brackets
				connectingIP = "[" + connectingIP + "]"
			}
			remoteConn, err := d.Dial("tcp", connectingIP+":"+sta.RemotePort)
			if err != nil {
				log.Errorf("Failed to establish new connections to remote: %v", err)
				// TODO increase the interval if failed multiple times
				time.Sleep(time.Second * 3)
				goto makeconn
			}
			sk, err := client.PrepareConnection(sta, remoteConn)
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

	sessionKey := _sessionKey.Load().([]byte)
	obfuscator, err := mux.GenerateObfs(sta.EncryptionMethod, sessionKey)
	if err != nil {
		log.Fatal(err)
	}

	seshConfig := &mux.SessionConfig{
		Obfuscator: obfuscator,
		Valve:      nil,
		UnitRead:   util.ReadTLS,
		Unordered:  unordered,
	}
	sesh := mux.MakeSession(sta.SessionID, seshConfig)

	for i := 0; i < sta.NumConn; i++ {
		conn := <-connsCh
		sesh.AddConnection(conn)
	}

	log.Infof("Session %v established", sta.SessionID)
	return sesh
}

func routeUDP(sta *client.State, adminUID []byte) {
	var sesh *mux.Session
	localUDPAddr, err := net.ResolveUDPAddr("udp", sta.LocalHost+":"+sta.LocalPort)
	if err != nil {
		log.Fatal(err)
	}
	localConn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		var otherEnd atomic.Value
		data := make([]byte, 10240)
		i, oe, err := localConn.ReadFromUDP(data)
		if err != nil {
			log.Errorf("Failed to read first packet from proxy client: %v", err)
			localConn.Close()
			return
		}
		otherEnd.Store(oe)

		if sesh == nil || sesh.IsClosed() {
			sesh = makeSession(sta, adminUID != nil, true)
		}
		log.Debugf("proxy local address %v", otherEnd.Load().(*net.UDPAddr).String())
		stream, err := sesh.OpenStream()
		if err != nil {
			log.Errorf("Failed to open stream: %v", err)
			localConn.Close()
			//localConnWrite.Close()
			return
		}
		_, err = stream.Write(data[:i])
		if err != nil {
			log.Errorf("Failed to write to stream: %v", err)
			localConn.Close()
			//localConnWrite.Close()
			stream.Close()
			return
		}

		// stream to proxy
		go func() {
			buf := make([]byte, 16380)
			for {
				i, err := io.ReadAtLeast(stream, buf, 1)
				if err != nil {
					log.Print(err)
					go localConn.Close()
					go stream.Close()
					return
				}
				i, err = localConn.WriteToUDP(buf[:i], otherEnd.Load().(*net.UDPAddr))
				if err != nil {
					log.Print(err)
					go localConn.Close()
					go stream.Close()
					return
				}
			}
		}()

		// proxy to stream
		buf := make([]byte, 16380)
		for {
			i, oe, err := localConn.ReadFromUDP(buf)
			if err != nil {
				log.Print(err)
				go localConn.Close()
				go stream.Close()
				return
			}
			otherEnd.Store(oe)
			i, err = stream.Write(buf[:i])
			if err != nil {
				log.Print(err)
				go localConn.Close()
				go stream.Close()
				return
			}
		}
	}

}

func routeTCP(sta *client.State, adminUID []byte) {
	tcpListener, err := net.Listen("tcp", sta.LocalHost+":"+sta.LocalPort)
	if err != nil {
		log.Fatal(err)
	}
	var sesh *mux.Session
	for {
		localConn, err := tcpListener.Accept()
		if err != nil {
			log.Fatal(err)
			continue
		}
		if sesh == nil || sesh.IsClosed() {
			sesh = makeSession(sta, adminUID != nil, false)
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

func main() {
	// Should be 127.0.0.1 to listen to a proxy client on this machine
	var localHost string
	// port used by proxy clients to communicate with cloak client
	var localPort string
	// The ip of the proxy server
	var remoteHost string
	// The proxy port,should be 443
	var remotePort string
	var udp bool
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
		flag.StringVar(&localHost, "i", "127.0.0.1", "localHost: Cloak listens to proxy clients on this ip")
		flag.StringVar(&localPort, "l", "1984", "localPort: Cloak listens to proxy clients on this port")
		flag.StringVar(&remoteHost, "s", "", "remoteHost: IP of your proxy server")
		flag.StringVar(&remotePort, "p", "443", "remotePort: proxy port, should be 443")
		flag.BoolVar(&udp, "u", false, "udp: set this flag if the underlying proxy is using UDP protocol")
		flag.StringVar(&config, "c", "ckclient.json", "config: path to the configuration file or options seperated with semicolons")
		flag.StringVar(&b64AdminUID, "a", "", "adminUID: enter the adminUID to serve the admin api")
		askVersion := flag.Bool("v", false, "Print the version number")
		printUsage := flag.Bool("h", false, "Print this message")
		verbosity := flag.String("verbosity", "info", "verbosity level")
		flag.Parse()

		if *askVersion {
			fmt.Printf("ck-client %s", version)
			return
		}

		if *printUsage {
			flag.Usage()
			return
		}

		lvl, err := log.ParseLevel(*verbosity)
		if err != nil {
			log.Fatal(err)
		}
		log.SetLevel(lvl)

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

	var adminUID []byte
	if b64AdminUID != "" {
		adminUID, err = base64.StdEncoding.DecodeString(b64AdminUID)
		if err != nil {
			log.Fatal(err)
		}
	}

	if adminUID != nil {
		log.Infof("API base is %v:%v", listeningIP, sta.LocalPort)
		sta.SessionID = 0
		sta.UID = adminUID
		sta.NumConn = 1
	} else {
		var network string
		if udp {
			network = "udp"
		} else {
			network = "tcp"
		}
		log.Infof("Listening on %v %v:%v for proxy clients", network, listeningIP, sta.LocalPort)
	}

	if udp {
		routeUDP(sta, adminUID)
	} else {
		routeTCP(sta, adminUID)
	}
}
