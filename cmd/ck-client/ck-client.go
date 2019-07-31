// +build go1.11

package main

import (
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/client/TLS"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/util"
)

var version string

func pipe(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
	// The maximum size of TLS message will be 16380+12+16. 12 because of the stream header and 16
	// because of the salt/mac
	// 16408 is the max TLS message size on Firefox
	buf := make([]byte, 16380)
	for {
		i, err := io.ReadAtLeast(src, buf, 1)
		if err != nil {
			go dst.Close()
			go src.Close()
			return
		}
		i, err = dst.Write(buf[:i])
		if err != nil {
			go dst.Close()
			go src.Close()
			return
		}
	}
}

// This establishes a connection with ckserver and performs a handshake
func makeRemoteConn(sta *client.State) (net.Conn, error) {

	// For android
	d := net.Dialer{Control: protector}

	clientHello := TLS.ComposeInitHandshake(sta)
	connectingIP := sta.RemoteHost
	if net.ParseIP(connectingIP).To4() == nil {
		// IPv6 needs square brackets
		connectingIP = "[" + connectingIP + "]"
	}
	remoteConn, err := d.Dial("tcp", connectingIP+":"+sta.RemotePort)
	if err != nil {
		log.Printf("Connecting to remote: %v\n", err)
		return nil, err
	}
	_, err = remoteConn.Write(clientHello)
	if err != nil {
		log.Printf("Sending ClientHello: %v\n", err)
		return nil, err
	}

	// Three discarded messages: ServerHello, ChangeCipherSpec and Finished
	discardBuf := make([]byte, 1024)
	for c := 0; c < 3; c++ {
		_, err = util.ReadTLS(remoteConn, discardBuf)
		if err != nil {
			log.Printf("Reading discarded message %v: %v\n", c, err)
			return nil, err
		}
	}

	reply := TLS.ComposeReply()
	_, err = remoteConn.Write(reply)
	if err != nil {
		log.Printf("Sending reply to remote: %v\n", err)
		return nil, err
	}

	return remoteConn, nil

}

func makeSession(sta *client.State) *mux.Session {
	log.Println("Attemtping to start a new session")
	if !sta.IsAdmin {
		// sessionID is usergenerated. There shouldn't be a security concern because the scope of
		// sessionID is limited to its UID.
		quad := make([]byte, 4)
		rand.Read(quad)
		sta.SessionID = binary.BigEndian.Uint32(quad)
	}

	sta.UpdateIntervalKeys()

	_, tthKey := sta.GetIntervalKeys()
	sesh := mux.MakeSession(sta.SessionID, mux.UNLIMITED_VALVE, mux.MakeObfs(tthKey, sta.Cipher), mux.MakeDeobfs(tthKey, sta.Cipher), util.ReadTLS)

	var wg sync.WaitGroup
	for i := 0; i < sta.NumConn; i++ {
		wg.Add(1)
		go func() {
		makeconn:
			conn, err := makeRemoteConn(sta)
			if err != nil {
				log.Printf("Failed to establish new connections to remote: %v\n", err)
				time.Sleep(time.Second * 3)
				goto makeconn
			}
			sesh.AddConnection(conn)
			wg.Done()
		}()
	}
	wg.Wait()

	log.Printf("Session %v established", sta.SessionID)
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

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log_init()

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
			fmt.Printf("ck-client %s\n", version)
			return
		}

		if *printUsage {
			flag.Usage()
			return
		}

		log.Println("Starting standalone mode")
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
	if sta.TicketTimeHint == 0 {
		log.Fatal("TicketTimeHint cannot be empty or 0")
	}

	listeningIP := sta.LocalHost
	if net.ParseIP(listeningIP).To4() == nil {
		// IPv6 needs square brackets
		listeningIP = "[" + listeningIP + "]"
	}
	listener, err := net.Listen("tcp", listeningIP+":"+sta.LocalPort)
	log.Println("Listening on " + listeningIP + ":" + sta.LocalPort)
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
		sta.IsAdmin = true
		sta.SessionID = 0
		sta.UID = adminUID
		sta.NumConn = 1
	}

	var sesh *mux.Session

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		if sesh == nil || sesh.IsClosed() {
			sesh = makeSession(sta)
		}
		go func() {
			data := make([]byte, 10240)
			i, err := io.ReadAtLeast(localConn, data, 1)
			if err != nil {
				log.Println(err)
				localConn.Close()
				return
			}
			stream, err := sesh.OpenStream()
			if err != nil {
				log.Println(err)
				localConn.Close()
				return
			}
			_, err = stream.Write(data[:i])
			if err != nil {
				log.Println(err)
				localConn.Close()
				stream.Close()
				return
			}
			go pipe(localConn, stream)
			pipe(stream, localConn)
		}()
	}

}
