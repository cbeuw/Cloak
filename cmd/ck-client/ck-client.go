// +build go1.11

package main

import (
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
	isAdmin := new(bool)

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
		flag.StringVar(&localPort, "l", "", "localPort: Cloak listens to proxy clients on this port")
		flag.StringVar(&remoteHost, "s", "", "remoteHost: IP of your proxy server")
		flag.StringVar(&remotePort, "p", "443", "remotePort: proxy port, should be 443")
		flag.StringVar(&config, "c", "ckclient.json", "config: path to the configuration file or options seperated with semicolons")
		askVersion := flag.Bool("v", false, "Print the version number")
		isAdmin = flag.Bool("a", false, "Admin mode")
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

	if *isAdmin {
		sta := client.InitState("", "", "", "", time.Now)
		err := sta.ParseConfig(config)
		if err != nil {
			log.Fatal(err)
		}
		err = adminPrompt(sta)
		if err != nil {
			log.Println(err)
		}
		return
	}

	sta := client.InitState(localHost, localPort, remoteHost, remotePort, time.Now)
	err := sta.ParseConfig(config)
	if err != nil {
		log.Fatal(err)
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
	log.Println("Listening for proxy clients on " + listeningIP + ":" + sta.LocalPort)
	if err != nil {
		log.Fatal(err)
	}

start:
	log.Println("Attemtping to start a new session")
	// sessionID is usergenerated. There shouldn't be a security concern because the scope of
	// sessionID is limited to its UID.
	rand.Seed(time.Now().UnixNano())
	sessionID := rand.Uint32()
	sta.SetSessionID(sessionID)
	var UNLIMITED_DOWN int64 = 1e15
	var UNLIMITED_UP int64 = 1e15
	valve := mux.MakeValve(1e12, 1e12, &UNLIMITED_DOWN, &UNLIMITED_UP)

	var crypto mux.Crypto
	switch sta.EncryptionMethod {
	case 0x00:
		crypto = &mux.Plain{}
	case 0x01:
		crypto, err = mux.MakeAESGCMCipher(sta.UID)
		if err != nil {
			log.Println(err)
			return
		}
	case 0x02:
		crypto, err = mux.MakeCPCipher(sta.UID)
		if err != nil {
			log.Println(err)
			return
		}
	}

	obfs := mux.MakeObfs(sta.UID, crypto)
	deobfs := mux.MakeDeobfs(sta.UID, crypto)
	sesh := mux.MakeSession(sessionID, valve, obfs, deobfs, util.ReadTLS)

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

	log.Printf("Session %v established", sessionID)

	for {
		if sesh.IsBroken() {
			goto start
		}
		localConn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
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
