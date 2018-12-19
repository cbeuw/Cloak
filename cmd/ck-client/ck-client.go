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

	"github.com/cbeuw/Cloak/tree/master/internal/client"
	"github.com/cbeuw/Cloak/tree/master/internal/client/TLS"
	mux "github.com/cbeuw/Cloaktree/master/internal/multiplex"
	"github.com/cbeuw/Cloak/tree/master/internal/util"
)

var version string

func pipe(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
	// TODO: auto reconnect
	// The maximum size of TLS message will be 16396+12. 12 because of the stream header
	// 16408 is the max TLS message size on Firefox
	buf := make([]byte, 16396)
	for {
		i, err := io.ReadAtLeast(src, buf, 1)
		if err != nil || i == 0 {
			go dst.Close()
			go src.Close()
			return
		}
		i, err = dst.Write(buf[:i])
		if err != nil || i == 0 {
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
	remoteConn, err := d.Dial("tcp", sta.SS_REMOTE_HOST+":"+sta.SS_REMOTE_PORT)
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

func adminPrompt(sta *client.State) error {
	a, err := adminHandshake(sta)
	if err != nil {
		return err
	}
	log.Println(err)
	buf := make([]byte, 16000)
	for {
		req, err := a.getRequest()
		if err != nil {
			log.Println(err)
			continue
		}
		a.adminConn.Write(req)
		n, err := a.adminConn.Read(buf)
		if err != nil {
			return err
		}
		resp, err := a.checkAndDecrypt(buf[:n])
		if err != nil {
			return err
		}
		fmt.Println(string(resp))
	}
}

func main() {
	// Should be 127.0.0.1 to listen to ss-local on this machine
	var localHost string
	// server_port in ss config, ss sends data on loopback using this port
	var localPort string
	// The ip of the proxy server
	var remoteHost string
	// The proxy port,should be 443
	var remotePort string
	var pluginOpts string
	var isAdmin *bool

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log_init()

	if os.Getenv("SS_LOCAL_HOST") != "" {
		localHost = os.Getenv("SS_LOCAL_HOST")
		localPort = os.Getenv("SS_LOCAL_PORT")
		remoteHost = os.Getenv("SS_REMOTE_HOST")
		remotePort = os.Getenv("SS_REMOTE_PORT")
		pluginOpts = os.Getenv("SS_PLUGIN_OPTIONS")
	} else {
		localHost = "127.0.0.1"
		flag.StringVar(&localPort, "l", "", "localPort: same as server_port in ss config, the plugin listens to SS using this")
		flag.StringVar(&remoteHost, "s", "", "remoteHost: IP of your proxy server")
		flag.StringVar(&remotePort, "p", "443", "remotePort: proxy port, should be 443")
		flag.StringVar(&pluginOpts, "c", "ckclient.json", "pluginOpts: path to ckclient.json or options seperated with semicolons")
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

		log.Printf("Starting standalone mode. Listening for ss on %v:%v\n", localHost, localPort)
	}

	// sessionID is usergenerated. There shouldn't be a security concern because the scope of
	// sessionID is limited to its UID.
	rand.Seed(time.Now().UnixNano())
	var sessionID uint32
	if *isAdmin {
		sessionID = 0
	} else {
		sessionID = rand.Uint32()
	}

	// opaque is used to generate the padding of session ticket
	sta := client.InitState(localHost, localPort, remoteHost, remotePort, time.Now, sessionID)
	err := sta.ParseConfig(pluginOpts)
	if err != nil {
		log.Fatal(err)
	}

	if *isAdmin {
		err = adminPrompt(sta)
		if err != nil {
			log.Println(err)
		}
		return
	}

	if sta.SS_LOCAL_PORT == "" {
		log.Fatal("Must specify localPort")
	}
	if sta.SS_REMOTE_HOST == "" {
		log.Fatal("Must specify remoteHost")
	}
	if sta.TicketTimeHint == 0 {
		log.Fatal("TicketTimeHint cannot be empty or 0")
	}

	var UNLIMITED int64 = 1e12
	valve := mux.MakeValve(1e12, 1e12, &UNLIMITED, &UNLIMITED)
	obfs := mux.MakeObfs(sta.UID)
	deobfs := mux.MakeDeobfs(sta.UID)
	sesh := mux.MakeSession(0, valve, obfs, deobfs, util.ReadTLS)

	var wg sync.WaitGroup
	for i := 0; i < sta.NumConn; i++ {
		wg.Add(1)
		go func() {
			conn, err := makeRemoteConn(sta)
			if err != nil {
				log.Printf("Failed to establish new connections to remote: %v\n", err)
				return
			}
			sesh.AddConnection(conn)
			wg.Done()
		}()
	}
	wg.Wait()

	// TODO: ipv6
	listener, err := net.Listen("tcp", sta.SS_LOCAL_HOST+":"+sta.SS_LOCAL_PORT)
	if err != nil {
		log.Fatal(err)
	}
	for {
		ssConn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go func() {
			data := make([]byte, 10240)
			i, err := io.ReadAtLeast(ssConn, data, 1)
			if err != nil {
				log.Println(err)
				ssConn.Close()
				return
			}
			stream, err := sesh.OpenStream()
			if err != nil {
				log.Println(err)
				ssConn.Close()
				return
			}
			_, err = stream.Write(data[:i])
			if err != nil {
				log.Println(err)
				ssConn.Close()
				stream.Close()
				return
			}
			go pipe(ssConn, stream)
			pipe(stream, ssConn)
		}()
	}

}
