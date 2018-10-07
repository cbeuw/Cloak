// +build go1.11

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/client/TLS"
	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/util"
)

var version string

func pipe(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
	buf := make([]byte, 20480)
	for {
		i, err := src.Read(buf)
		if err != nil {
			go dst.Close()
			go src.Close()
			return
		}
		_, err = dst.Write(buf[:i])
		if err != nil {
			go dst.Close()
			go src.Close()
			return
		}
	}
}

// This establishes a connection with ckserver and performs a handshake
func makeRemoteConn(sta *client.State) net.Conn {

	d := net.Dialer{Control: protector}

	clientHello := TLS.ComposeInitHandshake(sta)
	remoteConn, err := d.Dial("tcp", sta.SS_REMOTE_HOST+":"+sta.SS_REMOTE_PORT)
	if err != nil {
		log.Printf("Connecting to remote: %v\n", err)
		return nil
	}
	_, err = remoteConn.Write(clientHello)
	if err != nil {
		log.Printf("Sending ClientHello: %v\n", err)
		return nil
	}

	// Three discarded messages: ServerHello, ChangeCipherSpec and Finished
	discardBuf := make([]byte, 1024)
	for c := 0; c < 3; c++ {
		_, err = util.ReadTillDrain(remoteConn, discardBuf)
		if err != nil {
			log.Printf("Reading discarded message %v: %v\n", c, err)
			return nil
		}
	}

	reply := TLS.ComposeReply()
	_, err = remoteConn.Write(reply)
	if err != nil {
		log.Printf("Sending reply to remote: %v\n", err)
		return nil
	}

	return remoteConn

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

	sta := &client.State{
		SS_LOCAL_HOST:  localHost,
		SS_LOCAL_PORT:  localPort,
		SS_REMOTE_HOST: remoteHost,
		SS_REMOTE_PORT: remotePort,
		Now:            time.Now,
	}
	err := sta.ParseConfig(pluginOpts)
	if err != nil {
		log.Fatal(err)
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

	initRemoteConn := makeRemoteConn(sta)

	obfs := util.MakeObfs(sta.SID)
	deobfs := util.MakeDeobfs(sta.SID)
	// TODO: where to put obfs deobfs and rtd?
	sesh := mux.MakeSession(0, initRemoteConn, obfs, deobfs, util.ReadTillDrain)

	for i := 0; i < sta.NumConn-1; i++ {
		go func() {
			conn := makeRemoteConn(sta)
			sesh.AddConnection(conn)
		}()
	}

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
			stream, err := sesh.OpenStream()
			if err != nil {
				ssConn.Close()
			}
			go pipe(ssConn, stream)
			pipe(stream, ssConn)
		}()
	}

}
