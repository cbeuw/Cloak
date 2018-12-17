package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"github.com/cbeuw/Cloak/internal/util"
)

var version string

func pipe(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
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

func dispatchConnection(conn net.Conn, sta *server.State) {
	goWeb := func(data []byte) {
		webConn, err := net.Dial("tcp", sta.WebServerAddr)
		if err != nil {
			log.Printf("Making connection to redirection server: %v\n", err)
			go webConn.Close()
			return
		}
		webConn.Write(data)
		go pipe(webConn, conn)
		go pipe(conn, webConn)
	}

	buf := make([]byte, 1500)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	i, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil {
		go conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	data := buf[:i]
	ch, err := server.ParseClientHello(data)
	if err != nil {
		log.Printf("+1 non SS non (or malformed) TLS traffic from %v\n", conn.RemoteAddr())
		goWeb(data)
		return
	}

	isSS, UID, sessionID := server.TouchStone(ch, sta)
	if !isSS {
		log.Printf("+1 non SS TLS traffic from %v\n", conn.RemoteAddr())
		goWeb(data)
		return
	}

	finishHandshake := func() error {
		reply := server.ComposeReply(ch)
		_, err = conn.Write(reply)
		if err != nil {
			go conn.Close()
			return err
		}

		// Two discarded messages: ChangeCipherSpec and Finished
		discardBuf := make([]byte, 1024)
		for c := 0; c < 2; c++ {
			_, err = util.ReadTLS(conn, discardBuf)
			if err != nil {
				go conn.Close()
				return err
			}
		}
		return nil
	}

	if bytes.Equal(UID, sta.AdminUID) && sessionID == 0 {
		err = finishHandshake()
		if err != nil {
			log.Println(err)
			return
		}
		c := sta.Userpanel.MakeController(sta.AdminUID)
		for {
			n, err := conn.Read(data)
			if err != nil {
				log.Println(err)
				return
			}
			resp, err := c.HandleRequest(data[:n])
			if err != nil {
				log.Println(err)
				return
			}
			_, err = conn.Write(resp)
			if err != nil {
				log.Println(err)
				return
			}
		}

	}

	var user *usermanager.User
	if bytes.Equal(UID, sta.AdminUID) {
		user, err = sta.Userpanel.GetAndActivateAdminUser(UID)
	} else {
		user, err = sta.Userpanel.GetAndActivateUser(UID)
	}
	if err != nil {
		log.Printf("+1 unauthorised user from %v, uid: %x\n", conn.RemoteAddr(), UID)
		goWeb(data)
		return
	}

	err = finishHandshake()
	if err != nil {
		log.Println(err)
		return
	}

	if sesh, existing := user.GetSession(sessionID, mux.MakeObfs(UID), mux.MakeDeobfs(UID), util.ReadTLS); existing {
		sesh.AddConnection(conn)
		return
	} else {
		log.Printf("UID: %x\n", UID)
		sesh.AddConnection(conn)
		for {
			newStream, err := sesh.AcceptStream()
			if err != nil {
				log.Printf("Failed to get new stream: %v\n", err)
				if err == mux.ErrBrokenSession {
					log.Printf("Session closed: %x:%v\n", UID, sessionID)
					user.DelSession(sessionID)
					return
				} else {
					continue
				}
			}
			ssConn, err := net.Dial("tcp", sta.SS_LOCAL_HOST+":"+sta.SS_LOCAL_PORT)
			if err != nil {
				log.Printf("Failed to connect to ssserver: %v\n", err)
				continue
			}
			go pipe(ssConn, newStream)
			go pipe(newStream, ssConn)
		}
	}

}

func main() {
	runtime.SetBlockProfileRate(5)
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:8001", nil))
	}()
	// Should be 127.0.0.1 to listen to ss-server on this machine
	var localHost string
	// server_port in ss config, same as remotePort in plugin mode
	var localPort string
	// server in ss config, the outbound listening ip
	var remoteHost string
	// Outbound listening ip, should be 443
	var remotePort string
	var pluginOpts string

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if os.Getenv("SS_LOCAL_HOST") != "" {
		localHost = os.Getenv("SS_LOCAL_HOST")
		localPort = os.Getenv("SS_LOCAL_PORT")
		remoteHost = os.Getenv("SS_REMOTE_HOST")
		remotePort = os.Getenv("SS_REMOTE_PORT")
		pluginOpts = os.Getenv("SS_PLUGIN_OPTIONS")
	} else {
		localAddr := flag.String("r", "", "localAddr: 127.0.0.1:server_port as set in SS config")
		flag.StringVar(&remoteHost, "s", "0.0.0.0", "remoteHost: outbound listing ip, set to 0.0.0.0 to listen to everything")
		flag.StringVar(&remotePort, "p", "443", "remotePort: outbound listing port, should be 443")
		flag.StringVar(&pluginOpts, "c", "server.json", "pluginOpts: path to server.json or options seperated by semicolons")
		askVersion := flag.Bool("v", false, "Print the version number")
		printUsage := flag.Bool("h", false, "Print this message")

		genUID := flag.Bool("u", false, "Generate a UID")
		genKeyPair := flag.Bool("k", false, "Generate a pair of public and private key, output in the format of pubkey,pvkey")

		flag.Parse()

		if *askVersion {
			fmt.Printf("ck-server %s\n", version)
			return
		}
		if *printUsage {
			flag.Usage()
			return
		}
		if *genUID {
			fmt.Println(generateUID())
			return
		}
		if *genKeyPair {
			pub, pv := generateKeyPair()
			fmt.Printf("%v,%v", pub, pv)
			return
		}

		if *localAddr == "" {
			log.Fatal("Must specify localAddr")
		}
		localHost = strings.Split(*localAddr, ":")[0]
		localPort = strings.Split(*localAddr, ":")[1]
		log.Printf("Starting standalone mode, listening on %v:%v to ss at %v:%v\n", remoteHost, remotePort, localHost, localPort)
	}
	sta, _ := server.InitState(localHost, localPort, remoteHost, remotePort, time.Now, "userinfo.db")

	err := sta.ParseConfig(pluginOpts)
	if err != nil {
		log.Fatalf("Configuration file error: %v", err)
	}

	if sta.AdminUID == nil {
		log.Fatalln("AdminUID cannot be empty!")
	}

	go sta.UsedRandomCleaner()

	listen := func(addr, port string) {
		listener, err := net.Listen("tcp", addr+":"+port)
		log.Println("Listening on " + addr + ":" + port)
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("%v", err)
				continue
			}
			go dispatchConnection(conn, sta)
		}
	}

	// When listening on an IPv6 and IPv4, SS gives REMOTE_HOST as e.g. ::|0.0.0.0
	listeningIP := strings.Split(sta.SS_REMOTE_HOST, "|")
	for i, ip := range listeningIP {
		if net.ParseIP(ip).To4() == nil {
			// IPv6 needs square brackets
			ip = "[" + ip + "]"
		}

		// The last listener must block main() because the program exits on main return.
		if i == len(listeningIP)-1 {
			listen(ip, sta.SS_REMOTE_PORT)
		} else {
			go listen(ip, sta.SS_REMOTE_PORT)
		}
	}

}
