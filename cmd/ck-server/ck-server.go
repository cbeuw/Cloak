package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server"
	"github.com/cbeuw/Cloak/internal/util"
)

var b64 = base64.StdEncoding
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

func dispatchConnection(conn net.Conn, sta *server.State) {
	goWeb := func(data []byte) {
		webConn, err := net.Dial("tcp", sta.RedirAddr)
		if err != nil {
			log.Printf("Making connection to redirection server: %v\n", err)
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
		log.Printf("+1 non Cloak non (or malformed) TLS traffic from %v\n", conn.RemoteAddr())
		goWeb(data)
		return
	}

	isCloak, UID, sessionID, proxyMethod, encryptionMethod, sessionKey := server.TouchStone(ch, sta)
	if !isCloak {
		log.Printf("+1 non Cloak TLS traffic from %v\n", conn.RemoteAddr())
		goWeb(data)
		return
	}
	if _, ok := sta.ProxyBook[proxyMethod]; !ok {
		log.Printf("+1 Cloak TLS traffic with invalid proxy method `%v` from %v\n", proxyMethod, conn.RemoteAddr())
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

	/*
		// adminUID can use the server as normal with unlimited QoS credits. The adminUID is not
		// added to the userinfo database. The distinction between going into the admin mode
		// and normal proxy mode is that sessionID needs == 0 for admin mode
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
				}
				_, err = conn.Write(resp)
				if err != nil {
					log.Println(err)
					return
				}
			}

		}
	*/

	user, err := sta.Panel.GetUser(UID)
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

	var crypto mux.Crypto
	switch encryptionMethod {
	case 0x00:
		crypto = &mux.Plain{}
	case 0x01:
		crypto, err = mux.MakeAESGCMCipher(UID)
		if err != nil {
			log.Println(err)
			goWeb(data)
			return
		}
	case 0x02:
		crypto, err = mux.MakeCPCipher(UID)
		if err != nil {
			log.Println(err)
			goWeb(data)
			return
		}
	default:
		log.Println("Unknown encryption method")
		goWeb(data)
		return
	}

	sesh, existing, err := user.GetSession(sessionID, mux.MakeObfs(sessionKey, crypto), mux.MakeDeobfs(sessionKey, crypto), util.ReadTLS)
	if err != nil {
		user.DelSession(sessionID)
		log.Println(err)
		return
	}

	if existing {
		sesh.AddConnection(conn)
		return
	} else {
		log.Printf("New session from UID:%v, sessionID:%v\n", b64.EncodeToString(UID), sessionID)
		sesh.AddConnection(conn)
		for {
			newStream, err := sesh.Accept()
			if err != nil {
				if err == mux.ErrBrokenSession {
					log.Printf("Session closed for UID:%v, sessionID:%v\n", b64.EncodeToString(UID), sessionID)
					user.DelSession(sessionID)
					return
				} else {
					continue
				}
			}
			localConn, err := net.Dial("tcp", sta.ProxyBook[proxyMethod])
			if err != nil {
				log.Printf("Failed to connect to %v: %v\n", proxyMethod, err)
				continue
			}
			go pipe(localConn, newStream)
			go pipe(newStream, localConn)
		}
	}

}

func main() {
	// server in ss config, the outbound listening ip
	var bindHost string
	// Outbound listening ip, should be 443
	var bindPort string
	var config string

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if os.Getenv("SS_LOCAL_HOST") != "" {
		bindHost = os.Getenv("SS_REMOTE_HOST")
		bindPort = os.Getenv("SS_REMOTE_PORT")
		config = os.Getenv("SS_PLUGIN_OPTIONS")
	} else {
		flag.StringVar(&bindHost, "s", "0.0.0.0", "bindHost: ip to bind to, set to 0.0.0.0 to listen to everything")
		flag.StringVar(&bindPort, "p", "443", "bindPort: port to bind to, should be 443")
		flag.StringVar(&config, "c", "server.json", "config: path to the configuration file or its content")
		askVersion := flag.Bool("v", false, "Print the version number")
		printUsage := flag.Bool("h", false, "Print this message")

		genUID := flag.Bool("u", false, "Generate a UID")
		genKeyPair := flag.Bool("k", false, "Generate a pair of public and private key, output in the format of pubkey,pvkey")

		pprofAddr := flag.String("d", "", "debug use: ip:port to be listened by pprof profiler")

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

		if *pprofAddr != "" {
			startPprof(*pprofAddr)
		}

		log.Printf("Starting standalone mode, listening on %v:%v", bindHost, bindPort)
	}
	sta, _ := server.InitState(bindHost, bindPort, time.Now)

	err := sta.ParseConfig(config)
	if err != nil {
		log.Fatalf("Configuration file error: %v", err)
	}

	// when cloak is started as a shadowsocks plugin
	if os.Getenv("SS_LOCAL_HOST") != "" && os.Getenv("SS_LOCAL_PORT") != "" {
		ssLocalHost := os.Getenv("SS_LOCAL_HOST")
		ssLocalPort := os.Getenv("SS_LOCAL_PORT")
		if net.ParseIP(ssLocalHost).To4() == nil {
			ssLocalHost = "[" + ssLocalHost + "]"
		}
		sta.ProxyBook["shadowsocks"] = ssLocalHost + ":" + ssLocalPort
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
	listeningIP := strings.Split(sta.BindHost, "|")
	for i, ip := range listeningIP {
		if net.ParseIP(ip).To4() == nil {
			// IPv6 needs square brackets
			ip = "[" + ip + "]"
		}

		// The last listener must block main() because the program exits on main return.
		if i == len(listeningIP)-1 {
			listen(ip, sta.BindPort)
		} else {
			go listen(ip, sta.BindPort)
		}
	}

}
