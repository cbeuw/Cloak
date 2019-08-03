package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	"github.com/cbeuw/Cloak/internal/server"
	"github.com/cbeuw/Cloak/internal/util"
	log "github.com/sirupsen/logrus"
)

var b64 = base64.StdEncoding.EncodeToString
var version string

func dispatchConnection(conn net.Conn, sta *server.State) {
	remoteAddr := conn.RemoteAddr()
	var err error
	rejectLogger := log.WithFields(log.Fields{
		"remoteAddr": remoteAddr,
		"error":      err,
	})
	buf := make([]byte, 1500)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	i, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil {
		go conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	data := buf[:i]

	goWeb := func() {
		webConn, err := net.Dial("tcp", sta.RedirAddr)
		if err != nil {
			log.Errorf("Making connection to redirection server: %v", err)
			return
		}
		_, err = webConn.Write(data)
		if err != nil {
			log.Error("Failed to send first packet to redirection server", err)
		}
		go util.Pipe(webConn, conn)
		go util.Pipe(conn, webConn)
	}

	ch, err := server.ParseClientHello(data)
	if err != nil {
		rejectLogger.Warn("+1 non Cloak non (or malformed) TLS traffic")
		goWeb()
		return
	}

	UID, sessionID, proxyMethod, encryptionMethod, sharedSecret, err := server.TouchStone(ch, sta)
	if err != nil {
		rejectLogger.Warn("+1 non Cloak TLS traffic")
		goWeb()
		return
	}
	if _, ok := sta.ProxyBook[proxyMethod]; !ok {
		log.WithFields(log.Fields{
			"UID":         UID,
			"proxyMethod": proxyMethod,
		}).Warn("+1 Cloak TLS traffic with invalid proxy method")
		goWeb()
		return
	}

	finishHandshake := func(sessionKey []byte) error {
		reply := server.ComposeReply(ch, sharedSecret, sessionKey)
		_, err = conn.Write(reply)
		if err != nil {
			go conn.Close()
			return err
		}
		return nil
	}

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	obfuscator, err := mux.GenerateObfs(encryptionMethod, sessionKey)
	if err != nil {
		log.Error(err)
		goWeb()
	}

	// adminUID can use the server as normal with unlimited QoS credits. The adminUID is not
	// added to the userinfo database. The distinction between going into the admin mode
	// and normal proxy mode is that sessionID needs == 0 for admin mode
	if bytes.Equal(UID, sta.AdminUID) && sessionID == 0 {
		err = finishHandshake(sessionKey)
		if err != nil {
			log.Error(err)
			return
		}
		sesh := mux.MakeSession(0, mux.UNLIMITED_VALVE, obfuscator, util.ReadTLS)
		sesh.AddConnection(conn)
		//TODO: Router could be nil in cnc mode
		log.WithField("remoteAddr", conn.RemoteAddr()).Info("New admin session")
		err = http.Serve(sesh, sta.LocalAPIRouter)
		if err != nil {
			log.Error(err)
			return
		}
	}

	user, err := sta.Panel.GetUser(UID)
	if err != nil {
		log.WithFields(log.Fields{
			"UID":        b64(UID),
			"remoteAddr": remoteAddr,
			"error":      err,
		}).Warn("+1 unauthorised UID")
		goWeb()
		return
	}

	sesh, existing, err := user.GetSession(sessionID, obfuscator, util.ReadTLS)
	if err != nil {
		user.DelSession(sessionID)
		log.Error(err)
		return
	}

	if existing {
		err = finishHandshake(sesh.SessionKey)
		if err != nil {
			log.Error(err)
			return
		}
		sesh.AddConnection(conn)
		return
	}

	err = finishHandshake(sessionKey)
	if err != nil {
		log.Error(err)
		return
	}

	log.WithFields(log.Fields{
		"UID":       b64(UID),
		"sessionID": sessionID,
	}).Info("New session")
	sesh.AddConnection(conn)

	for {
		newStream, err := sesh.Accept()
		if err != nil {
			if err == mux.ErrBrokenSession {
				log.WithFields(log.Fields{
					"UID":       b64(UID),
					"sessionID": sessionID,
					"reason":    sesh.TerminalMsg(),
				}).Info("Session closed")
				user.DelSession(sessionID)
				return
			} else {
				continue
			}
		}
		localConn, err := net.Dial("tcp", sta.ProxyBook[proxyMethod])
		if err != nil {
			log.Errorf("Failed to connect to %v: %v", proxyMethod, err)
			sesh.Close()
			continue
		}
		go util.Pipe(localConn, newStream)
		go util.Pipe(newStream, localConn)
	}

}

func main() {
	// server in ss config, the outbound listening ip
	var bindHost string
	// Outbound listening ip, should be 443
	var bindPort string
	var config string

	log.SetLevel(log.DebugLevel)

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
			fmt.Printf("ck-server %s", version)
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
			runtime.SetBlockProfileRate(5)
			go func() {
				log.Info(http.ListenAndServe(*pprofAddr, nil))
			}()
			log.Infof("pprof listening on %v", *pprofAddr)

		}

		log.Infof("Starting standalone mode, listening on %v:%v", bindHost, bindPort)
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

	listen := func(addr, port string) {
		listener, err := net.Listen("tcp", addr+":"+port)
		log.Infof("Listening on " + addr + ":" + port)
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Errorf("%v", err)
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
