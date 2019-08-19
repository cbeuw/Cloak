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
		go util.Pipe(webConn, conn, 0)
		go util.Pipe(conn, webConn, 0)
	}

	ci, finishHandshake, err := server.PrepareConnection(data, sta, conn)
	if err != nil {
		log.WithFields(log.Fields{
			"remoteAddr":       remoteAddr,
			"UID":              b64(ci.UID),
			"sessionId":        ci.SessionId,
			"proxyMethod":      ci.ProxyMethod,
			"encryptionMethod": ci.EncryptionMethod,
		}).Warn(err)
		goWeb()
		return
	}

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	obfuscator, err := mux.GenerateObfs(ci.EncryptionMethod, sessionKey)
	if err != nil {
		log.Error(err)
		goWeb()
		return
	}

	// adminUID can use the server as normal with unlimited QoS credits. The adminUID is not
	// added to the userinfo database. The distinction between going into the admin mode
	// and normal proxy mode is that sessionID needs == 0 for admin mode
	if bytes.Equal(ci.UID, sta.AdminUID) && ci.SessionId == 0 {
		err = finishHandshake(sessionKey)
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("finished handshake")
		seshConfig := &mux.SessionConfig{
			Obfuscator: obfuscator,
			Valve:      nil,
			UnitRead:   util.ReadTLS,
		}
		sesh := mux.MakeSession(0, seshConfig)
		sesh.AddConnection(conn)
		//TODO: Router could be nil in cnc mode
		log.WithField("remoteAddr", conn.RemoteAddr()).Info("New admin session")
		err = http.Serve(sesh, sta.LocalAPIRouter)
		if err != nil {
			log.Error(err)
			return
		}
	}

	var user *server.ActiveUser
	if sta.IsBypass(ci.UID) {
		user, err = sta.Panel.GetBypassUser(ci.UID)
	} else {
		user, err = sta.Panel.GetUser(ci.UID)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"UID":        b64(ci.UID),
			"remoteAddr": remoteAddr,
			"error":      err,
		}).Warn("+1 unauthorised UID")
		goWeb()
		return
	}

	seshConfig := &mux.SessionConfig{
		Obfuscator: obfuscator,
		Valve:      nil,
		UnitRead:   util.ReadTLS,
		Unordered:  ci.Unordered,
	}
	sesh, existing, err := user.GetSession(ci.SessionId, seshConfig)
	if err != nil {
		user.DeleteSession(ci.SessionId, "")
		log.Error(err)
		return
	}

	if existing {
		err = finishHandshake(sesh.SessionKey)
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("finished handshake")
		sesh.AddConnection(conn)
		return
	}

	err = finishHandshake(sessionKey)
	if err != nil {
		log.Error(err)
		return
	}
	log.Trace("finished handshake")

	log.WithFields(log.Fields{
		"UID":       b64(ci.UID),
		"sessionID": ci.SessionId,
	}).Info("New session")
	sesh.AddConnection(conn)

	for {
		newStream, err := sesh.Accept()
		if err != nil {
			if err == mux.ErrBrokenSession {
				log.WithFields(log.Fields{
					"UID":       b64(ci.UID),
					"sessionID": ci.SessionId,
					"reason":    sesh.TerminalMsg(),
				}).Info("Session closed")
				user.DeleteSession(ci.SessionId, "")
				return
			} else {
				continue
			}
		}
		proxyAddr := sta.ProxyBook[ci.ProxyMethod]
		localConn, err := net.Dial(proxyAddr.Network(), proxyAddr.String())
		if err != nil {
			log.Errorf("Failed to connect to %v: %v", ci.ProxyMethod, err)
			user.DeleteSession(ci.SessionId, "Failed to connect to proxy server")
			continue
		}
		log.Debugf("%v endpoint has been successfully connected", ci.ProxyMethod)

		go util.Pipe(localConn, newStream, 0)
		go util.Pipe(newStream, localConn, sta.Timeout)

	}

}

func main() {
	// server in ss config, the outbound listening ip
	var bindHost string
	// Outbound listening ip, should be 443
	var bindPort string
	var config string

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
		verbosity := flag.String("verbosity", "info", "verbosity level")

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

		lvl, err := log.ParseLevel(*verbosity)
		if err != nil {
			log.Fatal(err)
		}
		log.SetLevel(lvl)

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
		sta.ProxyBook["shadowsocks"], err = net.ResolveTCPAddr("tcp", ssLocalHost+":"+ssLocalPort)
		if err != nil {
			log.Fatal(err)
		}
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
