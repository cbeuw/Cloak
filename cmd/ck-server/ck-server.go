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

	// TODO: potential fingerprint for active probers here
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	i, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil {
		go conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	data := buf[:i]

	goWeb := func() {
		_, remotePort, _ := net.SplitHostPort(conn.LocalAddr().String())
		webConn, err := net.Dial("tcp", net.JoinHostPort(sta.RedirAddr.String(), remotePort))
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
	obfuscator, err := mux.GenerateObfs(ci.EncryptionMethod, sessionKey, ci.Transport.HasRecordLayer())
	if err != nil {
		log.Error(err)
		goWeb()
		return
	}

	// adminUID can use the server as normal with unlimited QoS credits. The adminUID is not
	// added to the userinfo database. The distinction between going into the admin mode
	// and normal proxy mode is that sessionID needs == 0 for admin mode
	if bytes.Equal(ci.UID, sta.AdminUID) && ci.SessionId == 0 {
		preparedConn, err := finishHandshake(sessionKey)
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("finished handshake")
		seshConfig := &mux.SessionConfig{
			Obfuscator: obfuscator,
			Valve:      nil,
			UnitRead:   ci.Transport.UnitReadFunc(),
		}
		sesh := mux.MakeSession(0, seshConfig)
		sesh.AddConnection(preparedConn)
		//TODO: Router could be nil in cnc mode
		log.WithField("remoteAddr", preparedConn.RemoteAddr()).Info("New admin session")
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
		UnitRead:   ci.Transport.UnitReadFunc(),
		Unordered:  ci.Unordered,
	}
	sesh, existing, err := user.GetSession(ci.SessionId, seshConfig)
	if err != nil {
		user.CloseSession(ci.SessionId, "")
		log.Error(err)
		return
	}

	if existing {
		preparedConn, err := finishHandshake(sesh.SessionKey)
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("finished handshake")
		sesh.AddConnection(preparedConn)
		return
	}

	preparedConn, err := finishHandshake(sessionKey)
	if err != nil {
		log.Error(err)
		return
	}
	log.Trace("finished handshake")

	log.WithFields(log.Fields{
		"UID":       b64(ci.UID),
		"sessionID": ci.SessionId,
	}).Info("New session")
	sesh.AddConnection(preparedConn)

	for {
		newStream, err := sesh.Accept()
		if err != nil {
			if err == mux.ErrBrokenSession {
				log.WithFields(log.Fields{
					"UID":       b64(ci.UID),
					"sessionID": ci.SessionId,
					"reason":    sesh.TerminalMsg(),
				}).Info("Session closed")
				user.CloseSession(ci.SessionId, "")
				return
			} else {
				continue
			}
		}
		proxyAddr := sta.ProxyBook[ci.ProxyMethod]
		localConn, err := net.Dial(proxyAddr.Network(), proxyAddr.String())
		if err != nil {
			log.Errorf("Failed to connect to %v: %v", ci.ProxyMethod, err)
			user.CloseSession(ci.SessionId, "Failed to connect to proxy server")
			continue
		}
		log.Tracef("%v endpoint has been successfully connected", ci.ProxyMethod)

		go util.Pipe(localConn, newStream, 0)
		go util.Pipe(newStream, localConn, sta.Timeout)

	}

}

func main() {
	// set TLS bind host through commandline for legacy support, default 0.0.0,0
	var ssRemoteHost string
	// set TLS bind port through commandline for legacy support, default 443
	var ssRemotePort string
	var config string

	var pluginMode bool

	if os.Getenv("SS_LOCAL_HOST") != "" && os.Getenv("SS_LOCAL_PORT") != "" {
		pluginMode = true
		ssRemoteHost = os.Getenv("SS_REMOTE_HOST")
		ssRemotePort = os.Getenv("SS_REMOTE_PORT")
		config = os.Getenv("SS_PLUGIN_OPTIONS")
	} else {
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

		log.Infof("Starting standalone mode")
	}
	sta, _ := server.InitState(time.Now)

	err := sta.ParseConfig(config)
	if err != nil {
		log.Fatalf("Configuration file error: %v", err)
	}

	if !pluginMode && len(sta.BindAddr) == 0 {
		log.Fatalf("bind address cannot be empty")
	}

	// when cloak is started as a shadowsocks plugin
	if pluginMode {
		ssLocalHost := os.Getenv("SS_LOCAL_HOST")
		ssLocalPort := os.Getenv("SS_LOCAL_PORT")

		sta.ProxyBook["shadowsocks"], err = net.ResolveTCPAddr("tcp", net.JoinHostPort(ssLocalHost, ssLocalPort))
		if err != nil {
			log.Fatal(err)
		}

		var ssBind string
		// When listening on an IPv6 and IPv4, SS gives REMOTE_HOST as e.g. ::|0.0.0.0
		v4nv6 := len(strings.Split(ssRemoteHost, "|")) == 2
		if v4nv6 {
			ssBind = ":" + ssRemotePort
		} else {
			ssBind = net.JoinHostPort(ssRemoteHost, ssRemotePort)
		}
		ssBindAddr, err := net.ResolveTCPAddr("tcp", ssBind)
		if err != nil {
			log.Fatalf("unable to resolve bind address provided by SS: %v", err)
		}

		shouldAppend := true
		for i, addr := range sta.BindAddr {
			if addr.String() == ssBindAddr.String() {
				shouldAppend = false
			}
			if addr.String() == ":"+ssRemotePort { // already listening on all interfaces
				shouldAppend = false
			}
			if addr.String() == "0.0.0.0:"+ssRemotePort || addr.String() == "[::]:"+ssRemotePort {
				// if config listens on one ip version but ss wants to listen on both,
				// listen on both
				if ssBindAddr.String() == ":"+ssRemotePort {
					shouldAppend = true
					sta.BindAddr[i] = ssBindAddr
				}
			}
		}
		if shouldAppend {
			sta.BindAddr = append(sta.BindAddr, ssBindAddr)
		}
	}

	listen := func(bindAddr net.Addr) {
		listener, err := net.Listen("tcp", bindAddr.String())
		log.Infof("Listening on %v", bindAddr)
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

	for i, addr := range sta.BindAddr {
		if i != len(sta.BindAddr)-1 {
			go listen(addr)
		} else {
			listen(addr)
		}
	}

}
