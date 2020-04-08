package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cbeuw/Cloak/internal/server"
	log "github.com/sirupsen/logrus"
)

var version string

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
		https, _ := net.ResolveTCPAddr("tcp", ":443")
		http, _ := net.ResolveTCPAddr("tcp", ":80")
		sta.BindAddr = []net.Addr{https, http}
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
			go server.DispatchConnection(conn, sta)
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
