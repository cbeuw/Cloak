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

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/server"
	log "github.com/sirupsen/logrus"
)

var version string

func resolveBindAddr(bindAddrs []string) ([]net.Addr, error) {
	var addrs []net.Addr
	for _, addr := range bindAddrs {
		bindAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, bindAddr)
	}
	return addrs, nil
}

// parse what shadowsocks server wants us to bind and harmonise it with what's already in bindAddr from
// our own config's BindAddr. This prevents duplicate bindings etc.
func parseSSBindAddr(ssRemoteHost string, ssRemotePort string, ckBindAddr *[]net.Addr) error {
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
		return fmt.Errorf("unable to resolve bind address provided by SS: %v", err)
	}

	shouldAppend := true
	for i, addr := range *ckBindAddr {
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
				(*ckBindAddr)[i] = ssBindAddr
			}
		}
	}
	if shouldAppend {
		*ckBindAddr = append(*ckBindAddr, ssBindAddr)
	}
	return nil
}

func main() {
	var config string

	var pluginMode bool

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	if os.Getenv("SS_LOCAL_HOST") != "" && os.Getenv("SS_LOCAL_PORT") != "" {
		pluginMode = true
		config = os.Getenv("SS_PLUGIN_OPTIONS")
	} else {
		flag.StringVar(&config, "c", "server.json", "config: path to the configuration file or its content")
		askVersion := flag.Bool("v", false, "Print the version number")
		printUsage := flag.Bool("h", false, "Print this message")

		genUIDScript := flag.Bool("u", false, "Generate a UID to STDOUT")
		genKeyPairScript := flag.Bool("k", false, "Generate a pair of public and private key and output to STDOUT in the format of <public key>,<private key>")

		genUIDHuman := flag.Bool("uid", false, "Generate and print out a UID")
		genKeyPairHuman := flag.Bool("key", false, "Generate and print out a public-private key pair")

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
		if *genUIDScript || *genUIDHuman {
			uid := generateUID()
			if *genUIDScript {
				fmt.Println(uid)
			} else {
				fmt.Printf("\x1B[35mYour UID is:\u001B[0m %s\n", uid)
			}
			return
		}
		if *genKeyPairScript || *genKeyPairHuman {
			pub, pv := generateKeyPair()
			if *genKeyPairScript {
				fmt.Printf("%v,%v\n", pub, pv)
			} else {
				fmt.Printf("\x1B[36mYour PUBLIC key is:\x1B[0m %65s\n", pub)
				fmt.Printf("\x1B[33mYour PRIVATE key is (keep it secret):\x1B[0m %47s\n", pv)
			}
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

	raw, err := server.ParseConfig(config)
	if err != nil {
		log.Fatalf("Configuration file error: %v", err)
	}

	bindAddr, err := resolveBindAddr(raw.BindAddr)
	if err != nil {
		log.Fatalf("unable to parse BindAddr: %v", err)
	}

	// in case the user hasn't specified any local address to bind to, we listen on 443 and 80
	if !pluginMode && len(bindAddr) == 0 {
		https, _ := net.ResolveTCPAddr("tcp", ":443")
		http, _ := net.ResolveTCPAddr("tcp", ":80")
		bindAddr = []net.Addr{https, http}
	}

	// when cloak is started as a shadowsocks plugin, we parse the address ss-server
	// is listening on into ProxyBook, and we parse the list of bindAddr
	if pluginMode {
		ssLocalHost := os.Getenv("SS_LOCAL_HOST")
		ssLocalPort := os.Getenv("SS_LOCAL_PORT")
		raw.ProxyBook["shadowsocks"] = []string{"tcp", net.JoinHostPort(ssLocalHost, ssLocalPort)}

		ssRemoteHost := os.Getenv("SS_REMOTE_HOST")
		ssRemotePort := os.Getenv("SS_REMOTE_PORT")
		err = parseSSBindAddr(ssRemoteHost, ssRemotePort, &bindAddr)
		if err != nil {
			log.Fatalf("failed to parse SS_REMOTE_HOST and SS_REMOTE_PORT: %v", err)
		}
	}

	sta, err := server.InitState(raw, common.RealWorldState)
	if err != nil {
		log.Fatalf("unable to initialise server state: %v", err)
	}

	listen := func(bindAddr net.Addr) {
		listener, err := net.Listen("tcp", bindAddr.String())
		log.Infof("Listening on %v", bindAddr)
		if err != nil {
			log.Fatal(err)
		}
		server.Serve(listener, sta)
	}

	for i, addr := range bindAddr {
		if i != len(bindAddr)-1 {
			go listen(addr)
		} else {
			// we block the main goroutine here so it doesn't quit
			listen(addr)
		}
	}

}
