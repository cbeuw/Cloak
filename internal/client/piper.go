package client

import (
	"github.com/cbeuw/Cloak/internal/common"
	"io"
	"net"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
)

func RouteUDP(bindFunc func() (*net.UDPConn, error), streamTimeout time.Duration, singleplex bool, newSeshFunc func() *mux.Session) {
	var sesh *mux.Session
	localConn, err := bindFunc()
	if err != nil {
		log.Fatal(err)
	}

	streams := make(map[string]*mux.Stream)

	data := make([]byte, 8192)
	for {
		i, addr, err := localConn.ReadFrom(data)
		if err != nil {
			log.Errorf("Failed to read first packet from proxy client: %v", err)
			continue
		}

		if !singleplex && (sesh == nil || sesh.IsClosed()) {
			sesh = newSeshFunc()
		}

		stream, ok := streams[addr.String()]
		if !ok {
			if singleplex {
				sesh = newSeshFunc()
			}

			stream, err = sesh.OpenStream()
			if err != nil {
				if singleplex {
					sesh.Close()
				}
				log.Errorf("Failed to open stream: %v", err)
				continue
			}

			streams[addr.String()] = stream
			proxyAddr := addr
			go func(stream *mux.Stream, localConn *net.UDPConn) {
				buf := make([]byte, 8192)
				for {
					n, err := stream.Read(buf)
					if err != nil {
						log.Tracef("copying stream to proxy client: %v", err)
						stream.Close()
						return
					}

					_, err = localConn.WriteTo(buf[:n], proxyAddr)
					if err != nil {
						log.Tracef("copying stream to proxy client: %v", err)
						stream.Close()
						return
					}
				}
			}(stream, localConn)
		}

		_, err = stream.Write(data[:i])
		if err != nil {
			log.Tracef("copying proxy client to stream: %v", err)
			delete(streams, addr.String())
			stream.Close()
			continue
		}
	}
}

func RouteTCP(listener net.Listener, streamTimeout time.Duration, singleplex bool, newSeshFunc func() *mux.Session) {
	var sesh *mux.Session
	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			continue
		}
		if !singleplex && (sesh == nil || sesh.IsClosed()) {
			sesh = newSeshFunc()
		}
		go func(sesh *mux.Session, localConn net.Conn, timeout time.Duration) {
			if singleplex {
				sesh = newSeshFunc()
			}

			data := make([]byte, 10240)
			_ = localConn.SetReadDeadline(time.Now().Add(streamTimeout))
			i, err := io.ReadAtLeast(localConn, data, 1)
			if err != nil {
				log.Errorf("Failed to read first packet from proxy client: %v", err)
				localConn.Close()
				return
			}
			var zeroTime time.Time
			_ = localConn.SetReadDeadline(zeroTime)

			stream, err := sesh.OpenStream()
			if err != nil {
				log.Errorf("Failed to open stream: %v", err)
				localConn.Close()
				if singleplex {
					sesh.Close()
				}
				return
			}

			_, err = stream.Write(data[:i])
			if err != nil {
				log.Errorf("Failed to write to stream: %v", err)
				localConn.Close()
				stream.Close()
				return
			}

			go func() {
				if _, err := common.Copy(localConn, stream); err != nil {
					log.Tracef("copying stream to proxy client: %v", err)
				}
			}()
			if _, err = common.Copy(stream, localConn); err != nil {
				log.Tracef("copying proxy client to stream: %v", err)
			}
		}(sesh, localConn, streamTimeout)
	}
}
