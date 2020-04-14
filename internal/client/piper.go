package client

import (
	"github.com/cbeuw/Cloak/internal/common"
	"io"
	"net"
	"sync/atomic"
	"time"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
)

func RouteUDP(listen func(string, string) (net.PacketConn, error), localConfig LocalConnConfig, newSeshFunc func() *mux.Session) {
	var sesh *mux.Session
start:
	localConn, err := listen("udp", localConfig.LocalAddr)
	if err != nil {
		log.Fatal(err)
	}
	var otherEnd atomic.Value
	data := make([]byte, 10240)
	i, oe, err := localConn.ReadFrom(data)
	if err != nil {
		log.Errorf("Failed to read first packet from proxy client: %v", err)
		localConn.Close()
		return
	}
	otherEnd.Store(oe)

	if sesh == nil || sesh.IsClosed() {
		sesh = newSeshFunc()
	}
	log.Debugf("proxy local address %v", otherEnd.Load().(net.Addr).String())
	stream, err := sesh.OpenStream()
	if err != nil {
		log.Errorf("Failed to open stream: %v", err)
		localConn.Close()
		//localConnWrite.Close()
		return
	}
	_, err = stream.Write(data[:i])
	if err != nil {
		log.Errorf("Failed to write to stream: %v", err)
		localConn.Close()
		//localConnWrite.Close()
		stream.Close()
		return
	}

	// stream to proxy
	go func() {
		buf := make([]byte, 16380)
		for {
			i, err := io.ReadAtLeast(stream, buf, 1)
			if err != nil {
				log.Print(err)
				localConn.Close()
				stream.Close()
				break
			}
			_, err = localConn.WriteTo(buf[:i], otherEnd.Load().(net.Addr))
			if err != nil {
				log.Print(err)
				localConn.Close()
				stream.Close()
				break
			}
		}
	}()

	// proxy to stream
	buf := make([]byte, 16380)
	if localConfig.Timeout != 0 {
		localConn.SetReadDeadline(time.Now().Add(localConfig.Timeout))
	}
	for {
		if localConfig.Timeout != 0 {
			localConn.SetReadDeadline(time.Now().Add(localConfig.Timeout))
		}
		i, oe, err := localConn.ReadFrom(buf)
		if err != nil {
			localConn.Close()
			stream.Close()
			break
		}
		otherEnd.Store(oe)
		_, err = stream.Write(buf[:i])
		if err != nil {
			localConn.Close()
			stream.Close()
			break
		}
	}
	goto start

}

func RouteTCP(listener net.Listener, streamTimeout time.Duration, newSeshFunc func() *mux.Session) {
	var sesh *mux.Session
	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			continue
		}
		if sesh == nil || sesh.IsClosed() {
			sesh = newSeshFunc()
		}
		go func() {
			data := make([]byte, 10240)
			i, err := io.ReadAtLeast(localConn, data, 1)
			if err != nil {
				log.Errorf("Failed to read first packet from proxy client: %v", err)
				localConn.Close()
				return
			}
			stream, err := sesh.OpenStream()
			if err != nil {
				log.Errorf("Failed to open stream: %v", err)
				localConn.Close()
				return
			}
			_, err = stream.Write(data[:i])
			if err != nil {
				log.Errorf("Failed to write to stream: %v", err)
				localConn.Close()
				stream.Close()
				return
			}

			stream.SetReadFromTimeout(streamTimeout) // if localConn hasn't sent anything to stream to a period of time, stream closes
			go func() {
				if _, err := common.Copy(localConn, stream); err != nil {
					log.Tracef("copying stream to proxy client: %v", err)
				}
			}()
			if _, err = common.Copy(stream, localConn); err != nil {
				log.Tracef("copying proxy client to stream: %v", err)
			}
		}()
	}

}
