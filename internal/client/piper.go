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

func RouteUDP(localConfig localConnConfig, newSeshFunc func() *mux.Session) {
	var sesh *mux.Session
	localUDPAddr, err := net.ResolveUDPAddr("udp", localConfig.LocalAddr)
	if err != nil {
		log.Fatal(err)
	}
start:
	localConn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		log.Fatal(err)
	}
	var otherEnd atomic.Value
	data := make([]byte, 10240)
	i, oe, err := localConn.ReadFromUDP(data)
	if err != nil {
		log.Errorf("Failed to read first packet from proxy client: %v", err)
		localConn.Close()
		return
	}
	otherEnd.Store(oe)

	if sesh == nil || sesh.IsClosed() {
		sesh = newSeshFunc()
	}
	log.Debugf("proxy local address %v", otherEnd.Load().(*net.UDPAddr).String())
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
			_, err = localConn.WriteToUDP(buf[:i], otherEnd.Load().(*net.UDPAddr))
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
		i, oe, err := localConn.ReadFromUDP(buf)
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

func RouteTCP(localConfig localConnConfig, newSeshFunc func() *mux.Session) {
	tcpListener, err := net.Listen("tcp", localConfig.LocalAddr)
	if err != nil {
		log.Fatal(err)
	}
	var sesh *mux.Session
	for {
		localConn, err := tcpListener.Accept()
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
			go func() {
				if _, err := common.Copy(localConn, stream, 0); err != nil {
					log.Tracef("copying stream to proxy client: %v", err)
				}
			}()
			//util.Pipe(stream, localConn, localConfig.Timeout)
			if _, err = common.Copy(stream, localConn, localConfig.Timeout); err != nil {
				log.Tracef("copying proxy client to stream: %v", err)
			}
		}()
	}

}
