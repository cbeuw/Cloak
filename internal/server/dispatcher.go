package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/server/usermanager"

	mux "github.com/cbeuw/Cloak/internal/multiplex"
	log "github.com/sirupsen/logrus"
)

var b64 = base64.StdEncoding.EncodeToString

func Serve(l net.Listener, sta *State) {
	waitDur := [10]time.Duration{
		50 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second,
		3 * time.Second, 5 * time.Second, 10 * time.Second, 15 * time.Second, 30 * time.Second}

	fails := 0
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Errorf("%v, retrying", err)
			time.Sleep(waitDur[fails])
			if fails < 9 {
				fails++
			}
			continue
		}
		fails = 0
		go dispatchConnection(conn, sta)
	}
}

func connReadLine(conn net.Conn, buf []byte) (int, error) {
	i := 0
	for ; i < len(buf); i++ {
		_, err := io.ReadFull(conn, buf[i:i+1])
		if err != nil {
			return i, err
		}
		if buf[i] == '\n' {
			return i + 1, nil
		}
	}
	return i, io.ErrShortBuffer
}

var ErrUnrecognisedProtocol = errors.New("unrecognised protocol")

func readFirstPacket(conn net.Conn, buf []byte, timeout time.Duration) (int, Transport, bool, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	_, err := io.ReadFull(conn, buf[:1])
	if err != nil {
		err = fmt.Errorf("read error after connection is established: %v", err)
		conn.Close()
		return 0, nil, false, err
	}

	// TODO: give the option to match the protocol with port
	bufOffset := 1
	var transport Transport
	switch buf[0] {
	case 0x16:
		transport = TLS{}
		recordLayerLength := 5

		i, err := io.ReadFull(conn, buf[bufOffset:recordLayerLength])
		bufOffset += i
		if err != nil {
			err = fmt.Errorf("read error after connection is established: %v", err)
			conn.Close()
			return bufOffset, transport, false, err
		}
		dataLength := int(binary.BigEndian.Uint16(buf[3:5]))
		if dataLength+recordLayerLength > len(buf) {
			return bufOffset, transport, true, io.ErrShortBuffer
		}

		i, err = io.ReadFull(conn, buf[recordLayerLength:dataLength+recordLayerLength])
		bufOffset += i
		if err != nil {
			err = fmt.Errorf("read error after connection is established: %v", err)
			conn.Close()
			return bufOffset, transport, false, err
		}
	case 0x47:
		transport = WebSocket{}

		for {
			i, err := connReadLine(conn, buf[bufOffset:])
			line := buf[bufOffset : bufOffset+i]
			bufOffset += i
			if err != nil {
				if err == io.ErrShortBuffer {
					return bufOffset, transport, true, err
				} else {
					err = fmt.Errorf("error reading first packet: %v", err)
					conn.Close()
					return bufOffset, transport, false, err
				}
			}

			if bytes.Equal(line, []byte("\r\n")) {
				break
			}
		}
	default:
		return bufOffset, transport, true, ErrUnrecognisedProtocol
	}
	return bufOffset, transport, true, nil
}

func dispatchConnection(conn net.Conn, sta *State) {
	var err error
	buf := make([]byte, 1500)

	i, transport, redirOnErr, err := readFirstPacket(conn, buf, 15*time.Second)
	data := buf[:i]

	goWeb := func() {
		redirPort := sta.RedirPort
		if redirPort == "" {
			_, redirPort, _ = net.SplitHostPort(conn.LocalAddr().String())
		}
		webConn, err := sta.RedirDialer.Dial("tcp", net.JoinHostPort(sta.RedirHost.String(), redirPort))
		if err != nil {
			log.Errorf("Making connection to redirection server: %v", err)
			return
		}
		_, err = webConn.Write(data)
		if err != nil {
			log.Error("Failed to send first packet to redirection server", err)
			return
		}
		go common.Copy(webConn, conn)
		go common.Copy(conn, webConn)
	}

	if err != nil {
		log.WithField("remoteAddr", conn.RemoteAddr()).
			Warnf("error reading first packet: %v", err)
		if redirOnErr {
			goWeb()
		} else {
			conn.Close()
		}
		return
	}

	ci, finishHandshake, err := AuthFirstPacket(data, transport, sta)
	if err != nil {
		log.WithFields(log.Fields{
			"remoteAddr":       conn.RemoteAddr(),
			"UID":              b64(ci.UID),
			"sessionId":        ci.SessionId,
			"proxyMethod":      ci.ProxyMethod,
			"encryptionMethod": ci.EncryptionMethod,
		}).Warn(err)
		goWeb()
		return
	}

	var sessionKey [32]byte
	common.RandRead(sta.WorldState.Rand, sessionKey[:])
	obfuscator, err := mux.MakeObfuscator(ci.EncryptionMethod, sessionKey)
	if err != nil {
		log.WithFields(log.Fields{
			"remoteAddr":       conn.RemoteAddr(),
			"UID":              b64(ci.UID),
			"sessionId":        ci.SessionId,
			"proxyMethod":      ci.ProxyMethod,
			"encryptionMethod": ci.EncryptionMethod,
		}).Error(err)
		goWeb()
		return
	}

	seshConfig := mux.SessionConfig{
		Obfuscator:         obfuscator,
		Valve:              nil,
		Unordered:          ci.Unordered,
		MsgOnWireSizeLimit: appDataMaxLength,
	}

	// adminUID can use the server as normal with unlimited QoS credits. The adminUID is not
	// added to the userinfo database. The distinction between going into the admin mode
	// and normal proxy mode is that sessionID needs == 0 for admin mode
	if len(sta.AdminUID) != 0 && bytes.Equal(ci.UID, sta.AdminUID) && ci.SessionId == 0 {
		sesh := mux.MakeSession(0, seshConfig)
		preparedConn, err := finishHandshake(conn, sessionKey, sta.WorldState.Rand)
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("finished handshake")
		sesh.AddConnection(preparedConn)
		//TODO: Router could be nil in cnc mode
		log.WithField("remoteAddr", preparedConn.RemoteAddr()).Info("New admin session")
		err = http.Serve(sesh, usermanager.APIRouterOf(sta.Panel.Manager))
		// http.Serve never returns with non-nil error
		log.Error(err)
		return
	}

	if _, ok := sta.ProxyBook[ci.ProxyMethod]; !ok {
		log.WithFields(log.Fields{
			"remoteAddr":       conn.RemoteAddr(),
			"UID":              b64(ci.UID),
			"sessionId":        ci.SessionId,
			"proxyMethod":      ci.ProxyMethod,
			"encryptionMethod": ci.EncryptionMethod,
		}).Error(ErrBadProxyMethod)
		goWeb()
		return
	}

	var user *ActiveUser
	if sta.IsBypass(ci.UID) {
		user, err = sta.Panel.GetBypassUser(ci.UID)
	} else {
		user, err = sta.Panel.GetUser(ci.UID)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"UID":        b64(ci.UID),
			"remoteAddr": conn.RemoteAddr(),
			"error":      err,
		}).Warn("+1 unauthorised UID")
		goWeb()
		return
	}

	sesh, existing, err := user.GetSession(ci.SessionId, seshConfig)
	if err != nil {
		user.CloseSession(ci.SessionId, "")
		log.Error(err)
		return
	}

	preparedConn, err := finishHandshake(conn, sesh.GetSessionKey(), sta.WorldState.Rand)
	if err != nil {
		log.Error(err)
		return
	}
	log.Trace("finished handshake")
	sesh.AddConnection(preparedConn)

	if !existing {
		// if the session was newly made, we serve connections from the session streams to the proxy server
		log.WithFields(log.Fields{
			"UID":       b64(ci.UID),
			"sessionID": ci.SessionId,
		}).Info("New session")

		serveSession(sesh, ci, user, sta)
	}
}

func serveSession(sesh *mux.Session, ci ClientInfo, user *ActiveUser, sta *State) error {
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
				return nil
			} else {
				log.Errorf("unhandled error on session.Accept(): %v", err)
				continue
			}
		}
		proxyAddr := sta.ProxyBook[ci.ProxyMethod]
		localConn, err := sta.ProxyDialer.Dial(proxyAddr.Network(), proxyAddr.String())
		if err != nil {
			log.Errorf("Failed to connect to %v: %v", ci.ProxyMethod, err)
			user.CloseSession(ci.SessionId, "Failed to connect to proxy server")
			return err
		}
		log.Tracef("%v endpoint has been successfully connected", ci.ProxyMethod)

		go func() {
			if _, err := common.Copy(localConn, newStream); err != nil {
				log.Tracef("copying stream to proxy server: %v", err)
			}
		}()

		go func() {
			if _, err := common.Copy(newStream, localConn); err != nil {
				log.Tracef("copying proxy server to stream: %v", err)
			}
		}()
	}
}
