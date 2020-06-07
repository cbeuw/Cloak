package server

import (
	"bytes"
	"encoding/base64"
	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/Cloak/internal/server/usermanager"
	"io"
	"net"
	"net/http"
	"time"

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

func dispatchConnection(conn net.Conn, sta *State) {
	remoteAddr := conn.RemoteAddr()
	var err error
	buf := make([]byte, 1500)

	// TODO: potential fingerprint for active probers here
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	i, err := io.ReadAtLeast(conn, buf, 1)
	if err != nil {
		log.WithField("remoteAddr", remoteAddr).
			Infof("failed to read anything after connection is established: %v", err)
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
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
		go io.Copy(webConn, conn)
		go io.Copy(conn, webConn)
	}

	ci, finishHandshake, err := AuthFirstPacket(data, sta)
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

	var sessionKey [32]byte
	common.RandRead(sta.WorldState.Rand, sessionKey[:])
	obfuscator, err := mux.MakeObfuscator(ci.EncryptionMethod, sessionKey)
	if err != nil {
		log.Error(err)
		goWeb()
		return
	}

	seshConfig := mux.SessionConfig{
		Obfuscator:   obfuscator,
		Valve:        nil,
		Unordered:    ci.Unordered,
		MaxFrameSize: appDataMaxLength,
	}

	// adminUID can use the server as normal with unlimited QoS credits. The adminUID is not
	// added to the userinfo database. The distinction between going into the admin mode
	// and normal proxy mode is that sessionID needs == 0 for admin mode
	if bytes.Equal(ci.UID, sta.AdminUID) && ci.SessionId == 0 {
		preparedConn, err := finishHandshake(conn, sessionKey, sta.WorldState.Rand)
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("finished handshake")
		sesh := mux.MakeSession(0, seshConfig)
		sesh.AddConnection(preparedConn)
		//TODO: Router could be nil in cnc mode
		log.WithField("remoteAddr", preparedConn.RemoteAddr()).Info("New admin session")
		err = http.Serve(sesh, usermanager.APIRouterOf(sta.Panel.Manager))
		if err != nil {
			log.Error(err)
			return
		}
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
			"remoteAddr": remoteAddr,
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

	if existing {
		preparedConn, err := finishHandshake(conn, sesh.SessionKey, sta.WorldState.Rand)
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("finished handshake")
		sesh.AddConnection(preparedConn)
		return
	}

	preparedConn, err := finishHandshake(conn, sessionKey, sta.WorldState.Rand)
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
				// TODO: other errors
				continue
			}
		}
		proxyAddr := sta.ProxyBook[ci.ProxyMethod]
		localConn, err := sta.ProxyDialer.Dial(proxyAddr.Network(), proxyAddr.String())
		if err != nil {
			log.Errorf("Failed to connect to %v: %v", ci.ProxyMethod, err)
			user.CloseSession(ci.SessionId, "Failed to connect to proxy server")
			continue
		}
		log.Tracef("%v endpoint has been successfully connected", ci.ProxyMethod)

		// if stream has nothing to send to proxy server for sta.Timeout period of time, stream will return error
		newStream.(*mux.Stream).SetWriteToTimeout(sta.Timeout)
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
