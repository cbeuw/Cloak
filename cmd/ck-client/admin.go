//build !android

package main

// TODO: rewrite this. Think of another way of admin control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cbeuw/Cloak/internal/client"
	"github.com/cbeuw/Cloak/internal/client/TLS"
	"github.com/cbeuw/Cloak/internal/util"
)

type UserInfo struct {
	UID []byte
	// ALL of the following fields have to be accessed atomically
	SessionsCap uint32
	UpRate      int64
	DownRate    int64
	UpCredit    int64
	DownCredit  int64
	ExpiryTime  int64
}

type administrator struct {
	adminConn net.Conn
	adminUID  []byte
}

func adminPrompt(sta *client.State) error {
	a, err := adminHandshake(sta)
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Println(`1       listActiveUsers         none            []uids
2       listAllUsers            none            []userinfo
3       getUserInfo             uid             userinfo
4       addNewUser              userinfo        ok
5       delUser                 uid             ok
6       syncMemFromDB           uid             ok
                                                  
7       setSessionsCap          uid cap         ok
8       setUpRate               uid rate        ok
9       setDownRate             uid rate        ok
10      setUpCredit             uid credit      ok
11      setDownCredit           uid credit      ok
12      setExpiryTime           uid time        ok
13      addUpCredit             uid delta       ok
14      addDownCredit           uid delta       ok`)
	buf := make([]byte, 16000)
	for {
		req, err := a.getRequest()
		if err != nil {
			log.Println(err)
			continue
		}
		a.adminConn.Write(req)
		n, err := a.adminConn.Read(buf)
		if err != nil {
			return err
		}
		resp, err := a.checkAndDecrypt(buf[:n])
		if err != nil {
			return err
		}
		fmt.Println(string(resp))
	}
}

func adminHandshake(sta *client.State) (*administrator, error) {
	fmt.Println("Enter the ip:port of your server")
	var addr string
	fmt.Scanln(&addr)
	fmt.Println("Enter the admin UID")
	var b64AdminUID string
	fmt.Scanln(&b64AdminUID)
	adminUID, err := base64.StdEncoding.DecodeString(b64AdminUID)
	if err != nil {
		return nil, err
	}

	sta.UID = adminUID

	remoteConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	clientHello := TLS.ComposeInitHandshake(sta)
	_, err = remoteConn.Write(clientHello)

	// Three discarded messages: ServerHello, ChangeCipherSpec and Finished
	discardBuf := make([]byte, 1024)
	for c := 0; c < 3; c++ {
		_, err = util.ReadTLS(remoteConn, discardBuf)
		if err != nil {
			return nil, err
		}
	}

	reply := TLS.ComposeReply()
	_, err = remoteConn.Write(reply)
	a := &administrator{remoteConn, adminUID}
	return a, nil
}

func (a *administrator) getRequest() (req []byte, err error) {
	promptUID := func() []byte {
		fmt.Println("Enter UID")
		var b64UID string
		fmt.Scanln(&b64UID)
		ret, _ := base64.StdEncoding.DecodeString(b64UID)
		return ret
	}

	promptInt64 := func(name string) []byte {
		fmt.Println("Enter New " + name)
		var val int64
		fmt.Scanln(&val)
		ret := make([]byte, 8)
		binary.BigEndian.PutUint64(ret, uint64(val))
		return ret
	}
	promptUint32 := func(name string) []byte {
		fmt.Println("Enter New " + name)
		var val uint32
		fmt.Scanln(&val)
		ret := make([]byte, 4)
		binary.BigEndian.PutUint32(ret, val)
		return ret
	}

	fmt.Println("Select your command")
	var cmd string
	fmt.Scanln(&cmd)
	switch cmd {
	case "1":
		req = a.request([]byte{0x01})
	case "2":
		req = a.request([]byte{0x02})
	case "3":
		UID := promptUID()
		req = a.request(append([]byte{0x03}, UID...))
	case "4":
		var uinfo UserInfo
		var b64UID string
		fmt.Printf("UID:")
		fmt.Scanln(&b64UID)
		UID, _ := base64.StdEncoding.DecodeString(b64UID)
		uinfo.UID = UID
		fmt.Printf("SessionsCap:")
		fmt.Scanf("%d", &uinfo.SessionsCap)
		fmt.Printf("UpRate:")
		fmt.Scanf("%d", &uinfo.UpRate)
		fmt.Printf("DownRate:")
		fmt.Scanf("%d", &uinfo.DownRate)
		fmt.Printf("UpCredit:")
		fmt.Scanf("%d", &uinfo.UpCredit)
		fmt.Printf("DownCredit:")
		fmt.Scanf("%d", &uinfo.DownCredit)
		fmt.Printf("ExpiryTime:")
		fmt.Scanf("%d", &uinfo.ExpiryTime)
		marshed, _ := json.Marshal(uinfo)
		req = a.request(append([]byte{0x04}, marshed...))
	case "5":
		UID := promptUID()
		fmt.Println("Are you sure to delete this user? y/n")
		var ans string
		fmt.Scanln(&ans)
		if ans != "y" && ans != "Y" {
			return
		}
		req = a.request(append([]byte{0x05}, UID...))
	case "6":
		UID := promptUID()
		req = a.request(append([]byte{0x06}, UID...))
	case "7":
		arg := make([]byte, 36)
		copy(arg, promptUID())
		copy(arg[32:], promptUint32("SessionsCap"))
		req = a.request(append([]byte{0x07}, arg...))
	case "8":
		arg := make([]byte, 40)
		copy(arg, promptUID())
		copy(arg[32:], promptInt64("UpRate"))
		req = a.request(append([]byte{0x08}, arg...))
	case "9":
		arg := make([]byte, 40)
		copy(arg, promptUID())
		copy(arg[32:], promptInt64("DownRate"))
		req = a.request(append([]byte{0x09}, arg...))
	case "10":
		arg := make([]byte, 40)
		copy(arg, promptUID())
		copy(arg[32:], promptInt64("UpCredit"))
		req = a.request(append([]byte{0x0a}, arg...))
	case "11":
		arg := make([]byte, 40)
		copy(arg, promptUID())
		copy(arg[32:], promptInt64("DownCredit"))
		req = a.request(append([]byte{0x0b}, arg...))
	case "12":
		arg := make([]byte, 40)
		copy(arg, promptUID())
		copy(arg[32:], promptInt64("ExpiryTime"))
		req = a.request(append([]byte{0x0c}, arg...))
	case "13":
		arg := make([]byte, 40)
		copy(arg, promptUID())
		copy(arg[32:], promptInt64("UpCredit to add"))
		req = a.request(append([]byte{0x0d}, arg...))
	case "14":
		arg := make([]byte, 40)
		copy(arg, promptUID())
		copy(arg[32:], promptInt64("DownCredit to add"))
		req = a.request(append([]byte{0x0e}, arg...))
	default:
		return nil, errors.New("Unreconised cmd")
	}
	return req, nil
}

// protocol: 0[TLS record layer 5 bytes]5[IV 16 bytes]21[data][hmac 32 bytes]
func (a *administrator) request(data []byte) []byte {
	dataLen := len(data)

	buf := make([]byte, 5+16+dataLen+32)
	buf[0] = 0x17
	buf[1] = 0x03
	buf[2] = 0x03
	binary.BigEndian.PutUint16(buf[3:5], uint16(16+dataLen+32))

	rand.Read(buf[5:21]) //iv
	copy(buf[21:], data)
	block, _ := aes.NewCipher(a.adminUID[0:16])
	stream := cipher.NewCTR(block, buf[5:21])
	stream.XORKeyStream(buf[21:21+dataLen], buf[21:21+dataLen])

	mac := hmac.New(sha256.New, a.adminUID[16:32])
	mac.Write(buf[5 : 21+dataLen])
	copy(buf[21+dataLen:], mac.Sum(nil))

	return buf
}

var ErrInvalidMac = errors.New("Mac mismatch")

func (a *administrator) checkAndDecrypt(data []byte) ([]byte, error) {
	macIndex := len(data) - 32
	mac := hmac.New(sha256.New, a.adminUID[16:32])
	mac.Write(data[5:macIndex])
	expected := mac.Sum(nil)
	if !hmac.Equal(data[macIndex:], expected) {
		return nil, ErrInvalidMac
	}

	iv := data[5:21]
	ret := data[21:macIndex]
	block, _ := aes.NewCipher(a.adminUID[0:16])
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ret, ret)
	return ret, nil
}
