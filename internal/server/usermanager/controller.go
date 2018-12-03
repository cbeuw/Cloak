package usermanager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
)

// FIXME: sanity checks. The server may panic due to user input

/*
0	reserved
1	listActiveUsers		none		[]uids
2	listAllUsers		none		[]userinfo
3	getUserInfo		uid		userinfo

4	addNewUser		userinfo	ok
5	delUser			uid 		ok
6	syncMemFromDB 		uid		ok

7	setSessionsCap		uid cap		ok
8	setUpRate 		uid rate	ok
9	setDownRate		uid rate	ok
10	setUpCredit		uid credit	ok
11	setDownCredit		uid credit	ok
12	setExpiryTime		uid time	ok
13	addUpcredit		uid delta	ok
14	addDownCredit		uid delta	ok
*/

type controller struct {
	*Userpanel
	adminUID []byte
}

func (up *Userpanel) MakeController(adminUID []byte) *controller {
	return &controller{up, adminUID}
}

func (c *controller) HandleRequest(req []byte) ([]byte, error) {
	plain, err := c.checkAndDecrypt(req)
	if err == ErrInvalidMac {
		log.Printf("!!!CONTROL MESSAGE AND HMAC MISMATCH!!!\n raw request:\n%x\ndecrypted msg:\n%x", req, plain)
		return nil, err
	}

	switch plain[0] {
	case 1:
		UIDs := c.listActiveUsers()
		resp, _ := json.Marshal(UIDs)
		return c.respond(resp), nil
	case 2:
		uinfos := c.listAllUsers()
		resp, _ := json.Marshal(uinfos)
		return c.respond(resp), nil
	case 3:
		uinfo, err := c.getUserInfo(plain[1:33])
		if err != nil {
			return c.respond([]byte(err.Error())), nil
		}
		resp, _ := json.Marshal(uinfo)
		return c.respond(resp), nil
	case 4:
		var uinfo UserInfo
		err = json.Unmarshal(plain[1:], &uinfo)
		if err != nil {
			return c.respond([]byte(err.Error())), nil
		}

		err = c.addNewUser(uinfo)
		if err != nil {
			return c.respond([]byte(err.Error())), nil
		} else {
			return c.respond([]byte("ok")), nil
		}
	case 5:
		err = c.delUser(plain[1:])
		if err != nil {
			return c.respond([]byte(err.Error())), nil
		} else {
			return c.respond([]byte("ok")), nil
		}

	case 6:
		err = c.syncMemFromDB(plain[1:33])
		if err != nil {
			return c.respond([]byte(err.Error())), nil
		} else {
			return c.respond([]byte("ok")), nil
		}
		// TODO: implement the rest
	default:
		return c.respond([]byte("Unsupported action")), nil

	}

}

var ErrInvalidMac = errors.New("Mac mismatch")

// protocol: [TLS record layer 5 bytes][IV 16 bytes][data][hmac 32 bytes]
func (c *controller) respond(resp []byte) []byte {
	respLen := len(resp)

	buf := make([]byte, 5+16+respLen+32)
	buf[0] = 0x17
	buf[1] = 0x03
	buf[2] = 0x03
	PutUint16(buf[3:5], uint16(16+respLen+32))

	rand.Read(buf[5:21]) //iv
	copy(buf[21:], resp)
	block, _ := aes.NewCipher(c.adminUID[0:16])
	stream := cipher.NewCTR(block, buf[5:21])
	stream.XORKeyStream(buf[21:21+respLen], buf[21:21+respLen])

	mac := hmac.New(sha256.New, c.adminUID[16:32])
	mac.Write(buf[5 : 21+respLen])
	copy(buf[21+respLen:], mac.Sum(nil))

	return buf
}

func (c *controller) checkAndDecrypt(data []byte) ([]byte, error) {
	macIndex := len(data) - 32
	mac := hmac.New(sha256.New, c.adminUID[16:32])
	mac.Write(data[5:macIndex])
	expected := mac.Sum(nil)
	if !hmac.Equal(data[macIndex:], expected) {
		return nil, ErrInvalidMac
	}

	iv := data[5:21]
	ret := data[21:macIndex]
	block, _ := aes.NewCipher(c.adminUID[0:16])
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ret, ret)
	return ret, nil
}
