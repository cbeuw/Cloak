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

// TODO: manual backup

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
13	addUpCredit		uid delta	ok
14	addDownCredit		uid delta	ok
*/

type controller struct {
	*Userpanel
	adminUID []byte
}

func (up *Userpanel) MakeController(adminUID []byte) *controller {
	return &controller{up, adminUID}
}

var errInvalidArgument = errors.New("Invalid argument format")

func (c *controller) HandleRequest(req []byte) (resp []byte, err error) {
	check := func(err error) []byte {
		if err != nil {
			return c.respond([]byte(err.Error()))
		} else {
			return c.respond([]byte("ok"))
		}
	}
	plain, err := c.checkAndDecrypt(req)
	if err == ErrInvalidMac {
		log.Printf("!!!CONTROL MESSAGE AND HMAC MISMATCH!!!\n raw request:\n%x\ndecrypted msg:\n%x", req, plain)
		return nil, err
	} else if err != nil {
		log.Println(err)
		return c.respond([]byte(err.Error())), nil
	}

	typ := plain[0]
	var arg []byte
	if len(plain) > 1 {
		arg = plain[1:]
	}
	switch typ {
	case 1:
		UIDs := c.listActiveUsers()
		resp, _ = json.Marshal(UIDs)
		resp = c.respond(resp)
	case 2:
		uinfos := c.listAllUsers()
		resp, _ = json.Marshal(uinfos)
		resp = c.respond(resp)
	case 3:
		uinfo, err := c.getUserInfo(arg)
		if err != nil {
			resp = c.respond([]byte(err.Error()))
			break
		}
		resp, _ = json.Marshal(uinfo)
		resp = c.respond(resp)
	case 4:
		var uinfo UserInfo
		err = json.Unmarshal(arg, &uinfo)
		if err != nil {
			resp = c.respond([]byte(err.Error()))
			break
		}

		err = c.addNewUser(uinfo)
		resp = check(err)
	case 5:
		err = c.delUser(arg)
		resp = check(err)
	case 6:
		err = c.syncMemFromDB(arg)
		resp = check(err)
	case 7:
		if len(arg) < 36 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.setSessionsCap(arg[0:32], Uint32(arg[32:36]))
		resp = check(err)
	case 8:
		if len(arg) < 40 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.setUpRate(arg[0:32], int64(Uint64(arg[32:40])))
		resp = check(err)
	case 9:
		if len(arg) < 40 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.setDownRate(arg[0:32], int64(Uint64(arg[32:40])))
		resp = check(err)
	case 10:
		if len(arg) < 40 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.setUpCredit(arg[0:32], int64(Uint64(arg[32:40])))
		resp = check(err)
	case 11:
		if len(arg) < 40 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.setDownCredit(arg[0:32], int64(Uint64(arg[32:40])))
		resp = check(err)
	case 12:
		if len(arg) < 40 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.setExpiryTime(arg[0:32], int64(Uint64(arg[32:40])))
		resp = check(err)
	case 13:
		if len(arg) < 40 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.addUpCredit(arg[0:32], int64(Uint64(arg[32:40])))
		resp = check(err)
	case 14:
		if len(arg) < 40 {
			resp = c.respond([]byte(errInvalidArgument.Error()))
			break
		}
		err = c.addDownCredit(arg[0:32], int64(Uint64(arg[32:40])))
		resp = check(err)
	default:
		return c.respond([]byte("Unsupported action")), nil

	}
	return

}

var ErrInvalidMac = errors.New("Mac mismatch")
var errMsgTooShort = errors.New("Message length is less than 54")

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
	if len(data) < 54 {
		return nil, errMsgTooShort
	}
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
