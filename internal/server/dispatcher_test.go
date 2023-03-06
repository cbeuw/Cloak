package server

import (
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/stretchr/testify/assert"
)

type rfpReturnValue struct {
	n          int
	transport  Transport
	redirOnErr bool
	err        error
}

const timeout = 500 * time.Millisecond

func TestReadFirstPacket(t *testing.T) {
	rfp := func(conn net.Conn, buf []byte, retChan chan<- rfpReturnValue) {
		ret := rfpReturnValue{}
		ret.n, ret.transport, ret.redirOnErr, ret.err = readFirstPacket(conn, buf, timeout)
		retChan <- ret
	}

	t.Run("Good TLS", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		first, _ := hex.DecodeString("1603010200010001fc0303ac530b5778469dbbc3f9a83c6ac35b63aa6a70c2014026ade30f2faf0266f0242068424f320bcad49b4315a761f9f6dec32b0a403c2d8c0ab337608a694c6e411c0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00204655c2c83aaed1db2e89ed17d671fcdc76dc96e36bde8840022f1bda2f31019600170041543af1f8d28b37d984073f40e8361613da502f16e4039f00656f427de0f66480b2e77e3e552e126bb0cc097168f6e5454c7f9501126a2377fb40151f6cfc007e0e002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		local.Write(first)

		ret := <-retChan

		assert.Equal(t, len(first), ret.n)
		assert.Equal(t, first, buf[:ret.n])
		assert.IsType(t, TLS{}, ret.transport)
		assert.NoError(t, ret.err)
	})

	t.Run("Good TLS but buf too small", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 10)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		first, _ := hex.DecodeString("1603010200010001fc0303ac530b5778469dbbc3f9a83c6ac35b63aa6a70c2014026ade30f2faf0266f0242068424f320bcad49b4315a761f9f6dec32b0a403c2d8c0ab337608a694c6e411c0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00204655c2c83aaed1db2e89ed17d671fcdc76dc96e36bde8840022f1bda2f31019600170041543af1f8d28b37d984073f40e8361613da502f16e4039f00656f427de0f66480b2e77e3e552e126bb0cc097168f6e5454c7f9501126a2377fb40151f6cfc007e0e002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		local.Write(first)

		ret := <-retChan

		assert.Equal(t, io.ErrShortBuffer, ret.err)
		assert.True(t, ret.redirOnErr)
		assert.Equal(t, first[:ret.n], buf[:ret.n])

	})

	t.Run("Incomplete timeout", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		first, _ := hex.DecodeString("160301")
		local.Write(first)
		select {
		case ret := <-retChan:
			assert.Equal(t, len(first), ret.n)
			assert.False(t, ret.redirOnErr)
			assert.Error(t, ret.err)
		case <-time.After(2 * timeout):
			assert.Fail(t, "readFirstPacket should have timed out")
		}
	})

	t.Run("Incomplete payload timeout", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		first, _ := hex.DecodeString("16030101010000")
		local.Write(first)
		select {
		case ret := <-retChan:
			assert.Equal(t, len(first), ret.n)
			assert.False(t, ret.redirOnErr)
			assert.Error(t, ret.err)
		case <-time.After(2 * timeout):
			assert.Fail(t, "readFirstPacket should have timed out")
		}
	})

	t.Run("Good TLS staggered", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		first, _ := hex.DecodeString("1603010200010001fc0303ac530b5778469dbbc3f9a83c6ac35b63aa6a70c2014026ade30f2faf0266f0242068424f320bcad49b4315a761f9f6dec32b0a403c2d8c0ab337608a694c6e411c0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100018f00000011000f00000c7777772e62696e672e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000033006b0069001d00204655c2c83aaed1db2e89ed17d671fcdc76dc96e36bde8840022f1bda2f31019600170041543af1f8d28b37d984073f40e8361613da502f16e4039f00656f427de0f66480b2e77e3e552e126bb0cc097168f6e5454c7f9501126a2377fb40151f6cfc007e0e002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001500920000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		local.Write(first[:100])
		time.Sleep(timeout / 2)
		local.Write(first[100:])

		ret := <-retChan

		assert.Equal(t, len(first), ret.n)
		assert.Equal(t, first, buf[:ret.n])
		assert.IsType(t, TLS{}, ret.transport)
		assert.NoError(t, ret.err)
	})

	t.Run("TLS bad recordlayer length", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		first, _ := hex.DecodeString("160301ffff")
		local.Write(first)

		ret := <-retChan

		assert.Equal(t, len(first), ret.n)
		assert.Equal(t, first, buf[:ret.n])
		assert.IsType(t, TLS{}, ret.transport)
		assert.Equal(t, io.ErrShortBuffer, ret.err)
		assert.True(t, ret.redirOnErr)
	})

	t.Run("Good WebSocket", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		reqStr := "GET / HTTP/1.1\r\nHost: d2jkinvisak5y9.cloudfront.net:443\r\nUser-Agent: Go-http-client/1.1\r\nConnection: Upgrade\r\nHidden: oJxeEwfDWg5k5Jbl8ttZD1sc0fHp8VjEtXHsqEoSrnaLRe/M+KGXkOzpc/2fRRg9Vk+wIWRsfv8IpoBPLbqO+ZfGsPXTjUJGiI9BqxrcJfkxncXA7FAHGpTc84tzBtZZ\r\nSec-WebSocket-Key: lJYh7X8DRXW1U0h9WKwVMA==\r\nSec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n"
		req := []byte(reqStr)
		local.Write(req)

		ret := <-retChan

		assert.Equal(t, len(req), ret.n)
		assert.Equal(t, req, buf[:ret.n])
		assert.IsType(t, WebSocket{}, ret.transport)
		assert.NoError(t, ret.err)
	})

	t.Run("Good WebSocket but buf too small", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 10)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		reqStr := "GET / HTTP/1.1\r\nHost: d2jkinvisak5y9.cloudfront.net:443\r\nUser-Agent: Go-http-client/1.1\r\nConnection: Upgrade\r\nHidden: oJxeEwfDWg5k5Jbl8ttZD1sc0fHp8VjEtXHsqEoSrnaLRe/M+KGXkOzpc/2fRRg9Vk+wIWRsfv8IpoBPLbqO+ZfGsPXTjUJGiI9BqxrcJfkxncXA7FAHGpTc84tzBtZZ\r\nSec-WebSocket-Key: lJYh7X8DRXW1U0h9WKwVMA==\r\nSec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n"
		req := []byte(reqStr)
		local.Write(req)

		ret := <-retChan

		assert.Equal(t, io.ErrShortBuffer, ret.err)
		assert.True(t, ret.redirOnErr)
		assert.Equal(t, req[:ret.n], buf[:ret.n])
	})

	t.Run("Incomplete WebSocket timeout", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		reqStr := "GET /"
		req := []byte(reqStr)
		local.Write(req)

		select {
		case ret := <-retChan:
			assert.Equal(t, len(req), ret.n)
			assert.False(t, ret.redirOnErr)
			assert.Error(t, ret.err)
		case <-time.After(2 * timeout):
			assert.Fail(t, "readFirstPacket should have timed out")
		}
	})

	t.Run("Staggered WebSocket", func(t *testing.T) {
		local, remote := connutil.AsyncPipe()
		buf := make([]byte, 1500)
		retChan := make(chan rfpReturnValue)
		go rfp(remote, buf, retChan)

		reqStr := "GET / HTTP/1.1\r\nHost: d2jkinvisak5y9.cloudfront.net:443\r\nUser-Agent: Go-http-client/1.1\r\nConnection: Upgrade\r\nHidden: oJxeEwfDWg5k5Jbl8ttZD1sc0fHp8VjEtXHsqEoSrnaLRe/M+KGXkOzpc/2fRRg9Vk+wIWRsfv8IpoBPLbqO+ZfGsPXTjUJGiI9BqxrcJfkxncXA7FAHGpTc84tzBtZZ\r\nSec-WebSocket-Key: lJYh7X8DRXW1U0h9WKwVMA==\r\nSec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n"
		req := []byte(reqStr)
		local.Write(req[:100])
		time.Sleep(timeout / 2)
		local.Write(req[100:])

		ret := <-retChan

		assert.Equal(t, len(req), ret.n)
		assert.Equal(t, req, buf[:ret.n])
		assert.IsType(t, WebSocket{}, ret.transport)
		assert.NoError(t, ret.err)
	})
}
