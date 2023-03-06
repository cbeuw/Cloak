//go:build gofuzz
// +build gofuzz

package server

import (
	"errors"
	"net"
	"time"

	"github.com/cbeuw/Cloak/internal/common"
	"github.com/cbeuw/connutil"
)

type rfpReturnValue_fuzz struct {
	n          int
	transport  Transport
	redirOnErr bool
	err        error
}

func Fuzz(data []byte) int {
	var bypassUID [16]byte

	var pv [32]byte

	sta := &State{
		BypassUID: map[[16]byte]struct{}{
			bypassUID: {},
		},
		ProxyBook: map[string]net.Addr{
			"shadowsocks": nil,
		},
		UsedRandom: map[[32]byte]int64{},
		StaticPv:   &pv,
		WorldState: common.RealWorldState,
	}

	rfp := func(conn net.Conn, buf []byte, retChan chan<- rfpReturnValue_fuzz) {
		ret := rfpReturnValue_fuzz{}
		ret.n, ret.transport, ret.redirOnErr, ret.err = readFirstPacket(conn, buf, 500*time.Millisecond)
		retChan <- ret
	}

	local, remote := connutil.AsyncPipe()
	buf := make([]byte, 1500)
	retChan := make(chan rfpReturnValue_fuzz)
	go rfp(remote, buf, retChan)

	local.Write(data)

	ret := <-retChan

	if ret.err != nil {
		return 1
	}

	_, _, err := AuthFirstPacket(buf[:ret.n], ret.transport, sta)

	if !errors.Is(err, ErrReplay) && !errors.Is(err, ErrBadDecryption) {
		return 1
	}
	return 0
}
