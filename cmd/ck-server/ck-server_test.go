package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBindAddr(t *testing.T) {
	t.Run("port only", func(t *testing.T) {
		addrs, err := resolveBindAddr([]string{":443"})
		assert.NoError(t, err)
		assert.Equal(t, ":443", addrs[0].String())
	})

	t.Run("specific address", func(t *testing.T) {
		addrs, err := resolveBindAddr([]string{"192.168.1.123:443"})
		assert.NoError(t, err)
		assert.Equal(t, "192.168.1.123:443", addrs[0].String())
	})

	t.Run("ipv6", func(t *testing.T) {
		addrs, err := resolveBindAddr([]string{"[::]:443"})
		assert.NoError(t, err)
		assert.Equal(t, "[::]:443", addrs[0].String())
	})

	t.Run("mixed", func(t *testing.T) {
		addrs, err := resolveBindAddr([]string{":80", "[::]:443"})
		assert.NoError(t, err)
		assert.Equal(t, ":80", addrs[0].String())
		assert.Equal(t, "[::]:443", addrs[1].String())
	})
}

func assertSetEqual(t *testing.T, list1, list2 interface{}, msgAndArgs ...interface{}) (ok bool) {
	return assert.Subset(t, list1, list2, msgAndArgs) && assert.Subset(t, list2, list1, msgAndArgs)
}

func TestParseSSBindAddr(t *testing.T) {
	testTable := []struct {
		name         string
		ssRemoteHost string
		ssRemotePort string
		ckBindAddr   []net.Addr
		expectedAddr []net.Addr
	}{
		{
			"ss only ipv4",
			"127.0.0.1",
			"443",
			[]net.Addr{},
			[]net.Addr{
				&net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 443,
				},
			},
		},
		{
			"ss only ipv6",
			"::",
			"443",
			[]net.Addr{},
			[]net.Addr{
				&net.TCPAddr{
					IP:   net.ParseIP("::"),
					Port: 443,
				},
			},
		},
		//{
		//	"ss only ipv4 and v6",
		//	"::|127.0.0.1",
		//	"443",
		//	[]net.Addr{},
		//	[]net.Addr{
		//		&net.TCPAddr{
		//			IP:   net.ParseIP("::"),
		//			Port: 443,
		//		},
		//		&net.TCPAddr{
		//			IP:   net.ParseIP("127.0.0.1"),
		//			Port: 443,
		//		},
		//	},
		//},
		{
			"ss and existing agrees",
			"::",
			"443",
			[]net.Addr{
				&net.TCPAddr{
					IP:   net.ParseIP("::"),
					Port: 443,
				},
			},
			[]net.Addr{
				&net.TCPAddr{
					IP:   net.ParseIP("::"),
					Port: 443,
				},
			},
		},
		{
			"ss adds onto existing",
			"127.0.0.1",
			"80",
			[]net.Addr{
				&net.TCPAddr{
					IP:   net.ParseIP("::"),
					Port: 443,
				},
			},
			[]net.Addr{
				&net.TCPAddr{
					IP:   net.ParseIP("::"),
					Port: 443,
				},
				&net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 80,
				},
			},
		},
	}

	for _, test := range testTable {
		test := test
		t.Run(test.name, func(t *testing.T) {
			assert.NoError(t, parseSSBindAddr(test.ssRemoteHost, test.ssRemotePort, &test.ckBindAddr))
			assertSetEqual(t, test.ckBindAddr, test.expectedAddr)
		})
	}
}
