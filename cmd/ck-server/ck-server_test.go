package main

import "testing"

func TestParseBindAddr(t *testing.T) {
	t.Run("port only", func(t *testing.T) {
		addrs, err := parseBindAddr([]string{":443"})
		if err != nil {
			t.Error(err)
			return
		}
		if addrs[0].String() != ":443" {
			t.Errorf("expected %v got %v", ":443", addrs[0].String())
		}
	})

	t.Run("specific address", func(t *testing.T) {
		addrs, err := parseBindAddr([]string{"192.168.1.123:443"})
		if err != nil {
			t.Error(err)
			return
		}
		if addrs[0].String() != "192.168.1.123:443" {
			t.Errorf("expected %v got %v", "192.168.1.123:443", addrs[0].String())
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		addrs, err := parseBindAddr([]string{"[::]:443"})
		if err != nil {
			t.Error(err)
			return
		}
		if addrs[0].String() != "[::]:443" {
			t.Errorf("expected %v got %v", "[::]:443", addrs[0].String())
		}
	})

	t.Run("mixed", func(t *testing.T) {
		addrs, err := parseBindAddr([]string{":80", "[::]:443"})
		if err != nil {
			t.Error(err)
			return
		}
		if addrs[0].String() != ":80" {
			t.Errorf("expected %v got %v", ":80", addrs[0].String())
		}
		if addrs[1].String() != "[::]:443" {
			t.Errorf("expected %v got %v", "[::]:443", addrs[1].String())
		}
	})
}
