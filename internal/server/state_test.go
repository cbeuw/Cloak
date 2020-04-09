package server

import (
	"net"
	"testing"
)

func TestParseRedirAddr(t *testing.T) {
	t.Run("ipv4 without port", func(t *testing.T) {
		ipv4noPort := "1.2.3.4"
		host, port, err := parseRedirAddr(ipv4noPort)
		if err != nil {
			t.Errorf("parsing %v error: %v", ipv4noPort, err)
			return
		}
		if host.String() != "1.2.3.4" {
			t.Errorf("expected %v got %v", "1.2.3.4", host.String())
		}
		if port != "" {
			t.Errorf("port not empty when there is no port")
		}
	})

	t.Run("ipv4 with port", func(t *testing.T) {
		ipv4wPort := "1.2.3.4:1234"
		host, port, err := parseRedirAddr(ipv4wPort)
		if err != nil {
			t.Errorf("parsing %v error: %v", ipv4wPort, err)
			return
		}
		if host.String() != "1.2.3.4" {
			t.Errorf("expected %v got %v", "1.2.3.4", host.String())
		}
		if port != "1234" {
			t.Errorf("wrong port: expected %v, got %v", "1234", port)
		}
	})

	t.Run("domain without port", func(t *testing.T) {
		domainNoPort := "example.com"
		host, port, err := parseRedirAddr(domainNoPort)
		if err != nil {
			t.Errorf("parsing %v error: %v", domainNoPort, err)
			return
		}
		expHost, err := net.ResolveIPAddr("ip", "example.com")
		if err != nil {
			t.Errorf("tester error: cannot resolve example.com: %v", err)
			return
		}
		if host.String() != expHost.String() {
			t.Errorf("expected %v got %v", expHost.String(), host.String())
		}
		if port != "" {
			t.Errorf("port not empty when there is no port")
		}
	})

	t.Run("domain with port", func(t *testing.T) {
		domainWPort := "example.com:80"
		host, port, err := parseRedirAddr(domainWPort)
		if err != nil {
			t.Errorf("parsing %v error: %v", domainWPort, err)
			return
		}
		expHost, err := net.ResolveIPAddr("ip", "example.com")
		if err != nil {
			t.Errorf("tester error: cannot resolve example.com: %v", err)
			return
		}
		if host.String() != expHost.String() {
			t.Errorf("expected %v got %v", expHost.String(), host.String())
		}
		if port != "80" {
			t.Errorf("wrong port: expected %v, got %v", "80", port)
		}
	})

	t.Run("ipv6 without port", func(t *testing.T) {
		ipv6noPort := "a:b:c:d::"
		host, port, err := parseRedirAddr(ipv6noPort)
		if err != nil {
			t.Errorf("parsing %v error: %v", ipv6noPort, err)
			return
		}
		if host.String() != "a:b:c:d::" {
			t.Errorf("expected %v got %v", "a:b:c:d::", host.String())
		}
		if port != "" {
			t.Errorf("port not empty when there is no port")
		}
	})

	t.Run("ipv6 with port", func(t *testing.T) {
		ipv6wPort := "[a:b:c:d::]:80"
		host, port, err := parseRedirAddr(ipv6wPort)
		if err != nil {
			t.Errorf("parsing %v error: %v", ipv6wPort, err)
			return
		}
		if host.String() != "a:b:c:d::" {
			t.Errorf("expected %v got %v", "a:b:c:d::", host.String())
		}
		if port != "80" {
			t.Errorf("wrong port: expected %v, got %v", "80", port)
		}
	})
}
