//go:build !android
// +build !android

package main

import "syscall"

func protector(string, string, syscall.RawConn) error {
	return nil
}
