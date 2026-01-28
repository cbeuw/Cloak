//go:build !protector_android
// +build !protector_android

package main

import "syscall"

func protector(string, string, syscall.RawConn) error {
	return nil
}
