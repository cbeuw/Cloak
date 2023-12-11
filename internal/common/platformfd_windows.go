//go:build windows
// +build windows

package common

import "syscall"

func Platformfd(fd uintptr) syscall.Handle {
	return syscall.Handle(fd)
}
