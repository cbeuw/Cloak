//go:build linux
// +build linux

package common

func Platformfd(fd uintptr) int {
	return int(fd)
}
