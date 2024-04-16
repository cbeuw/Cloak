//go:build darwin
// +build darwin

package common

func Platformfd(fd uintptr) int {
	return int(fd)
}
