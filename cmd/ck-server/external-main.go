//go:build external_main
// +build external_main

package main

import (
	"os"
	"C"
	"unsafe"
)

//export external_main
func external_main(argc C.int, argv **C.char) {
	var offset = unsafe.Sizeof(uintptr(0))
	var go_argv []string
	for i := 0; i < int(argc); i++ {
		go_argv = append(go_argv, C.GoString(*argv))
		argv = (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(argv)) + offset))
	}

	os.Args = go_argv
	main()
}
