// +build !pprof

package main

import "log"

func startPprof(x string) {
	log.Println("pprof not available in release builds to reduce binary size")
}
