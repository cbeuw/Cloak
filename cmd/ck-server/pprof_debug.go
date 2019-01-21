// +build pprof

package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
)

func startPprof(pprofAddr string) {
	runtime.SetBlockProfileRate(5)
	go func() {
		log.Println(http.ListenAndServe(pprofAddr, nil))
	}()
	log.Println("pprof listening on " + pprofAddr)
}
