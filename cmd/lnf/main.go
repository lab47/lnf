package main

import (
	"flag"
	"net"

	"github.com/lab47/lnf/vhostuser"
	"github.com/lab47/lsvd/logger"
)

var fSocketPath = flag.String("socket-path", "", "path to listen on")

func main() {
	flag.Parse()

	if *fSocketPath == "" {
		panic("provide a socket path")
	}

	addr, err := net.ResolveUnixAddr("unix", *fSocketPath)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		panic(err)
	}

	defer l.Close()

	log := logger.New(logger.Trace)

	for {
		c, err := l.AcceptUnix()
		if err != nil {
			l.Close()
			return
		}

		n, err := vhostuser.NewNetDevice()
		if err != nil {
			panic(err)
		}

		d := vhostuser.NewDevice(log, c, n)

		err = d.Process()
		if err != nil {
			log.Error("error processing requests", "error", err)
			return
		}
	}

}
