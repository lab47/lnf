package main

import (
	"context"
	_ "expvar"
	"flag"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"

	ethswitch "github.com/lab47/lnf/switch"
	"github.com/lab47/lnf/vhostuser"
	"github.com/lab47/lsvd/logger"
)

var fSocketPath = flag.String("socket-path", "", "path to listen on")
var fTapInterface = flag.String("tap", "", "tap interface to join to switch")
var fMetricAddr = flag.String("metric-addr", ":2122", "address to listen on for metrics")

func main() {
	flag.Parse()

	if *fSocketPath == "" {
		panic("provide a socket path")
	}

	// Will also include pprof via the init() in net/http/pprof
	go http.ListenAndServe(*fMetricAddr, nil)

	addr, err := net.ResolveUnixAddr("unix", *fSocketPath)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		panic(err)
	}

	defer l.Close()

	log := logger.New(logger.Info)

	sw := ethswitch.NewSwitch(log)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if *fTapInterface != "" {
		tp, err := ethswitch.OpenTapPort(log, *fTapInterface)
		if err != nil {
			panic(err)
		}

		sw.AddPort(ctx, "h0", tp)

		log.Info("added tap port", "name", *fTapInterface)
	}

	go func() {
		<-ctx.Done()

		log.Info("shutting down")
		l.Close()
	}()

	for {
		c, err := l.AcceptUnix()
		if err != nil {
			l.Close()
			return
		}

		go func() {
			n, err := vhostuser.NewNetDevice()
			if err != nil {
				panic(err)
			}

			d := vhostuser.NewDevice(log, c, n)

			err = d.Startup(ctx)
			if err != nil {
				log.Error("error processing requests", "error", err)
				return
			}

			name := sw.NextPortName()

			log.Info("attaching new switch port", "name", name)
			//bp := ethswitch.NewBufferedPort(ctx, log, 1024, d)
			sw.AddPort(ctx, name, d)

			go func() {
				err := d.Process()
				if err != nil {
					log.Info("port shutdown", "name", name)
					sw.DelPort(ctx, name)
				}
			}()
		}()
	}

}
