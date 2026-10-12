// Command dns-verify answers four questions about the DNS of this machine:
// whether a resolver of your own is in use, whether every lookup leaves through
// the proxy, whether answers are hijacked, and whether queries leak.
//
// It is macOS only. The configuration it reads is the merged
// SystemConfiguration state, which no other platform exposes the same way.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/fdaio/dns-verify/internal/render"
	"github.com/fdaio/dns-verify/internal/run"
)

// checkTimeout bounds the whole run. Each probe has its own shorter timeout, so
// this only stops a run that hangs on an unresponsive system call.
const checkTimeout = 90 * time.Second

func main() {
	if runtime.GOOS != "darwin" {
		fmt.Fprintf(os.Stderr, "dns-verify: %s is not supported, this check reads macOS DNS state\n",
			runtime.GOOS)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	report, err := run.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns-verify: %v\n", err)
		os.Exit(1)
	}
	if err := render.Report(os.Stdout, report); err != nil {
		fmt.Fprintf(os.Stderr, "dns-verify: %v\n", err)
		os.Exit(1)
	}
}
