// Command dns-verify reports the DNS posture of a macOS workstation: whether a
// resolver of your own is in use, whether every lookup leaves through the proxy,
// whether answers are hijacked, and whether queries leak.
//
// It is macOS only. The configuration it reads is the merged
// SystemConfiguration state, which no other platform exposes the same way.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/fdaio/dns-verify/internal/analyze"
	"github.com/fdaio/dns-verify/internal/render"
	"github.com/fdaio/dns-verify/internal/run"
)

// checkTimeout bounds the whole run. Each probe has its own shorter timeout, so
// this only stops a run that hangs on an unresponsive system call.
const checkTimeout = 90 * time.Second

// checker performs one full check. Taking it as a parameter keeps the flags and
// the exit code testable without a network.
type checker func(context.Context) (analyze.Report, error)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr, run.Run))
}

func realMain(args []string, stdout, stderr io.Writer, check checker) int {
	if runtime.GOOS != "darwin" {
		fmt.Fprintf(stderr, "dns-verify: %s is not supported, this check reads macOS DNS state\n",
			runtime.GOOS)
		return 2
	}

	flags := flag.NewFlagSet("dns-verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	verbose := flags.Bool("v", false, "print the measurements behind each verdict")
	failUnder := flags.Int("fail-under", 0,
		fmt.Sprintf("exit 1 when the score is below this value (0 to %d)", analyze.MaxScore))
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "dns-verify: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if *failUnder < 0 || *failUnder > analyze.MaxScore {
		fmt.Fprintf(stderr, "dns-verify: --fail-under must be between 0 and %d\n", analyze.MaxScore)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	report, err := check(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "dns-verify: %v\n", err)
		return 1
	}
	if err := render.Report(stdout, report, *verbose); err != nil {
		fmt.Fprintf(stderr, "dns-verify: %v\n", err)
		return 1
	}

	// The threshold is off by default, so a plain run never fails on a score.
	if *failUnder > 0 && report.Score() < *failUnder {
		fmt.Fprintf(stderr, "dns-verify: score %d is below --fail-under %d\n",
			report.Score(), *failUnder)
		return 1
	}
	return 0
}
