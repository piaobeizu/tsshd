/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const kDefaultConnectTimeout = 10 * time.Second

const (
	kExitCodeNormal       = 0
	kExitCodeAlreadyRun   = 90
	kExitCodeBackground   = 91
	kExitCodeOutputFail   = 92
	kExitCodeInitServer   = 93
	kExitCodeConnTimeout  = 94
	kExitCodeAliveTimeout = 95
	kExitCodeSignalKill   = 96
	kExitCodeApplyOptions = 97
	kExitCodeListFailed   = 98
	kExitCodeViewFailed   = 99
	kExitCodeAttachFailed = 100
)

var exitChan = make(chan int, 1)

func exitWithCode(code int) {
	select {
	case exitChan <- code:
	default:
	}
}

type tsshdArgs struct {
	Help           bool
	VerShort       bool
	VerDetailed    bool
	KCP            bool
	TCP            bool
	IPv4           bool
	IPv6           bool
	Debug          bool
	Attachable     bool
	Socket         bool
	List           bool
	View           string
	Attach         string
	MTU            uint16
	Port           string
	ConnectTimeout time.Duration

	// KcpWireRate is the downlink WIRE budget in bytes/s for KCP connections:
	// the ceiling on wire bytes offered to the link (FEC parity packets and
	// transport framing included) by pacing session PTY output. 0 (the
	// default) disables pacing. The payload token rate granted to PTY output
	// is KcpWireRate / kWireAmpEstimate (see output.go).
	KcpWireRate uint64

	// kcpWireRateSet records that --kcp-wire-rate appeared on the command
	// line, so an explicit `--kcp-wire-rate 0` overrides a nonzero
	// sshd_config KcpWireRate (flag presence, not flag value, wins).
	kcpWireRateSet bool
}

func printHelp() int {
	fmt.Printf("usage: tsshd [-h|-v|-V] [--kcp] [--tcp] [--ipv4] [--ipv6] [--debug] " +
		"[--attachable] [--socket] [--list] [--view <PID>.<SID>] [--attach <PID>] " +
		"[--mtu N] [--port low-high] [--connect-timeout t]\n\n" +
		"tsshd: A UDP-based SSH server with seamless roaming and auto-reconnect.\n\n" +
		"optional arguments:\n" +
		"  -h, --help             show this help message and exit\n" +
		"  -v                     show short version number and exit\n" +
		"  -V                     show detailed version info and exit\n" +
		"  --kcp                  KCP protocol (default is QUIC protocol)\n" +
		"  --tcp                  Use UDP-over-TCP to bypass UDP blocking\n" +
		"  --ipv4                 UDP only listens on IPv4, ignoring IPv6\n" +
		"  --ipv6                 UDP only listens on IPv6, ignoring IPv4\n" +
		"  --debug                Send debugging messages to the client\n" +
		"  --attachable           Allow another client to attach to server\n" +
		"  --socket               Listen on a socket to allow reattachment\n" +
		"  --list                 List all tsshd sessions for current user\n" +
		"  --view <PID>.<SID>     Print the screen contents of the session\n" +
		"  --attach <PID>         Attach to tsshd session specified by PID\n" +
		"  --mtu N                Sets the Maximum Transmission Unit (MTU)\n" +
		"  --kcp-wire-rate N      KCP only: pace session output below a downlink wire budget\n" +
		"                           in bytes/s (0 = off, the default). Recommended: ~0.7 x the\n" +
		"                           bottleneck link's rate. Payload output is granted roughly\n" +
		"                           N/2.6 bytes/s (FEC 1+1 doubles wire datagrams plus framing and\n" +
		"                           retransmission overhead; see docs/weak-network-agent-design.md).\n" +
		"                           Keeps the bottleneck queue out of saturation so control input\n" +
		"                           and uplink ACKs get through while output floods. Ignored\n" +
		"                           without --kcp. Can also be set in sshd_config as KcpWireRate.\n" +
		"  --port low-high        UDP port range that the tsshd listens on\n" +
		"  --connect-timeout t    The timeout for tssh connecting to tsshd\n")
	return 0
}

func parseTsshdArgs() *tsshdArgs {
	args := &tsshdArgs{}
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-h", "--help":
			args.Help = true
		case "-v", "--version":
			args.VerShort = true
		case "-V":
			args.VerDetailed = true
		case "--kcp":
			args.KCP = true
		case "--tcp":
			args.TCP = true
		case "--ipv4":
			args.IPv4 = true
		case "--ipv6":
			args.IPv6 = true
		case "--debug":
			args.Debug = true
		case "--attachable":
			args.Attachable = true
		case "--socket":
			args.Socket = true
		case "--list":
			args.List = true
		case "--view":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				args.View = os.Args[i+1]
				i++
			}
		case "--attach":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				args.Attach = os.Args[i+1]
				i++
			}
		case "--mtu":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				if mtu, err := strconv.ParseUint(os.Args[i+1], 10, 16); err == nil {
					args.MTU = uint16(mtu)
				}
				i++
			}
		case "--kcp-wire-rate":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				if rate, err := strconv.ParseUint(os.Args[i+1], 10, 64); err == nil {
					args.KcpWireRate = rate
					args.kcpWireRateSet = true
				} else {
					warning("--kcp-wire-rate [%s] invalid: %v", os.Args[i+1], err)
				}
				i++
			}
		case "--port":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				args.Port = os.Args[i+1]
				i++
			}
		case "--connect-timeout":
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
				if timeout, err := strconv.ParseUint(os.Args[i+1], 10, 32); err == nil {
					args.ConnectTimeout = time.Duration(timeout) * time.Second
				}
				i++
			}
		}
	}
	return args
}

const kEnvTsshdBackground = "TRZSZ-SSHD-BACKGROUND"

// resolveKcpWireRate applies the --kcp-wire-rate precedence: the command-line
// flag wins; when it is unset (0 = off, the default), the sshd_config
// `KcpWireRate <bytes/s>` key is honored so deployments can configure the
// recipe without editing the client-facing command. An invalid config value
// is a warning plus "off", never a startup failure. The knob only applies to
// KCP connections and is ignored (with a warning) without --kcp; QUIC has its
// own congestion control.
// kMinKcpWireRate is the pacing floor below which the configuration is almost
// certainly a mistake: at this rate the payload token grant is 4096/2.6 ~=
// 1.575 KB/s, so a single 32 KiB output chunk holds its session's writer (and,
// on a closing connection, that writer's goroutine) for ~21 s. The pacer still
// runs below it - the floor only produces a warning, never a silent clamp.
const kMinKcpWireRate = 4096

func resolveKcpWireRate(flagRate uint64, flagSet bool, configVal string, kcp bool) uint64 {
	if !flagSet && flagRate == 0 && configVal != "" {
		if rate, err := strconv.ParseUint(configVal, 10, 64); err == nil {
			flagRate = rate
		} else {
			warning("sshd_config KcpWireRate [%s] invalid: %v", configVal, err)
		}
	}
	if flagRate > 0 && !kcp {
		warning("--kcp-wire-rate %d B/s ignored: not a KCP (--kcp) server; output pacing is KCP-only", flagRate)
		return 0
	}
	if flagRate > 0 && flagRate < kMinKcpWireRate {
		warning("--kcp-wire-rate %d B/s is below the %d B/s floor: at such rates a single 32 KiB output chunk would hold its session's writer for a very long time, and shutdown of a paced connection can retain the writer goroutine for up to that long; the pacer will run but is almost certainly misconfigured", flagRate, kMinKcpWireRate)
	}
	return flagRate
}

func background() (bool, io.ReadCloser, error) {
	if v := os.Getenv(kEnvTsshdBackground); v == "TRUE" {
		return false, nil, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		exePath = os.Args[0]
	}

	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Env = append(os.Environ(), kEnvTsshdBackground+"=TRUE")
	cmd.SysProcAttr = getSysProcAttr()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return true, nil, fmt.Errorf("background stdout pipe failed: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return true, nil, fmt.Errorf("background stderr pipe failed: %v", err)
	}

	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

	if err := cmd.Start(); err != nil {
		return true, nil, fmt.Errorf("background cmd start failed: %v", err)
	}

	return true, stdout, nil
}

var onExitFuncs []func()
var onExitMutex sync.Mutex

func cleanupOnExit() {
	onExitMutex.Lock()
	funcs := append([]func(){}, onExitFuncs...)
	onExitFuncs = nil
	onExitMutex.Unlock()

	for i := len(funcs) - 1; i >= 0; i-- {
		funcs[i]()
	}
}

func addOnExitFunc(fn func()) {
	onExitMutex.Lock()
	defer onExitMutex.Unlock()
	onExitFuncs = append(onExitFuncs, fn)
}

var mainOnce atomic.Bool

// RunMain is the main entry point for the tsshd daemon process.
//
// The code before RunMain is executed in the original parent process,
// and again in the forked child process during daemon initialization.
//
// After forking, the parent process will exit,
// and only the child process continues running.
func RunMain(opts ...Option) (int, error) {
	if !mainOnce.CompareAndSwap(false, true) {
		return kExitCodeAlreadyRun, fmt.Errorf("tsshd server already running")
	}

	for _, opt := range opts {
		if err := opt(); err != nil {
			return kExitCodeApplyOptions, fmt.Errorf("apply option failed: %v", err)
		}
	}

	args := parseTsshdArgs()
	if args.Help {
		return printHelp(), nil
	}
	if args.VerShort {
		return printVersionShort(), nil
	}
	if args.VerDetailed {
		return printVersionDetailed(), nil
	}

	if args.List {
		return handleListCommand()
	}
	if args.View != "" {
		return handleViewCommand(args.View)
	}
	if args.Attach != "" {
		return handleAttachCommand(args.Attach)
	}

	parent, stdout, err := background()
	if err != nil {
		return kExitCodeBackground, fmt.Errorf("run in background failed: %v", err)
	}

	if parent {
		defer func() { _ = stdout.Close() }()
		if _, err := io.Copy(os.Stdout, stdout); err != nil {
			return kExitCodeOutputFail, fmt.Errorf("forward stdout failed: %v", err)
		}
		return 0, nil
	}

	// cleanup on exit
	defer cleanupOnExit()

	// default connect timeout
	if args.ConnectTimeout <= 0 {
		args.ConnectTimeout = kDefaultConnectTimeout
	}

	// init logging and sshd_config
	enableWarningLogging = true

	if args.Debug {
		initDebugLogging()
	}

	initSshdConfig()

	args.KcpWireRate = resolveKcpWireRate(args.KcpWireRate, args.kcpWireRateSet, getSshdConfig("KcpWireRate"), args.KCP)

	if !enableDebugLogging {
		if v := getSshdConfig("LogLevel"); strings.EqualFold(v, "quiet") || strings.EqualFold(v, "fatal") {
			enableWarningLogging = false
		}
	}

	// init tsshd server
	serverInfo, infoStr, err := initServer(args)
	if err != nil {
		debug("init server failed: %v", err)
		fmt.Println(err)
		_ = os.Stdout.Close()
		return kExitCodeInitServer, nil // Error has been forwarded to stdout for parent handling
	}

	// Initialize global socket info before publishing server info,
	// so incoming client connections can populate the session name.
	if args.Attachable && args.Socket {
		go startSocketServer(serverInfo)
	}

	fmt.Printf("\a%s\n", infoStr)

	addOnExitFunc(func() {
		if server := activeSshUdpServer.Load(); server != nil {
			_, _ = doWithTimeout(func() (int, error) { server.Close(); return 0, nil }, time.Second)
			// If the client is still active on exit, logs have likely been delivered,
			// so the server-side debug log can be cleaned up.
			if enableDebugLogging && server.isClientAlive() {
				cleanupDebugLog.Store(true)
			}
		}
	})

	_ = os.Stdout.Close()

	// start background liveness watchdog
	go monitorServerLiveness(args)

	// start signal listener (SIGTERM/SIGHUP/Interrupt)
	go handleExitSignals()

	// wait for exit
	return <-exitChan, nil
}

func monitorServerLiveness(args *tsshdArgs) {
	beginTime := time.Now()

	for {
		server := activeSshUdpServer.Load()
		if server == nil {
			// NOTE: Do not check server.serving.Load() here. In attachable mode,
			// there is a brief window where the server may not be marked as serving,
			// which could cause the process to exit unexpectedly.

			// The client is expected to connect within ConnectTimeout (default: 10s).
			// Otherwise, it is considered a network issue and the process exits.
			if time.Since(beginTime) > args.ConnectTimeout {
				exitWithCode(kExitCodeConnTimeout)
				return
			}
			time.Sleep(time.Second)
			continue
		}

		// Skip liveness check if aliveTimeout is zero.
		// NOTE: In attachable mode, a new server may set a different aliveTimeout.
		if server.aliveTimeout == 0 {
			time.Sleep(time.Second)
			continue
		}

		// Check the last received client heartbeat. Exit if it exceeds aliveTimeout.
		if time.Since(time.UnixMilli(server.clientAliveTime.Load())) > server.aliveTimeout {
			warning("tsshd keep alive timeout")
			exitWithCode(kExitCodeAliveTimeout)
			return
		}

		time.Sleep(max(server.intervalTime, time.Second))
	}
}

func handleExitSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGTERM, // Default signal for the kill command
		syscall.SIGHUP,  // Terminal closed (System reboot/shutdown)
		os.Interrupt,    // Ctrl+C signal
	)

	sig := <-sigChan

	go func() {
		// Allow a 1-second grace period for cleanup/UDP transmission
		time.Sleep(time.Second)
		debug("force quitting on signal [%v]: failed to exit in 1s (client might have disconnected)", sig)
		exitWithCode(kExitCodeSignalKill)
	}()

	if s := activeSshUdpServer.Load(); s != nil {
		// Notify the client to initiate a graceful shutdown
		if err := s.sendBusMessage("quit", quitMessage{fmt.Sprintf("receiving signal [%v] from the operating system", sig)}); err != nil {
			warning("send quit message failed: %v", err)
		}
	}
}
