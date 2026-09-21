//go:build unix

// Package boottest drives a RouterOS console exposed by qemu on a unix serial
// socket.  It is a Go port of tools/boot_test.py: it logs in (admin with an
// empty password), runs "/system license print" and retries until the expected
// licence level shows up or the timeout expires.  The first boot installs the
// licence, so the old level may be visible for a while.
//
// Every wait also stops as soon as the console goes away, either because the
// socket reached EOF or because the qemu process (when Options.PID is set) has
// exited, so a dead guest fails fast instead of spinning until the timeout.
// The package never prints the serial log; failures are returned as *Error,
// which carries the reason, the last licence level seen and the console tail.
package boottest

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// keepBytes is how much console output is kept for matching/reporting.
	keepBytes = 8192
	// tailBytes is how much of the buffer Error.Tail carries.
	tailBytes = 800
	// connectRetry is the delay between connection attempts.
	connectRetry = 500 * time.Millisecond
	// drainSlice is the longest a single drain step waits for data.
	drainSlice = 500 * time.Millisecond

	defaultTimeout  = 600 * time.Second
	defaultExpect   = "p-unlimited"
	defaultLogin    = "admin"
	defaultInterval = 5 * time.Second
	defaultGrace    = 30 * time.Second
)

// Reasons reported by Error.Reason.
const (
	ReasonTimeout       = "timeout"               // the deadline was reached
	ReasonQEMUExited    = "qemu exited"           // Options.PID is gone
	ReasonConsoleClosed = "serial console closed" // socket EOF or read error
)

// licenceRe matches `level: <value>` in the console output.
var licenceRe = regexp.MustCompile(`level:\s*(\S+)`)

// Options configures Run.
type Options struct {
	Socket   string        // unix socket path (required)
	PID      int           // qemu pid, 0 = unknown
	Timeout  time.Duration // total timeout for boot+login+licence (default 600s)
	Expect   string        // expected licence level (default "p-unlimited")
	Login    string        // console user (default "admin")
	Interval time.Duration // between licence checks (default 5s)
	Grace    time.Duration // keep retrying after a wrong level is seen (default 30s)
}

// Error describes a failed boot test.  Error never contains the console log;
// callers that want to show it can print Tail.
type Error struct {
	Message string // human-readable failure, e.g. licence level is "h-2.9.16", expected "p-unlimited"
	Reason  string // why the wait stopped: ReasonTimeout, ReasonQEMUExited or ReasonConsoleClosed
	Level   string // last licence level seen, "" when none was seen
	Expect  string // expected licence level
	Tail    string // last 800 bytes of console output
}

func (e *Error) Error() string {
	return fmt.Sprintf("boot test: %s (%s)", e.Message, e.Reason)
}

// Run performs the boot test.  It returns nil when the expected licence level
// is seen, and a non-nil error otherwise (a *Error carrying the reason and the
// last level seen).
func Run(opts Options) error {
	if opts.Socket == "" {
		return errors.New("boottest: Socket is required")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	expect := opts.Expect
	if expect == "" {
		expect = defaultExpect
	}
	login := opts.Login
	if login == "" {
		login = defaultLogin
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	grace := opts.Grace
	if grace <= 0 {
		grace = defaultGrace
	}

	con := &console{
		path:     opts.Socket,
		deadline: time.Now().Add(timeout),
		pid:      opts.PID,
	}

	if !con.connect() {
		return con.failure(fmt.Sprintf("cannot connect to %s", opts.Socket))
	}
	if !con.waitFor([]string{"Login:", "login:"}, 0) {
		return con.failure("no login prompt (image did not boot?)")
	}
	if !con.send(login + "\r") {
		return con.failure("console closed while logging in")
	}
	if !con.waitFor([]string{"Password:"}, 0) {
		return con.failure("no password prompt")
	}
	if !con.send("\r") {
		return con.failure("console closed while logging in")
	}
	if !con.waitFor([]string{"> "}, 0) {
		return con.failure("no console prompt after login")
	}

	var (
		level     string
		firstSeen time.Time
	)
	for time.Now().Before(con.deadline) {
		if !con.alive() {
			return con.failure("console died during the licence check")
		}
		if !con.send("/system license print\r") {
			return con.failure("console closed during the licence check")
		}
		con.waitFor([]string{"[admin@", "> "}, interval)
		con.drain(time.Second)
		if lv := con.licenceLevel(); lv != "" {
			level = lv
			if level == expect {
				return nil
			}
			// The licence may still be getting installed; give it a moment.
			if firstSeen.IsZero() {
				firstSeen = time.Now()
			} else if time.Since(firstSeen) > grace {
				break
			}
		}
		time.Sleep(interval)
	}

	err := con.failure(fmt.Sprintf("licence level is %q, expected %q", level, expect))
	err.Level = level
	err.Expect = expect
	return err
}

// console is the serial console driver.  buf keeps the last keepBytes bytes of
// output, which is what prompts, licence levels and the reported tail are
// matched against; like the Python driver it is never consumed.
type console struct {
	path     string
	deadline time.Time
	pid      int

	sock   net.Conn
	buf    []byte
	eof    bool
	exited bool
}

func (c *console) failure(msg string) *Error {
	return &Error{Message: msg, Reason: c.why(), Tail: c.tail()}
}

// why is the short explanation for a wait that stopped early.
func (c *console) why() string {
	switch {
	case c.exited:
		return ReasonQEMUExited
	case c.eof:
		return ReasonConsoleClosed
	default:
		return ReasonTimeout
	}
}

// alive reports whether the console can still make progress.  It is false
// once the socket reached EOF or the qemu process is gone.  A zombie process
// (exited but not reaped by its parent yet) counts as gone: kill(pid, 0)
// succeeds for zombies, which would otherwise stall the wait until the
// timeout.
func (c *console) alive() bool {
	if c.eof {
		return false
	}
	if c.pid > 0 {
		if zombie(c.pid) {
			c.exited = true
			return false
		}
		// SIG 0 only performs the permission/existence check.  ESRCH means
		// the process is gone; EPERM means it is alive but not ours.
		if err := syscall.Kill(c.pid, 0); errors.Is(err, syscall.ESRCH) {
			c.exited = true
			return false
		}
	}
	return true
}

// zombie reports whether pid is a zombie or otherwise exiting.
func zombie(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// The state is the field after the (possibly parenthesised) command name.
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return false
	}
	switch data[i+2] {
	case 'Z', 'X':
		return true
	}
	return false
}

// connect retries until the socket accepts or the deadline passes.
func (c *console) connect() bool {
	for time.Now().Before(c.deadline) {
		if !c.alive() {
			return false
		}
		conn, err := net.DialTimeout("unix", c.path, connectRetry)
		if err == nil {
			c.sock = conn
			return true
		}
		time.Sleep(connectRetry)
	}
	return false
}

// drain reads whatever arrives within d, keeping the last keepBytes bytes.
func (c *console) drain(d time.Duration) {
	if c.sock == nil || c.eof || c.exited {
		return
	}
	end := time.Now().Add(d)
	chunk := make([]byte, 65536)
	for time.Now().Before(end) {
		if err := c.sock.SetReadDeadline(end); err != nil {
			c.eof = true
			return
		}
		n, err := c.sock.Read(chunk)
		if n > 0 {
			c.buf = append(c.buf, chunk[:n]...)
			if len(c.buf) > keepBytes {
				c.buf = append(c.buf[:0], c.buf[len(c.buf)-keepBytes:]...)
			}
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return
			}
			c.eof = true
			return
		}
	}
}

// waitFor drains until one of needles appears in the buffer.  A timeout <= 0
// waits until the overall deadline.  It returns false when the console dies.
func (c *console) waitFor(needles []string, timeout time.Duration) bool {
	end := time.Now().Add(timeout)
	if timeout <= 0 {
		end = c.deadline
	}
	for time.Now().Before(end) {
		c.drain(drainSlice)
		for _, needle := range needles {
			if bytes.Contains(c.buf, []byte(needle)) {
				return true
			}
		}
		if !c.alive() {
			return false
		}
	}
	return false
}

// send writes text to the console; it reports false when the console is gone.
func (c *console) send(text string) bool {
	if c.sock == nil {
		c.eof = true
		return false
	}
	if _, err := c.sock.Write([]byte(text)); err != nil {
		c.eof = true
		return false
	}
	return true
}

// licenceLevel returns the last `level: <value>` in the current buffer.
func (c *console) licenceLevel() string {
	matches := licenceRe.FindAllSubmatch(c.buf, -1)
	if matches == nil {
		return ""
	}
	return string(matches[len(matches)-1][1])
}

// tail decodes the last tailBytes of console output for diagnosis.
func (c *console) tail() string {
	b := c.buf
	if len(b) > tailBytes {
		b = b[len(b)-tailBytes:]
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}
