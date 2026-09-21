//go:build unix

package boottest

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	banner   = "MikroTik 7.24.4 (stable)\r\nCHR Login: "
	password = "Password: "
	prompt   = "[admin@MikroTik] > "
)

// startFakeRouter listens on a unix socket and emulates just enough of the
// RouterOS serial console for Run: the login handshake, then one line of
// output per "/system license print".  The last response is repeated.
func startFakeRouter(t *testing.T, responses ...string) string {
	t.Helper()
	if len(responses) == 0 {
		responses = []string{""}
	}
	sock := filepath.Join(t.TempDir(), "serial.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	conns := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conns <- conn
		serveFakeRouter(conn, responses)
		conn.Close()
	}()

	t.Cleanup(func() {
		ln.Close()
		select {
		case conn := <-conns:
			conn.Close()
		default:
		}
	})
	return sock
}

// startClosingRouter accepts a connection, emits the banner and closes the
// socket, emulating a console that goes away.
func startClosingRouter(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "serial.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte(banner))
		conn.Close()
	}()
	return sock
}

func serveFakeRouter(conn net.Conn, responses []string) {
	var pending []byte
	readUntil := func(needle string) bool {
		for {
			if i := bytes.Index(pending, []byte(needle)); i >= 0 {
				pending = pending[i+len(needle):]
				return true
			}
			chunk := make([]byte, 256)
			n, err := conn.Read(chunk)
			if n > 0 {
				pending = append(pending, chunk[:n]...)
			}
			if err != nil {
				return false
			}
		}
	}
	write := func(s string) bool {
		_, err := conn.Write([]byte(s))
		return err == nil
	}

	if !write(banner) || !readUntil("admin\r") {
		return
	}
	if !write(password) || !readUntil("\r") {
		return
	}
	if !write(prompt) {
		return
	}
	for i := 0; readUntil("/system license print"); i++ {
		resp := responses[len(responses)-1]
		if i < len(responses) {
			resp = responses[i]
		}
		if !write("\r\n" + resp + "\r\n" + prompt) {
			return
		}
	}
}

func TestRunSucceeds(t *testing.T) {
	sock := startFakeRouter(t, "        level: p-unlimited")
	start := time.Now()
	err := Run(Options{
		Socket:   sock,
		Timeout:  10 * time.Second,
		Expect:   "p-unlimited",
		Login:    "admin",
		Interval: 50 * time.Millisecond,
		Grace:    200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Run took %v, want well under the timeout", elapsed)
	}
}

func TestRunRetriesUntilLevelChanges(t *testing.T) {
	// The first boot still reports the old level while the licence package
	// installs the new one; Run must re-run the command and succeed.
	sock := startFakeRouter(t,
		"        level: h-2.9.16",
		"        level: p-unlimited",
	)
	err := Run(Options{
		Socket:   sock,
		Timeout:  10 * time.Second,
		Expect:   "p-unlimited",
		Interval: 50 * time.Millisecond,
		Grace:    time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunWrongLevelFails(t *testing.T) {
	sock := startFakeRouter(t, "        level: h-2.9.16")
	err := Run(Options{
		Socket:   sock,
		Timeout:  10 * time.Second,
		Expect:   "p-unlimited",
		Interval: 50 * time.Millisecond,
		Grace:    100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Run succeeded, want an error")
	}
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("Run returned %T (%v), want *Error", err, err)
	}
	if be.Level != "h-2.9.16" {
		t.Errorf("Level = %q, want h-2.9.16", be.Level)
	}
	if be.Expect != "p-unlimited" {
		t.Errorf("Expect = %q, want p-unlimited", be.Expect)
	}
	if !strings.Contains(be.Error(), "h-2.9.16") || !strings.Contains(be.Error(), "p-unlimited") {
		t.Errorf("error %q does not mention both levels", be.Error())
	}
	if !strings.Contains(be.Tail, "level: h-2.9.16") {
		t.Errorf("Tail = %q, want the console output", be.Tail)
	}
}

func TestRunLevelNeverAppears(t *testing.T) {
	sock := startFakeRouter(t) // answers the licence command with no level
	start := time.Now()
	err := Run(Options{
		Socket:   sock,
		Timeout:  700 * time.Millisecond,
		Interval: 50 * time.Millisecond,
		Grace:    100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Run succeeded, want a timeout error")
	}
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("Run returned %T (%v), want *Error", err, err)
	}
	if be.Reason != ReasonTimeout {
		t.Errorf("Reason = %q, want %q", be.Reason, ReasonTimeout)
	}
	if be.Level != "" {
		t.Errorf("Level = %q, want empty", be.Level)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Run took %v, want it to stop at the timeout", elapsed)
	}
}

func TestRunConsoleClosedFailsFast(t *testing.T) {
	sock := startClosingRouter(t)
	start := time.Now()
	err := Run(Options{
		Socket:   sock,
		Timeout:  10 * time.Second,
		Interval: 50 * time.Millisecond,
		Grace:    time.Second,
	})
	if err == nil {
		t.Fatal("Run succeeded, want an error")
	}
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("Run returned %T (%v), want *Error", err, err)
	}
	if be.Reason != ReasonConsoleClosed {
		t.Errorf("Reason = %q, want %q", be.Reason, ReasonConsoleClosed)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Run took %v, want a fast failure", elapsed)
	}
}

func TestRunQEMUExitedFailsFast(t *testing.T) {
	// Spawn a process and reap it, so its pid is certainly gone.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	if err := cmd.Run(); err != nil {
		t.Fatalf("spawn helper: %v", err)
	}
	start := time.Now()
	err := Run(Options{
		Socket:  filepath.Join(t.TempDir(), "missing.sock"),
		PID:     cmd.Process.Pid,
		Timeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("Run succeeded, want an error")
	}
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("Run returned %T (%v), want *Error", err, err)
	}
	if be.Reason != ReasonQEMUExited {
		t.Errorf("Reason = %q, want %q", be.Reason, ReasonQEMUExited)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Run took %v, want a fast failure", elapsed)
	}
}

func TestRunMissingSocketFails(t *testing.T) {
	err := Run(Options{
		Socket:  filepath.Join(t.TempDir(), "missing.sock"),
		Timeout: 300 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Run succeeded, want an error")
	}
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("Run returned %T (%v), want *Error", err, err)
	}
	if !strings.Contains(be.Error(), "cannot connect") {
		t.Errorf("error %q does not mention the failed connection", be.Error())
	}
}

func TestRunRequiresSocket(t *testing.T) {
	if err := Run(Options{}); err == nil {
		t.Fatal("Run succeeded without a socket, want an error")
	}
}

// TestZombieCountsAsDead makes sure an exited-but-unreaped qemu does not keep
// the wait alive until the timeout.
func TestZombieCountsAsDead(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Leave the child unreaped on purpose: it becomes a zombie.
	time.Sleep(100 * time.Millisecond)
	c := &console{path: "/nonexistent", deadline: time.Now().Add(time.Second), pid: cmd.Process.Pid}
	if c.alive() {
		t.Fatal("zombie process reported as alive")
	}
	if c.why() != "qemu exited" {
		t.Fatalf("reason = %q", c.why())
	}
	cmd.Wait()
}
