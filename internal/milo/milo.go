// Package milo runs MikroTik's x86 legacy-BIOS bootloader installer (milo)
// without root.  Milo expects a mounted boot filesystem and block devices: it
// creates /dev/bootdev and /dev/bootpart with mknod, uses FIBMAP on the boot
// files and writes the VBR to the partition device.
//
// The sandbox starts milo under ptrace and emulates exactly the pieces it
// needs: it fakes the /dev mknod/unlink calls, redirects the device opens to
// ordinary files, answers FIBMAP from a caller-supplied block map and pretends
// the staging directory lives on a 1 KiB-block ext2 filesystem.
//
// It is an emulation shim, not a security boundary: the tracee runs with the
// caller's privileges and can still read or write any file the caller can.
package milo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Options configures a sandbox run.
type Options struct {
	// MiloPath is the milo binary (static 32-bit i386).
	MiloPath string
	// StageDir holds the boot files (EFI/BOOT/BOOTX64.EFI) and receives the
	// map file milo generates.  It is passed to milo as the prefix argument.
	StageDir string
	// DiskImage backs /dev/bootdev (the whole disk, read-only for milo).
	DiskImage string
	// BootPart backs /dev/bootpart (the boot partition, read-write for milo).
	BootPart string
	// Blocks returns the block list (in filesystem block units) for a path
	// relative to StageDir.  Returning ok=false makes FIBMAP answer 0.
	Blocks func(rel string) (blocks []uint64, ok bool)
	// BlockSize is the filesystem block size reported by fstatfs (default 1024).
	BlockSize uint32
	// Timeout bounds the run; milo is killed when it expires (default 2m).
	Timeout time.Duration
	Stdout  io.Writer
	Stderr  io.Writer
}

// i386 syscall numbers used by the sandbox.
const (
	sysOpen     = 5
	sysOpenat   = 295
	sysIoctl    = 54
	sysMknod    = 14
	sysMknodat  = 306
	sysUnlink   = 10
	sysUnlinkat = 302
	sysFstatfs  = 100

	sysStat64    = 195
	sysLstat64   = 196
	sysFstat64   = 197
	sysFstatat64 = 300
)

const (
	fibmap    = 1
	ext2Magic = 0xEF53

	// bootDev is the st_dev reported for the staging directory.  Milo derives
	// the partition index from the device's minor number, so report a
	// partition-1 device (like /dev/nbd0p1) to make it pick MBR entry 1.
	bootDev = uint64(43<<8 | 1)

	ptraceGetRegs        = 0x4204 // PTRACE_GETREGSET
	ptraceSetRegs        = 0x4205 // PTRACE_SETREGSET
	ptraceGetSyscallInfo = 0x420e // PTRACE_GET_SYSCALL_INFO
	ntPrstatus           = 1
	regsSize             = 68 // i386 user_regs_struct
)

// regs32 is the 32-bit register set PTRACE_GETREGSET returns for a compat
// tracee: ebx, ecx, edx, esi, edi, ebp, eax, segments, orig_eax, eip, ...
type regs32 struct {
	buf [regsSize]byte
}

func (r *regs32) u32(off int) uint32 {
	return uint32(r.buf[off]) | uint32(r.buf[off+1])<<8 | uint32(r.buf[off+2])<<16 | uint32(r.buf[off+3])<<24
}

func (r *regs32) setU32(off int, v uint32) {
	r.buf[off] = byte(v)
	r.buf[off+1] = byte(v >> 8)
	r.buf[off+2] = byte(v >> 16)
	r.buf[off+3] = byte(v >> 24)
}

func (r *regs32) arg(i int) uintptr      { return uintptr(r.u32(i * 4)) }
func (r *regs32) setArg(i int, v uint32) { r.setU32(i*4, v) }
func (r *regs32) syscallNr() int         { return int(r.u32(44)) }
func (r *regs32) setSyscallNr(v uint32)  { r.setU32(44, v) }
func (r *regs32) retval() uint32         { return r.u32(24) }
func (r *regs32) setRetval(v uint32)     { r.setU32(24, v) }

// syscallInfo is the kernel's struct ptrace_syscall_info.  The kernel's op
// enum starts at NONE = 0, so op 1 is a syscall entry and op 2 an exit.  Using
// it makes the classification authoritative instead of relying on stop
// alternation, which can desynchronise when a syscall is restarted.
type syscallInfo struct {
	buf [88]byte
}

func (s *syscallInfo) op() uint8 { return s.buf[0] }

func (s *syscallInfo) nr() int {
	return int(int64(binary.LittleEndian.Uint64(s.buf[24:])))
}

func (s *syscallInfo) arg(i int) uintptr {
	return uintptr(binary.LittleEndian.Uint64(s.buf[32+i*8:]))
}

func (s *syscallInfo) rval() int64 {
	return int64(binary.LittleEndian.Uint64(s.buf[24:]))
}

func (t *tracer) syscallInfo() (*syscallInfo, error) {
	info := &syscallInfo{}
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, ptraceGetSyscallInfo,
		uintptr(t.pid), uintptr(len(info.buf)), uintptr(unsafe.Pointer(&info.buf[0])), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return info, nil
}

type tracer struct {
	opts    Options
	pid     int
	scratch uintptr
	debug   bool

	fdPaths  map[int]string
	fibmap   *fibmapCall
	fake     bool
	exited   bool
	timedOut atomic.Bool
	statPtr  uintptr
	lastNr   int
	lastSig  syscall.Signal
	curNr    int
	curArgs  [6]uintptr
}

type fibmapCall struct {
	fd    int
	index uint32
	ptr   uintptr
}

// Run executes milo in the sandbox.  It returns nil when milo exits 0.
//
// The whole run happens on one locked OS thread: ptrace requests must come
// from the thread that forked the tracee (child->parent == current), and Go's
// scheduler would otherwise migrate the goroutine between threads, making
// requests fail with ESRCH at random.
func Run(opts Options) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if opts.MiloPath == "" || opts.StageDir == "" {
		return errors.New("milo: MiloPath and StageDir are required")
	}
	if opts.Blocks == nil {
		return errors.New("milo: Blocks is required")
	}
	if opts.BlockSize == 0 {
		opts.BlockSize = 1024
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	stage, err := filepath.Abs(opts.StageDir)
	if err != nil {
		return err
	}
	opts.StageDir = stage

	cmd := exec.Command(opts.MiloPath, stage)
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
		// The run holds a locked OS thread, so this fires when the whole
		// process dies: make sure the tracee is not left behind.
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("milo: start: %w", err)
	}
	t := &tracer{
		opts:    opts,
		pid:     cmd.Process.Pid,
		fdPaths: map[int]string{},
		debug:   os.Getenv("MILO_DEBUG") != "",
	}
	// Register the cleanup before any ptrace request can fail: a tracee left
	// in a ptrace stop would linger until this process exits.
	defer func() {
		if !t.exited {
			syscall.Kill(t.pid, syscall.SIGKILL)
			var ws syscall.WaitStatus
			syscall.Wait4(t.pid, &ws, 0, nil)
		}
	}()

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(t.pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("milo: wait for exec: %w", err)
	}
	if err := syscall.PtraceSetOptions(t.pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		return fmt.Errorf("milo: ptrace options: %w", err)
	}
	if t.scratch, err = t.findScratch(); err != nil {
		return err
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Minute
	}
	watchdog := make(chan struct{})
	go func() {
		select {
		case <-watchdog:
		case <-time.After(opts.Timeout):
			t.timedOut.Store(true)
			syscall.Kill(t.pid, syscall.SIGKILL)
		}
	}()
	defer close(watchdog)

	for {
		if err := syscall.PtraceSyscall(t.pid, 0); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				break
			}
			return fmt.Errorf("milo: ptrace syscall: %w", err)
		}
		if _, err := syscall.Wait4(t.pid, &ws, 0, nil); err != nil {
			if errors.Is(err, syscall.ECHILD) {
				break
			}
			return fmt.Errorf("milo: wait: %w", err)
		}
		switch {
		case ws.Exited():
			t.exited = true
			if ws.ExitStatus() != 0 {
				return fmt.Errorf("milo: exited with status %d (last syscall %d)", ws.ExitStatus(), t.lastNr)
			}
			return nil
		case ws.Signaled():
			t.exited = true
			if t.timedOut.Load() {
				return fmt.Errorf("milo: timed out after %v", opts.Timeout)
			}
			return fmt.Errorf("milo: killed by signal %v", ws.Signal())
		case ws.Stopped():
			sig := ws.StopSignal()
			if os.Getenv("MILO_DEBUG_STOPS") != "" {
				if info, ierr := t.syscallInfo(); ierr == nil {
					fmt.Fprintf(os.Stderr, "milo-debug: stop sig=%#x op=%d nr=%d err=%v\n", uint32(sig), info.op(), info.nr(), ierr)
				} else {
					fmt.Fprintf(os.Stderr, "milo-debug: stop sig=%#x info error %v\n", uint32(sig), ierr)
				}
			}
			t.lastSig = sig
			if sig == syscall.SIGTRAP|0x80 {
				if err := t.syscallStop(); err != nil {
					return err
				}
				continue
			}
			if err := syscall.PtraceSyscall(t.pid, int(sig)); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("milo: resume: %w", err)
			}
		}
	}
	var final syscall.WaitStatus
	syscall.Wait4(t.pid, &final, 0, nil)
	return nil
}

// findScratch picks a writable scratch area inside the tracee's stack mapping
// so path strings can be rewritten.
func (t *tracer) findScratch() (uintptr, error) {
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", t.pid))
	if err != nil {
		return 0, fmt.Errorf("milo: read maps: %w", err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		if !strings.HasSuffix(strings.TrimSpace(line), "[stack]") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err := strconv.ParseUint(bounds[0], 16, 64)
		if err != nil {
			continue
		}
		// The stack grows downwards: the low end of the mapping is unused.
		return uintptr(start) + 512, nil
	}
	return 0, errors.New("milo: no stack mapping found for scratch memory")
}

func (t *tracer) getRegs(r *regs32) error {
	iov := struct{ base, size uintptr }{uintptr(unsafe.Pointer(&r.buf[0])), regsSize}
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, ptraceGetRegs, uintptr(t.pid), ntPrstatus, uintptr(unsafe.Pointer(&iov)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (t *tracer) setRegs(r *regs32) error {
	iov := struct{ base, size uintptr }{uintptr(unsafe.Pointer(&r.buf[0])), regsSize}
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, ptraceSetRegs, uintptr(t.pid), ntPrstatus, uintptr(unsafe.Pointer(&iov)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (t *tracer) syscallStop() error {
	info, err := t.syscallInfo()
	if err != nil {
		return fmt.Errorf("milo: syscall info: %w", err)
	}
	if info.op() == 1 {
		t.curNr = info.nr()
		t.lastNr = t.curNr
		var args [6]uintptr
		for i := range args {
			args[i] = info.arg(i)
		}
		t.curArgs = args
		return t.onEntry(t.curNr, args)
	}
	return t.onExit(info.rval())
}

func (t *tracer) onEntry(nr int, args [6]uintptr) error {
	if t.debug {
		fmt.Fprintf(os.Stderr, "milo-debug: entry nr=%d args %#x %#x %#x %#x %#x\n",
			nr, args[0], args[1], args[2], args[3], args[4])
	}
	switch nr {
	case sysOpen, sysOpenat:
		pathPtr := args[0]
		if nr == sysOpenat {
			pathPtr = args[1]
		}
		path, err := t.readString(pathPtr)
		if err != nil {
			return nil
		}
		replacement := t.redirect(path)
		if replacement == "" {
			return nil
		}
		if err := t.writeString(t.scratch, replacement); err != nil {
			return err
		}
		return t.replaceArg(nr, 0, uint32(t.scratch))
	case sysMknod, sysMknodat, sysUnlink, sysUnlinkat:
		pathPtr := args[0]
		if nr == sysMknodat || nr == sysUnlinkat {
			pathPtr = args[1]
		}
		path, err := t.readString(pathPtr)
		if err != nil {
			return nil
		}
		if path == "/dev/bootdev" || path == "/dev/bootpart" {
			// Never let these run: fake the result at the exit stop.
			t.fake = true
			return t.fakeSyscallNr()
		}
	case sysIoctl:
		if args[1] == fibmap {
			ptr := args[2]
			index, err := t.readU32(ptr)
			if err == nil {
				t.fibmap = &fibmapCall{fd: int(int32(args[0])), index: index, ptr: ptr}
			}
		}
	case sysStat64, sysLstat64:
		path, err := t.readString(args[0])
		if err == nil && t.isStagePath(path) {
			t.statPtr = args[1]
		}
	case sysFstatat64:
		path, err := t.readString(args[1])
		if err == nil && t.isStagePath(path) {
			t.statPtr = args[2]
		}
	case sysFstat64:
		if path, err := t.fdPath(int(int32(args[0]))); err == nil && t.isStagePath(path) {
			t.statPtr = args[1]
		}
	}
	return nil
}

// isStagePath reports whether path names the staging directory itself.
func (t *tracer) isStagePath(path string) bool {
	clean := filepath.Clean(path)
	return clean == t.opts.StageDir
}

func (t *tracer) onExit(rval int64) error {
	if t.fake {
		t.fake = false
		return t.setRetval(0)
	}
	if call := t.fibmap; call != nil {
		t.fibmap = nil
		block := uint64(0)
		if path, err := t.fdPath(call.fd); err == nil {
			if blocks, ok := t.opts.Blocks(t.relPath(path)); ok && call.index < uint32(len(blocks)) {
				block = blocks[call.index]
			}
		}
		if err := t.writeU32(call.ptr, uint32(block)); err != nil {
			return err
		}
		return t.setRetval(0)
	}
	if t.statPtr != 0 {
		ptr := t.statPtr
		t.statPtr = 0
		if err := t.writeU64(ptr, bootDev); err != nil {
			return err
		}
	}
	if t.curNr == sysFstatfs {
		// struct statfs on i386: f_type at 0, f_bsize at 4.
		ptr := t.curArgs[1]
		if err := t.writeU32(ptr, ext2Magic); err != nil {
			return err
		}
		if err := t.writeU32(ptr+4, t.opts.BlockSize); err != nil {
			return err
		}
	}
	return nil
}

// replaceArg rewrites a syscall argument (via the register set).
func (t *tracer) replaceArg(nr int, slot int, value uint32) error {
	var regs regs32
	if err := t.getRegs(&regs); err != nil {
		return err
	}
	if nr == sysOpen {
		regs.setArg(0, value)
	} else {
		regs.setArg(slot+1, value)
	}
	return t.setRegs(&regs)
}

// setRetval fakes a successful syscall return.
func (t *tracer) setRetval(v uint32) error {
	var regs regs32
	if err := t.getRegs(&regs); err != nil {
		return err
	}
	regs.setRetval(v)
	return t.setRegs(&regs)
}

// fakeSyscallNr replaces the syscall with an invalid one so it returns ENOSYS.
func (t *tracer) fakeSyscallNr() error {
	var regs regs32
	if err := t.getRegs(&regs); err != nil {
		return err
	}
	regs.setSyscallNr(^uint32(0))
	return t.setRegs(&regs)
}

func (t *tracer) redirect(path string) string {
	switch path {
	case "/dev/bootdev":
		if t.opts.DiskImage != "" {
			return t.opts.DiskImage
		}
	case "/dev/bootpart":
		if t.opts.BootPart != "" {
			return t.opts.BootPart
		}
	}
	return ""
}

func (t *tracer) relPath(path string) string {
	prefix := t.opts.StageDir + "/"
	if strings.HasPrefix(path, prefix) {
		return strings.TrimPrefix(path, prefix)
	}
	return path
}

func (t *tracer) fdPath(fd int) (string, error) {
	if p, ok := t.fdPaths[fd]; ok {
		return p, nil
	}
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", t.pid, fd))
	if err != nil {
		return "", err
	}
	t.fdPaths[fd] = p
	return p, nil
}

func (t *tracer) readString(addr uintptr) (string, error) {
	if addr == 0 {
		return "", errors.New("null pointer")
	}
	buf := make([]byte, 512)
	if _, err := syscall.PtracePeekData(t.pid, addr, buf); err != nil {
		return "", err
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i]), nil
		}
	}
	return "", errors.New("string not terminated")
}

func (t *tracer) writeString(addr uintptr, s string) error {
	data := append([]byte(s), 0)
	if _, err := syscall.PtracePokeData(t.pid, addr, data); err != nil {
		return fmt.Errorf("milo: write %q at %#x: %w%s", s, addr, err, t.diag())
	}
	return nil
}

// diag reports what happened to the tracee for error messages.
func (t *tracer) diag() string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", t.pid))
	if err != nil {
		return fmt.Sprintf(" (tracee gone: %v, last syscall %d, exited=%v)", err, t.lastNr, t.exited)
	}
	fields := strings.Fields(string(data))
	state := "?"
	if len(fields) > 2 {
		state = fields[2]
	}
	extra := ""
	if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", t.pid)); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "SigPnd:") || strings.HasPrefix(line, "ShdPnd:") || strings.HasPrefix(line, "SigQ:") {
				extra += " " + strings.Join(strings.Fields(line), "=")
			}
		}
	}
	return fmt.Sprintf(" (tracee state %s, last syscall %d, last signal %d, exited=%v%s)", state, t.lastNr, t.lastSig, t.exited, extra)
}

func (t *tracer) readU32(addr uintptr) (uint32, error) {
	buf := make([]byte, 4)
	if _, err := syscall.PtracePeekData(t.pid, addr, buf); err != nil {
		return 0, err
	}
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24, nil
}

func (t *tracer) writeU64(addr uintptr, v uint64) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	if _, err := syscall.PtracePokeData(t.pid, addr, buf); err != nil {
		return fmt.Errorf("milo: poke %#x: %w%s", addr, err, t.diag())
	}
	return nil
}

func (t *tracer) writeU32(addr uintptr, v uint32) error {
	buf := []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	if _, err := syscall.PtracePokeData(t.pid, addr, buf); err != nil {
		return fmt.Errorf("milo: poke %#x: %w%s", addr, err, t.diag())
	}
	return nil
}
