// Device configuration blob I/O: the 512-byte blob lives on /dev/flash and is
// reached through custom ioctls, with a plain-file fallback to /dev/root-disk.
package keygen

import (
	"io"
	"os"
	"syscall"
	"unsafe"
)

// Device paths and helpers, overridable through the environment.
const (
	DefaultFlashDev = "/dev/flash"
	DefaultDiskDev  = "/dev/root-disk"
	DefaultUUIDPath = "/sys/class/dmi/id/product_uuid"
	DefaultKeyman   = "/nova/bin/keyman"
)

// Config blob layout.
const (
	ConfigSize = 512
	OffSWID    = 0x100
	OffLic     = 0x110
	OffMode    = 0x150
)

// Custom /dev/flash ioctls.
const (
	ioctlSize  = 0x4601
	ioctlRead  = 0x90004602
	ioctlWrite = 0x50004603
)

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// ioctl performs one raw ioctl(2) with a pointer argument.
func ioctl(fd int, req uintptr, arg unsafe.Pointer) (int, error) {
	r1, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}

// ReadConfig reads the configuration blob from /dev/flash (KEYGEN_FLASH),
// falling back to the first 512 bytes of /dev/root-disk (KEYGEN_DISK),
// zero-padded when the file is shorter.
func ReadConfig() ([]byte, error) {
	flash := envOr("KEYGEN_FLASH", DefaultFlashDev)
	if fd, err := syscall.Open(flash, syscall.O_RDONLY|syscall.O_LARGEFILE, 0); err == nil {
		if size, err := ioctl(fd, ioctlSize, nil); err == nil && size >= 256 && size <= 0x4000 {
			if size < ConfigSize {
				size = ConfigSize // the caller touches bytes up to 0x151
			}
			buf := make([]byte, size)
			if _, err := ioctl(fd, ioctlRead, unsafe.Pointer(&buf[0])); err == nil {
				syscall.Close(fd)
				return buf, nil
			}
		}
		syscall.Close(fd)
	}

	disk := envOr("KEYGEN_DISK", DefaultDiskDev)
	f, err := os.Open(disk)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, ConfigSize)
	_, _ = io.ReadFull(f, buf) // shorter files stay zero-padded
	return buf, nil
}

// WriteConfig writes the blob back through the flash ioctl (errors are
// ignored, like the original) and mirrors it to /dev/root-disk, up to
// ConfigSize bytes.
func WriteConfig(data []byte) error {
	if len(data) > ConfigSize {
		data = data[:ConfigSize]
	}
	flash := envOr("KEYGEN_FLASH", DefaultFlashDev)
	if fd, err := syscall.Open(flash, syscall.O_RDONLY|syscall.O_LARGEFILE, 0); err == nil {
		if len(data) > 0 {
			_, _ = ioctl(fd, ioctlWrite, unsafe.Pointer(&data[0]))
		}
		syscall.Close(fd)
	}

	disk := envOr("KEYGEN_DISK", DefaultDiskDev)
	f, err := os.OpenFile(disk, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// readUUIDText returns the DMI product UUID text (KEYGEN_UUID overrides the
// path) or "" when it cannot be read; ChrLicVal then treats it as 16 zero
// bytes, exactly like the original's zero-filled buffer.
func readUUIDText() string {
	b, err := os.ReadFile(envOr("KEYGEN_UUID", DefaultUUIDPath))
	if err != nil {
		return ""
	}
	return string(b)
}
