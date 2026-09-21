package build

import (
	"archive/zip"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"mikrotikpatch/internal/boottest"
	"mikrotikpatch/internal/image"
	"mikrotikpatch/internal/milo"
	"mikrotikpatch/internal/npk"
	"mikrotikpatch/internal/patch"
)

// biosMBR is the legacy-BIOS boot code written at offset 0 of the MBR.
const biosMBR = "FA31C08ED0BC007C89E65007501FFBFCBF0006B90001F2A5EA1D060000BEBE07B304803C807423803C00750983C610FECB75EFCD18BE9B06AC3C00740B56BB0700B40ECD105EEBF0EBFE8B148B4C0289F5BF0500BB007CB8010257CD135F730C31C0CD134F75EDBE7C06EBCCBFFE7D813D55AA75C289EEEA007C00004572726F72206C6F6164696E67206F7065726174696E672073797374656D004D697373696E67206F7065726174696E672073797374656D0000000000"

// pendingImage is a built image waiting for its boot test and publication.
type pendingImage struct {
	path string
	bios bool
}

// buildImages builds the CHR disk images for one architecture, boot-tests them
// (in parallel) and publishes the zips.
func (c *Config) buildImages(arch, ext, buildDir, publishDir, npkPath string) error {
	pkg, err := npk.Load(npkPath)
	if err != nil {
		return err
	}
	imageData, err := os.ReadFile(npkPath)
	if err != nil {
		return err
	}
	chrWork := filepath.Join(buildDir, "chr")
	if err := os.MkdirAll(chrWork, 0o755); err != nil {
		return err
	}
	rosEntries := func(bash, miloBin []byte) []image.Entry {
		var entries []image.Entry
		for _, dir := range []string{"var", "var/pdb", "var/pdb/system", "boot", "bin", "rw", "rw/disk"} {
			entries = append(entries, image.Entry{Path: dir, Mode: image.DirMode | 0o755})
		}
		entries = append(entries, image.Entry{Path: "var/pdb/system/image", Data: imageData, Mode: 0o644})
		if len(miloBin) > 0 {
			entries = append(entries, image.Entry{Path: "bin/milo", Data: miloBin, Mode: 0o755})
		}
		if len(bash) > 0 {
			entries = append(entries, image.Entry{Path: "bin/bash", Data: bash, Mode: 0o755})
		}
		return entries
	}

	var images []pendingImage
	switch arch {
	case "x86":
		efi, err := pkg.ExtractFile("boot/EFI/BOOT/BOOTX64.EFI")
		if err != nil {
			return err
		}
		miloBin, err := pkg.ExtractFile("bin/milo")
		if err != nil {
			return err
		}
		bash, err := pkg.ExtractFile("bin/bash")
		if err != nil {
			return err
		}
		ros := rosEntries(bash, miloBin)

		c.logln("🚀 Creating CHR image for x86...")
		c.logln("🔄 Creating CHR image for x86 UEFI ...")
		uefiImg := filepath.Join(buildDir, fmt.Sprintf("chr-%s%s.img", c.Version, ext))
		if err := c.assemble(uefiImg, "fat16",
			[]image.Entry{{Path: "EFI/BOOT/BOOTX64.EFI", Data: efi, Mode: 0o644}},
			ros, nil); err != nil {
			return err
		}
		images = append(images, pendingImage{path: uefiImg})

		if c.LegacyBIOS {
			c.logln("Creating CHR image for x86 legacy BIOS ...")
			biosImg := filepath.Join(buildDir, fmt.Sprintf("chr-%s%s-legacy-bios.img", c.Version, ext))
			if err := c.buildBIOSImage(biosImg, efi, miloBin, ros); err != nil {
				return fmt.Errorf("failed to build x86 legacy BIOS image: %w", err)
			}
			images = append(images, pendingImage{path: biosImg, bios: true})
		}
	case "arm64":
		kernel, err := pkg.ExtractFile("boot/kernel")
		if err != nil {
			return err
		}
		bash, err := pkg.ExtractFile("bin/bash")
		if err != nil {
			return err
		}
		c.logln("🚀 Creating CHR image for arm64...")
		kernelPath := filepath.Join(chrWork, "kernel")
		efiPath := filepath.Join(chrWork, "BOOTAA64.EFI")
		if err := os.WriteFile(kernelPath, kernel, 0o644); err != nil {
			return err
		}
		if err := patch.BuildEFI(kernelPath, efiPath); err != nil {
			return err
		}
		os.Remove(kernelPath)
		efi, err := os.ReadFile(efiPath)
		if err != nil {
			return err
		}
		c.logln("🔄 Creating CHR image for arm64 UEFI ...")
		img := filepath.Join(buildDir, fmt.Sprintf("chr-%s%s.img", c.Version, ext))
		if err := c.assemble(img, "fat16",
			[]image.Entry{{Path: "EFI/BOOT/BOOTAA64.EFI", Data: efi, Mode: 0o644}},
			rosEntries(bash, nil), nil); err != nil {
			return err
		}
		images = append(images, pendingImage{path: img})
	default:
		c.logf("⚠️  no CHR image recipe for arch %s\n", arch)
	}

	if c.BootTest {
		if err := c.verifyImages(images, arch); err != nil {
			return err
		}
	}
	for _, img := range images {
		if err := c.publishImage(img.path, publishDir); err != nil {
			return err
		}
	}
	return os.RemoveAll(chrWork)
}

// verifyImages boot-tests every image, at most a few at a time.
func (c *Config) verifyImages(images []pendingImage, arch string) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(images))
	for _, img := range images {
		img := img
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.vmSem <- struct{}{}
			defer func() { <-c.vmSem }()
			if err := c.verifyBootImage(img.path, arch, img.bios); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

// assemble writes one disk image with the given boot filesystem.
func (c *Config) assemble(target, bootFS string, bootEntries, rosEntries []image.Entry, biosCode []byte) error {
	im, err := image.Create(target, biosCode)
	if err != nil {
		return err
	}
	switch bootFS {
	case "fat16":
		err = im.WriteFAT16(bootEntries)
	case "ext2":
		err = im.WriteExt2(bootEntries)
	default:
		err = fmt.Errorf("unsupported boot filesystem %s", bootFS)
	}
	if err == nil {
		err = im.WriteExt4(rosEntries)
	}
	if cerr := im.Close(); err == nil {
		err = cerr
	}
	return err
}

// buildBIOSImage creates the legacy-BIOS image: the boot partition is an ext2
// filesystem whose boot sector is written by milo, run through the ptrace
// sandbox so no root privileges are needed.
func (c *Config) buildBIOSImage(target string, efi, miloBin []byte, rosEntries []image.Entry) error {
	biosCode, err := hex.DecodeString(biosMBR)
	if err != nil {
		return err
	}
	work := target + ".work"
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	defer os.RemoveAll(work)
	stage := filepath.Join(work, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "EFI", "BOOT"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "EFI", "BOOT", "BOOTX64.EFI"), efi, 0o644); err != nil {
		return err
	}
	miloPath := filepath.Join(work, "milo")
	if err := os.WriteFile(miloPath, miloBin, 0o755); err != nil {
		return err
	}
	diskImage := filepath.Join(work, "disk.img")
	bootPart := filepath.Join(work, "bootpart.img")
	ros := rosEntries

	// Initial image and a copy of the boot partition for milo.
	build := func(mapData []byte) error {
		entries := []image.Entry{{Path: "EFI/BOOT/BOOTX64.EFI", Data: efi, Mode: 0o644}}
		if mapData != nil {
			entries = append(entries, image.Entry{Path: "map", Data: mapData, Mode: 0o644})
		}
		if err := c.assemble(diskImage, "ext2", entries, ros, biosCode); err != nil {
			return err
		}
		return extractPartition(diskImage, bootPart, image.BootStart, image.BootEnd)
	}
	runMilo := func(blocks func(string) ([]uint64, bool)) error {
		return milo.Run(milo.Options{
			MiloPath:  miloPath,
			StageDir:  stage,
			DiskImage: diskImage,
			BootPart:  bootPart,
			Blocks:    blocks,
		})
	}

	if err := build(nil); err != nil {
		return err
	}
	// Pass 1: size the map file.  The values do not affect its size, but the
	// reported block counts do, so answer with as many non-zero blocks as the
	// staged file has.
	sizingBlocks := func(rel string) ([]uint64, bool) {
		st, err := os.Stat(filepath.Join(stage, rel))
		if err != nil {
			return nil, false
		}
		// Answer with a consecutive, non-zero run: duplicate sector numbers
		// make milo spin while it builds its sector tables.
		n := int((st.Size()+1023)/1024) + 1
		blocks := make([]uint64, n)
		for i := range blocks {
			blocks[i] = uint64(100 + i)
		}
		return blocks, true
	}
	if err := runMilo(sizingBlocks); err != nil {
		return fmt.Errorf("milo sizing pass: %w", err)
	}
	mapData, err := os.ReadFile(filepath.Join(stage, "map"))
	if err != nil {
		return fmt.Errorf("milo did not create the map file: %w", err)
	}
	if err := build(make([]byte, len(mapData))); err != nil {
		return err
	}
	layout, err := ext2FileLayout(mustReadFile(diskImage), image.BootStart)
	if err != nil {
		return err
	}
	if _, ok := layout["map"]; !ok {
		return fmt.Errorf("map file not found in the boot filesystem layout")
	}
	// Pass 2: answer FIBMAP from the real layout and capture the VBR.
	if err := runMilo(func(rel string) ([]uint64, bool) {
		b, ok := layout[rel]
		return b, ok
	}); err != nil {
		return fmt.Errorf("milo install pass: %w", err)
	}
	finalMap, err := os.ReadFile(filepath.Join(stage, "map"))
	if err != nil {
		return err
	}
	if len(finalMap) != len(mapData) {
		return fmt.Errorf("milo map size changed between passes (%d -> %d)", len(mapData), len(finalMap))
	}
	if err := writeAtBlocks(diskImage, image.BootStart, layout["map"], finalMap); err != nil {
		return err
	}
	bootBytes, err := os.ReadFile(bootPart)
	if err != nil {
		return err
	}
	if len(bootBytes) < 512 {
		return fmt.Errorf("milo wrote no VBR")
	}
	f, err := os.OpenFile(diskImage, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(bootBytes[:512], int64(image.BootStart)*512); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(diskImage, target)
}

// publishImage zips a built image into the publish directory and removes the
// uncompressed file.
func (c *Config) publishImage(img, publishDir string) error {
	name := filepath.Base(img)
	dest := filepath.Join(publishDir, name+".zip")
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	w, err := zw.Create(name)
	if err != nil {
		out.Close()
		return err
	}
	f, err := os.Open(img)
	if err != nil {
		out.Close()
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		f.Close()
		out.Close()
		return err
	}
	f.Close()
	if err := zw.Close(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Remove(img); err != nil {
		return err
	}
	c.logf("✅ published: %s\n", dest)
	return nil
}

// verifyBootImage boots an image in qemu and checks the licence level.  The
// legacy BIOS image boots through SeaBIOS, everything else through UEFI.
func (c *Config) verifyBootImage(imagePath, arch string, bios bool) error {
	var qemu string
	switch arch {
	case "x86":
		qemu = "qemu-system-x86_64"
	case "arm64":
		qemu = "qemu-system-aarch64"
	default:
		c.logf("⚠️  boot test skipped: unsupported arch %s\n", arch)
		return nil
	}
	if _, err := exec.LookPath(qemu); err != nil {
		c.logf("⚠️  boot test skipped: %s not installed\n", qemu)
		return nil
	}
	firmware := ""
	if !bios {
		firmware = findEFIFirmware(arch)
		if firmware == "" {
			c.logf("⚠️  boot test skipped: no UEFI firmware for %s (install ovmf / qemu-efi-aarch64)\n", arch)
			return nil
		}
	}
	tmp, err := os.MkdirTemp("", "mikrotikpatch-boot")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	socket := filepath.Join(tmp, "serial.sock")
	logPath := filepath.Join(tmp, "serial.log")
	bootCopy := filepath.Join(tmp, "boot.img")
	if err := copyFile(imagePath, bootCopy); err != nil {
		return err
	}
	args := []string{"-m", "1024", "-smp", "2"}
	// KVM can only accelerate a guest of the host's architecture.
	useKVM := kvmAvailable() && ((arch == "x86" && runtime.GOARCH == "amd64") ||
		(arch == "arm64" && runtime.GOARCH == "arm64"))
	switch arch {
	case "arm64":
		args = append(args, "-M", "virt")
		if useKVM {
			args = append(args, "-enable-kvm", "-cpu", "host")
		} else {
			args = append(args, "-cpu", "cortex-a72")
		}
	default:
		if useKVM {
			args = append(args, "-enable-kvm", "-cpu", "host")
		} else {
			args = append(args, "-cpu", "max")
		}
	}
	args = append(args, "-drive", "file="+bootCopy+",if=virtio,format=raw")
	if bios {
		args = append(args, "-boot", "c")
	} else {
		args = append(args, "-drive", "if=pflash,format=raw,readonly=on,file="+firmware)
	}
	args = append(args,
		"-display", "none",
		"-chardev", "socket,id=ser,path="+socket+",server=on,wait=off,logfile="+logPath,
		"-serial", "chardev:ser",
	)
	fwName := "SeaBIOS"
	if firmware != "" {
		fwName = filepath.Base(firmware)
	}
	c.logf("==> boot test: %s (%s, %s)\n", qemu, arch, fwName)
	cmd := exec.Command(qemu, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	err = boottest.Run(boottest.Options{
		Socket:  socket,
		PID:     cmd.Process.Pid,
		Timeout: c.BootTestTimeout,
		Expect:  "p-unlimited",
	})
	if err != nil {
		c.logf("❌ boot test failed for %s: %v\n", imagePath, err)
		if log, rerr := os.ReadFile(logPath); rerr == nil {
			tail := log
			if len(tail) > 4000 {
				tail = tail[len(tail)-4000:]
			}
			c.logf("---- serial output tail ----\n%s\n----------------------------\n", tail)
		}
		return err
	}
	c.logln("boot test: licence level = p-unlimited")
	return nil
}

func kvmAvailable() bool {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func findEFIFirmware(arch string) string {
	var candidates []string
	switch arch {
	case "x86":
		candidates = []string{
			"/usr/share/edk2/x64/OVMF_CODE.4m.fd",
			"/usr/share/edk2/x64/OVMF_CODE.fd",
			"/usr/share/OVMF/OVMF_CODE_4M.fd",
			"/usr/share/OVMF/OVMF_CODE.fd",
		}
	case "arm64":
		candidates = []string{
			"/usr/share/edk2/aarch64/QEMU_EFI.fd",
			"/usr/share/AAVMF/AAVMF_CODE.fd",
			"/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
		}
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}
	return ""
}

// extractPartition copies a partition range out of a disk image.
func extractPartition(diskImage, dest string, start, end uint64) error {
	src, err := os.Open(diskImage)
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	const chunk = 1 << 20
	buf := make([]byte, chunk)
	remaining := int64((end - start + 1) * 512)
	offset := int64(start) * 512
	for remaining > 0 {
		n := int64(chunk)
		if n > remaining {
			n = remaining
		}
		read, err := src.ReadAt(buf[:n], offset)
		if read > 0 {
			if _, werr := out.Write(buf[:read]); werr != nil {
				return werr
			}
			offset += int64(read)
			remaining -= int64(read)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return out.Close()
}

// writeAtBlocks writes data at 1 KiB filesystem blocks inside partition 1.
func writeAtBlocks(diskImage string, partStart uint64, blocks []uint64, data []byte) error {
	f, err := os.OpenFile(diskImage, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	for i, block := range blocks {
		if i*1024 >= len(data) {
			break
		}
		end := (i + 1) * 1024
		if end > len(data) {
			end = len(data)
		}
		off := int64(partStart)*512 + int64(block)*1024
		if _, err := f.WriteAt(data[i*1024:end], off); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func mustReadFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}
