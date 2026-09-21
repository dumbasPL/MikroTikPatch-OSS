package patch

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mikrotikpatch/internal/npk"
	"mikrotikpatch/internal/squashfs"
)

// serviceVars maps stock hosts/keys to the custom values patch_v7.sh exports.
var serviceVars = []struct{ old, new string }{
	{"MIKRO_LICENCE_URL", "CUSTOM_LICENCE_URL"},
	{"MIKRO_UPGRADE_URL", "CUSTOM_UPGRADE_URL"},
	{"MIKRO_CLOUD_URL", "CUSTOM_CLOUD_URL"},
	{"MIKRO_CLOUD2_URL", "CUSTOM_CLOUD2_URL"},
	{"MIKRO_CLOUD_PUBLIC_KEY", "CUSTOM_CLOUD_PUBLIC_KEY"},
}

// ServiceReplacements collects the configured host/key replacements.  Every
// replacement has to be the same length as the stock value, because the
// replacements happen in place inside binaries.
func ServiceReplacements() (map[string]string, error) {
	result := map[string]string{}
	for _, v := range serviceVars {
		old, new := os.Getenv(v.old), os.Getenv(v.new)
		if old == "" || new == "" {
			continue
		}
		if len(old) != len(new) {
			return nil, fmt.Errorf("length mismatch: %q (%d) -> %q (%d); in-place binary replacement requires equal lengths",
				old, len(old), new, len(new))
		}
		result[old] = new
	}
	return result, nil
}

// ArchName returns the keygen variant name for the ARCH environment variable.
func ArchName() string { return KeygenName(os.Getenv("ARCH")) }

// KeygenName maps a RouterOS architecture to the keygen binary variant.  An
// empty value means x86, like the old ARCH environment default.
func KeygenName(arch string) string {
	arch = strings.ReplaceAll(arch, "-", "")
	if arch == "" {
		arch = "x86"
	}
	switch arch {
	case "x86", "i386", "x8664", "amd64":
		return "x86"
	default:
		return "arm64"
	}
}

// FindKeygen locates keygen/keygen_<name>.  It looks at $KEYGEN_DIR, next to
// the executable, the working directory and then walks upwards.
func FindKeygen(name string) (string, error) {
	file := "keygen_" + name
	var dirs []string
	if d := os.Getenv("KEYGEN_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "keygen"))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(wd, "keygen"))
		for d := wd; ; {
			dirs = append(dirs, filepath.Join(d, "keygen"))
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}
	for _, d := range dirs {
		p := filepath.Join(d, file)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("keygen binary %s not found", file)
}

// InstallMode replaces "mode" with the keygen (keeping the stock tool as
// "mode2") inside one squashfs directory.  arch is the RouterOS architecture
// (ARCH-style, e.g. "x86" or "arm64").
func InstallMode(dir *squashfs.Node, arch string) error {
	mode := childFile(dir, "mode")
	if mode == nil {
		return nil
	}
	if mode2 := childFile(dir, "mode2"); mode2 != nil {
		mode2.Data = mode.Data
		mode2.Mode = 0o755
	} else {
		dir.Children = append(dir.Children, &squashfs.Node{
			Name:  "mode2",
			Type:  squashfs.TypeFile,
			Mode:  0o755,
			MTime: mode.MTime,
			Data:  mode.Data,
		})
	}
	keygen, err := FindKeygen(KeygenName(arch))
	if err != nil {
		return fmt.Errorf("%w; build it with `keygen/build.sh %s`", err, KeygenName(arch))
	}
	data, err := os.ReadFile(keygen)
	if err != nil {
		return err
	}
	st, err := os.Stat(keygen)
	if err == nil {
		mode.MTime = uint32(st.ModTime().Unix())
	}
	mode.Data = data
	mode.Mode = 0o755
	return nil
}

func childFile(dir *squashfs.Node, name string) *squashfs.Node {
	for _, c := range dir.Children {
		if c.Name == name && c.Type == squashfs.TypeFile {
			return c
		}
	}
	return nil
}

// PatchSquashfs patches keys and bootstrap URLs in an extracted squashfs tree.
// "mode"/"keyman" carry the licence key material and get the keygen installed
// next to them; every other file is scanned for the stock keys and hosts.
// arch is the RouterOS architecture (ARCH-style).
func PatchSquashfs(root *squashfs.Node, keys []KeyPair, arch string) error {
	replacements, err := ServiceReplacements()
	if err != nil {
		return err
	}
	var walk func(dir *squashfs.Node, path string) error
	walk = func(dir *squashfs.Node, path string) error {
		has := func(name string) bool { return childFile(dir, name) != nil }
		if has("mode") && has("keyman") {
			for _, filename := range []string{"mode", "keyman"} {
				file := childFile(dir, filename)
				data := ReplaceStrings(file.Data, replacements, path+"/"+filename)
				for _, k := range keys {
					data = ReplaceKeyArch(k.Old, k.New, data, path+"/"+filename, arch)
				}
				file.Data = data
			}
			if err := InstallMode(dir, arch); err != nil {
				return err
			}
		}
		if efi := childFile(dir, "BOOTX64.EFI"); efi != nil {
			newData, err := PatchKernel(efi.Data, keys, arch)
			if err != nil {
				return fmt.Errorf("%s/BOOTX64.EFI: %w", path, err)
			}
			if bytes.Equal(newData, efi.Data) {
				return fmt.Errorf("%s/BOOTX64.EFI: key not patched", path)
			}
			efi.Data = newData
		}
		for _, c := range dir.Children {
			if c.Type != squashfs.TypeFile {
				continue
			}
			switch c.Name {
			case "mode", "keyman", "loader", "BOOTX64.EFI":
				continue
			}
			filePath := path + "/" + c.Name
			data := c.Data
			for _, k := range keys {
				data = ReplaceKeyArch(k.Old, k.New, data, filePath, arch)
			}
			data = ReplaceStrings(data, replacements, filePath)
			c.Data = data
		}
		for _, c := range dir.Children {
			if c.Type == squashfs.TypeDir {
				if err := walk(c, path+"/"+c.Name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(root, "")
}

// PatchNPKPackage patches a "system" package: the kernel files in the file
// container and the squashfs tree.  arch is the RouterOS architecture.
func PatchNPKPackage(pkg *npk.Package, keys []KeyPair, arch string) error {
	ni := pkg.Get(npk.PartNameInfo)
	if ni == nil || ni.Info == nil || ni.Info.Name != "system" {
		return nil
	}
	fcPart := pkg.Get(npk.PartFileContainer)
	if fcPart == nil {
		return errors.New("patch: system package has no file container")
	}
	container, err := npk.UnserializeFileContainer(fcPart.Bytes())
	if err != nil {
		return err
	}
	for _, item := range container.Items {
		switch string(item.Name) {
		case "boot/EFI/BOOT/BOOTX64.EFI", "boot/kernel", "boot/initrd.rgz":
			Logf("patching %s ...\n", item.Name)
			item.Data, err = PatchKernel(item.Data, keys, arch)
			if err != nil {
				return fmt.Errorf("%s: %w", item.Name, err)
			}
		}
	}
	if fcPart.Raw, err = container.Serialize(); err != nil {
		return err
	}
	fcPart.Info = nil

	sqPart := pkg.Get(npk.PartSquashfs)
	if sqPart == nil {
		return nil
	}
	data := sqPart.Bytes()
	tree, err := squashfs.ReadAll(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("patch: unpack squashfs: %w", err)
	}
	if err := PatchSquashfs(tree, keys, arch); err != nil {
		return err
	}
	packed, err := squashfs.Marshal(tree, nil)
	if err != nil {
		return fmt.Errorf("patch: repack squashfs: %w", err)
	}
	sqPart.Raw = packed
	sqPart.Info = nil
	return nil
}

// PatchNPKFile patches and re-signs a main routeros NPK file.  arch selects
// the ARM key-table handling and the keygen variant to install; a zero
// buildTime keeps the package's original timestamp.
func PatchNPKFile(keys []KeyPair, kcdsaPrivate, eddsaPrivate []byte, arch string, buildTime time.Time, input, output string) error {
	pkg, err := npk.Load(input)
	if err != nil {
		return err
	}
	for _, p := range pkg.AllPackages() {
		if err := PatchNPKPackage(p, keys, arch); err != nil {
			return err
		}
	}
	if err := pkg.Sign(kcdsaPrivate, eddsaPrivate, buildTime); err != nil {
		return err
	}
	if output == "" {
		output = input
	}
	return pkg.Save(output)
}
