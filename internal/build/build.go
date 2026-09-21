// Package build implements the patch_v7 pipeline: download and patch RouterOS
// packages for one or more architectures and produce the CHR disk images.
package build

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"mikrotikpatch/internal/iso"
	"mikrotikpatch/internal/keys"
	"mikrotikpatch/internal/npk"
	"mikrotikpatch/internal/patch"
)

// Options mirrors patch_v7.sh's command line.
type Options struct {
	Version         string
	Archs           []string
	BuildTime       string
	KeysFile        string
	BuildRoot       string
	PublishRoot     string
	BootTest        bool
	BootTestTimeout time.Duration
	LegacyBIOS      bool
	SkipKeygen      bool
	// Jobs bounds CPU-heavy parallel work (component signing, package
	// patching).  Zero means min(NumCPU, 8).
	Jobs int
}

// RequiredKeys are the variables check_keys demands.
var RequiredKeys = []string{
	"MIKRO_LICENSE_PUBLIC_KEY",
	"CUSTOM_LICENSE_PUBLIC_KEY",
	"CUSTOM_LICENSE_PRIVATE_KEY",
	"MIKRO_NPK_SIGN_PUBLIC_KEY",
	"CUSTOM_NPK_SIGN_PUBLIC_KEY",
	"CUSTOM_NPK_SIGN_PRIVATE_KEY",
	"MIKRO_CLOUD_PUBLIC_KEY",
	"CUSTOM_CLOUD_PUBLIC_KEY",
	"MIKRO_LICENCE_URL",
	"CUSTOM_LICENCE_URL",
	"MIKRO_UPGRADE_URL",
	"CUSTOM_UPGRADE_URL",
	"MIKRO_CLOUD_URL",
	"CUSTOM_CLOUD_URL",
	"MIKRO_CLOUD2_URL",
	"CUSTOM_CLOUD2_URL",
}

// Config carries the resolved options for one run.
type Config struct {
	Options
	RepoRoot string
	Env      map[string]string

	jobs   int
	cpuSem chan struct{} // bounds CPU-heavy work across architectures
	vmSem  chan struct{} // bounds concurrent qemu boot tests
	logMu  sync.Mutex

	buildTime time.Time // zero keeps the packages' original timestamps
}

// logf writes a progress line, serialised across the parallel workers.
func (c *Config) logf(format string, args ...any) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	fmt.Printf(format, args...)
}

func (c *Config) logln(args ...any) {
	c.logMu.Lock()
	defer c.logMu.Unlock()
	fmt.Println(args...)
}

// initConcurrency sizes the semaphores.
func (c *Config) initConcurrency() {
	jobs := c.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
		if jobs > 8 {
			jobs = 8
		}
	}
	if jobs < 1 {
		jobs = 1
	}
	c.jobs = jobs
	c.cpuSem = make(chan struct{}, jobs)
	vm := 4
	if jobs < vm {
		vm = jobs
	}
	c.vmSem = make(chan struct{}, vm)
}

// acquireCPU/releaseCPU bound the CPU-heavy phases.
func (c *Config) acquireCPU() { c.cpuSem <- struct{}{} }
func (c *Config) releaseCPU() { <-c.cpuSem }

// Run executes the pipeline.
func Run(opts Options) error {
	if opts.Version == "" {
		return fmt.Errorf("--version is required (e.g. --version 7.24.4)")
	}
	if len(opts.Archs) == 0 {
		opts.Archs = []string{"x86", "arm64"}
	}
	if opts.KeysFile == "" {
		opts.KeysFile = "keys.env"
	}
	if opts.BuildRoot == "" {
		opts.BuildRoot = "/tmp/build"
	}
	if opts.PublishRoot == "" {
		opts.PublishRoot = "publish"
	}
	if opts.BootTestTimeout == 0 {
		opts.BootTestTimeout = 600 * time.Second
	}
	repo, err := RepoRoot()
	if err != nil {
		return err
	}
	env := map[string]string{}
	if file, err := keys.LoadEnvFile(opts.KeysFile); err == nil {
		fmt.Printf("==> loading keys from %s\n", opts.KeysFile)
		env = keys.MergeEnv(file, os.Environ())
	} else if os.IsNotExist(err) {
		fmt.Printf("==> warning: keys file not found (%s); relying on the environment\n", opts.KeysFile)
		env = keys.MergeEnv(nil, os.Environ())
	} else {
		return err
	}
	if err := validateKeys(env); err != nil {
		return err
	}
	// Export the merged values so the keygen build script and the in-place
	// host replacements see the keys file, like `set -a; . keys.env`.
	for k, v := range env {
		os.Setenv(k, v)
	}
	buildTime, err := npk.ParseBuildTime(opts.BuildTime)
	if err != nil {
		return err
	}
	cfg := &Config{Options: opts, RepoRoot: repo, Env: env, buildTime: buildTime}
	cfg.initConcurrency()
	patch.Logf = cfg.logf
	// Identify as the RouterOS upgrade client to MikroTik's hosts.
	userAgent = "RouterOS " + opts.Version
	if !opts.SkipKeygen {
		if err := cfg.buildKeygen(); err != nil {
			return err
		}
	}
	if err := cfg.verifyKeygen(); err != nil {
		return err
	}
	if err := cfg.fetchChangelog(); err != nil {
		return err
	}
	// Architectures are independent: build them in parallel, bounded by the
	// shared CPU semaphore.
	var wg sync.WaitGroup
	errCh := make(chan error, len(opts.Archs))
	for _, arch := range opts.Archs {
		arch := arch
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cfg.patchArch(arch); err != nil {
				errCh <- fmt.Errorf("arch %s: %w", arch, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}
	cfg.logf("\nAll done.  Artifacts are under: %s/%s\n", opts.PublishRoot, opts.Version)
	return nil
}

// fetchChangelog downloads the release notes once and stores them in the
// publish directory.
func (c *Config) fetchChangelog() error {
	publishDir := filepath.Join(c.PublishRoot, c.Version)
	if err := os.MkdirAll(publishDir, 0o755); err != nil {
		return err
	}
	changeLog, err := fetchString("https://" + c.Env["MIKRO_UPGRADE_URL"] + "/routeros/" + c.Version + "/CHANGELOG")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(publishDir, "CHANGELOG"), []byte(changeLog)); err != nil {
		return err
	}
	c.logf("%s", changeLog)
	if !strings.HasSuffix(changeLog, "\n") {
		c.logln()
	}
	return nil
}

// RepoRoot finds the repository root (the directory with go.mod and keygen/).
func RepoRoot() (string, error) {
	var candidates []string
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	for _, start := range candidates {
		dir := start
		for {
			if fileExists(filepath.Join(dir, "go.mod")) && dirExists(filepath.Join(dir, "keygen")) {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", fmt.Errorf("cannot locate the repository root (run from the repo or build the binary there)")
}

// buildKeygen runs keygen/build.sh for the requested architectures only, so a
// single-arch run does not need the other architecture's toolchain.
func (c *Config) buildKeygen() error {
	fmt.Printf("==> building keygen for %s\n", strings.Join(c.Archs, " "))
	args := []string{filepath.Join(c.RepoRoot, "keygen", "build.sh")}
	args = append(args, c.Archs...)
	cmd := exec.Command("sh", args...)
	cmd.Dir = c.RepoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keygen/build.sh: %w", err)
	}
	os.Setenv("KEYGEN_DIR", filepath.Join(c.RepoRoot, "keygen"))
	return nil
}

// keygenPath returns the keygen binary for one architecture.  The repo copy is
// preferred; FindKeygen covers builds run from another working directory.
func (c *Config) keygenPath(name string) (string, error) {
	path := filepath.Join(c.RepoRoot, "keygen", "keygen_"+name)
	if fileExists(path) {
		return path, nil
	}
	return patch.FindKeygen(name)
}

// verifyKeygen checks that each requested architecture's keygen binary embeds
// the custom licence public key.  A stale keygen (built before the keys file
// existed or changed, or without it) would sign licences the patched kernel
// rejects, a combination otherwise visible only in a boot test.
func (c *Config) verifyKeygen() error {
	publicKey := c.Env["CUSTOM_LICENSE_PUBLIC_KEY"]
	for _, arch := range c.Archs {
		name := patch.KeygenName(arch)
		path, err := c.keygenPath(name)
		if err != nil {
			return fmt.Errorf("keygen for %s: %w (build it with keygen/build.sh %s)", arch, err, name)
		}
		if err := checkKeygenEmbedded(path, publicKey); err != nil {
			return fmt.Errorf("%w; rebuild it with keygen/build.sh %s", err, name)
		}
	}
	return nil
}

// checkKeygenEmbedded verifies that a keygen binary embeds the licence public
// key.  keygen.c compiles the key in as an ASCII hex string, so a byte search
// is enough.  A keygen built without -DKEYGEN_LICENSE_PUBLIC_HEX carries the
// built-in fallback key and does not match.
func checkKeygenEmbedded(path, publicKeyHex string) error {
	want := strings.ToLower(strings.TrimSpace(publicKeyHex))
	if want == "" {
		return errors.New("CUSTOM_LICENSE_PUBLIC_KEY is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Contains(bytes.ToLower(data), []byte(want)) {
		return fmt.Errorf("%s does not embed CUSTOM_LICENSE_PUBLIC_KEY", path)
	}
	return nil
}

func validateKeys(env map[string]string) error {
	var missing []string
	for _, k := range RequiredKeys {
		if strings.TrimSpace(env[k]) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintln(os.Stderr, "ERROR: missing key material / hosts:")
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  - %s\n", m)
		}
		fmt.Fprintln(os.Stderr, "\nDefine them in the keys file or the environment;")
		fmt.Fprintln(os.Stderr, "tools/genkeys (mikrotikpatch genkeys) writes a complete set.")
		return fmt.Errorf("%d required key variables are missing", len(missing))
	}
	// Key material must decode to the expected sizes.
	for _, k := range []string{"MIKRO_LICENSE_PUBLIC_KEY", "CUSTOM_LICENSE_PUBLIC_KEY",
		"CUSTOM_LICENSE_PRIVATE_KEY", "MIKRO_NPK_SIGN_PUBLIC_KEY",
		"CUSTOM_NPK_SIGN_PUBLIC_KEY", "CUSTOM_NPK_SIGN_PRIVATE_KEY"} {
		b, err := hex.DecodeString(strings.TrimSpace(env[k]))
		if err != nil || len(b) != 32 {
			return fmt.Errorf("%s must be 32 bytes of hex", k)
		}
	}
	return nil
}

// archExt returns the package name suffix for an architecture.
func archExt(arch string) string {
	if arch == "x86" {
		return ""
	}
	return "-" + arch
}

func (c *Config) patchArch(arch string) error {
	ext := archExt(arch)
	buildDir := filepath.Join(c.BuildRoot, c.Version+ext)
	publishDir := filepath.Join(c.PublishRoot, c.Version)

	c.logf("\n================================================================\n")
	c.logf("==> arch=%s  version=%s\n", arch, c.Version)
	c.logf("================================================================\n")

	c.logln("==> [1/7] setup environment")
	for _, d := range []string{buildDir, publishDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for _, d := range []string{"all_packages", "chr", "iso"} {
		if err := os.RemoveAll(filepath.Join(buildDir, d)); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(buildDir, "all_packages"), 0o755); err != nil {
		return err
	}
	c.logf("BUILD_DIR:   %s\nPUBLISH_DIR: %s\n", buildDir, publishDir)

	upgradeURL := c.Env["MIKRO_UPGRADE_URL"]
	csvText, err := fetchString("https://" + upgradeURL + "/routeros/" + c.Version + "/packages.csv")
	if err != nil {
		return err
	}
	packages, err := packagesForArch(csvText, arch)
	if err != nil {
		return err
	}
	c.logf("PACKAGES: %s\n", strings.Join(packages, " "))

	c.logf("==> [2/7] get mikrotik-%s%s.iso\n", c.Version, ext)
	isoPath := filepath.Join(buildDir, fmt.Sprintf("mikrotik-%s%s.iso", c.Version, ext))
	if err := download("https://download.mikrotik.com/routeros/"+c.Version+"/"+filepath.Base(isoPath), isoPath); err != nil {
		return err
	}

	c.logln("==> [3/7] unpack ISO")
	if err := c.unpackISO(isoPath, buildDir, c.Version, ext); err != nil {
		return err
	}

	c.logln("==> [4/7] check and download missing packages")
	if err := c.downloadMissing(packages, buildDir, ext); err != nil {
		return err
	}

	// Signing the components and patching the main package are independent;
	// run them together.
	c.logln("==> [5/7] sign component NPK files")
	componentDir := filepath.Join(buildDir, "all_packages")
	mainName := fmt.Sprintf("routeros-%s%s.npk", c.Version, ext)
	publishMain := filepath.Join(publishDir, mainName)

	var wg sync.WaitGroup
	var signErr, patchErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		signErr = c.signComponents(arch, componentDir, publishDir)
	}()
	go func() {
		defer wg.Done()
		c.acquireCPU()
		defer c.releaseCPU()
		c.logf("==> [6/7] patch and sign the main package\n")
		patchErr = patch.PatchNPKFile(
			keyPairs(c.Env),
			keyBytes(c.Env, "CUSTOM_LICENSE_PRIVATE_KEY"),
			keyBytes(c.Env, "CUSTOM_NPK_SIGN_PRIVATE_KEY"),
			arch,
			c.buildTime,
			filepath.Join(buildDir, mainName),
			publishMain,
		)
		if patchErr == nil {
			c.logf("✅ main package npk patched: %s\n", publishMain)
		}
	}()
	wg.Wait()
	if patchErr != nil {
		return patchErr
	}
	if signErr != nil {
		return signErr
	}

	c.logln("==> [7/7] build CHR images")
	if err := c.buildImages(arch, ext, buildDir, publishDir, publishMain); err != nil {
		return err
	}
	c.logf("==> done for %s\n", arch)
	return nil
}

// downloadMissing fetches the component packages the ISO does not carry.
func (c *Config) downloadMissing(packages []string, buildDir, ext string) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(packages))
	sem := make(chan struct{}, minInt(4, c.jobs))
	for _, pkg := range packages {
		pkg := pkg
		name := fmt.Sprintf("%s-%s%s.npk", pkg, c.Version, ext)
		dest := filepath.Join(buildDir, "all_packages", name)
		if fileExists(dest) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := download("https://download.mikrotik.com/routeros/"+c.Version+"/"+name, dest); err != nil {
				errCh <- err
				return
			}
			c.logf("✅ package downloaded: %s\n", name)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

// signComponents re-signs every component NPK with a worker pool.
func (c *Config) signComponents(arch, componentDir, publishDir string) error {
	entries, err := os.ReadDir(componentDir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".npk") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("no packages found in %s", componentDir)
	}
	sort.Strings(names)

	var wg sync.WaitGroup
	errCh := make(chan error, len(names))
	for _, name := range names {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.acquireCPU()
			defer c.releaseCPU()
			path := filepath.Join(componentDir, name)
			pkg, err := npk.Load(path)
			if err != nil {
				errCh <- fmt.Errorf("%s: %w", name, err)
				return
			}
			if err := pkg.Sign(keyBytes(c.Env, "CUSTOM_LICENSE_PRIVATE_KEY"), keyBytes(c.Env, "CUSTOM_NPK_SIGN_PRIVATE_KEY"), c.buildTime); err != nil {
				errCh <- fmt.Errorf("%s: %w", name, err)
				return
			}
			if err := pkg.Save(path); err != nil {
				errCh <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	c.logln("✅ all package npk files signed:")
	for _, name := range names {
		if st, err := os.Stat(filepath.Join(componentDir, name)); err == nil {
			c.logf("    %s (%d bytes)\n", name, st.Size())
		}
	}
	zipName := fmt.Sprintf("all_packages-%s-%s.zip", arch, c.Version)
	c.acquireCPU()
	err = zipDir(componentDir, filepath.Join(publishDir, zipName))
	c.releaseCPU()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := moveFile(filepath.Join(componentDir, name), filepath.Join(publishDir, name)); err != nil {
			return err
		}
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// unpackISO copies every root-level .npk out of the ISO, leaving the main
// routeros package in the build directory.
func (c *Config) unpackISO(isoPath, buildDir, version, ext string) error {
	f, err := os.Open(isoPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	image, err := iso.Open(f, st.Size())
	if err != nil {
		return fmt.Errorf("open ISO: %w", err)
	}
	allPackages := filepath.Join(buildDir, "all_packages")
	mainName := fmt.Sprintf("routeros-%s%s.npk", version, ext)
	for _, node := range image.Root().Children {
		if node.IsDir || !strings.HasSuffix(strings.ToLower(node.Name), ".npk") {
			continue
		}
		data, err := image.ReadFile(node.Name)
		if err != nil {
			return fmt.Errorf("read %s: %w", node.Name, err)
		}
		dest := filepath.Join(allPackages, node.Name)
		if node.Name == mainName {
			dest = filepath.Join(buildDir, mainName)
		}
		if err := writeFileAtomic(dest, data); err != nil {
			return err
		}
		c.logf("    %s (%d bytes)\n", node.Name, len(data))
	}
	if !fileExists(filepath.Join(buildDir, mainName)) {
		return fmt.Errorf("ISO does not contain %s", mainName)
	}
	return nil
}

// packagesForArch extracts the component package names for one architecture.
func packagesForArch(csvText, arch string) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(csvText))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse packages.csv: %w", err)
	}
	var out []string
	for i, rec := range records {
		if i == 0 || len(rec) < 2 {
			continue
		}
		if strings.TrimSpace(rec[0]) == arch {
			out = append(out, strings.TrimSpace(rec[1]))
		}
	}
	return out, nil
}

// zipDir writes a deflate zip of every file in dir (non-recursive names).
func zipDir(dir, dest string) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	zw := zip.NewWriter(out)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		// Skip directories and download-cache artefacts (see download in
		// http.go): only the actual package files belong in the zip.
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sha256") || strings.HasSuffix(e.Name(), ".part") {
			continue
		}
		w, err := zw.Create(e.Name())
		if err != nil {
			return err
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	return zw.Close()
}

// keyPairs returns the licence/NPK key replacements in application order.
func keyPairs(env map[string]string) []patch.KeyPair {
	return []patch.KeyPair{
		{Old: keyBytes(env, "MIKRO_LICENSE_PUBLIC_KEY"), New: keyBytes(env, "CUSTOM_LICENSE_PUBLIC_KEY")},
		{Old: keyBytes(env, "MIKRO_NPK_SIGN_PUBLIC_KEY"), New: keyBytes(env, "CUSTOM_NPK_SIGN_PUBLIC_KEY")},
	}
}

func keyBytes(env map[string]string, name string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(env[name]))
	if err != nil {
		panic(fmt.Sprintf("invalid %s: %v", name, err))
	}
	return b
}

// moveFile renames src to dst, falling back to a copy when the two paths are
// on different filesystems (the default build dir is /tmp, a tmpfs).
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

// writeFileAtomic replaces path even when the existing file is read-only
// (ISO extractions keep the ISO's 0444 permissions).
func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}
