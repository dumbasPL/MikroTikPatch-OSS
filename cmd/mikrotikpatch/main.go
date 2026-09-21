// Command mikrotikpatch is the one-stop tool for patching RouterOS v7 packages
// and building CHR disk images: it replaces patch_v7.sh and the Python tools
// (npk.py, patch.py, mikro.py, keygen.py, genkeys.py, boot_test.py).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"mikrotikpatch/internal/boottest"
	"mikrotikpatch/internal/build"
	"mikrotikpatch/internal/keygen"
	"mikrotikpatch/internal/keys"
	"mikrotikpatch/internal/npk"
	"mikrotikpatch/internal/patch"
)

const usageText = `mikrotikpatch - MikroTik RouterOS v7 patcher and CHR image builder

Usage:
  mikrotikpatch patch-v7 --version <x.y.z> [options]
  mikrotikpatch npk sign [--buildtime <seconds>] <in.npk> [out.npk]
  mikrotikpatch npk extract <in.npk> <name> <out>
  mikrotikpatch patch npk [--buildtime <seconds>] [-O out.npk] <in.npk>
  mikrotikpatch patch buildefi <kernel> <out.efi>
  mikrotikpatch genkeys [--out keys.env]
  mikrotikpatch keygen [chr|x86|--selftest|--print|--verify <file>]
  mikrotikpatch boot-test --socket <path> [--pid N] [--timeout S] [--expect level]

patch-v7 options:
  --version <x.y.z>          RouterOS version (required)
  --archs x86,arm64         comma list, or "all" (default all)
  --buildtime <seconds>      custom build time (empty = original)
  --keys-file <path>         env file with the key material (default keys.env)
  --build-dir <path>         scratch directory (default /tmp/build)
  --publish-dir <path>       output directory (default ./publish)
  --boot-test                boot each built image in qemu and check the licence
  --boot-test-timeout <s>    per-image boot test timeout, seconds or duration (600)
  --legacy-bios              also build the x86 legacy-BIOS image
  --skip-keygen              do not rebuild keygen_x86/keygen_arm64
  --jobs <n>                 parallel CPU workers (default min(NumCPU,8))
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
	switch args[0] {
	case "patch-v7":
		return cmdPatchV7(args[1:])
	case "npk":
		return cmdNpk(args[1:])
	case "patch":
		return cmdPatch(args[1:])
	case "genkeys":
		return cmdGenkeys(args[1:])
	case "keygen":
		return keygen.Main(args[1:], os.Stdin, os.Stdout)
	case "boot-test":
		return cmdBootTest(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usageText)
		return 2
	}
}

func cmdPatchV7(args []string) int {
	fs := flag.NewFlagSet("patch-v7", flag.ExitOnError)
	version := fs.String("version", "", "RouterOS version")
	archs := fs.String("archs", "all", "architecture list")
	buildTime := fs.String("buildtime", "", "custom build time")
	keysFile := fs.String("keys-file", "keys.env", "keys env file")
	buildDir := fs.String("build-dir", "/tmp/build", "scratch directory")
	publishDir := fs.String("publish-dir", "publish", "output directory")
	bootTest := fs.Bool("boot-test", false, "boot test the built images")
	bootTimeout := 600 * time.Second
	fs.Var(secondsFlag{&bootTimeout}, "boot-test-timeout", "per-image boot test timeout in seconds (default 600)")
	legacyBIOS := fs.Bool("legacy-bios", false, "build the legacy BIOS image too")
	skipKeygen := fs.Bool("skip-keygen", false, "do not rebuild the keygen")
	jobs := fs.Int("jobs", 0, "parallel CPU workers (default min(NumCPU,8))")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	archList, err := parseArchs(*archs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 2
	}
	if err := build.Run(build.Options{
		Version:         *version,
		Archs:           archList,
		BuildTime:       *buildTime,
		KeysFile:        *keysFile,
		BuildRoot:       *buildDir,
		PublishRoot:     *publishDir,
		BootTest:        *bootTest,
		BootTestTimeout: bootTimeout,
		LegacyBIOS:      *legacyBIOS,
		SkipKeygen:      *skipKeygen,
		Jobs:            *jobs,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	return 0
}

func parseArchs(input string) ([]string, error) {
	switch input {
	case "all", "ALL":
		return []string{"x86", "arm64"}, nil
	}
	var list []string
	seen := map[string]bool{}
	for _, a := range strings.Split(input, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		switch a {
		case "x86", "arm64":
		default:
			return nil, fmt.Errorf("unknown architecture %q (supported: x86, arm64)", a)
		}
		if seen[a] {
			return nil, fmt.Errorf("duplicate architecture %q", a)
		}
		seen[a] = true
		list = append(list, a)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no architectures specified")
	}
	return list, nil
}

func cmdNpk(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: mikrotikpatch npk sign|extract ...")
		return 2
	}
	switch args[0] {
	case "sign":
		fs := flag.NewFlagSet("npk sign", flag.ExitOnError)
		buildTime := fs.String("buildtime", "", "build time override in seconds (default BUILD_TIME)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() < 1 || fs.NArg() > 2 {
			fmt.Fprintln(os.Stderr, "usage: mikrotikpatch npk sign [--buildtime <seconds>] <in.npk> [out.npk]")
			return 2
		}
		in := fs.Arg(0)
		out := in
		if fs.NArg() == 2 {
			out = fs.Arg(1)
		}
		bt, err := buildTimeValue(*buildTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		pkg, err := npk.Load(in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		fmt.Printf("signing %s\n", in)
		if err := pkg.Sign(envKey("CUSTOM_LICENSE_PRIVATE_KEY"), envKey("CUSTOM_NPK_SIGN_PRIVATE_KEY"), bt); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		if err := pkg.Save(out); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		return 0
	case "extract":
		if len(args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: mikrotikpatch npk extract <in.npk> <name> <out>")
			return 2
		}
		pkg, err := npk.Load(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		data, err := pkg.ExtractFile(args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		if err := os.WriteFile(args[3], data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		fmt.Printf("extracted %s to %s\n", args[2], args[3])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown npk command %q\n", args[0])
		return 2
	}
}

func cmdPatch(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: mikrotikpatch patch npk|buildefi ...")
		return 2
	}
	switch args[0] {
	case "npk":
		fs := flag.NewFlagSet("patch npk", flag.ExitOnError)
		out := fs.String("O", "", "output file (default: in place)")
		fs.StringVar(out, "output", "", "output file (default: in place)")
		buildTime := fs.String("buildtime", "", "build time override in seconds (default BUILD_TIME)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: mikrotikpatch patch npk [--buildtime <seconds>] [-O out.npk] <in.npk>")
			return 2
		}
		input := fs.Arg(0)
		fmt.Printf("patching %s ...\n", input)
		env := environ()
		if err := validatePatchKeys(env); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		bt, err := buildTimeValue(*buildTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		keys := []patch.KeyPair{
			{Old: hexKey(env, "MIKRO_LICENSE_PUBLIC_KEY"), New: hexKey(env, "CUSTOM_LICENSE_PUBLIC_KEY")},
			{Old: hexKey(env, "MIKRO_NPK_SIGN_PUBLIC_KEY"), New: hexKey(env, "CUSTOM_NPK_SIGN_PUBLIC_KEY")},
		}
		if err := patch.PatchNPKFile(keys, hexKey(env, "CUSTOM_LICENSE_PRIVATE_KEY"), hexKey(env, "CUSTOM_NPK_SIGN_PRIVATE_KEY"), patch.ArchName(), bt, input, *out); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		return 0
	case "buildefi":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: mikrotikpatch patch buildefi <kernel> <out.efi>")
			return 2
		}
		fmt.Printf("building EFI from %s ...\n", args[1])
		if err := patch.BuildEFI(args[1], args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown patch command %q\n", args[0])
		return 2
	}
}

func cmdGenkeys(args []string) int {
	fs := flag.NewFlagSet("genkeys", flag.ExitOnError)
	out := fs.String("out", "keys.env", "output env file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ks, err := keys.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	if err := keys.WriteEnvFile(*out, ks); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	fmt.Printf("wrote %s\n\n", *out)
	fmt.Printf("licence private : %s\n", ks.LicensePrivate)
	fmt.Printf("licence public  : %s\n", ks.LicensePublic)
	fmt.Printf("npk private     : %s\n", ks.NPKSignPrivate)
	fmt.Printf("npk public      : %s\n", ks.NPKSignPublic)
	fmt.Printf("cloud private   : %s\n", ks.CloudPrivate)
	fmt.Printf("cloud public    : %s\n", ks.CloudPublic)
	return 0
}

func cmdBootTest(args []string) int {
	fs := flag.NewFlagSet("boot-test", flag.ExitOnError)
	socket := fs.String("socket", "", "unix socket of the qemu serial port")
	pid := fs.Int("pid", 0, "qemu process id")
	timeout := 600 * time.Second
	fs.Var(secondsFlag{&timeout}, "timeout", "seconds for boot + login + licence")
	expect := fs.String("expect", "p-unlimited", "expected licence level")
	interval := 5 * time.Second
	fs.Var(secondsFlag{&interval}, "interval", "seconds between licence checks")
	grace := 30 * time.Second
	fs.Var(secondsFlag{&grace}, "grace", "seconds to keep retrying after a wrong level")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *socket == "" {
		fmt.Fprintln(os.Stderr, "boot-test: --socket is required")
		return 2
	}
	err := boottest.Run(boottest.Options{
		Socket:   *socket,
		PID:      *pid,
		Timeout:  timeout,
		Expect:   *expect,
		Interval: interval,
		Grace:    grace,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("boot test: licence level = %s\n", *expect)
	return 0
}

// buildTimeValue resolves the --buildtime flag, falling back to the
// BUILD_TIME environment variable; an empty value keeps the original
// timestamps.
func buildTimeValue(flagValue string) (time.Time, error) {
	if flagValue == "" {
		flagValue = os.Getenv("BUILD_TIME")
	}
	return npk.ParseBuildTime(flagValue)
}

// secondsFlag is a flag.Value for timeouts that are documented in seconds but
// also accept Go duration strings: both "--timeout 600" and "--timeout 10m"
// work.
type secondsFlag struct {
	value *time.Duration
}

func (f secondsFlag) String() string {
	if f.value == nil {
		return "0"
	}
	return strconv.FormatInt(int64(f.value.Seconds()), 10)
}

func (f secondsFlag) Set(s string) error {
	d, err := parseSeconds(s)
	if err != nil {
		return err
	}
	*f.value = d
	return nil
}

// parseSeconds parses a bare number of seconds ("600", "0.5") or a Go
// duration string ("10m", "600s").
func parseSeconds(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	seconds, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use seconds, e.g. 600, or a duration such as 10m)", s)
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

func environ() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}
	return env
}

func envKey(name string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(os.Getenv(name)))
	if err != nil || len(b) != 32 {
		fmt.Fprintf(os.Stderr, "ERROR: %s must be 32 bytes of hex in the environment\n", name)
		os.Exit(1)
	}
	return b
}

func hexKey(env map[string]string, name string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(env[name]))
	if err != nil || len(b) != 32 {
		fmt.Fprintf(os.Stderr, "ERROR: %s must be 32 bytes of hex\n", name)
		os.Exit(1)
	}
	return b
}

func validatePatchKeys(env map[string]string) error {
	for _, name := range []string{
		"MIKRO_LICENSE_PUBLIC_KEY", "CUSTOM_LICENSE_PUBLIC_KEY", "CUSTOM_LICENSE_PRIVATE_KEY",
		"MIKRO_NPK_SIGN_PUBLIC_KEY", "CUSTOM_NPK_SIGN_PUBLIC_KEY", "CUSTOM_NPK_SIGN_PRIVATE_KEY",
	} {
		b, err := hex.DecodeString(strings.TrimSpace(env[name]))
		if err != nil || len(b) != 32 {
			return fmt.Errorf("%s must be 32 bytes of hex", name)
		}
	}
	return nil
}
