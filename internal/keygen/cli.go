// Terminal output, the three entry points and the command line, matching
// keygen.py byte for byte.
package keygen

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"mikrotikpatch/internal/mikro"
)

// ANSI colours used by the original's terminal output.
const (
	CReset = "\x1b[0m"
	CBlue  = "\x1b[1;34m"
	CCyan  = "\x1b[1;36m"
	CRed   = "\x1b[1;31m"
	CGreen = "\x1b[1;32m"
)

// PrintLicense writes the licence the way keygen.py's print_license does.
func PrintLicense(w io.Writer, systemID, licText string) {
	fmt.Fprintf(w, "%sSystem ID: %s%s%s\n", CBlue, CCyan, systemID, CReset)
	fmt.Fprintf(w, "%sLicense Key:%s\n", CBlue, CReset)
	for _, line := range strings.Split(strings.TrimRight(licText, "\n"), "\n") {
		fmt.Fprintf(w, "%s%s%s\n", CCyan, line, CReset)
	}
	fmt.Fprintf(w, "%sRouterOS is now licensed%s\n", CGreen, CReset)
}

// RunGenerate generates a licence for this device, installs it in the config
// blob and prints it (keygen.py's run_generate).
func RunGenerate(stdout io.Writer) error {
	cfg, err := ReadConfig()
	if err != nil {
		return err
	}
	if !SWIDValid(cfg[OffSWID : OffSWID+16]) {
		swid, err := GenerateSWID()
		if err != nil {
			return err
		}
		copy(cfg[OffSWID:OffSWID+16], swid)
		if err := WriteConfig(cfg); err != nil {
			return err
		}
	}

	serial := ""
	if cfg[OffMode] != 1 {
		serial = KeymanSoftwareID()
	}
	licval, systemID, err := LicenceValueFromConfig(cfg, readUUIDText(), serial)
	if err != nil {
		return err
	}
	decoded, err := SignLicVal(licval)
	if err != nil {
		return err
	}
	copy(cfg[OffLic:OffLic+64], decoded)
	if err := WriteConfig(cfg); err != nil {
		return err
	}
	licText, err := MakeLicense(licval)
	if err != nil {
		return err
	}
	PrintLicense(stdout, systemID, licText)
	return nil
}

// RunMode switches the device to CHR (chr true) or x86 mode and offers a
// reboot, like keygen.py's run_mode.  A line that trims to "n" or "N" answers
// the reboot prompt with no; anything else runs "reboot -f".
func RunMode(chr bool, stdin io.Reader, stdout io.Writer) error {
	cfg, err := ReadConfig()
	if err != nil {
		return err
	}
	if !SWIDValid(cfg[OffSWID : OffSWID+16]) {
		swid, err := GenerateSWID()
		if err != nil {
			return err
		}
		copy(cfg[OffSWID:OffSWID+16], swid)
	}
	if chr {
		cfg[OffMode] = 1
	} else {
		cfg[OffMode] = 0
	}
	if err := WriteConfig(cfg); err != nil {
		return err
	}

	mode := "x86"
	if chr {
		mode = "chr"
	}
	fmt.Fprintf(stdout, "RouterOS has been set to %s%s%s mode\n", CRed, mode, CReset)
	fmt.Fprintf(stdout, "Reboot your device [Y/n]: ")

	if stdin == nil {
		stdin = strings.NewReader("")
	}
	ans, _ := bufio.NewReader(stdin).ReadString('\n')
	if s := strings.TrimSpace(ans); s != "n" && s != "N" {
		_ = exec.Command("reboot", "-f").Run()
	}
	return nil
}

// Selftest runs the crypto and key sanity checks of keygen.py's _selftest and
// reports whether all of them passed.
func Selftest(out io.Writer) bool {
	ok := true
	report := func(name string, cond bool) {
		state := "!!"
		if cond {
			state = "ok"
		}
		fmt.Fprintf(out, "  [%s] %s\n", state, name)
	}
	check := func(name string, cond bool) {
		report(name, cond)
		ok = ok && cond
	}
	silent := func(cond bool) { ok = ok && cond }

	// Transforms and MT-base64 (silent asserts in keygen.py).
	v := make([]byte, 16)
	for i := range v {
		v[i] = byte(i)
	}
	silent(bytes.Equal(mikro.MTTransformRev(mikro.MTTransform(v)), v))
	if dec, err := mikro.MTB64Decode(mikro.MTB64Encode(v, true)); err != nil {
		silent(false)
	} else {
		silent(bytes.Equal(dec, v))
	}

	// Known answers (silent asserts in keygen.py).
	stored := mustDecodeHex("151206fa4fcb2140d48cc427d578ecd0")
	licval := mikro.MTTransform(stored)
	silent(hex.EncodeToString(licval) == "d8d170a64c0006010000000000000000")
	silent(hex.EncodeToString(mikro.MTSHA256(licval)) ==
		"c4bcfeb4cc6d0daa4088381b68ba10fde31a2f10f929ca908017adaf77e1593f")

	// Embedded key pair.
	d := CustomPrivateKey()
	pubx := CustomPublicKeyX()
	p := mikro.CurveScalarMult(d, mikro.CurveGKeygen)
	check("private key reproduces custom public key", p != nil && !p.Inf && p.X.Cmp(pubx) == 0)
	report("public key words match mode2", hex.EncodeToString(transformBlob(CustomKeyPublic)) ==
		"271501494893987a0a50d41dfc7500ffd4f7b32f455f2c0e7c7439d3bd7b0876")
	pubxBytes := mikro.LEBytes(pubx, 32)

	// Software id round trip.
	sid, err := GenerateSWID()
	check("software id checksum", err == nil && SWIDValid(sid))

	// CHR derivation reproduces the observed sample.
	sampleSwid := mustDecodeHex("0011223344556677889973a000000000")
	lv := ChrLicVal("00112233-4455-6677-8899-aabbccddeeff", sampleSwid)
	check("CHR licence value (sample)", hex.EncodeToString(lv) == "db4e0997ab453e0c005786f403000000")
	fmt.Fprintf(out, "  [ok] CHR System ID = %s\n", mikro.MTB64Encode(lv[:8], false))

	// An unreadable DMI UUID must behave as 16 zero bytes, not an empty string.
	empty := ChrLicVal("", sampleSwid)
	zero := mikro.MTSHA256(append(make([]byte, 16), sampleSwid...))[:8]
	check("CHR empty-UUID uses 16 zero bytes", bytes.Equal(empty[:8], zero))

	// Sign with the embedded key and verify both ways.
	sig, err := mikro.KCDSASignKeygen(lv, d)
	check("licence sign/verify", err == nil && mikro.KCDSAVerifyKeygen(lv, sig, pubxBytes))
	check("licence verifies on the device point", err == nil && mikro.KCDSAVerifyDevice(lv, sig, pubxBytes))

	fmt.Fprintf(out, "selftest: %s\n", map[bool]string{true: "PASS", false: "FAIL"}[ok])
	return ok
}

// Main implements the keygen command line.  args is the argument list without
// the program name (Python's sys.argv[1:]); it returns the process exit code
// (0 success, 1 failure, 2 usage error).
func Main(args []string, stdin io.Reader, stdout io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	selftestFlag := fs.Bool("selftest", false, "run the crypto/key sanity checks")
	printOnly := fs.Bool("print", false, "offline: print a licence, do not touch the config")
	serial := fs.String("serial", "", "software serial for --print (x86 format)")
	uuid := fs.String("uuid", "", "product UUID for --print (CHR format)")
	softwareID := fs.String("software-id", "", "software id hex for --print (CHR format)")
	verify := fs.String("verify", "", "verify a licence file")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stdout, "keygen: %v\n", err)
		return 2
	}
	rest := fs.Args()
	if len(rest) > 1 {
		fmt.Fprintf(stdout, "keygen: unrecognized arguments: %s\n", strings.Join(rest[1:], " "))
		return 2
	}
	mode := ""
	if len(rest) == 1 {
		if rest[0] != "chr" && rest[0] != "x86" {
			fmt.Fprintf(stdout, "keygen: invalid mode %q (choose chr or x86)\n", rest[0])
			return 2
		}
		mode = rest[0]
	}

	if *selftestFlag {
		if Selftest(stdout) {
			return 0
		}
		return 1
	}

	if *verify != "" {
		text, err := os.ReadFile(*verify)
		if err != nil {
			fmt.Fprintf(stdout, "keygen: %v\n", err)
			return 1
		}
		licval, witness, sig := ParseLicense(string(text))
		full := make([]byte, 0, len(witness)+len(sig))
		full = append(full, witness...)
		full = append(full, sig...)
		valid := mikro.KCDSAVerifyKeygen(licval, full, mikro.LEBytes(CustomPublicKeyX(), 32))
		if valid {
			fmt.Fprintln(stdout, "valid")
			return 0
		}
		fmt.Fprintln(stdout, "INVALID")
		return 1
	}

	if *printOnly {
		var (
			licval   []byte
			systemID string
			err      error
		)
		switch {
		case *serial != "":
			licval, err = X86LicVal(*serial)
			systemID = *serial
		case *uuid != "":
			swid := make([]byte, 16)
			if *softwareID != "" {
				if swid, err = hex.DecodeString(*softwareID); err != nil {
					break
				}
			}
			licval = ChrLicVal(*uuid, swid)
			systemID = mikro.MTB64Encode(licval[:8], false)
		default:
			fmt.Fprintln(stdout, "keygen: --print needs --serial or --uuid")
			return 2
		}
		if err != nil {
			fmt.Fprintf(stdout, "keygen: %v\n", err)
			return 1
		}
		licText, err := MakeLicense(licval)
		if err != nil {
			fmt.Fprintf(stdout, "keygen: %v\n", err)
			return 1
		}
		PrintLicense(stdout, systemID, licText)
		return 0
	}

	if mode != "" {
		if err := RunMode(mode == "chr", stdin, stdout); err != nil {
			fmt.Fprintf(stdout, "keygen: %v\n", err)
			return 1
		}
		return 0
	}

	if err := RunGenerate(stdout); err != nil {
		fmt.Fprintf(stdout, "keygen: %v\n", err)
		return 1
	}
	return 0
}
