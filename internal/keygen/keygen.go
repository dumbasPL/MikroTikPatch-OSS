// Package keygen is a Go port of keygen.py, the host-side mirror of the
// RouterOS keygen tool that runs on the device (keygen/keygen.c).
//
// It generates and installs licences, switches the device between CHR and x86
// mode, prints licences offline and verifies licence files.  All persistent
// state lives in the 512-byte configuration blob on /dev/flash (also mirrored
// to /dev/root-disk):
//
//	offset  size  meaning
//	0x000   256   reserved / other RouterOS configuration
//	0x100    16   software id (10 random bytes + checksum + 4 zero bytes)
//	0x110    64   licence (stored(16) || witness(16) || signature(32))
//	0x150     1   mode flag: 1 = CHR, 0 = x86
//
// The host environment overrides are handy for testing on a normal Linux box:
//
//	KEYGEN_FLASH, KEYGEN_DISK, KEYGEN_UUID, KEYGEN_KEYMAN
package keygen

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os/exec"
	"strings"

	"mikrotikpatch/internal/mikro"
)

// Licence text framing, byte for byte as the original prints it.
const (
	LicHeader = "-----BEGIN MIKROTIK SOFTWARE KEY------------"
	LicFooter = "-----END MIKROTIK SOFTWARE KEY--------------"
)

// Fixed bytes the original writes into the licence value.
var (
	chrTail = []byte{0x00, 0x57, 0x86, 0xf4, 0x03, 0x00, 0x00, 0x00} // sub_830ED80
	x86Tail = []byte{0x06, 0x16}                                     // sub_830F1F0
)

// SWIDTable is the alphabet used to decode x86 serials.
const SWIDTable = "TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE"

// Recovered custom key material: the MT_Transform_Rev images of the custom key
// pair whose public words are embedded in mode2 (keygen.py's
// CUSTOM_KEY_PUBLIC / CUSTOM_KEY_PRIVATE).
var (
	CustomKeyPublic  = mustDecodeHex("b122e075fb0501555c32a7c94cc3d124846dea4b526bad2cbbfce3121df1718d")
	CustomKeyPrivate = mustDecodeHex("0e8920a2c15fc27c1b4f55c7bca4c4584e3792409c3f42209b297a689b26bd3d")
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("keygen: bad constant blob: " + err.Error())
	}
	return b
}

// transformBlob applies MTTransform to each 16-byte half, like keygen.py's _t32.
func transformBlob(blob []byte) []byte {
	out := make([]byte, 0, 32)
	out = append(out, mikro.MTTransform(blob[:16])...)
	out = append(out, mikro.MTTransform(blob[16:32])...)
	return out
}

// CustomPrivateKey returns the recovered custom private scalar:
//
//	m = int_le(MT_Transform_Rev(CUSTOM_KEY_PRIVATE))
//	d = -m mod n
//
// with the parity normalised exactly like keygen.py's custom_private_key: the
// device reconstructs the public point with its own square-root convention and
// accepts the scalar whose d*G has an odd y under CurveGKeygen, so an even y
// negates the scalar.  Negating keeps the same x, i.e. the same public key.
func CustomPrivateKey() *big.Int {
	m := mikro.BigFromLE(transformBlob(CustomKeyPrivate))
	d := new(big.Int).Neg(m)
	d.Mod(d, mikro.CurveN)
	p := mikro.CurveScalarMult(d, mikro.CurveGKeygen)
	if p != nil && !p.Inf && p.Y.Bit(0) == 0 {
		d.Sub(mikro.CurveN, d)
		d.Mod(d, mikro.CurveN)
	}
	return d
}

// CustomPublicKeyX returns the custom public key x-coordinate as an integer.
func CustomPublicKeyX() *big.Int {
	return mikro.BigFromLE(transformBlob(CustomKeyPublic))
}

// swidChecksum is keygen.py's _swid_checksum: the complement of the little
// endian 16-bit word sum of the first 10 bytes (0xffff when the sum is zero)
// XOR the first MT_SHA256 word (7919 when that is zero).
func swidChecksum(id16 []byte) uint16 {
	var total uint32
	for i := 0; i+1 < 10; i += 2 {
		total += uint32(id16[i]) | uint32(id16[i+1])<<8
	}
	chk := uint16(0xFFFF)
	if total != 0 {
		chk = ^uint16(total)
	}
	hw := binary.LittleEndian.Uint16(mikro.MTSHA256(id16[:10])[:2])
	if hw == 0 {
		hw = 7919
	}
	return chk ^ hw
}

// SWIDValid reports whether the first 16 bytes of id16 carry a valid software
// id checksum.
func SWIDValid(id16 []byte) bool {
	if len(id16) < 16 {
		return false
	}
	return binary.LittleEndian.Uint16(id16[10:12]) == swidChecksum(id16)
}

// GenerateSWID returns a fresh software id: 10 random bytes, the checksum word
// and four zero bytes.
func GenerateSWID() ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id[:10]); err != nil {
		return nil, fmt.Errorf("keygen: cannot read random bytes: %w", err)
	}
	binary.LittleEndian.PutUint16(id[10:], swidChecksum(id))
	return id, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// ParseUUID turns a DMI product UUID into 16 bytes: every hex digit is kept
// (up to 32, separators such as '-' are ignored) and the result is padded on
// the right with zeros.  An empty or unreadable UUID therefore yields 16 zero
// bytes, like the fixed buffer of the original.
func ParseUUID(text string) []byte {
	hx := make([]byte, 0, 32)
	for i := 0; i < len(text) && len(hx) < 32; i++ {
		if hexVal(text[i]) >= 0 {
			hx = append(hx, text[i])
		}
	}
	out := make([]byte, 16)
	for i := 0; i+1 < len(hx); i += 2 {
		out[i/2] = byte(hexVal(hx[i])<<4 | hexVal(hx[i+1]))
	}
	return out
}

// swapPairs byte-swaps every 16-bit pair of b (keygen.py's _swap_pairs).
func swapPairs(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i+1 < len(b); i += 2 {
		out[i], out[i+1] = b[i+1], b[i]
	}
	if len(b)%2 == 1 {
		out[len(b)-1] = b[len(b)-1]
	}
	return out
}

// ChrLicVal derives the CHR licence value from a DMI product UUID and the
// software id, like keygen.py's chr_licval.
func ChrLicVal(uuidText string, swid []byte) []byte {
	h := mikro.MTSHA256(append(swapPairs(ParseUUID(uuidText)), swid...))
	out := make([]byte, 0, 16)
	out = append(out, h[:8]...)
	out = append(out, chrTail...)
	return out
}

// swidDecode decodes an x86 serial (e.g. "ABCD-EFGH") to its integer value.
// Characters outside SWIDTable are an error, like the Python reference.
func swidDecode(serial string) (uint64, error) {
	const radix = uint64(len(SWIDTable))
	v := uint64(0)
	for i := len(serial) - 1; i >= 0; i-- {
		ch := serial[i]
		if ch == '-' {
			continue
		}
		idx := strings.IndexByte(SWIDTable, ch)
		if idx < 0 {
			return 0, fmt.Errorf("keygen: invalid character %q in serial %q", ch, serial)
		}
		if v > (math.MaxUint64-uint64(idx))/radix {
			return 0, fmt.Errorf("keygen: serial %q overflows", serial)
		}
		v = v*radix + uint64(idx)
	}
	return v, nil
}

// X86LicVal derives the x86 licence value from a serial:
//
//	value = SWID(6, LE) || 06 16 || 00 * 8
func X86LicVal(serial string) ([]byte, error) {
	v, err := swidDecode(serial)
	if err != nil {
		return nil, err
	}
	if v > 1<<48-1 {
		return nil, fmt.Errorf("keygen: serial %q does not fit in 6 bytes", serial)
	}
	var word [8]byte
	binary.LittleEndian.PutUint64(word[:], v)
	out := make([]byte, 0, 16)
	out = append(out, word[:6]...)
	out = append(out, x86Tail...)
	out = append(out, make([]byte, 8)...)
	return out, nil
}

// KeymanSoftwareID runs /nova/bin/keyman --software-id (KEYGEN_KEYMAN
// overrides the path) and returns the last non-empty output line, or "" when
// the helper cannot be run.
func KeymanSoftwareID() string {
	cmd := exec.Command(envOr("KEYGEN_KEYMAN", DefaultKeyman), "--software-id")
	out, _ := cmd.Output() // stderr goes to /dev/null; the exit status is ignored
	last := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r", "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			last = line
		}
	}
	return strings.TrimSpace(last)
}

// StoredLicenceValid reports whether the 64-byte stored licence already is a
// valid signature for licval under the custom public key, using the device's
// odd-root convention.  The mode role keeps such a licence instead of
// re-signing it on every boot: RouterOS treats a rewritten licence as a new
// software key and reboots to activate it.
func StoredLicenceValid(stored, licval []byte) bool {
	if len(stored) < 64 || len(licval) != 16 {
		return false
	}
	if !bytes.Equal(mikro.MTTransform(stored[:16]), licval) {
		return false
	}
	pub := mikro.LEBytes(CustomPublicKeyX(), 32)
	return mikro.KCDSAVerifyDevice(licval, stored[16:64], pub)
}

// SignLicVal returns MT_Transform_Rev(licval) followed by the 48-byte
// EC-KCDSA keygen signature, i.e. the 64 bytes stored in the config blob.
func SignLicVal(licval []byte) ([]byte, error) {
	if len(licval) != 16 {
		return nil, errors.New("keygen: licence value must be 16 bytes")
	}
	sig, err := mikro.KCDSASignKeygen(licval, CustomPrivateKey())
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 64)
	out = append(out, mikro.MTTransformRev(licval)...)
	out = append(out, sig...)
	return out, nil
}

// MakeLicense signs licval and renders the licence text: the header, the
// MT-base64 of the 64 signed bytes split over two lines and the footer.
func MakeLicense(licval []byte) (string, error) {
	decoded, err := SignLicVal(licval)
	if err != nil {
		return "", err
	}
	enc := mikro.MTB64Encode(decoded, true)
	half := (len(enc) + 1) / 2
	return fmt.Sprintf("%s\n%s\n%s\n%s\n", LicHeader, enc[:half], enc[half:], LicFooter), nil
}

// ParseLicense extracts the licence value, witness and signature from a
// licence body (or bare base64), like keygen.py's parse_license.  It returns
// nils when the body is too short to hold a licence value.
func ParseLicense(text string) (licval, witness, sig []byte) {
	var body []string
	inside := false
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(s, "-----BEGIN"):
			inside = true
			continue
		case strings.HasPrefix(s, "-----END"):
			inside = false
			continue
		}
		if inside && s != "" {
			body = append(body, s)
		}
	}
	if len(body) == 0 { // bare base64
		for _, line := range strings.Split(text, "\n") {
			if s := strings.TrimSpace(line); s != "" {
				body = append(body, s)
			}
		}
	}
	decoded, err := mikro.MTB64Decode(strings.Join(body, ""))
	if err != nil || len(decoded) < 16 {
		return nil, nil, nil
	}
	if len(decoded) >= 32 {
		witness = decoded[16:32]
	}
	if len(decoded) >= 64 {
		sig = decoded[32:64]
	}
	return mikro.MTTransform(decoded[:16]), witness, sig
}

// LicenceValueFromConfig mirrors the licence-value branch of run_generate:
// mode 1 derives the value from the DMI UUID and returns the MT-base64 system
// id, every other mode decodes the serial.  The caller supplies the serial so
// that keyman only runs when it is actually needed.
func LicenceValueFromConfig(cfg []byte, uuidText, serial string) ([]byte, string, error) {
	if len(cfg) > OffMode && cfg[OffMode] == 1 {
		if len(cfg) < OffSWID+16 {
			return nil, "", errors.New("keygen: config blob is too short for a software id")
		}
		lv := ChrLicVal(uuidText, cfg[OffSWID:OffSWID+16])
		return lv, mikro.MTB64Encode(lv[:8], false), nil
	}
	lv, err := X86LicVal(serial)
	if err != nil {
		return nil, "", err
	}
	return lv, serial, nil
}
