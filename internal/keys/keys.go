// Package keys generates the MikroTikPatch key material and reads and writes
// the shell-style keys.env files consumed by the build orchestrator.  It is a
// Go replacement for tools/genkeys.py.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"mikrotikpatch/internal/mikro"
)

// Stock MikroTik values (the "old" side of every replacement).  These were
// extracted from the official routeros-7.24.4.npk and are fixed.
const (
	MikroLicensePublicKey = "8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"
	MikroNPKSignPublicKey = "c293ced638a2a33c681fc8de98ee26c54eadc5390c2dfce197d35c83c416cf59"
	MikroCloudPublicKey   = "MCowBQYDK2VwAyEAowuXGdXRuNO0WEanhXcs6Lero+Crw8kh3ESWNDi2A/I="
)

// Custom hosts use the reserved .invalid TLD (RFC 2606) so they can never
// resolve.  patch.py rewrites the stock hosts in place, so each custom host is
// exactly as long as its stock counterpart.
const (
	mikroLicenceURL  = "licence.mikrotik.com"
	mikroUpgradeURL  = "upgrade.mikrotik.com"
	mikroCloudURL    = "cloud.mikrotik.com"
	mikroCloud2URL   = "cloud2.mikrotik.com"
	customLicenceURL = "licence.mikr.invalid"
	customUpgradeURL = "upgrade.mikr.invalid"
	customCloudURL   = "cloud.mikr.invalid"
	customCloud2URL  = "cloud2.mikr.invalid"
)

// KeySet holds one complete, self-consistent set of generated keys, already
// encoded the way the env file stores them.
type KeySet struct {
	LicensePrivate string // 32-byte scalar, little-endian hex
	LicensePublic  string // 32-byte x-coordinate, little-endian hex
	NPKSignPrivate string // 32-byte Ed25519 seed hex
	NPKSignPublic  string // 32-byte Ed25519 public key hex
	CloudPrivate   string // 32-byte Ed25519 seed hex
	CloudPublic    string // base64 SPKI (DER = 302a300506032b6570032100 || pub)
}

// spkiEd25519Prefix is the DER SubjectPublicKeyInfo prefix for an Ed25519 key
// (OID 1.3.101.112): SEQUENCE { SEQUENCE { OID }, BIT STRING { 32 bytes } }.
var spkiEd25519Prefix = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
}

// Generate creates a fresh licence (EC-KCDSA over Curve25519), NPK sign
// (Ed25519) and cloud (Ed25519 SPKI) key set, matching tools/genkeys.py.
func Generate() (*KeySet, error) {
	licPriv, licPub, err := generateLicenseKey()
	if err != nil {
		return nil, fmt.Errorf("keys: licence key: %w", err)
	}

	npkSeed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(npkSeed); err != nil {
		return nil, fmt.Errorf("keys: NPK sign seed: %w", err)
	}

	cloudSeed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(cloudSeed); err != nil {
		return nil, fmt.Errorf("keys: cloud seed: %w", err)
	}
	cloudPub := mikro.EdDSAPublicFromSeed(cloudSeed)
	spki := make([]byte, 0, len(spkiEd25519Prefix)+len(cloudPub))
	spki = append(spki, spkiEd25519Prefix...)
	spki = append(spki, cloudPub...)

	return &KeySet{
		LicensePrivate: licPriv,
		LicensePublic:  licPub,
		NPKSignPrivate: hex.EncodeToString(npkSeed),
		NPKSignPublic:  hex.EncodeToString(mikro.EdDSAPublicFromSeed(npkSeed)),
		CloudPrivate:   hex.EncodeToString(cloudSeed),
		CloudPublic:    base64.StdEncoding.EncodeToString(spki),
	}, nil
}

// generateLicenseKey returns the little-endian hex licence scalar and public
// x-coordinate.  The device reconstructs the public point from x using the
// even-y convention, so the scalar is negated when y(d*G) is odd; negating
// keeps the same x with the opposite y.
func generateLicenseKey() (priv, pub string, err error) {
	limit := new(big.Int).Sub(mikro.CurveN, big.NewInt(1))
	d, err := rand.Int(rand.Reader, limit) // [0, n-2]
	if err != nil {
		return "", "", err
	}
	d.Add(d, big.NewInt(1)) // uniform in [1, n-1]

	point := mikro.CurveScalarBaseMult(d)
	if point == nil || point.Inf {
		return "", "", errors.New("scalar multiplication produced the point at infinity")
	}
	if point.Y.Bit(0) == 1 {
		d = new(big.Int).Sub(mikro.CurveN, d)
		point = mikro.CurveScalarBaseMult(d)
		if point == nil || point.Inf {
			return "", "", errors.New("scalar multiplication produced the point at infinity")
		}
	}

	return hex.EncodeToString(mikro.LEBytes(d, 32)),
		hex.EncodeToString(mikro.LEBytes(point.X, 32)), nil
}

// WriteEnvFile writes a complete keys.env to path, with the same variable set
// and order as tools/genkeys.py.  The file is created with 0600 permissions.
func WriteEnvFile(path string, ks *KeySet) error {
	if ks == nil {
		return errors.New("keys: nil KeySet")
	}

	var b strings.Builder
	write := func(key, value string) {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(value)
		b.WriteByte('\n')
	}

	// licence / software key (EC-KCDSA Curve25519)
	write("CUSTOM_LICENSE_PRIVATE_KEY", ks.LicensePrivate)
	write("CUSTOM_LICENSE_PUBLIC_KEY", ks.LicensePublic)
	write("MIKRO_LICENSE_PUBLIC_KEY", MikroLicensePublicKey)
	// NPK sign key (Ed25519)
	write("CUSTOM_NPK_SIGN_PRIVATE_KEY", ks.NPKSignPrivate)
	write("CUSTOM_NPK_SIGN_PUBLIC_KEY", ks.NPKSignPublic)
	write("MIKRO_NPK_SIGN_PUBLIC_KEY", MikroNPKSignPublicKey)
	// cloud key (Ed25519 SPKI)
	write("CUSTOM_CLOUD_PUBLIC_KEY", ks.CloudPublic)
	write("MIKRO_CLOUD_PUBLIC_KEY", MikroCloudPublicKey)
	// stock and custom hosts
	write("MIKRO_LICENCE_URL", mikroLicenceURL)
	write("MIKRO_UPGRADE_URL", mikroUpgradeURL)
	write("MIKRO_CLOUD_URL", mikroCloudURL)
	write("MIKRO_CLOUD2_URL", mikroCloud2URL)
	write("CUSTOM_LICENCE_URL", customLicenceURL)
	write("CUSTOM_UPGRADE_URL", customUpgradeURL)
	write("CUSTOM_CLOUD_URL", customCloudURL)
	write("CUSTOM_CLOUD2_URL", customCloud2URL)

	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// LoadEnvFile parses a shell-style KEY=VALUE file and returns its variables.
// Full-line comments starting with # and blank lines are ignored; an optional
// "export " prefix is accepted and single or double quotes around a value are
// stripped.  Later assignments override earlier ones, so the result reflects
// what `set -a; . file` would export.
func LoadEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	vars := make(map[string]string)
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := cutExport(line); ok {
			line = strings.TrimSpace(rest)
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("keys: %s:%d: not a KEY=VALUE assignment", path, i+1)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("keys: %s:%d: empty variable name", path, i+1)
		}
		vars[key] = unquote(strings.TrimSpace(value))
	}
	return vars, nil
}

// cutExport strips a leading "export" keyword (followed by whitespace) from a
// trimmed assignment line.
func cutExport(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "export")
	if !ok {
		return "", false
	}
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return "", false
	}
	return rest, true
}

// unquote removes one layer of matching single or double quotes.
func unquote(v string) string {
	if len(v) >= 2 {
		if (v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// MergeEnv overlays the process environment with the values from a parsed env
// file.  The orchestrator loads keys.env with `set -a; . keys.env`, which
// overwrites already-exported variables: file values therefore win, and
// environ entries (normally os.Environ()) merely supply defaults for the
// variables the file does not define.
func MergeEnv(file map[string]string, environ []string) map[string]string {
	merged := make(map[string]string, len(file)+len(environ))
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			continue
		}
		merged[key] = value
	}
	for key, value := range file {
		merged[key] = value
	}
	return merged
}
