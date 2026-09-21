// Package npk implements the Nova package (NPK) container used by RouterOS:
// parsing, re-signing, file extraction and the FILE_CONTAINER record format.
package npk

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"mikrotikpatch/internal/mikro"
	"mikrotikpatch/internal/squashfs"
)

// PartID identifies an NPK part.
type PartID uint16

const (
	PartNameInfo      PartID = 0x01
	PartDescription   PartID = 0x02
	PartDependencies  PartID = 0x03
	PartFileContainer PartID = 0x04
	PartInstallScript PartID = 0x07
	PartUninstall     PartID = 0x08
	PartSignature     PartID = 0x09
	PartArchitecture  PartID = 0x10
	PartPkgConflicts  PartID = 0x11
	PartPkgInfo       PartID = 0x12
	PartFeatures      PartID = 0x13
	PartPkgFeatures   PartID = 0x14
	PartSquashfs      PartID = 0x15
	PartNullBlock     PartID = 0x16
	PartGitCommit     PartID = 0x17
	PartChannel       PartID = 0x18
	PartHeader        PartID = 0x19
)

// SignatureSize is the digest-and-signature part length: SHA1 + KCDSA + EdDSA.
const SignatureSize = 20 + 48 + 64

// magic is the NPK file magic.
const magic = 0xBAD0F11E

// Part is a single TLV part.  Info is set for NAME_INFO and PKG_INFO payloads.
type Part struct {
	ID   PartID
	Raw  []byte
	Info *NameInfo
}

// Bytes returns the serialised payload.
func (p *Part) Bytes() []byte {
	if p.Info != nil {
		return p.Info.Serialize()
	}
	return p.Raw
}

// Package is an ordered list of parts.
type Package struct {
	Parts []*Part
}

// Get returns the first part with the given id, or nil.
func (p *Package) Get(id PartID) *Part {
	for _, part := range p.Parts {
		if part.ID == id {
			return part
		}
	}
	return nil
}

// Ensure returns the part with the given id, appending an empty one if needed.
func (p *Package) Ensure(id PartID) *Part {
	if part := p.Get(id); part != nil {
		return part
	}
	part := &Part{ID: id}
	p.Parts = append(p.Parts, part)
	return part
}

// NameInfo is a NAME_INFO / PKG_INFO payload: name, version, build time and
// padding.  NAME_INFO parts carry 12 padding bytes, PKG_INFO parts 8.
type NameInfo struct {
	Name      string
	Version   string
	BuildTime time.Time
	Unknown   []byte
}

// NewNameInfo builds a NAME_INFO payload (12 padding bytes).
func NewNameInfo(name string) *NameInfo {
	return &NameInfo{Name: name, BuildTime: time.Now(), Unknown: make([]byte, 12)}
}

// NewPkgInfo builds a PKG_INFO payload (8 padding bytes).
func NewPkgInfo(name string) *NameInfo {
	return &NameInfo{Name: name, BuildTime: time.Now(), Unknown: make([]byte, 8)}
}

// Serialize encodes the payload; the padding length selects the layout.
func (n *NameInfo) Serialize() []byte {
	name := make([]byte, 16)
	copy(name, n.Name)
	out := make([]byte, 0, 36)
	out = append(out, name...)
	out = append(out, encodeVersion(n.Version)...)
	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], uint32(n.BuildTime.Unix()))
	out = append(out, ts[:]...)
	out = append(out, n.Unknown...)
	if len(out) < 32 {
		out = append(out, make([]byte, 32-len(out))...)
	}
	return out
}

func unserializeInfo(data []byte) (*NameInfo, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("npk: info payload too short (%d bytes)", len(data))
	}
	n := &NameInfo{
		Name:      string(bytes.TrimRight(data[:16], "\x00")),
		Version:   decodeVersion(data[16:20]),
		BuildTime: time.Unix(int64(binary.LittleEndian.Uint32(data[20:24])), 0),
	}
	if len(data) > 24 {
		n.Unknown = append([]byte(nil), data[24:]...)
	}
	return n, nil
}

func encodeVersion(version string) []byte {
	var numbers []int
	build := ""
	i := 0
	for i < len(version) {
		c := version[i]
		switch {
		case c >= '0' && c <= '9':
			num := 0
			for i < len(version) && version[i] >= '0' && version[i] <= '9' {
				num = num*10 + int(version[i]-'0')
				i++
			}
			numbers = append(numbers, num)
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			start := i
			for i < len(version) && ((version[i] >= 'a' && version[i] <= 'z') || (version[i] >= 'A' && version[i] <= 'Z')) {
				i++
			}
			build = version[start:i]
		default:
			i++
		}
	}
	major, minor, revision := 0, 0, 0
	if len(numbers) > 0 {
		major = numbers[0]
	}
	if len(numbers) > 1 {
		minor = numbers[1]
	}
	if len(numbers) > 2 {
		revision = numbers[2]
	}
	buildNum := 102
	switch build {
	case "alpha":
		buildNum = 97
	case "beta":
		buildNum = 98
	case "rc":
		buildNum = 99
	case "test":
		buildNum = 102
		revision |= 0x80
	default:
		revision &= 0x7F
	}
	return []byte{byte(revision), byte(buildNum), byte(minor), byte(major)}
}

func decodeVersion(value []byte) string {
	if len(value) < 4 {
		return ""
	}
	revision, build, minor, major := int(value[0]), int(value[1]), int(value[2]), int(value[3])
	suffix := ""
	switch build {
	case 97:
		suffix = fmt.Sprintf("alpha%d", revision)
	case 98:
		suffix = fmt.Sprintf("beta%d", revision)
	case 99:
		suffix = fmt.Sprintf("rc%d", revision)
	case 102:
		if revision&0x80 != 0 {
			suffix = fmt.Sprintf("test%d", revision&0x7F)
		} else if revision != 0 {
			suffix = fmt.Sprintf(".%d", revision)
		}
	default:
		suffix = "unknown"
	}
	return fmt.Sprintf("%d.%d%s", major, minor, suffix)
}

// NovaPackage is a parsed NPK file: a top-level part list plus embedded
// component packages (introduced by PKG_FEATURES).
type NovaPackage struct {
	Package
	Packages []*Package
}

// Load reads and parses an NPK file.
func Load(path string) (*NovaPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Unmarshal(data)
}

// Unmarshal parses a complete NPK file including its 8-byte header.
func Unmarshal(data []byte) (*NovaPackage, error) {
	if len(data) < 8 {
		return nil, errors.New("npk: file too short")
	}
	if binary.LittleEndian.Uint32(data) != magic {
		return nil, errors.New("npk: invalid Nova package magic")
	}
	size := binary.LittleEndian.Uint32(data[4:])
	if int(size) != len(data)-8 {
		return nil, fmt.Errorf("npk: invalid package size (%d != %d)", size, len(data)-8)
	}
	return Parse(data[8:])
}

// Parse parses the part stream (the file header must already be stripped).
func Parse(data []byte) (*NovaPackage, error) {
	npk := &NovaPackage{}
	offset := 0
	var current *Package
	inComponents := false
	for offset < len(data) {
		if offset+6 > len(data) {
			return nil, errors.New("npk: truncated part header")
		}
		id := PartID(binary.LittleEndian.Uint16(data[offset:]))
		size := int(binary.LittleEndian.Uint32(data[offset+2:]))
		offset += 6
		if offset+size > len(data) {
			return nil, fmt.Errorf("npk: part %#x overruns the file", id)
		}
		payload := data[offset : offset+size]
		offset += size

		part := &Part{ID: id}
		switch {
		case id == PartPkgFeatures:
			inComponents = true
			part.Raw = payload
			npk.Parts = append(npk.Parts, part)
		case !inComponents:
			switch id {
			case PartNameInfo, PartPkgInfo:
				info, err := unserializeInfo(payload)
				if err != nil {
					return nil, err
				}
				part.Info = info
			default:
				part.Raw = payload
			}
			npk.Parts = append(npk.Parts, part)
		default:
			if id == PartNameInfo {
				info, err := unserializeInfo(payload)
				if err != nil {
					return nil, err
				}
				current = &Package{}
				current.Parts = append(current.Parts, &Part{ID: id, Info: info})
				npk.Packages = append(npk.Packages, current)
			} else if current != nil {
				current.Parts = append(current.Parts, &Part{ID: id, Raw: payload})
			}
		}
	}
	return npk, nil
}

// packages returns the top-level package list, treating a single-package NPK
// as a one-element list.
func (npk *NovaPackage) packages() []*Package {
	if len(npk.Packages) > 0 {
		return npk.Packages
	}
	return []*Package{&npk.Package}
}

// AllPackages returns the embedded component packages, or the top-level
// package for a single-package NPK.
func (npk *NovaPackage) AllPackages() []*Package { return npk.packages() }

// partSize returns the serialised size of a part's payload.
func partSize(part *Part) int { return len(part.Bytes()) }

// packageSize returns the serialised size of a package (headers included).
func packageSize(p *Package) int {
	total := 0
	for _, part := range p.Parts {
		total += 6 + partSize(part)
	}
	return total
}

// digestParts hashes a package's parts up to the SIGNATURE part: the signature
// header is hashed with its final length, but its body is excluded.
func digestParts(h hash.Hash, p *Package) []byte {
	for _, part := range p.Parts {
		if part.ID == PartHeader {
			continue
		}
		data := part.Bytes()
		var hdr [6]byte
		binary.LittleEndian.PutUint16(hdr[0:], uint16(part.ID))
		binary.LittleEndian.PutUint32(hdr[2:], uint32(len(data)))
		h.Write(hdr[:])
		if part.ID == PartSignature {
			break
		}
		h.Write(data)
	}
	return h.Sum(nil)
}

// Sign repacks the squashfs images, normalises the build time and signs every
// package.  A zero buildTime keeps the package's original build timestamp.
func (npk *NovaPackage) Sign(kcdsaPrivate, eddsaPrivate []byte, buildTime time.Time) error {
	if err := npk.SetNullBlock(); err != nil {
		return err
	}
	if buildTime.IsZero() {
		buildTime = npk.defaultBuildTime()
	}
	if len(npk.Packages) > 0 {
		if pkgInfo := npk.Get(PartPkgInfo); pkgInfo != nil && pkgInfo.Info != nil {
			pkgInfo.Info.BuildTime = buildTime
		}
	}
	for _, pkg := range npk.packages() {
		nameInfo := pkg.Ensure(PartNameInfo)
		if nameInfo.Info == nil {
			nameInfo.Info = NewNameInfo("")
		}
		nameInfo.Info.BuildTime = buildTime

		sig := pkg.Ensure(PartSignature)
		sig.Raw = make([]byte, SignatureSize)
		sig.Info = nil

		digestSHA1 := digestParts(sha1.New(), pkg)
		digestSHA256 := digestParts(sha256.New(), pkg)
		kcdsaSig, err := mikro.KCDSASign(digestSHA1, kcdsaPrivate)
		if err != nil {
			return err
		}
		eddsaSig := mikro.EdDSASign(digestSHA256, eddsaPrivate)
		out := make([]byte, 0, SignatureSize)
		out = append(out, digestSHA1...)
		out = append(out, kcdsaSig...)
		out = append(out, eddsaSig...)
		sig.Raw = out
	}
	return nil
}

// Verify checks the signature of every package with the given public keys.
func (npk *NovaPackage) Verify(kcdsaPublic, eddsaPublic []byte) error {
	for _, pkg := range npk.packages() {
		sig := pkg.Get(PartSignature)
		if sig == nil || len(sig.Bytes()) != SignatureSize {
			return errors.New("npk: missing signature")
		}
		data := sig.Bytes()
		if !mikro.KCDSAVerify(digestPartsSHA1(pkg), data[20:68], kcdsaPublic) {
			return errors.New("npk: KCDSA signature mismatch")
		}
		if !mikro.EdDSAVerify(digestPartsSHA256(pkg), data[68:], eddsaPublic) {
			return errors.New("npk: EdDSA signature mismatch")
		}
	}
	return nil
}

func digestPartsSHA1(p *Package) []byte {
	// The signature body is skipped, so the digest only depends on the other
	// parts; the signature length is already final.
	return digestParts(sha1.New(), p)
}

func digestPartsSHA256(p *Package) []byte {
	return digestParts(sha256.New(), p)
}

func (npk *NovaPackage) defaultBuildTime() time.Time {
	var part *Part
	if len(npk.Packages) > 0 {
		part = npk.Get(PartPkgInfo)
	} else {
		part = npk.Get(PartNameInfo)
	}
	if part != nil && part.Info != nil {
		return part.Info.BuildTime
	}
	return time.Unix(0, 0)
}

// ParseBuildTime parses a seconds-since-the-epoch build time.  An empty value
// is the zero time, which keeps the package's original timestamp.
func ParseBuildTime(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	secs, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid build time %q: %w", v, err)
	}
	return time.Unix(secs, 0), nil
}

// SetNullBlock repacks every squashfs part and sizes the NULL_BLOCK parts so
// that each package ends on a 4 KiB boundary.
func (npk *NovaPackage) SetNullBlock() error {
	repack := func(pkg *Package) (bool, error) {
		found := false
		for _, part := range pkg.Parts {
			if part.ID != PartSquashfs {
				continue
			}
			data := part.Bytes()
			if len(data) < 4 || (string(data[:4]) != "hsqs" && string(data[:4]) != "sqsh") {
				continue
			}
			tree, err := squashfs.ReadAll(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				return false, fmt.Errorf("npk: unpack squashfs: %w", err)
			}
			packed, err := squashfs.Marshal(tree, nil)
			if err != nil {
				return false, fmt.Errorf("npk: repack squashfs: %w", err)
			}
			part.Raw = packed
			part.Info = nil
			found = true
		}
		return found, nil
	}
	setNull := func(pkg *Package, offset int) error {
		found, err := repack(pkg)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		for _, part := range pkg.Parts {
			offset += 6
			if part.ID == PartNullBlock {
				break
			}
			offset += partSize(part)
		}
		offset += 6
		pad := (4096 - offset%4096) % 4096
		null := pkg.Ensure(PartNullBlock)
		null.Raw = make([]byte, pad)
		null.Info = nil
		return nil
	}
	if err := setNull(&npk.Package, 8); err != nil {
		return err
	}
	offset := packageSize(&npk.Package)
	for _, pkg := range npk.Packages {
		if err := setNull(pkg, offset); err != nil {
			return err
		}
		offset += packageSize(pkg)
	}
	return nil
}

// Save writes the package to path, replacing read-only files (the ISO copies
// are read-only) by writing a temporary file and renaming it into place.
func (npk *NovaPackage) Save(path string) error {
	out := npk.Marshal()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// Marshal serialises the whole package including its 8-byte file header.
func (npk *NovaPackage) Marshal() []byte {
	body := npk.Bytes()
	out := make([]byte, 0, len(body)+8)
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:], magic)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(body)))
	out = append(out, hdr[:]...)
	out = append(out, body...)
	return out
}

// Bytes serialises the part stream (without the file header).
func (npk *NovaPackage) Bytes() []byte {
	var body bytes.Buffer
	for _, part := range npk.Parts {
		_ = writePart(&body, part)
	}
	for _, pkg := range npk.Packages {
		for _, part := range pkg.Parts {
			_ = writePart(&body, part)
		}
	}
	return body.Bytes()
}

func writePart(w io.Writer, part *Part) error {
	data := part.Bytes()
	var hdr [6]byte
	binary.LittleEndian.PutUint16(hdr[0:], uint16(part.ID))
	binary.LittleEndian.PutUint32(hdr[2:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// FileItem is one record of a FILE_CONTAINER part.
type FileItem struct {
	Perm       uint8
	Type       uint8
	UsrOrGrp   [6]byte
	ModifyTime uint32
	Revision   uint8
	RC         uint8
	Minor      uint8
	Major      uint8
	CreateTime uint32
	Unknown    uint32
	Name       []byte
	Data       []byte
}

// fileItemHeaderSize matches the packed '<BB6sIBBBBIIIH' record layout.
const fileItemHeaderSize = 1 + 1 + 6 + 4 + 1 + 1 + 1 + 1 + 4 + 4 + 4 + 2

// FileContainer is a parsed FILE_CONTAINER payload: a level-0 zlib stream of
// records.
type FileContainer struct {
	Items []*FileItem
}

func packFileItem(item *FileItem) []byte {
	out := make([]byte, 0, fileItemHeaderSize+len(item.Name)+len(item.Data))
	out = append(out, item.Perm, item.Type)
	out = append(out, item.UsrOrGrp[:]...)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], item.ModifyTime)
	out = append(out, b[:]...)
	out = append(out, item.Revision, item.RC, item.Minor, item.Major)
	binary.LittleEndian.PutUint32(b[:], item.CreateTime)
	out = append(out, b[:]...)
	binary.LittleEndian.PutUint32(b[:], item.Unknown)
	out = append(out, b[:]...)
	binary.LittleEndian.PutUint32(b[:], uint32(len(item.Data)))
	out = append(out, b[:]...)
	var nameLen [2]byte
	binary.LittleEndian.PutUint16(nameLen[:], uint16(len(item.Name)))
	out = append(out, nameLen[:]...)
	out = append(out, item.Name...)
	out = append(out, item.Data...)
	return out
}

// Serialize zlib-compresses (level 0, like the stock tooling) the records.
func (fc *FileContainer) Serialize() ([]byte, error) {
	var raw bytes.Buffer
	for _, item := range fc.Items {
		raw.Write(packFileItem(item))
	}
	var out bytes.Buffer
	zw, err := zlib.NewWriterLevel(&out, zlib.NoCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// UnserializeFileContainer parses a FILE_CONTAINER payload.
func UnserializeFileContainer(data []byte) (*FileContainer, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("npk: file container: %w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("npk: file container: %w", err)
	}
	fc := &FileContainer{}
	offset := 0
	for offset < len(raw) {
		if offset+fileItemHeaderSize > len(raw) {
			return nil, errors.New("npk: file container: truncated record")
		}
		h := raw[offset : offset+fileItemHeaderSize]
		dataSize := int(binary.LittleEndian.Uint32(h[24:]))
		nameSize := int(binary.LittleEndian.Uint16(h[28:]))
		offset += fileItemHeaderSize
		if offset+nameSize+dataSize > len(raw) {
			return nil, errors.New("npk: file container: record overruns payload")
		}
		item := &FileItem{
			Perm:       h[0],
			Type:       h[1],
			ModifyTime: binary.LittleEndian.Uint32(h[4:]),
			Revision:   h[8],
			RC:         h[9],
			Minor:      h[10],
			Major:      h[11],
			CreateTime: binary.LittleEndian.Uint32(h[12:]),
			Unknown:    binary.LittleEndian.Uint32(h[16:]),
			Name:       append([]byte(nil), raw[offset:offset+nameSize]...),
		}
		copy(item.UsrOrGrp[:], h[2:8])
		offset += nameSize
		item.Data = append([]byte(nil), raw[offset:offset+dataSize]...)
		offset += dataSize
		fc.Items = append(fc.Items, item)
	}
	return fc, nil
}

// FindSystemContainer returns the FILE_CONTAINER of the "system" package, or
// nil when there is none.
func (npk *NovaPackage) FindSystemContainer() (*FileContainer, error) {
	for _, pkg := range npk.packages() {
		ni := pkg.Get(PartNameInfo)
		if ni == nil || ni.Info == nil || ni.Info.Name != "system" {
			continue
		}
		part := pkg.Get(PartFileContainer)
		if part == nil {
			return nil, nil
		}
		return UnserializeFileContainer(part.Bytes())
	}
	return nil, nil
}

// ExtractFile returns the content of a file in the system package.
func (npk *NovaPackage) ExtractFile(name string) ([]byte, error) {
	fc, err := npk.FindSystemContainer()
	if err != nil {
		return nil, err
	}
	if fc == nil {
		return nil, errors.New("npk: no system package")
	}
	for _, item := range fc.Items {
		if string(item.Name) == name {
			return item.Data, nil
		}
	}
	return nil, fmt.Errorf("npk: %s not found", name)
}
