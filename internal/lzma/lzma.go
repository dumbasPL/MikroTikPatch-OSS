// Package lzma wraps the system liblzma (xz) library for the XZ streams the
// patch pipeline has to decode and re-encode.  It intentionally offers only
// the filter chains the RouterOS payloads use: plain LZMA2 and the x86 BCJ
// filter followed by LZMA2, both with a CRC32 check.
package lzma

/*
#cgo LDFLAGS: -llzma
#include <lzma.h>
#include <stdint.h>
#include <stdlib.h>

static int mkt_lzma_encode(int bcj, uint32_t preset, uint32_t dict_size, int set_props,
                           uint32_t lc, uint32_t lp, uint32_t pb, uint32_t check,
                           const uint8_t *in, size_t in_size,
                           uint8_t **out, size_t *out_size) {
	lzma_options_lzma opt;
	if (lzma_lzma_preset(&opt, preset))
		return (int)LZMA_OPTIONS_ERROR;
	if (dict_size)
		opt.dict_size = dict_size;
	if (set_props) {
		opt.lc = lc;
		opt.lp = lp;
		opt.pb = pb;
	}
	lzma_filter filters[3];
	int n = 0;
	lzma_options_bcj bcj_opt;
	bcj_opt.start_offset = 0;
	if (bcj) {
		filters[n].id = LZMA_FILTER_X86;
		filters[n].options = &bcj_opt;
		n++;
	}
	filters[n].id = LZMA_FILTER_LZMA2;
	filters[n].options = &opt;
	n++;
	filters[n].id = LZMA_VLI_UNKNOWN;
	filters[n].options = NULL;

	// Use the streaming encoder: like Python's lzma.compress it omits the
	// block sizes from the block header, which keeps the output
	// byte-for-byte identical to the Python tooling.
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret ret = lzma_stream_encoder(&strm, filters, (lzma_check)check);
	if (ret != LZMA_OK)
		return (int)ret;
	size_t cap = lzma_stream_buffer_bound(in_size);
	uint8_t *buf = (uint8_t *)malloc(cap ? cap : 1);
	if (!buf) {
		lzma_end(&strm);
		return (int)LZMA_MEM_ERROR;
	}
	strm.next_in = in;
	strm.avail_in = in_size;
	strm.next_out = buf;
	strm.avail_out = cap;
	for (;;) {
		ret = lzma_code(&strm, LZMA_FINISH);
		if (ret == LZMA_STREAM_END)
			break;
		if (ret == LZMA_OK && strm.avail_out == 0) {
			size_t used = (size_t)(strm.next_out - buf);
			size_t ncap = cap * 2;
			uint8_t *nbuf = (uint8_t *)realloc(buf, ncap);
			if (!nbuf) {
				free(buf);
				lzma_end(&strm);
				return (int)LZMA_MEM_ERROR;
			}
			buf = nbuf;
			cap = ncap;
			strm.next_out = buf + used;
			strm.avail_out = cap - used;
			continue;
		}
		free(buf);
		lzma_end(&strm);
		return (int)ret;
	}
	*out = buf;
	*out_size = (size_t)(strm.next_out - buf);
	lzma_end(&strm);
	return 0;
}

static int mkt_lzma_decode(const uint8_t *in, size_t in_size, uint8_t **out, size_t *out_size) {
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
	if (ret != LZMA_OK)
		return (int)ret;
	size_t cap = in_size * 4 + (1u << 20);
	uint8_t *buf = (uint8_t *)malloc(cap);
	if (!buf) {
		lzma_end(&strm);
		return (int)LZMA_MEM_ERROR;
	}
	strm.next_in = in;
	strm.avail_in = in_size;
	strm.next_out = buf;
	strm.avail_out = cap;
	for (;;) {
		ret = lzma_code(&strm, LZMA_FINISH);
		if (ret == LZMA_STREAM_END)
			break;
		if (ret == LZMA_OK && strm.avail_out == 0) {
			size_t used = (size_t)(strm.next_out - buf);
			size_t ncap = cap * 2;
			uint8_t *nbuf = (uint8_t *)realloc(buf, ncap);
			if (!nbuf) {
				free(buf);
				lzma_end(&strm);
				return (int)LZMA_MEM_ERROR;
			}
			buf = nbuf;
			cap = ncap;
			strm.next_out = buf + used;
			strm.avail_out = cap - used;
			continue;
		}
		free(buf);
		lzma_end(&strm);
		return (int)ret;
	}
	*out = buf;
	*out_size = (size_t)(strm.next_out - buf);
	lzma_end(&strm);
	return 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Check is an xz integrity check id.
type Check uint32

const (
	CheckNone  Check = 0
	CheckCRC32 Check = 1
	CheckCRC64 Check = 4
)

// Preset flags for Options.Preset.
const (
	PresetDefault = 6
	PresetExtreme = 1 << 31
)

// Options controls encoding.  Preset is always applied; DictSize overrides the
// preset's dictionary when non-zero, and SetProps overrides lc/lp/pb.
type Options struct {
	BCJX86   bool
	Preset   uint32
	DictSize uint32
	LC       uint32
	LP       uint32
	PB       uint32
	SetProps bool
	Check    Check
}

// LZMA2 is the plain filter chain with a 32 MiB dictionary.
func LZMA2(preset uint32) Options {
	return Options{Preset: preset, Check: CheckCRC32}
}

// X86BCJ is the x86 BCJ + LZMA2 chain used for bzImage payloads.
func X86BCJ(preset uint32) Options {
	return Options{BCJX86: true, Preset: preset, Check: CheckCRC32}
}

// Encode compresses data into a single xz stream.
func Encode(data []byte, opt Options) ([]byte, error) {
	var inPtr *C.uint8_t
	if len(data) > 0 {
		inPtr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	var out *C.uint8_t
	var outLen C.size_t
	ret := C.mkt_lzma_encode(
		boolInt(opt.BCJX86),
		C.uint32_t(opt.Preset),
		C.uint32_t(opt.DictSize),
		boolInt(opt.SetProps),
		C.uint32_t(opt.LC),
		C.uint32_t(opt.LP),
		C.uint32_t(opt.PB),
		C.uint32_t(opt.Check),
		inPtr,
		C.size_t(len(data)),
		&out,
		&outLen,
	)
	if ret != 0 {
		return nil, fmt.Errorf("lzma: encode failed (liblzma error %d)", int(ret))
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// Decode decompresses a single xz stream.  Trailing bytes after the stream are
// ignored.
func Decode(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("lzma: empty input")
	}
	var out *C.uint8_t
	var outLen C.size_t
	ret := C.mkt_lzma_decode(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&out,
		&outLen,
	)
	if ret != 0 {
		return nil, fmt.Errorf("lzma: decode failed (liblzma error %d, size %d, header %x)",
			int(ret), len(data), data[:min(20, len(data))])
	}
	defer C.free(unsafe.Pointer(out))
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

func boolInt(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
