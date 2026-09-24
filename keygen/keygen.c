/*
 * keygen.c -- licence keygen and the device's /nova/bin/mode replacement.
 *
 * A single-file, dependency-free C program; the only library it links against
 * is a statically linked musl libc.  It replaces the earlier Go build and
 * behaves identically (keygen.py is the annotated Python mirror of the same
 * logic, and the two agree byte for byte):
 *
 *   keygen         generate a licence for this device and store it
 *   keygen chr     switch the device to CHR mode (and offer a reboot)
 *   keygen x86     switch the device to x86 mode (and offer a reboot)
 *   --selftest     crypto / key sanity checks (not part of the original)
 *
 * It has a second role: patch.py installs the same binary as /nova/bin/mode,
 * where it generates and installs the licence at boot and then hands over to
 * the key-patched stock tool at /nova/bin/mode2 (see run_mode_role below).
 * The role is chosen by argv[0], so the device binary stays usable as a plain
 * keygen when renamed (and the host build keeps the full CLI).
 *
 * Where the data lives
 * --------------------
 * The keygen keeps everything in a single 512-byte "config" blob that lives
 * on the flash device /dev/flash (custom ioctls) and is mirrored to
 * /dev/root-disk:
 *
 *   offset  size  meaning
 *   0x000   256   reserved / other RouterOS configuration
 *   0x100    16   software id (10 random bytes + checksum, see below)
 *   0x110    64   licence (stored(16) || witness(16) || signature(32))
 *   0x150     1   mode flag: 1 = CHR, 0 = x86
 *
 * The software id is generated once and validated on every run.  It is
 *
 *   random[10] || word(checksum ^ hashword) || 0000
 *
 * where checksum = ~sum_le16(random) (0xFFFF if the sum is 0) and
 * hashword = MT_SHA256(random)[0:2] (7919 if zero).
 *
 * The software id / licence value
 * -------------------------------
 * CHR (mode flag == 1) derives the licence value from the VM UUID:
 *
 *   uuid    = /sys/class/dmi/id/product_uuid, 32 hex digits -> 16 bytes
 *   swapped = uuid with every 16-bit pair byte-swapped
 *   h       = MT_SHA256(swapped || software_id)
 *   value   = h[0:8] || 00 57 86 f4 || 03 00 00 00
 *   "System ID" = MT-base64(value[0:8])
 *
 * x86 (mode flag == 0) asks the RouterOS key manager for the serial:
 *
 *   /nova/bin/keyman --software-id      -> e.g. "ABCD-EFGH"
 *   value = SWID(6, LE) || 06 16 || 00 * 8
 *
 * Both are signed with the embedded custom key pair and the resulting 64-byte
 * licence is stored at 0x110 and printed.
 *
 * The licence key pair is baked in at compile time (see build.sh):
 *
 *   -DKEYGEN_LICENSE_PUBLIC_HEX='"<32-byte x, little-endian hex>"'
 *   -DKEYGEN_LICENSE_PRIVATE_HEX='"<32-byte scalar, little-endian hex>"'
 *
 * Environment overrides (handy for testing on a normal Linux box):
 *   KEYGEN_FLASH, KEYGEN_DISK, KEYGEN_UUID, KEYGEN_KEYMAN
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

/* ------------------------------------------------------------------------- */
/* 0. Embedded licence key pair                                              */
/* ------------------------------------------------------------------------- */

/* The defaults are the key recovered from the shipped keygen.  A real build
 * injects its own pair with the defines above, exactly like the Go build did
 * with -ldflags -X.  Both values are little-endian; the private key is the
 * 32-byte scalar, the public key the 32-byte Curve25519 x-coordinate. */
#ifndef KEYGEN_LICENSE_PUBLIC_HEX
#define KEYGEN_LICENSE_PUBLIC_HEX \
    "271501494893987a0a50d41dfc7500ffd4f7b32f455f2c0e7c7439d3bd7b0876"
#endif
#ifndef KEYGEN_LICENSE_PRIVATE_HEX
#define KEYGEN_LICENSE_PRIVATE_HEX \
    "b80c01a25ad30465dcfd99e121f9b6f25fbd8cdd26718caf924bdaa20aef5204"
#endif

static const char license_public_hex[]  = KEYGEN_LICENSE_PUBLIC_HEX;
static const char license_private_hex[] = KEYGEN_LICENSE_PRIVATE_HEX;

/* ------------------------------------------------------------------------- */
/* 1. Fixed-width big integers (8 x 32-bit limbs, little-endian)             */
/* ------------------------------------------------------------------------- */

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define NLIMBS 8

typedef struct { u32 v[NLIMBS]; } u256;

static const u256 U256_ZERO = {{0, 0, 0, 0, 0, 0, 0, 0}};
static const u256 U256_ONE  = {{1, 0, 0, 0, 0, 0, 0, 0}};

static int u256_is_zero(const u256 *a) {
    u32 acc = 0;
    for (int i = 0; i < NLIMBS; i++) acc |= a->v[i];
    return acc == 0;
}

static int u256_cmp(const u256 *a, const u256 *b) {
    for (int i = NLIMBS - 1; i >= 0; i--) {
        if (a->v[i] != b->v[i]) return a->v[i] < b->v[i] ? -1 : 1;
    }
    return 0;
}

static int u256_bit(const u256 *a, int i) {
    return (int)((a->v[i >> 5] >> (i & 31)) & 1u);
}

/* r = a + b, returns the carry out (mod 2^256 arithmetic). */
static u32 u256_add(u256 *r, const u256 *a, const u256 *b) {
    u64 carry = 0;
    for (int i = 0; i < NLIMBS; i++) {
        u64 t = (u64)a->v[i] + (u64)b->v[i] + carry;
        r->v[i] = (u32)t;
        carry = t >> 32;
    }
    return (u32)carry;
}

/* r = a - b, returns the borrow (mod 2^256 arithmetic). */
static u32 u256_sub(u256 *r, const u256 *a, const u256 *b) {
    u64 borrow = 0;
    for (int i = 0; i < NLIMBS; i++) {
        u64 t = (u64)a->v[i] - (u64)b->v[i] - borrow;
        r->v[i] = (u32)t;
        borrow = (t >> 32) & 1u;
    }
    return (u32)borrow;
}

static void u256_from_bytes(u256 *r, const u8 b[32]) {
    for (int i = 0; i < NLIMBS; i++) {
        r->v[i] = (u32)b[4 * i] | ((u32)b[4 * i + 1] << 8) |
                  ((u32)b[4 * i + 2] << 16) | ((u32)b[4 * i + 3] << 24);
    }
}

static void u256_to_bytes(u8 b[32], const u256 *a) {
    for (int i = 0; i < NLIMBS; i++) {
        b[4 * i]     = (u8)(a->v[i]);
        b[4 * i + 1] = (u8)(a->v[i] >> 8);
        b[4 * i + 2] = (u8)(a->v[i] >> 16);
        b[4 * i + 3] = (u8)(a->v[i] >> 24);
    }
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode exactly outlen bytes of hex (ignoring nothing); 0 on failure. */
static int hex_decode(u8 *out, size_t outlen, const char *hex) {
    for (size_t i = 0; i < outlen; i++) {
        int hi = hex_nibble((unsigned char)hex[2 * i]);
        int lo = hex_nibble((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (u8)((hi << 4) | lo);
    }
    return hex[2 * outlen] == '\0';
}

/* ------------------------------------------------------------------------- */
/* 2. Montgomery arithmetic mod a 256-bit modulus                            */
/* ------------------------------------------------------------------------- */

typedef struct {
    u256 m;   /* the modulus (odd)                        */
    u256 rr;  /* R^2 mod m, R = 2^256                     */
    u32  n0;  /* -m^-1 mod 2^32                           */
} mont;

static void mont_init(mont *c, const u256 *m) {
    c->m = *m;

    /* n0 = -m^-1 mod 2^32 by Newton iteration (m is odd). */
    u32 inv = 1;
    for (int i = 0; i < 5; i++) inv *= 2u - m->v[0] * inv;
    c->n0 = 0u - inv;

    /* rr = 2^512 mod m by doubling 1 mod m. */
    u256 r = U256_ONE;
    for (int i = 0; i < 512; i++) {
        u32 carry = u256_add(&r, &r, &r);
        if (carry || u256_cmp(&r, m) >= 0) u256_sub(&r, &r, m);
    }
    c->rr = r;
}

/* Montgomery product: r = a * b * R^-1 mod m (HAC 14.36). a, b < m. */
static void mont_mul(u256 *r, const u256 *a, const u256 *b, const mont *c) {
    u32 t[NLIMBS + 2];
    memset(t, 0, sizeof(t));

    for (int i = 0; i < NLIMBS; i++) {
        u64 carry = 0;
        for (int j = 0; j < NLIMBS; j++) {
            u64 uv = (u64)t[j] + (u64)a->v[j] * b->v[i] + carry;
            t[j] = (u32)uv;
            carry = uv >> 32;
        }
        u64 uv = (u64)t[NLIMBS] + carry;
        t[NLIMBS] = (u32)uv;
        t[NLIMBS + 1] = (u32)(uv >> 32);

        u32 mp = (u32)((u64)t[0] * c->n0);
        uv = (u64)t[0] + (u64)mp * c->m.v[0];
        carry = uv >> 32;
        for (int j = 1; j < NLIMBS; j++) {
            uv = (u64)t[j] + (u64)mp * c->m.v[j] + carry;
            t[j - 1] = (u32)uv;
            carry = uv >> 32;
        }
        uv = (u64)t[NLIMBS] + carry;
        t[NLIMBS - 1] = (u32)uv;
        t[NLIMBS] = (u32)(t[NLIMBS + 1] + (uv >> 32));
    }

    u256 res;
    for (int i = 0; i < NLIMBS; i++) res.v[i] = t[i];
    if (t[NLIMBS] != 0 || u256_cmp(&res, &c->m) >= 0)
        u256_sub(&res, &res, &c->m);
    *r = res;
}

/* to/from Montgomery form (a < m required) */
static void mont_from(u256 *r, const u256 *a, const mont *c) {
    mont_mul(r, a, &c->rr, c);
}
static void mont_to(u256 *r, const u256 *a, const mont *c) {
    u256 one = U256_ONE;
    mont_mul(r, a, &one, c);
}

static void mont_add(u256 *r, const u256 *a, const u256 *b, const mont *c) {
    u32 carry = u256_add(r, a, b);
    if (carry || u256_cmp(r, &c->m) >= 0) u256_sub(r, r, &c->m);
}

static void mont_sub(u256 *r, const u256 *a, const u256 *b, const mont *c) {
    u32 borrow = u256_sub(r, a, b);
    if (borrow) u256_add(r, r, &c->m);
}

/* r = a^e mod m; e is a little-endian byte string. */
static void mont_pow(u256 *r, const u256 *a, const u8 *e, size_t elen,
                     const mont *c) {
    u256 acc, base = *a, one = U256_ONE;
    mont_from(&acc, &one, c); /* Montgomery representation of 1 */
    for (size_t i = elen; i-- > 0; ) {
        for (int bit = 7; bit >= 0; bit--) {
            mont_mul(&acc, &acc, &acc, c);
            if ((e[i] >> bit) & 1u) mont_mul(&acc, &acc, &base, c);
        }
    }
    *r = acc;
}

/* r = a^-1 mod m (both moduli used here are prime). */
static void mont_inv(u256 *r, const u256 *a, const mont *c) {
    u256 e = c->m, two = U256_ONE;
    u8 eb[32];
    two.v[0] = 2;
    u256_sub(&e, &e, &two);
    u256_to_bytes(eb, &e);
    mont_pow(r, a, eb, sizeof(eb), c);
}

/* ------------------------------------------------------------------------- */
/* 3. Curve25519 (y^2 = x^3 + 486662 x^2 + x) and EC-KCDSA                   */
/* ------------------------------------------------------------------------- */

/* p = 2^255 - 19 */
static const u8 P_LE[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
};

/* n = 2^252 + 27742317777372353535851937790883648493 (base point order) */
static const u8 N_LE[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/* y-coordinate of the generator (x = 9), the odd root as returned by the
 * Python mirror's Tonelli-Shanks; see custom_private_key() below. */
static const u8 GY_LE[32] = {
    0xd9, 0xd3, 0xce, 0x7e, 0xa2, 0xc5, 0xe9, 0x29,
    0xb2, 0x61, 0x7c, 0x6d, 0x7e, 0x4d, 0x3d, 0x92,
    0x4c, 0xd1, 0x48, 0x77, 0x2c, 0xdd, 0x1e, 0xe0,
    0xb4, 0x86, 0xa0, 0xb8, 0xa1, 0x19, 0xae, 0x20,
};

/* (p + 3) / 8 and (p - 1) / 4, little-endian: sqrt and sqrt(-1) exponents. */
static const u8 EXP_SQRT_LE[32] = {
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
};
static const u8 EXP_QTR_LE[32] = {
    0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f,
};

#define CURVE_A 486662

typedef struct { int inf; u256 x, y; } pt; /* affine, coordinates in Montgomery form */

static mont FP, FN;              /* field p and scalar group n */
static u256 MOD_P, MOD_N;        /* plain copies for comparisons  */
static u256 A_MONT, ONE_MONT_P;  /* 486662 and 1, Montgomery form */
static u256 SQRT_M1_MONT;        /* sqrt(-1) mod p, Montgomery    */
static pt   G_PT;                /* the generator                 */

static void crypto_init(void) {
    u256 t;

    u256_from_bytes(&MOD_P, P_LE);
    mont_init(&FP, &MOD_P);
    u256_from_bytes(&MOD_N, N_LE);
    mont_init(&FN, &MOD_N);

    t = U256_ZERO;
    t.v[0] = CURVE_A;
    mont_from(&A_MONT, &t, &FP);

    t = U256_ONE;
    mont_from(&ONE_MONT_P, &t, &FP);

    /* sqrt(-1) = 2^((p-1)/4) mod p */
    t = U256_ZERO;
    t.v[0] = 2;
    mont_from(&t, &t, &FP);
    mont_pow(&SQRT_M1_MONT, &t, EXP_QTR_LE, sizeof(EXP_QTR_LE), &FP);

    /* generator */
    t = U256_ZERO;
    t.v[0] = 9;
    mont_from(&G_PT.x, &t, &FP);
    u256_from_bytes(&t, GY_LE);
    mont_from(&G_PT.y, &t, &FP);
    G_PT.inf = 0;
}

/* Reduce a 256-bit value mod n by repeated subtraction (n > 2^252). */
static void reduce_mod_n(u256 *a) {
    for (int i = 0; i < 32 && u256_cmp(a, &MOD_N) >= 0; i++)
        u256_sub(a, a, &MOD_N);
}

/* r = p1 + p2 (affine, mirrors the Python/Go group law exactly). */
static void ec_add(pt *r, const pt *p1, const pt *p2) {
    u256 m, t, u;

    if (p1->inf) { *r = *p2; return; }
    if (p2->inf) { *r = *p1; return; }

    if (u256_cmp(&p1->x, &p2->x) == 0) {
        mont_add(&t, &p1->y, &p2->y, &FP);
        if (u256_is_zero(&t)) { r->inf = 1; return; } /* p2 == -p1 */
        /* doubling: m = (3x^2 + 2Ax + 1) / (2y) */
        mont_mul(&m, &p1->x, &p1->x, &FP);
        mont_add(&t, &m, &m, &FP);
        mont_add(&m, &t, &m, &FP);           /* 3x^2  */
        mont_mul(&t, &A_MONT, &p1->x, &FP);
        mont_add(&t, &t, &t, &FP);           /* 2Ax   */
        mont_add(&m, &m, &t, &FP);
        mont_add(&m, &m, &ONE_MONT_P, &FP);  /* +1    */
        mont_add(&t, &p1->y, &p1->y, &FP);   /* 2y    */
        mont_inv(&t, &t, &FP);
        mont_mul(&m, &m, &t, &FP);
    } else {
        mont_sub(&m, &p2->y, &p1->y, &FP);
        mont_sub(&t, &p2->x, &p1->x, &FP);
        mont_inv(&t, &t, &FP);
        mont_mul(&m, &m, &t, &FP);
    }

    /* x3 = m^2 - A - x1 - x2 ; y3 = m (x1 - x3) - y1 */
    mont_mul(&t, &m, &m, &FP);
    mont_sub(&t, &t, &A_MONT, &FP);
    mont_sub(&t, &t, &p1->x, &FP);
    mont_sub(&t, &t, &p2->x, &FP);
    mont_sub(&u, &p1->x, &t, &FP);
    mont_mul(&u, &m, &u, &FP);
    mont_sub(&u, &u, &p1->y, &FP);

    r->inf = 0;
    r->x = t;
    r->y = u;
}

/* r = k * p (k plain, up to 256 bits). */
static void ec_mul(pt *r, const u256 *k, const pt *p) {
    pt acc, q = *p;
    acc.inf = 1;
    for (int i = 0; i < 256; i++) {
        if (u256_bit(k, i)) ec_add(&acc, &acc, &q);
        ec_add(&q, &q, &q);
    }
    *r = acc;
}

/* r = the point with the given x and (want_odd ? odd : either) y; 0 if x is
 * not on the curve. */
static int ec_from_x(pt *r, const u256 *x_plain, int want_odd) {
    u256 xm, rhs, t, y, y2, ny;
    int ok = 0;

    mont_from(&xm, x_plain, &FP);

    /* rhs = x^3 + A x^2 + x */
    mont_mul(&rhs, &xm, &xm, &FP);
    mont_mul(&rhs, &rhs, &xm, &FP);
    mont_mul(&t, &A_MONT, &xm, &FP);
    mont_mul(&t, &t, &xm, &FP);
    mont_add(&rhs, &rhs, &t, &FP);
    mont_add(&rhs, &rhs, &xm, &FP);

    /* p = 5 mod 8: y = rhs^((p+3)/8), times sqrt(-1) if that is not a root */
    mont_pow(&y, &rhs, EXP_SQRT_LE, sizeof(EXP_SQRT_LE), &FP);
    mont_mul(&y2, &y, &y, &FP);
    if (u256_cmp(&y2, &rhs) != 0) {
        mont_mul(&y, &y, &SQRT_M1_MONT, &FP);
        mont_mul(&y2, &y, &y, &FP);
        if (u256_cmp(&y2, &rhs) != 0) goto out; /* not a square */
    }

    if (want_odd) {
        u256 yp;
        mont_to(&yp, &y, &FP);
        if ((yp.v[0] & 1u) == 0) {
            mont_sub(&ny, &U256_ZERO, &y, &FP); /* y = -y */
            y = ny;
        }
    }

    r->inf = 0;
    r->x = xm;
    r->y = y;
    ok = 1;
out:
    return ok;
}

/* ------------------------------------------------------------------------- */
/* 4. MikroTik custom SHA-256                                                */
/* ------------------------------------------------------------------------- */

static const u32 MT_K[64] = {
    0x0548D563, 0x98308EAB, 0x37AF7CCC, 0xDFBC4E3C,
    0xF125AAC9, 0xEC98ACB8, 0x8B540795, 0xD3E0EF0E,
    0x4904D6E5, 0x0DA84981, 0x9A1F8452, 0x00EB7EAA,
    0x96F8E3B3, 0xA6CDB655, 0xE7410F9E, 0x8EECB03D,
    0x9C6A7C25, 0xD77B072F, 0x6E8F650A, 0x124E3640,
    0x7E53785A, 0xE0150772, 0xC61EF4E0, 0xBC57E5E0,
    0xC0F9A285, 0xDB342856, 0x190834C7, 0xFBEB7D8E,
    0x251BED34, 0x0E9F2AAD, 0x256AB901, 0x0A5B7890,
    0x9F124F09, 0xD84A9151, 0x427AF67A, 0x8059C9AA,
    0x13EAB029, 0x3153CDF1, 0x262D405D, 0xA2105D87,
    0x9C745F15, 0xD1613847, 0x294CE135, 0x20FB0F3C,
    0x8424D8ED, 0x8F4201B6, 0x12CA1EA7, 0x2054B091,
    0x463D8288, 0xC83253C3, 0x33EA314A, 0x9696DC92,
    0xD041CE9A, 0xE5477160, 0xC7656BE8, 0x5179FE33,
    0x1F4726F1, 0x5F393AF0, 0x26E2D004, 0x6D020245,
    0x85FDF6D7, 0xB0237C56, 0xFF5FBD94, 0xA8B3F534,
};

static const u32 MT_IV[8] = {
    0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
    0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA,
};

static u32 rotr32(u32 x, int n) { return (x >> n) | (x << (32 - n)); }
static u32 rotl32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha256_block(u32 h[8], const u8 *p) {
    u32 w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)p[4 * i] << 24) | ((u32)p[4 * i + 1] << 16) |
               ((u32)p[4 * i + 2] << 8) | (u32)p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        u32 s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    u32 a = h[0], b = h[1], c = h[2], d = h[3];
    u32 e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = hh + S1 + ch + MT_K[i] + w[i];
        u32 S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        u32 maj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void mt_sha256(const u8 *msg, size_t len, u8 out[32]) {
    u32 h[8];
    u8 tail[128];
    size_t i = 0, rem, total;

    memcpy(h, MT_IV, sizeof(h));
    for (; i + 64 <= len; i += 64) sha256_block(h, msg + i);

    rem = len - i;
    memcpy(tail, msg + i, rem);
    tail[rem++] = 0x80;
    total = (rem <= 56) ? 64 : 128;
    memset(tail + rem, 0, total - rem - 8);
    {
        u64 bitlen = (u64)len * 8;
        for (int k = 0; k < 8; k++) tail[total - 1 - k] = (u8)(bitlen >> (8 * k));
    }
    for (size_t off = 0; off < total; off += 64) sha256_block(h, tail + off);

    for (int k = 0; k < 8; k++) {
        out[4 * k]     = (u8)(h[k] >> 24);
        out[4 * k + 1] = (u8)(h[k] >> 16);
        out[4 * k + 2] = (u8)(h[k] >> 8);
        out[4 * k + 3] = (u8)(h[k]);
    }
}

/* ------------------------------------------------------------------------- */
/* 5. MT_Transform / MT_Transform_Rev (operate on 16 bytes)                  */
/* ------------------------------------------------------------------------- */

static u32 rd_be32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static void wr_be32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}

/* MT_Transform: stored licence value -> licence value. */
static void mt_transform(u8 out[16], const u8 in[16]) {
    u32 w[4];
    for (int i = 0; i < 4; i++) w[i] = rd_be32(in + 4 * i);
    for (int i = 0; i < 16; i++) {
        w[(i + 2) % 4] -= w[(i + 0) % 4] + MT_K[i * 4 + 0];
        w[(i + 3) % 4] = (rotl32(w[(i + 0) % 4], MT_K[i * 4 + 0] & 0x0F) ^
                          w[(i + 3) % 4]) + w[(i + 0) % 4];
        w[(i + 1) % 4] -= w[(i + 3) % 4] + MT_K[i * 4 + 1];
        w[(i + 2) % 4] = (rotl32(w[(i + 1) % 4], MT_K[i * 4 + 1] & 0x0F) ^
                          w[(i + 2) % 4]) + w[(i + 1) % 4];
        w[(i + 0) % 4] -= w[(i + 2) % 4] + MT_K[i * 4 + 2];
        w[(i + 1) % 4] = (rotl32(w[(i + 2) % 4], MT_K[i * 4 + 2] & 0x0F) ^
                          w[(i + 1) % 4]) + w[(i + 2) % 4];
        w[(i + 3) % 4] -= w[(i + 1) % 4] + MT_K[i * 4 + 3];
        w[(i + 0) % 4] = (rotl32(w[(i + 3) % 4], MT_K[i * 4 + 3] & 0x0F) ^
                          w[(i + 0) % 4]) + w[(i + 3) % 4];
    }
    for (int i = 0; i < 4; i++) wr_be32(out + 4 * i, w[i]);
}

/* MT_Transform_Rev: licence value -> stored licence value. */
static void mt_transform_rev(u8 out[16], const u8 in[16]) {
    u32 w[4];
    for (int i = 0; i < 4; i++) w[i] = rd_be32(in + 4 * i);
    for (int i = 15; i >= 0; i--) {
        w[(i + 0) % 4] = rotl32(w[(i + 3) % 4], MT_K[i * 4 + 3] & 0x0F) ^
                         (w[(i + 0) % 4] - w[(i + 3) % 4]);
        w[(i + 3) % 4] += w[(i + 1) % 4] + MT_K[i * 4 + 3];
        w[(i + 1) % 4] = rotl32(w[(i + 2) % 4], MT_K[i * 4 + 2] & 0x0F) ^
                         (w[(i + 1) % 4] - w[(i + 2) % 4]);
        w[(i + 0) % 4] += w[(i + 2) % 4] + MT_K[i * 4 + 2];
        w[(i + 2) % 4] = rotl32(w[(i + 1) % 4], MT_K[i * 4 + 1] & 0x0F) ^
                         (w[(i + 2) % 4] - w[(i + 1) % 4]);
        w[(i + 1) % 4] += w[(i + 3) % 4] + MT_K[i * 4 + 1];
        w[(i + 3) % 4] = rotl32(w[(i + 0) % 4], MT_K[i * 4 + 0] & 0x0F) ^
                         (w[(i + 3) % 4] - w[(i + 0) % 4]);
        w[(i + 2) % 4] += w[(i + 0) % 4] + MT_K[i * 4 + 0];
    }
    for (int i = 0; i < 4; i++) wr_be32(out + 4 * i, w[i]);
}

/* ------------------------------------------------------------------------- */
/* 6. MT-base64                                                              */
/* ------------------------------------------------------------------------- */

static const char MT_B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encode data (n bytes) into out; out must hold 4*((n+2)/3)+8 bytes. */
static void mt_b64_encode(char *out, const u8 *data, size_t n, int pad) {
    size_t o = 0;
    int left = 0;
    for (size_t i = 0; i < n; i++) {
        if (left == 0) {
            out[o++] = MT_B64[data[i] & 0x3F];
            left = 2;
        } else if (left == 6) {
            out[o++] = MT_B64[data[i - 1] >> 2];
            out[o++] = MT_B64[data[i] & 0x3F];
            left = 2;
        } else {
            int index = ((data[i - 1] >> (8 - left)) | (data[i] << left)) & 0x3F;
            out[o++] = MT_B64[index];
            left += 2;
        }
    }
    if (left != 0) out[o++] = MT_B64[data[n - 1] >> (8 - left)];
    if (pad) {
        while (o % 4 != 0) out[o++] = '=';
    }
    out[o] = '\0';
}

static int mt_b64_index(int c) {
    const char *p = strchr(MT_B64, c);
    return p ? (int)(p - MT_B64) : -1;
}

/* Decode base64 text (padding ignored) into out; returns the byte count. */
static size_t mt_b64_decode(u8 *out, size_t outlen, const char *text) {
    size_t o = 0, n = strlen(text);
    int left = 0;
    for (size_t i = 0; i < n; i++) {
        if (text[i] == '=') continue;
        if (left == 0) {
            left = 6;
            continue;
        }
        int v1 = mt_b64_index((unsigned char)text[i - 1]);
        int v2 = mt_b64_index((unsigned char)text[i]);
        if (v1 < 0 || v2 < 0) { left -= 2; continue; }
        if (o < outlen) out[o++] = (u8)((v1 >> (6 - left)) | (v2 << left));
        left -= 2;
    }
    return o;
}

/* ------------------------------------------------------------------------- */
/* 7. Software id <-> serial                                                 */
/* ------------------------------------------------------------------------- */

static const char SWID_TABLE[] = "TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE";

/* Decode a serial such as "ABCD-EFGH" into its 64-bit value. */
static u64 swid_decode(const char *serial) {
    u64 v = 0;
    size_t n = strlen(serial);
    for (size_t i = n; i-- > 0; ) {
        const char *p = strchr(SWID_TABLE, (unsigned char)serial[i]);
        if (p == NULL || serial[i] == '\0') continue;
        v = v * (u64)strlen(SWID_TABLE) + (u64)(p - SWID_TABLE);
    }
    return v;
}

/* ------------------------------------------------------------------------- */
/* 8. Randomness                                                             */
/* ------------------------------------------------------------------------- */

static int rand_bytes(u8 *buf, size_t n) {
    size_t got = 0;
    ssize_t r = getrandom(buf, n, 0);
    if (r == (ssize_t)n) return 1;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    while (got < n) {
        r = read(fd, buf + got, n - got);
        if (r <= 0) { close(fd); return 0; }
        got += (size_t)r;
    }
    close(fd);
    return 1;
}

/* k in [1, n-1], from 32 random bytes reduced mod (n-1). */
static void gen_nonce(u256 *k) {
    u8 buf[32];
    u256 r, nm1 = MOD_N;
    if (!rand_bytes(buf, sizeof(buf))) {
        fprintf(stderr, "keygen: cannot read random bytes\n");
        exit(1);
    }
    u256_from_bytes(&r, buf);
    u256_sub(&nm1, &nm1, &U256_ONE); /* n - 1 */
    for (int i = 0; i < 32 && u256_cmp(&r, &nm1) >= 0; i++)
        u256_sub(&r, &r, &nm1);
    u256_add(&r, &r, &U256_ONE);
    *k = r;
}

/* ------------------------------------------------------------------------- */
/* 9. Licence key and EC-KCDSA                                               */
/* ------------------------------------------------------------------------- */

/* The signing scalar, normalised so that d*G has an odd y: the device
 * reconstructs the public point from the stored x with its own square-root
 * convention (the odd root), so this makes d*G the device's point.  Negating
 * the scalar keeps the same x, so the embedded public key is unchanged. */
static void load_private_key(u256 *d) {
    u8 b[32];
    pt p;

    if (!hex_decode(b, sizeof(b), license_private_hex)) {
        fprintf(stderr, "keygen: invalid KEYGEN_LICENSE_PRIVATE_HEX\n");
        exit(1);
    }
    u256_from_bytes(d, b);
    reduce_mod_n(d);
    ec_mul(&p, d, &G_PT);
    if (!p.inf) {
        u256 y;
        mont_to(&y, &p.y, &FP);
        if ((y.v[0] & 1u) == 0) u256_sub(d, &MOD_N, d);
    }
}

static void load_public_x(u256 *x) {
    u8 b[32];
    if (!hex_decode(b, sizeof(b), license_public_hex)) {
        fprintf(stderr, "keygen: invalid KEYGEN_LICENSE_PUBLIC_HEX\n");
        exit(1);
    }
    u256_from_bytes(x, b);
    for (int i = 0; i < 32 && u256_cmp(x, &MOD_P) >= 0; i++)
        u256_sub(x, x, &MOD_P);
}

/* Witness (16) || s (32).  nonce != NULL makes the signature deterministic. */
static int kcdsa_sign(u8 out[48], const u8 licval[16], const u256 *d,
                      const u256 *nonce) {
    for (int attempt = 0; attempt < 1000; attempt++) {
        u256 k, kM, e, eM, tM, dM, invM, sM, s, rx;
        pt R;
        u8 rxb[32], h[32];

        if (nonce != NULL) k = *nonce;
        else gen_nonce(&k);

        ec_mul(&R, &k, &G_PT);
        if (R.inf) {
            if (nonce != NULL) return 0;
            continue;
        }
        mont_to(&rx, &R.x, &FP);
        if (u256_cmp(&rx, &MOD_N) >= 0) { /* verifier hashes the unreduced x */
            if (nonce != NULL) return 0;
            continue;
        }

        u256_to_bytes(rxb, &rx);
        mt_sha256(rxb, sizeof(rxb), h);
        memcpy(out, h, 16); /* witness */

        mt_sha256(licval, 16, h);
        for (int i = 0; i < 16; i++) h[8 + i] ^= out[i];
        h[0] &= 0xF8;
        h[31] = (u8)((h[31] & 0x3F) | 0x40);
        u256_from_bytes(&e, h);

        /* s = d^-1 (k - e) mod n */
        reduce_mod_n(&e);
        mont_from(&kM, &k, &FN);
        mont_from(&eM, &e, &FN);
        mont_sub(&tM, &kM, &eM, &FN);
        mont_from(&dM, d, &FN);
        mont_inv(&invM, &dM, &FN);
        mont_mul(&sM, &invM, &tM, &FN);
        mont_to(&s, &sM, &FN);
        u256_to_bytes(out + 16, &s);
        return 1;
    }
    return 0;
}

static void sign_licval(u8 out[64], const u8 licval[16], const u256 *d) {
    mt_transform_rev(out, licval);
    if (!kcdsa_sign(out + 16, licval, d, NULL)) {
        fprintf(stderr, "keygen: no suitable nonce\n");
        exit(1);
    }
}

/* Verify a signature.  device_only restricts the public point to the odd root
 * (what the device's keyman does); otherwise both roots are accepted. */
static int kcdsa_verify(const u8 licval[16], const u8 sig[48],
                        const u256 *pubx, int device_only) {
    u8 witness[16], h[32], yxb[32], hh[32];
    u256 s, e;
    pt pub;

    memcpy(witness, sig, 16);
    u256_from_bytes(&s, sig + 16);

    mt_sha256(licval, 16, h);
    for (int i = 0; i < 16; i++) h[8 + i] ^= witness[i];
    h[0] &= 0xF8;
    h[31] = (u8)((h[31] & 0x3F) | 0x40);
    u256_from_bytes(&e, h);

    if (!ec_from_x(&pub, pubx, 1)) return 0;

    for (int which = 0; which < (device_only ? 1 : 2); which++) {
        pt p = pub, a, b, y;
        u256 yx;
        if (which == 1) mont_sub(&p.y, &U256_ZERO, &p.y, &FP);
        ec_mul(&a, &s, &p);
        ec_mul(&b, &e, &G_PT);
        ec_add(&y, &a, &b);
        if (y.inf) continue;
        mont_to(&yx, &y.x, &FP);
        u256_to_bytes(yxb, &yx);
        mt_sha256(yxb, sizeof(yxb), hh);
        if (memcmp(hh, witness, 16) == 0) return 1;
    }
    return 0;
}

/* True when the 64-byte stored licence already is a valid signature for
 * licval.  The mode role uses this to keep an installed licence instead of
 * re-signing it on every boot: RouterOS treats a rewritten licence as a new
 * software key and reboots to activate it, so regenerating it each boot puts
 * the device into a reboot loop. */
static int stored_licence_valid(const u8 stored[64], const u8 licval[16]) {
    u8 derived[16];
    u256 pubx;

    mt_transform(derived, stored);
    if (memcmp(derived, licval, sizeof(derived)) != 0)
        return 0;
    load_public_x(&pubx);
    return kcdsa_verify(licval, stored + 16, &pubx, 1);
}

/* ------------------------------------------------------------------------- */
/* 10. Licence-value derivation for the two modes                            */
/* ------------------------------------------------------------------------- */

static const u8 CHR_TAIL[8] = {0x00, 0x57, 0x86, 0xf4, 0x03, 0x00, 0x00, 0x00};

/* 32 hex digits (with or without '-') -> 16 bytes.  A failed/empty read
 * leaves a zero-filled 16-byte buffer, exactly like the original. */
static void parse_uuid(u8 out[16], const char *text) {
    u8 nib[32];
    size_t n = 0;
    memset(out, 0, 16);
    for (const char *p = text; *p && n < 32; p++) {
        int v = hex_nibble((unsigned char)*p);
        if (v >= 0) nib[n++] = (u8)v;
    }
    for (size_t i = 0; i + 1 < n; i += 2)
        out[i / 2] = (u8)((nib[i] << 4) | nib[i + 1]);
}

static void chr_licval(u8 licval[16], const char *uuid_text,
                       const u8 software_id[16]) {
    u8 uuid[16], buf[32], h[32];
    parse_uuid(uuid, uuid_text);
    for (int i = 0; i + 1 < 16; i += 2) {
        buf[i] = uuid[i + 1];
        buf[i + 1] = uuid[i];
    }
    memcpy(buf + 16, software_id, 16);
    mt_sha256(buf, sizeof(buf), h);
    memcpy(licval, h, 8);
    memcpy(licval + 8, CHR_TAIL, 8);
}

static void x86_licval(u8 licval[16], const char *serial) {
    u64 v = swid_decode(serial);
    memset(licval, 0, 16);
    for (int i = 0; i < 6; i++) licval[i] = (u8)(v >> (8 * i));
    licval[6] = 0x06;
    licval[7] = 0x16;
}

/* ------------------------------------------------------------------------- */
/* 11. Device configuration blob                                             */
/* ------------------------------------------------------------------------- */

#define CONFIG_SIZE 512
#define OFF_SWID 0x100
#define OFF_LIC  0x110
#define OFF_MODE 0x150

#define IOCTL_SIZE  0x4601
#define IOCTL_READ  0x90004602
#define IOCTL_WRITE 0x50004603

static const char *env_or(const char *name, const char *def) {
    const char *v = getenv(name);
    return (v != NULL && *v != '\0') ? v : def;
}

static u16 swid_checksum(const u8 id[16]) {
    u32 total = 0;
    u16 chk, hw;
    u8 h[32];

    for (int i = 0; i < 10; i += 2)
        total += (u32)id[i] | ((u32)id[i + 1] << 8);
    chk = (total != 0) ? (u16)~total : (u16)0xFFFF;
    mt_sha256(id, 10, h);
    hw = (u16)((u16)h[0] | ((u16)h[1] << 8));
    if (hw == 0) hw = 7919;
    return (u16)(chk ^ hw);
}

static int swid_valid(const u8 id[16]) {
    u16 stored = (u16)((u16)id[10] | ((u16)id[11] << 8));
    return stored == swid_checksum(id);
}

static void generate_swid(u8 id[16]) {
    u16 c;
    if (!rand_bytes(id, 10)) {
        fprintf(stderr, "keygen: cannot read random bytes\n");
        exit(1);
    }
    memset(id + 10, 0, 6);
    c = swid_checksum(id);
    id[10] = (u8)c;
    id[11] = (u8)(c >> 8);
}

/* Read the config from /dev/flash (custom ioctls), falling back to the first
 * 512 bytes of /dev/root-disk.  Returns a malloc'd buffer and its length. */
static u8 *read_config(size_t *out_len) {
    const char *flash = env_or("KEYGEN_FLASH", "/dev/flash");
    const char *disk  = env_or("KEYGEN_DISK", "/dev/root-disk");
    int fd = open(flash, O_RDONLY | O_LARGEFILE);

    if (fd >= 0) {
        long size = (long)ioctl(fd, (int)IOCTL_SIZE, 0);
        if (size >= 256 && size <= 0x4000) {
            size_t n = (size_t)size;
            u8 *buf;
            if (n < CONFIG_SIZE) n = CONFIG_SIZE; /* we touch 0x151 bytes */
            buf = (u8 *)calloc(1, n);
            if (buf != NULL) {
                if (ioctl(fd, (int)IOCTL_READ, buf) == 0) {
                    close(fd);
                    *out_len = n;
                    return buf;
                }
                free(buf);
            }
        }
        close(fd);
    }

    {
        u8 *buf = (u8 *)calloc(1, CONFIG_SIZE);
        if (buf == NULL) {
            fprintf(stderr, "keygen: out of memory\n");
            exit(1);
        }
        fd = open(disk, O_RDONLY | O_LARGEFILE);
        if (fd >= 0) {
            size_t got = 0;
            while (got < CONFIG_SIZE) {
                ssize_t r = read(fd, buf + got, CONFIG_SIZE - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
            close(fd);
        }
        *out_len = CONFIG_SIZE;
        return buf;
    }
}

/* Write the blob back through the flash ioctl and mirror it to the disk so
 * the licence survives a reboot. */
static void write_config(const u8 *data, size_t len) {
    const char *flash = env_or("KEYGEN_FLASH", "/dev/flash");
    const char *disk  = env_or("KEYGEN_DISK", "/dev/root-disk");
    int fd = open(flash, O_RDONLY | O_LARGEFILE);

    if (fd >= 0) {
        ioctl(fd, (int)IOCTL_WRITE, (void *)data);
        close(fd);
    }

    if (len > CONFIG_SIZE) len = CONFIG_SIZE;
    fd = open(disk, O_RDWR | O_LARGEFILE);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t w = write(fd, data + off, len - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        fsync(fd);
        close(fd);
    }
}

/* ------------------------------------------------------------------------- */
/* 12. External helpers                                                      */
/* ------------------------------------------------------------------------- */

/* Read /sys/class/dmi/id/product_uuid (or whatever KEYGEN_UUID points at). */
static void read_uuid_file(char *out, size_t outsz) {
    const char *path = env_or("KEYGEN_UUID", "/sys/class/dmi/id/product_uuid");
    int fd = open(path, O_RDONLY);
    size_t used = 0;
    out[0] = '\0';
    if (fd < 0) return;
    while (used + 1 < outsz) {
        ssize_t r = read(fd, out + used, outsz - 1 - used);
        if (r <= 0) break;
        used += (size_t)r;
    }
    out[used] = '\0';
    close(fd);
}

/* Run /nova/bin/keyman --software-id and return its last non-empty line. */
static void keyman_software_id(char *out, size_t outsz) {
    const char *path = env_or("KEYGEN_KEYMAN", "/nova/bin/keyman");
    int fds[2];
    char buf[1024];
    size_t used = 0;
    pid_t pid;

    out[0] = '\0';
    if (pipe(fds) != 0) return;

    pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        int devnull;
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(fds[1]);
        {
            char *argv[3];
            argv[0] = (char *)path;
            argv[1] = (char *)"--software-id";
            argv[2] = NULL;
            execv(path, argv);
        }
        _exit(127);
    }

    close(fds[1]);
    while (used < sizeof(buf) - 1) {
        ssize_t r = read(fds[0], buf + used, sizeof(buf) - 1 - used);
        if (r <= 0) break;
        used += (size_t)r;
    }
    buf[used] = '\0';
    close(fds[0]);
    waitpid(pid, NULL, 0);

    /* \r is a line separator too; keep the last line that is not all blanks */
    {
        const char *last = NULL;
        size_t lastlen = 0;
        const char *p = buf;
        while (*p) {
            const char *e = p;
            while (*e && *e != '\n' && *e != '\r') e++;
            {
                const char *s = p, *t = e;
                while (s < t && (*s == ' ' || *s == '\t' || *s == '\v' ||
                                 *s == '\f')) s++;
                while (t > s && (t[-1] == ' ' || t[-1] == '\t' || t[-1] == '\v' ||
                                 t[-1] == '\f')) t--;
                if (t > s) { last = s; lastlen = (size_t)(t - s); }
            }
            if (!*e) break;
            p = e + 1;
        }
        if (last != NULL) {
            if (lastlen > outsz - 1) lastlen = outsz - 1;
            memcpy(out, last, lastlen);
            out[lastlen] = '\0';
        }
    }
}

/* ------------------------------------------------------------------------- */
/* 13. Terminal output (matches the original byte for byte)                  */
/* ------------------------------------------------------------------------- */

#define C_RESET "\x1b[0m"
#define C_BLUE  "\x1b[1;34m"
#define C_CYAN  "\x1b[1;36m"
#define C_RED   "\x1b[1;31m"
#define C_GREEN "\x1b[1;32m"

static void print_license(const char *system_id, const u8 licval[16],
                          const u256 *d) {
    u8 decoded[64];
    char enc[128];
    size_t n, half;

    sign_licval(decoded, licval, d);
    mt_b64_encode(enc, decoded, sizeof(decoded), 1);
    n = strlen(enc);
    half = (n + 1) / 2;

    printf(C_BLUE "System ID: " C_CYAN "%s" C_RESET "\n", system_id);
    printf(C_BLUE "License Key:" C_RESET "\n");
    printf(C_CYAN "%.*s" C_RESET "\n", (int)half, enc);
    printf(C_CYAN "%s" C_RESET "\n", enc + half);
    printf(C_GREEN "RouterOS is now licensed" C_RESET "\n");
}

/* ------------------------------------------------------------------------- */
/* 14. The three entry points                                                */
/* ------------------------------------------------------------------------- */

static void run_generate(void) {
    size_t cfg_len;
    u8 *cfg = read_config(&cfg_len);
    u8 licval[16];
    char system_id[256];
    u256 d;

    if (!swid_valid(cfg + OFF_SWID)) {
        generate_swid(cfg + OFF_SWID);
        write_config(cfg, cfg_len);
    }

    if (cfg[OFF_MODE] == 1) {
        char uuid[512];
        read_uuid_file(uuid, sizeof(uuid));
        chr_licval(licval, uuid, cfg + OFF_SWID);
        mt_b64_encode(system_id, licval, 8, 0);
    } else {
        keyman_software_id(system_id, sizeof(system_id));
        x86_licval(licval, system_id);
    }

    load_private_key(&d);
    if (stored_licence_valid(cfg + OFF_LIC, licval)) {
        /* keep the installed licence (see stored_licence_valid) */
    } else {
        u8 decoded[64];
        sign_licval(decoded, licval, &d);
        memcpy(cfg + OFF_LIC, decoded, sizeof(decoded));
        write_config(cfg, cfg_len);
    }
    print_license(system_id, licval, &d);
    free(cfg);
}

static void run_mode(int chr_mode) {
    size_t cfg_len;
    u8 *cfg = read_config(&cfg_len);
    char ans[64];

    if (!swid_valid(cfg + OFF_SWID)) generate_swid(cfg + OFF_SWID);
    cfg[OFF_MODE] = chr_mode ? 1 : 0;
    write_config(cfg, cfg_len);
    printf("RouterOS has been set to " C_RED "%s" C_RESET " mode\n",
           chr_mode ? "chr" : "x86");
    printf("Reboot your device [Y/n]: ");
    fflush(stdout);

    ans[0] = '\0';
    if (scanf("%63s", ans) != 1) ans[0] = '\0';
    if (!((ans[0] == 'n' || ans[0] == 'N') && ans[1] == '\0')) {
        pid_t pid = fork();
        if (pid == 0) {
            execlp("reboot", "reboot", "-f", (char *)NULL);
            _exit(127);
        }
        if (pid > 0) waitpid(pid, NULL, 0);
    }
    free(cfg);
}

/* ------------------------------------------------------------------------- */
/* 15. Self test (not part of the original)                                  */
/* ------------------------------------------------------------------------- */

static int st_ok = 1;

static void check(const char *name, int cond) {
    printf("  [%s] %s\n", cond ? "ok" : "!!", name);
    if (!cond) st_ok = 0;
}

static void hexstr(char *out, const u8 *b, size_t n) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = '\0';
}

static int selftest(void) {
    u8 v[16], stored[16], licval[16], sig[48], h[32], obuf[32];
    char a[160];
    u256 d, pubx;
    pt p;

    crypto_init();

    /* transforms and hashes */
    for (int i = 0; i < 16; i++) v[i] = (u8)i;
    mt_transform_rev(stored, v);
    mt_transform(licval, stored);
    check("MT_Transform/Rev round trip", memcmp(licval, v, 16) == 0);

    mt_b64_encode(a, v, 16, 1);
    check("MT-base64 known answer", strcmp(a, "AEgADQQBGcACJowCM0gDPA==") == 0);
    memset(stored, 0, sizeof(stored));
    check("MT-base64 round trip",
          mt_b64_decode(stored, sizeof(stored), a) == 16 &&
          memcmp(stored, v, 16) == 0);

    {
        static const u8 sample[16] = {
            0x15, 0x12, 0x06, 0xfa, 0x4f, 0xcb, 0x21, 0x40,
            0xd4, 0x8c, 0xc4, 0x27, 0xd5, 0x78, 0xec, 0xd0};
        mt_transform(licval, sample);
        hexstr(a, licval, 16);
        check("MT_Transform known answer",
              strcmp(a, "d8d170a64c0006010000000000000000") == 0);
        mt_sha256(licval, 16, h);
        hexstr(a, h, 32);
        check("MT_SHA256 known answer",
              strcmp(a, "c4bcfeb4cc6d0daa4088381b68ba10fde31a2f10f929ca908017adaf77e1593f") == 0);
    }

    /* field arithmetic */
    {
        u256 inv, prod, oneM, t;

        t = U256_ONE;
        mont_from(&oneM, &t, &FN);

        /* known answers, then a round trip on both moduli */
        t = U256_ZERO; t.v[0] = 12345;
        mont_from(&t, &t, &FP);
        mont_inv(&inv, &t, &FP);
        mont_to(&inv, &inv, &FP);
        u256_to_bytes(obuf, &inv);
        hexstr(a, obuf, 32);
        check("inverse mod p (known answer)",
              strcmp(a, "295e499ea7d5c9d3f3a2becfce63cb30474f9917fe3b4b74d80a9dc35fa6f153") == 0);

        t = U256_ZERO; t.v[0] = 67890;
        mont_from(&t, &t, &FN);
        mont_inv(&inv, &t, &FN);
        mont_to(&inv, &inv, &FN);
        u256_to_bytes(obuf, &inv);
        hexstr(a, obuf, 32);
        check("inverse mod n (known answer)",
              strcmp(a, "8cade48e84b8982fb35aa1359e564a5c40e3833037fa566bffd435ce59dc8e01") == 0);

        t = U256_ZERO; t.v[0] = 12345;
        mont_from(&t, &t, &FP);
        mont_inv(&inv, &t, &FP);
        mont_mul(&prod, &t, &inv, &FP);
        check("a * a^-1 == 1 mod p", u256_cmp(&prod, &ONE_MONT_P) == 0);

        t = U256_ZERO; t.v[0] = 67890;
        mont_from(&t, &t, &FN);
        mont_inv(&inv, &t, &FN);
        mont_mul(&prod, &t, &inv, &FN);
        check("a * a^-1 == 1 mod n", u256_cmp(&prod, &oneM) == 0);
    }

    /* curve: known multiples of the generator */
    {
        static const struct { int k; const char *xhex; } kat[] = {
            {2, "fb4e68dd9c46ae5c5c0b351eed5c3f8f1471157d680c75d9b7f17318d542d320"},
            {3, "123c71fbaf030ac059081c62674e82f864ba1bc2914d5345e6ab576d1abc121c"},
            {5, "877c4978577d530dcb491d58bcc9cba87f9e075e6e02c003f27aee503cecb641"},
        };
        int ok = 1;
        for (size_t i = 0; i < sizeof(kat) / sizeof(kat[0]); i++) {
            u256 k = U256_ZERO, px;
            k.v[0] = (u32)kat[i].k;
            ec_mul(&p, &k, &G_PT);
            mont_to(&px, &p.x, &FP);
            u256_to_bytes(obuf, &px);
            hexstr(a, obuf, 32);
            if (strcmp(a, kat[i].xhex) != 0) ok = 0;
        }
        check("k*G x-coordinates", ok);
    }

    /* embedded key pair */
    load_private_key(&d);
    load_public_x(&pubx);
    ec_mul(&p, &d, &G_PT);
    {
        u256 px, py;
        mont_to(&px, &p.x, &FP);
        mont_to(&py, &p.y, &FP);
        check("private key reproduces public key", u256_cmp(&px, &pubx) == 0);
        check("d*G has the device's (odd) y", !p.inf && (py.v[0] & 1u));
    }
    printf("  [i] public key : %s\n", license_public_hex);

    /* software id */
    {
        u8 sid[16];
        generate_swid(sid);
        check("software id checksum", swid_valid(sid));
        check("serial decode", swid_decode("ABCD-EFGH") == 677531444044ULL);
    }

    /* licence values */
    {
        static const u8 sample_swid[16] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x73, 0xa0, 0x00, 0x00, 0x00, 0x00};
        u8 lv[16], zero_h[32], buf[32];
        chr_licval(lv, "00112233-4455-6677-8899-aabbccddeeff", sample_swid);
        hexstr(a, lv, 16);
        check("CHR licence value (sample)",
              strcmp(a, "db4e0997ab453e0c005786f403000000") == 0);
        mt_b64_encode(a, lv, 8, 0);
        check("CHR System ID", strcmp(a, "b7UCXuaR+wA") == 0);

        memset(buf, 0, 16);
        memcpy(buf + 16, sample_swid, 16);
        mt_sha256(buf, 32, zero_h);
        chr_licval(lv, "", sample_swid);
        check("CHR empty-UUID uses 16 zero bytes",
              memcmp(lv, zero_h, 8) == 0);

        x86_licval(lv, "ABCD-EFGH");
        hexstr(a, lv, 16);
        check("x86 licence value (sample)",
              strcmp(a, "4c6305c09d0006160000000000000000") == 0);
    }

    /* deterministic EC-KCDSA known answer (fixed scalar, nonce = 1) */
    {
        static const u8 lv[16] = {
            0xd8, 0xd1, 0x70, 0xa6, 0x4c, 0x00, 0x06, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        u256 td = U256_ZERO, one = U256_ONE;
        td.v[0] = 0xeb1f0ad2u; /* 12345678901234567890 = 0xab54a98ceb1f0ad2 */
        td.v[1] = 0xab54a98cu;
        if (!kcdsa_sign(sig, lv, &td, &one)) {
            check("EC-KCDSA known answer", 0);
        } else {
            hexstr(a, sig, 48);
            check("EC-KCDSA known answer",
                  strcmp(a, "d0f37d0277d7f5dc34184b53d4d16cbca5477c62618163a6001065f058fe7c48"
                            "1847af04b4bde811f007120471e94b00") == 0);
        }
        {
            u8 decoded[64];
            mt_transform_rev(decoded, lv);
            memcpy(decoded + 16, sig, 48);
            mt_b64_encode(a, decoded, 64, 1);
            check("licence text known answer",
                  strcmp(a, "VIhB6/0yhAE1MS8JVjH7QD989JwdXXP30gxSTRd0sxbpHxnYhF4YmCAElBPW+zHSY"
                            "c0rEQbvoHB8HIBBxl+SAA==") == 0);
        }
    }

    /* sign with the embedded key and verify both ways */
    {
        static const u8 sample[16] = {
            0x15, 0x12, 0x06, 0xfa, 0x4f, 0xcb, 0x21, 0x40,
            0xd4, 0x8c, 0xc4, 0x27, 0xd5, 0x78, 0xec, 0xd0};
        mt_transform(licval, sample);
        if (!kcdsa_sign(sig, licval, &d, NULL)) {
            check("licence sign", 0);
        } else {
            check("licence sign/verify", kcdsa_verify(licval, sig, &pubx, 0));
            check("licence verifies on the device point",
                  kcdsa_verify(licval, sig, &pubx, 1));
        }
    }

    printf("selftest: %s\n", st_ok ? "PASS" : "FAIL");
    return st_ok ? 0 : 1;
}

/* ------------------------------------------------------------------------- */
/* 16. main                                                                  */
/* ------------------------------------------------------------------------- */

/* The binary has two roles, chosen by argv[0]:
 *
 *   /nova/bin/mode   the device role (patch.py installs it there): generate
 *                    and install the licence, then hand over to the
 *                    key-patched stock tool at /nova/bin/mode2;
 *   anything else    the plain keygen CLI (see the file header).
 *
 * KEYGEN_MODE2 overrides the hand-off path for testing.
 */
static int run_mode_role(int argc, char **argv) {
    const char *mode2 = env_or("KEYGEN_MODE2", "/nova/bin/mode2");

    if (argc > 1 && strcmp(argv[1], "--selftest") == 0)
        return selftest();

    run_generate();
    fflush(NULL);                       /* don't lose the licence output on exec */
    execv(mode2, argv);
    fprintf(stderr, "keygen: cannot execute %s\n", mode2);
    return 1;
}

int main(int argc, char **argv) {
    const char *base = strrchr((argv[0] != NULL) ? argv[0] : "", '/');
    base = (base != NULL) ? base + 1 : ((argv[0] != NULL) ? argv[0] : "");

    crypto_init();
    if (strcmp(base, "mode") == 0)
        return run_mode_role(argc, argv);

    if (argc > 1) {
        if (strcmp(argv[1], "chr") == 0) { run_mode(1); return 0; }
        if (strcmp(argv[1], "x86") == 0) { run_mode(0); return 0; }
        if (strcmp(argv[1], "--selftest") == 0) return selftest();
    }
    run_generate();
    return 0;
}
