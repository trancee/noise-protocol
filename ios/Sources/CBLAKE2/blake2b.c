// BLAKE2b implementation (RFC 7693) optimized for Apple Silicon.
// 64-bit variant: 12 rounds, 128-byte blocks, up to 64-byte digest.

#include "blake2.h"
#include <string.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static inline uint64_t load64(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[0]      ) | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void store64(void *dst, uint64_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w      ); p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
    p[4] = (uint8_t)(w >> 32); p[5] = (uint8_t)(w >> 40);
    p[6] = (uint8_t)(w >> 48); p[7] = (uint8_t)(w >> 56);
}

static inline uint64_t rotr64(uint64_t w, unsigned c) {
    return (w >> c) | (w << (64 - c));
}

// ---------------------------------------------------------------------------
// Compression — fully unrolled G and rounds
// ---------------------------------------------------------------------------

#define G_B(r, i, a, b, c, d)                                  \
    do {                                                        \
        a = a + b + m[blake2b_sigma[(r) % 10][2*i+0]];         \
        d = rotr64(d ^ a, 32);                                  \
        c = c + d;                                              \
        b = rotr64(b ^ c, 24);                                  \
        a = a + b + m[blake2b_sigma[(r) % 10][2*i+1]];         \
        d = rotr64(d ^ a, 16);                                  \
        c = c + d;                                              \
        b = rotr64(b ^ c, 63);                                  \
    } while (0)

#define ROUND_B(r)                                              \
    do {                                                        \
        G_B(r, 0, v[ 0], v[ 4], v[ 8], v[12]);                 \
        G_B(r, 1, v[ 1], v[ 5], v[ 9], v[13]);                 \
        G_B(r, 2, v[ 2], v[ 6], v[10], v[14]);                 \
        G_B(r, 3, v[ 3], v[ 7], v[11], v[15]);                 \
        G_B(r, 4, v[ 0], v[ 5], v[10], v[15]);                 \
        G_B(r, 5, v[ 1], v[ 6], v[11], v[12]);                 \
        G_B(r, 6, v[ 2], v[ 7], v[ 8], v[13]);                 \
        G_B(r, 7, v[ 3], v[ 4], v[ 9], v[14]);                 \
    } while (0)

static void blake2b_compress(cblake2b_state *S,
                             const uint8_t block[128],
                             int last) {
    uint64_t m[16];
    uint64_t v[16];

    for (int i = 0; i < 16; ++i)
        m[i] = load64(block + i * 8);

    for (int i = 0; i < 8; ++i)
        v[i] = S->h[i];

    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = S->t[0] ^ blake2b_IV[4];
    v[13] = S->t[1] ^ blake2b_IV[5];
    v[14] = last ? (blake2b_IV[6] ^ 0xFFFFFFFFFFFFFFFFULL) : blake2b_IV[6];
    v[15] = blake2b_IV[7];

    ROUND_B( 0); ROUND_B( 1); ROUND_B( 2); ROUND_B( 3);
    ROUND_B( 4); ROUND_B( 5); ROUND_B( 6); ROUND_B( 7);
    ROUND_B( 8); ROUND_B( 9); ROUND_B(10); ROUND_B(11);

    for (int i = 0; i < 8; ++i)
        S->h[i] ^= v[i] ^ v[i + 8];
}

// ---------------------------------------------------------------------------
// Streaming API
// ---------------------------------------------------------------------------

static inline void blake2b_increment_counter(cblake2b_state *S, uint64_t inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

int cblake2b_init(cblake2b_state *S, size_t outlen) {
    if (outlen == 0 || outlen > 64) return -1;
    memset(S, 0, sizeof(*S));
    for (int i = 0; i < 8; ++i)
        S->h[i] = blake2b_IV[i];
    S->h[0] ^= 0x01010000ULL ^ (uint64_t)outlen;
    S->outlen = (uint8_t)outlen;
    return 0;
}

int cblake2b_update(cblake2b_state *S, const void *pin, size_t inlen) {
    if (inlen == 0) return 0;
    const uint8_t *in = (const uint8_t *)pin;

    if (S->buflen > 0) {
        size_t left = 128 - S->buflen;
        size_t fill = inlen < left ? inlen : left;
        memcpy(S->buf + S->buflen, in, fill);
        S->buflen += fill;
        in += fill;
        inlen -= fill;

        if (S->buflen == 128 && inlen > 0) {
            blake2b_increment_counter(S, 128);
            blake2b_compress(S, S->buf, 0);
            S->buflen = 0;
        }
    }

    while (inlen > 128) {
        blake2b_increment_counter(S, 128);
        blake2b_compress(S, in, 0);
        in += 128;
        inlen -= 128;
    }

    if (inlen > 0) {
        memcpy(S->buf + S->buflen, in, inlen);
        S->buflen += inlen;
    }
    return 0;
}

int cblake2b_final(cblake2b_state *S, void *out, size_t outlen) {
    if (outlen != S->outlen) return -1;

    blake2b_increment_counter(S, (uint64_t)S->buflen);
    memset(S->buf + S->buflen, 0, 128 - S->buflen);
    blake2b_compress(S, S->buf, 1);

    uint8_t buffer[64];
    for (int i = 0; i < 8; ++i)
        store64(buffer + i * 8, S->h[i]);
    memcpy(out, buffer, outlen);
    return 0;
}

// ---------------------------------------------------------------------------
// One-shot hash
// ---------------------------------------------------------------------------

int cblake2b(void *out, size_t outlen, const void *in, size_t inlen) {
    cblake2b_state S;
    if (cblake2b_init(&S, outlen) < 0) return -1;
    if (cblake2b_update(&S, in, inlen) < 0) return -1;
    return cblake2b_final(&S, out, outlen);
}

// ---------------------------------------------------------------------------
// HMAC-BLAKE2b (RFC 2104) — zero heap allocation
// ---------------------------------------------------------------------------

int cblake2b_hmac(void *out,
                  const void *key, size_t keylen,
                  const void *data, size_t datalen) {
    uint8_t k[128];
    uint8_t pad[128];
    uint8_t inner_hash[64];
    cblake2b_state S;

    memset(k, 0, 128);
    if (keylen > 128) {
        cblake2b(k, 64, key, keylen);
    } else {
        memcpy(k, key, keylen);
    }

    // Inner hash: BLAKE2b(ipad || data)
    for (int i = 0; i < 128; ++i)
        pad[i] = k[i] ^ 0x36;
    cblake2b_init(&S, 64);
    cblake2b_update(&S, pad, 128);
    cblake2b_update(&S, data, datalen);
    cblake2b_final(&S, inner_hash, 64);

    // Outer hash: BLAKE2b(opad || inner_hash)
    for (int i = 0; i < 128; ++i)
        pad[i] = k[i] ^ 0x5c;
    cblake2b_init(&S, 64);
    cblake2b_update(&S, pad, 128);
    cblake2b_update(&S, inner_hash, 64);
    cblake2b_final(&S, out, 64);

    return 0;
}

// ---------------------------------------------------------------------------
// HKDF (2 outputs)
// ---------------------------------------------------------------------------

int cblake2b_hkdf2(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2) {
    uint8_t temp_key[64];
    uint8_t buf[65]; // 64-byte output + 1-byte counter

    cblake2b_hmac(temp_key, chaining_key, ck_len, input_key_material, ikm_len);

    uint8_t counter = 0x01;
    cblake2b_hmac(output1, temp_key, 64, &counter, 1);

    memcpy(buf, output1, 64);
    buf[64] = 0x02;
    cblake2b_hmac(output2, temp_key, 64, buf, 65);

    return 0;
}

// ---------------------------------------------------------------------------
// HKDF (3 outputs)
// ---------------------------------------------------------------------------

int cblake2b_hkdf3(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2, void *output3) {
    uint8_t temp_key[64];
    uint8_t buf[65];

    cblake2b_hmac(temp_key, chaining_key, ck_len, input_key_material, ikm_len);

    uint8_t counter = 0x01;
    cblake2b_hmac(output1, temp_key, 64, &counter, 1);

    memcpy(buf, output1, 64);
    buf[64] = 0x02;
    cblake2b_hmac(output2, temp_key, 64, buf, 65);

    memcpy(buf, output2, 64);
    buf[64] = 0x03;
    cblake2b_hmac(output3, temp_key, 64, buf, 65);

    return 0;
}
