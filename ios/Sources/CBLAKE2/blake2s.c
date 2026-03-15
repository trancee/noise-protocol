// BLAKE2s implementation (RFC 7693) optimized for Apple Silicon.
// 32-bit variant: 10 rounds, 64-byte blocks, up to 32-byte digest.

#include "blake2.h"
#include <string.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

static const uint32_t blake2s_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] = {
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

static inline uint32_t load32(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0]      ) | ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w      ); p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}

static inline uint32_t rotr32(uint32_t w, unsigned c) {
    return (w >> c) | (w << (32 - c));
}

// ---------------------------------------------------------------------------
// Compression — fully unrolled G and rounds for best codegen
// ---------------------------------------------------------------------------

#define G_S(r, i, a, b, c, d)                           \
    do {                                                 \
        a = a + b + m[blake2s_sigma[r][2*i+0]];         \
        d = rotr32(d ^ a, 16);                           \
        c = c + d;                                       \
        b = rotr32(b ^ c, 12);                           \
        a = a + b + m[blake2s_sigma[r][2*i+1]];         \
        d = rotr32(d ^ a, 8);                            \
        c = c + d;                                       \
        b = rotr32(b ^ c, 7);                            \
    } while (0)

#define ROUND_S(r)                                       \
    do {                                                 \
        G_S(r, 0, v[ 0], v[ 4], v[ 8], v[12]);          \
        G_S(r, 1, v[ 1], v[ 5], v[ 9], v[13]);          \
        G_S(r, 2, v[ 2], v[ 6], v[10], v[14]);          \
        G_S(r, 3, v[ 3], v[ 7], v[11], v[15]);          \
        G_S(r, 4, v[ 0], v[ 5], v[10], v[15]);          \
        G_S(r, 5, v[ 1], v[ 6], v[11], v[12]);          \
        G_S(r, 6, v[ 2], v[ 7], v[ 8], v[13]);          \
        G_S(r, 7, v[ 3], v[ 4], v[ 9], v[14]);          \
    } while (0)

static void blake2s_compress(cblake2s_state *S,
                             const uint8_t block[64],
                             int last) {
    uint32_t m[16];
    uint32_t v[16];

    for (int i = 0; i < 16; ++i)
        m[i] = load32(block + i * 4);

    for (int i = 0; i < 8; ++i)
        v[i] = S->h[i];

    v[ 8] = blake2s_IV[0];
    v[ 9] = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = S->t[0] ^ blake2s_IV[4];
    v[13] = S->t[1] ^ blake2s_IV[5];
    v[14] = last ? (blake2s_IV[6] ^ 0xFFFFFFFFUL) : blake2s_IV[6];
    v[15] = blake2s_IV[7];

    ROUND_S(0); ROUND_S(1); ROUND_S(2); ROUND_S(3); ROUND_S(4);
    ROUND_S(5); ROUND_S(6); ROUND_S(7); ROUND_S(8); ROUND_S(9);

    for (int i = 0; i < 8; ++i)
        S->h[i] ^= v[i] ^ v[i + 8];
}

// ---------------------------------------------------------------------------
// Streaming API
// ---------------------------------------------------------------------------

static inline void blake2s_increment_counter(cblake2s_state *S, uint32_t inc) {
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

int cblake2s_init(cblake2s_state *S, size_t outlen) {
    if (outlen == 0 || outlen > 32) return -1;
    memset(S, 0, sizeof(*S));
    for (int i = 0; i < 8; ++i)
        S->h[i] = blake2s_IV[i];
    // Parameter block: digest_length=outlen, key_length=0, fanout=1, depth=1
    S->h[0] ^= 0x01010000UL ^ (uint32_t)outlen;
    S->outlen = (uint8_t)outlen;
    return 0;
}

int cblake2s_update(cblake2s_state *S, const void *pin, size_t inlen) {
    if (inlen == 0) return 0;
    const uint8_t *in = (const uint8_t *)pin;

    // Fill buffer
    if (S->buflen > 0) {
        size_t left = 64 - S->buflen;
        size_t fill = inlen < left ? inlen : left;
        memcpy(S->buf + S->buflen, in, fill);
        S->buflen += fill;
        in += fill;
        inlen -= fill;

        if (S->buflen == 64 && inlen > 0) {
            blake2s_increment_counter(S, 64);
            blake2s_compress(S, S->buf, 0);
            S->buflen = 0;
        }
    }

    // Process full blocks (always keep at least 1 byte for final)
    while (inlen > 64) {
        blake2s_increment_counter(S, 64);
        blake2s_compress(S, in, 0);
        in += 64;
        inlen -= 64;
    }

    // Buffer remaining
    if (inlen > 0) {
        memcpy(S->buf + S->buflen, in, inlen);
        S->buflen += inlen;
    }
    return 0;
}

int cblake2s_final(cblake2s_state *S, void *out, size_t outlen) {
    if (outlen != S->outlen) return -1;

    blake2s_increment_counter(S, (uint32_t)S->buflen);
    memset(S->buf + S->buflen, 0, 64 - S->buflen);
    blake2s_compress(S, S->buf, 1);

    uint8_t buffer[32];
    for (int i = 0; i < 8; ++i)
        store32(buffer + i * 4, S->h[i]);
    memcpy(out, buffer, outlen);
    return 0;
}

// ---------------------------------------------------------------------------
// One-shot hash
// ---------------------------------------------------------------------------

int cblake2s(void *out, size_t outlen, const void *in, size_t inlen) {
    cblake2s_state S;
    if (cblake2s_init(&S, outlen) < 0) return -1;
    if (cblake2s_update(&S, in, inlen) < 0) return -1;
    return cblake2s_final(&S, out, outlen);
}

// ---------------------------------------------------------------------------
// HMAC-BLAKE2s (RFC 2104) — zero heap allocation
// ---------------------------------------------------------------------------

int cblake2s_hmac(void *out,
                  const void *key, size_t keylen,
                  const void *data, size_t datalen) {
    uint8_t k[64];
    uint8_t pad[64];
    uint8_t inner_hash[32];
    cblake2s_state S;

    // Prepare key
    memset(k, 0, 64);
    if (keylen > 64) {
        cblake2s(k, 32, key, keylen);
    } else {
        memcpy(k, key, keylen);
    }

    // Inner hash: BLAKE2s(ipad || data)
    for (int i = 0; i < 64; ++i)
        pad[i] = k[i] ^ 0x36;
    cblake2s_init(&S, 32);
    cblake2s_update(&S, pad, 64);
    cblake2s_update(&S, data, datalen);
    cblake2s_final(&S, inner_hash, 32);

    // Outer hash: BLAKE2s(opad || inner_hash)
    for (int i = 0; i < 64; ++i)
        pad[i] = k[i] ^ 0x5c;
    cblake2s_init(&S, 32);
    cblake2s_update(&S, pad, 64);
    cblake2s_update(&S, inner_hash, 32);
    cblake2s_final(&S, out, 32);

    return 0;
}

// ---------------------------------------------------------------------------
// HKDF (2 outputs)
// ---------------------------------------------------------------------------

int cblake2s_hkdf2(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2) {
    uint8_t temp_key[32];
    uint8_t buf[33]; // max: 32-byte output + 1-byte counter

    // temp_key = HMAC(chaining_key, input_key_material)
    cblake2s_hmac(temp_key, chaining_key, ck_len, input_key_material, ikm_len);

    // output1 = HMAC(temp_key, 0x01)
    uint8_t counter = 0x01;
    cblake2s_hmac(output1, temp_key, 32, &counter, 1);

    // output2 = HMAC(temp_key, output1 || 0x02)
    memcpy(buf, output1, 32);
    buf[32] = 0x02;
    cblake2s_hmac(output2, temp_key, 32, buf, 33);

    return 0;
}

// ---------------------------------------------------------------------------
// HKDF (3 outputs)
// ---------------------------------------------------------------------------

int cblake2s_hkdf3(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2, void *output3) {
    uint8_t temp_key[32];
    uint8_t buf[33];

    cblake2s_hmac(temp_key, chaining_key, ck_len, input_key_material, ikm_len);

    uint8_t counter = 0x01;
    cblake2s_hmac(output1, temp_key, 32, &counter, 1);

    memcpy(buf, output1, 32);
    buf[32] = 0x02;
    cblake2s_hmac(output2, temp_key, 32, buf, 33);

    memcpy(buf, output2, 32);
    buf[32] = 0x03;
    cblake2s_hmac(output3, temp_key, 32, buf, 33);

    return 0;
}
