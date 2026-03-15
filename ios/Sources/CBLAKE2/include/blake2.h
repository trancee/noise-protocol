#ifndef CBLAKE2_H
#define CBLAKE2_H

#include <stdint.h>
#include <stddef.h>

// ---------------------------------------------------------------------------
// BLAKE2s (32-byte hash, 64-byte block)
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint8_t  buf[64];
    size_t   buflen;
    uint8_t  outlen;
} cblake2s_state;

int cblake2s_init(cblake2s_state *S, size_t outlen);
int cblake2s_update(cblake2s_state *S, const void *in, size_t inlen);
int cblake2s_final(cblake2s_state *S, void *out, size_t outlen);

/// One-shot BLAKE2s hash.
int cblake2s(void *out, size_t outlen, const void *in, size_t inlen);

/// HMAC-BLAKE2s (RFC 2104 with BLAKE2s as the hash function).
/// Always outputs 32 bytes.
int cblake2s_hmac(void *out,
                  const void *key, size_t keylen,
                  const void *data, size_t datalen);

/// HKDF using HMAC-BLAKE2s. Outputs 2 values of 32 bytes each.
int cblake2s_hkdf2(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2);

/// HKDF using HMAC-BLAKE2s. Outputs 3 values of 32 bytes each.
int cblake2s_hkdf3(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2, void *output3);

// ---------------------------------------------------------------------------
// BLAKE2b (64-byte hash, 128-byte block)
// ---------------------------------------------------------------------------

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint8_t  buf[128];
    size_t   buflen;
    uint8_t  outlen;
} cblake2b_state;

int cblake2b_init(cblake2b_state *S, size_t outlen);
int cblake2b_update(cblake2b_state *S, const void *in, size_t inlen);
int cblake2b_final(cblake2b_state *S, void *out, size_t outlen);

/// One-shot BLAKE2b hash.
int cblake2b(void *out, size_t outlen, const void *in, size_t inlen);

/// HMAC-BLAKE2b (RFC 2104 with BLAKE2b as the hash function).
/// Always outputs 64 bytes.
int cblake2b_hmac(void *out,
                  const void *key, size_t keylen,
                  const void *data, size_t datalen);

/// HKDF using HMAC-BLAKE2b. Outputs 2 values of 64 bytes each.
int cblake2b_hkdf2(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2);

/// HKDF using HMAC-BLAKE2b. Outputs 3 values of 64 bytes each.
int cblake2b_hkdf3(const void *chaining_key, size_t ck_len,
                   const void *input_key_material, size_t ikm_len,
                   void *output1, void *output2, void *output3);

#endif /* CBLAKE2_H */
