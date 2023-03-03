#pragma once

#include <monocypher.h>
#include <monocypher-ed25519.h>

void hs_monocypher_finalizer_aead_ctx(crypto_aead_ctx * ctx);
void hs_monocypher_finalizer_blake2b_ctx(crypto_blake2b_ctx * ctx);
void hs_monocypher_finalizer_poly1305_ctx(crypto_poly1305_ctx * ctx);
void hs_monocypher_finalizer_sha512_ctx(crypto_sha512_ctx * ctx);
void hs_monocypher_finalizer_sha512_hmac_ctx(crypto_sha512_hmac_ctx * ctx);

void hs_monocypher_crypto_argon2(
    uint8_t * hash,
    uint32_t hash_size,
    void * work_area,
    uint32_t algorithm,
    uint32_t nb_blocks,
    uint32_t nb_passes,
    uint32_t nb_lanes,
    const uint8_t * pass,
    uint32_t pass_size,
    const uint8_t * salt,
    uint32_t salt_size,
    const uint8_t * key,
    uint32_t key_size,
    const uint8_t * ad,
    uint32_t ad_size);
