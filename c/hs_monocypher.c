#include "hs_monocypher.h"
#include <stdlib.h>

void hs_monocypher_finalizer_aead_ctx(crypto_aead_ctx * ctx) {
  crypto_wipe(ctx, sizeof(*ctx));
}

void hs_monocypher_finalizer_blake2b_ctx(crypto_blake2b_ctx * ctx) {
  crypto_wipe(ctx, sizeof(*ctx));
}

void hs_monocypher_finalizer_poly1305_ctx(crypto_poly1305_ctx * ctx){
  crypto_wipe(ctx, sizeof(*ctx));
}

void hs_monocypher_finalizer_sha512_ctx(crypto_sha512_ctx * ctx) {
  crypto_wipe(ctx, sizeof(*ctx));
}

void hs_monocypher_finalizer_sha512_hmac_ctx(crypto_sha512_hmac_ctx * ctx) {
  crypto_wipe(ctx, sizeof(*ctx));
}

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
    uint32_t ad_size) {
  crypto_argon2_config config = {
    .algorithm = algorithm,
    .nb_blocks = nb_blocks,
    .nb_passes = nb_passes,
    .nb_lanes  = nb_lanes
  };
  crypto_argon2_inputs inputs = {
    .pass      = pass,
    .salt      = salt,
    .pass_size = pass_size,
    .salt_size = salt_size
  };
  crypto_argon2_extras extras = {
    .key      = key,
    .ad       = ad,
    .key_size = key_size,
    .ad_size  = ad_size
  };
  crypto_argon2(hash, hash_size, work_area, config, inputs, extras);
  // Wiping these is not strictly necessary, since they hold only
  // pointers, sizes, etc. We do it anyway, just in case.
  crypto_wipe(&config, sizeof(config));
  crypto_wipe(&inputs, sizeof(inputs));
  crypto_wipe(&extras, sizeof(extras));
}

