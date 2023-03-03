#include "hs_monocypher.h"

{-# LANGUAGE CApiFFI #-}

-- | Low level bindings to the [monocypher](https://monocypher.org) C library.
--
-- [Version]
--
-- The Haskell library @monocypher@ version @A.B.C.D@ is compatible with the C
-- library @monocypher@ version @A.B.C@, which is shipped and compiled together
-- with this Haskell library. The @D@ part of the version number is the only
-- one we increment in the  Haskell library independently from the C library.
--
-- [License]
--
-- This module is dual-licensed the same way the @monocypher@ C library is.
-- Namely, you can choose the license you prefer among
-- [CC0-1.0](https://spdx.org/licenses/CC0-1.0.html) or
-- [BSD-2-Clause](https://spdx.org/licenses/BSD-2-Clause.html).
--
-- [Differences from the C library]
--
-- * The the @crypto_@ prefix is dropped from every name.
--
-- * The 'argon2' function takes all its parameters separately instead
-- of wrapping them in different structures like the C @crypto_argon2@ version
-- does. Also, the necessary @work_area@ is allocated automatically.
--
-- * The @crypto_aead_ctx@, @crypto_blake2b@ and @crypto_poly1305_ctx@ C
-- structures are opaque, represented in Haskell by 'AEAD_CTX',
-- 'BLAKE2B_CTX', etc.  They can be allocated with 'aead_ctx_malloc',
-- 'blake2b_ctx_malloc', etc.
--
-- * We export type-level constants for sizes and alignments used throughout
-- this module. The names of these constants are not official, in the sense
-- that the C library doesn't use any names for constants, and instead it
-- mentions numbers like @32@ or @64@ directly.
module Monocypher.C {--}
 ( -- * Utils
   verify16
 , verify32
 , verify64
   -- * Memory
 , wipe
   -- * Aead
 , aead_lock
 , aead_unlock
   -- ** Incremental
 , AEAD_CTX(..)
 , aead_ctx_malloc
 , aead_init_x
 , aead_init_djb
 , aead_init_ietf
 , aead_write
 , aead_read

   -- * BLAKE2b
 , blake2b
 , blake2b_keyed
   -- ** Incremental
 , BLAKE2B_CTX(..)
 , blake2b_ctx_malloc
 , blake2b_init
 , blake2b_keyed_init
 , blake2b_update
 , blake2b_final

   -- * Argon2
 , Argon2Algorithm
 , argon2

   -- * X25519
 , x25519_public_key
 , x25519
 , x25519_to_eddsa
 , x25519_inverse
 , x25519_dirty_small
 , x25519_dirty_fast

   -- ** Elligator
 , elligator_map
 , elligator_rev
 , elligator_key_pair

   -- * EdDSA
   --
   -- $eddsa
 , eddsa_key_pair
 , eddsa_sign
 , eddsa_check
 , eddsa_to_x25519
 , eddsa_trim_scalar
 , eddsa_reduce
 , eddsa_mul_add
 , eddsa_scalarbase
 , eddsa_check_equation

   -- * ChaCha20
 , chacha20_h
 , chacha20_djb
 , chacha20_ietf
 , chacha20_x

   -- * Poly1305
 , poly1305
   -- ** Incremental
 , POLY1305_CTX(..)
 , poly1305_ctx_malloc
 , poly1305_init
 , poly1305_update
 , poly1305_final

   -- * SHA512
 , sha512
   -- ** Incremental
 , SHA512_CTX(..)
 , sha512_ctx_malloc
 , sha512_init
 , sha512_update
 , sha512_final

   -- * HMAC-SHA512
 , sha512_hmac
   -- ** Incremental
 , SHA512_HMAC_CTX(..)
 , sha512_hmac_ctx_malloc
 , sha512_hmac_init
 , sha512_hmac_update
 , sha512_hmac_final

   -- * HKDF-SHA512
 , sha512_hkdf_expand
 , sha512_hkdf

   -- * Ed25519
   --
   -- $ed25519
 , ed25519_key_pair
 , ed25519_sign
 , ed25519_check

   -- * Ed25519ph
   --
   -- $ed25519ph
 , ed25519_ph_sign
 , ed25519_ph_check

   -- * Constants
 , AEAD_CTX_SIZE
 , AEAD_CTX_ALIGNMENT
 , BLAKE2B_HASH_MAX_SIZE
 , BLAKE2B_KEY_MAX_SIZE
 , BLAKE2B_CTX_SIZE
 , BLAKE2B_CTX_ALIGNMENT
 , X25519_POINT_SIZE
 , X25519_PUBLIC_KEY_SIZE
 , X25519_SECRET_KEY_SIZE
 , X25519_SHARED_SECRET_SIZE
 , EDDSA_POINT_SIZE
 , EDDSA_PUBLIC_KEY_SIZE
 , EDDSA_SECRET_KEY_SIZE
 , EDDSA_SEED_SIZE
 , EDDSA_SHARED_SECRET_SIZE
 , EDDSA_SIGNATURE_SIZE
 , CHACHA20_OUT_SIZE
 , CHACHA20_KEY_SIZE
 , CHACHA20_DJB_NONCE_SIZE
 , CHACHA20_IETF_NONCE_SIZE
 , CHACHA20_X_NONCE_SIZE
 , HCHACHA20_NONCE_SIZE
 , POLY1305_KEY_SIZE
 , POLY1305_MAC_SIZE
 , POLY1305_CTX_SIZE
 , POLY1305_CTX_ALIGNMENT
 , ELLIGATOR_HIDDEN_SIZE
 , ELLIGATOR_SEED_SIZE
 , SHA512_HASH_SIZE
 , SHA512_CTX_SIZE
 , SHA512_CTX_ALIGNMENT
 , SHA512_HMAC_CTX_SIZE
 , SHA512_HMAC_CTX_ALIGNMENT

 ) --}
 where

import Data.Bits (toIntegralSized)
import Data.Word (Word8, Word32, Word64)
import Foreign.Ptr (Ptr)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.Marshal.Array (copyArray)
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Storable (Storable(..))
import GHC.ForeignPtr (ForeignPtr, FinalizerPtr, addForeignPtrFinalizer,
  mallocForeignPtr, withForeignPtr)

--------------------------------------------------------------------------------

-- | See [@crypto_verify16()@](https://monocypher.org/manual/verify)
foreign import capi unsafe "monocypher.h crypto_verify16"
  verify16
    :: Ptr Word8 -- ^ @const uint8_t __a__[16]@.
    -> Ptr Word8 -- ^ @const uint8_t __b__[16]@.
    -> CInt      -- ^ @0@ if @a@ and @b@ are equal, @-1@ otherwise.

-- | See [@crypto_verify32()@](https://monocypher.org/manual/verify)
foreign import capi unsafe "monocypher.h crypto_verify32"
  verify32
    :: Ptr Word8 -- ^ @const uint8_t __a__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __b__[32]@.
    -> CInt      -- ^ @0@ if @a@ and @b@ are equal, @-1@ otherwise.

-- | See [@crypto_verify64()@](https://monocypher.org/manual/verify)
foreign import capi unsafe "monocypher.h crypto_verify64"
  verify64
    :: Ptr Word8 -- ^ @const uint8_t __a__[64]@.
    -> Ptr Word8 -- ^ @const uint8_t __b__[64]@.
    -> CInt      -- ^ @0@ if @a@ and @b@ are equal, @-1@ otherwise.

--------------------------------------------------------------------------------

-- | [@wipe@](https://monocypher.org/manual/wipe)
foreign import capi unsafe "monocypher.h crypto_wipe"
  wipe
    :: Ptr Word8 -- ^ @void * __secret__@.
    -> CSize     -- ^ @size_t size@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_aead_lock()@](https://monocypher.org/manual/aead)
foreign import capi unsafe "monocypher.h crypto_aead_lock"
  aead_lock
    :: Ptr Word8 -- ^ @uint8_t * __cipher_text__@.
    -> Ptr Word8 -- ^ @uint8_t __mac__['POLY1305_MAC_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __nonce__['CHACHA20_X_NONCE_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t * __ad__@.
    -> CSize     -- ^ @size_t __ad_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __plain_text__@.
    -> CSize     -- ^ @size_t __text_size__@.
    -> IO ()

-- | See [@crypto_aead_unlock()@](https://monocypher.org/manual/aead)
foreign import capi unsafe "monocypher.h crypto_aead_unlock"
  aead_unlock
    :: Ptr Word8 -- ^ @uint8_t * __plain_text__@.
    -> Ptr Word8 -- ^ @const uint8_t __mac__['POLY1305_MAC_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __nonce__['CHACHA20_X_NONCE_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t * __ad__@.
    -> CSize     -- ^ @size_t __ad_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __cipher_text__@.
    -> CSize     -- ^ @size_t __text_size__@.
    -> IO CInt   -- ^ @0@ on successful decryption, @-1@ otherwise.

--------------------------------------------------------------------------------

-- | See [@crypto_aead_ctx@](https://monocypher.org/manual/aead).
--
-- Allocate with 'aead_ctx_malloc'.
newtype AEAD_CTX = AEAD_CTX (ForeignPtr AEAD_CTX)
  -- ^ The constructor is exposed in case your want to obtain the 'ForeignPtr'
  -- by means other than 'aead_ctx_malloc'.
  --
  -- You can use 'withForeignPtr' to obtain the 'Ptr' necessary by many of
  -- the functions in this module.

-- | Peek allocates memory using 'aead_ctx_malloc', so it will be automatically
-- wiped when unreachable.
instance Storable AEAD_CTX where
  sizeOf _ = {# sizeof  crypto_aead_ctx #}
  alignment _ = {# alignof crypto_aead_ctx #}
  poke pd (AEAD_CTX fps) = withForeignPtr fps $ \ps -> copyArray pd ps 1
  peek ps = do AEAD_CTX fpd <- aead_ctx_malloc
               withForeignPtr fpd $ \pd -> copyArray pd ps 1
               pure (AEAD_CTX fpd)

-- | Allocated with 'Foreign.Ptr.mallocForeignPtr', but also automatically
-- 'wipe'd when not reachable anymore, before being freed.
aead_ctx_malloc :: IO AEAD_CTX
aead_ctx_malloc = do
  fp <- mallocForeignPtr
  addForeignPtrFinalizer finalizer_aead_ctx fp
  pure (AEAD_CTX fp)

foreign import capi unsafe
  "hs_monocypher.h &hs_monocypher_finalizer_aead_ctx"
  finalizer_aead_ctx :: FinalizerPtr AEAD_CTX

--------------------------------------------------------------------------------

-- | See [@crypto_aead_init_x()@](https://monocypher.org/manual/aead)
foreign import capi unsafe "monocypher.h crypto_aead_init_x"
  aead_init_x
    :: Ptr AEAD_CTX -- ^ @crypto_aead_ctx * __ctx__@.
                   -- Allocate with 'aead_ctx_malloc'
    -> Ptr Word8   -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8   -- ^ @const uint8_t nonce['CHACHA20_X_NONCE_SIZE']@.
    -> IO ()

-- | See [@crypto_aead_init_djb()@](https://monocypher.org/manual/aead)
foreign import capi unsafe "monocypher.h crypto_aead_init_djb"
  aead_init_djb
    :: Ptr AEAD_CTX -- ^ @crypto_aead_ctx * __ctx__@.
                   -- Allocate with 'aead_ctx_malloc'
    -> Ptr Word8   -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8   -- ^ @const uint8_t __nonce__['CHACHA20_DJB_NONCE_SIZE']@.
    -> IO ()

-- | See [@crypto_aead_init_ietf()@](https://monocypher.org/manual/aead)
foreign import capi unsafe "monocypher.h crypto_aead_init_ietf"
  aead_init_ietf
    :: Ptr AEAD_CTX -- ^ @crypto_aead_ctx * __ctx__@.
                   -- Allocate with 'aead_ctx_malloc'
    -> Ptr Word8   -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8   -- ^ @const uint8_t __nonce__['CHACHA20_IETF_NONCE_SIZE']@.
    -> IO ()

-- | See [@crypto_aead_write()@](https://monocypher.org/manual/aead)
foreign import capi unsafe "monocypher.h crypto_aead_write"
  aead_write
    :: Ptr AEAD_CTX -- ^ @crypto_aead_ctx * __ctx__@.
    -> Ptr Word8   -- ^ @uint8_t * __cipher_text__@.
    -> Ptr Word8   -- ^ @uint8_t mac['POLY1305_MAC_SIZE']@.
    -> Ptr Word8   -- ^ @const uint8_t * __ad__@.
    -> CSize       -- ^ @size_t __ad_size__@.
    -> Ptr Word8   -- ^ @const uint8_t * __plain_text__@.
    -> CSize       -- ^ @size_t __text_size__@.
    -> IO ()

-- | See [@crypto_aead_read()@](https://monocypher.org/manual/aead)
foreign import capi unsafe "monocypher.h crypto_aead_read"
  aead_read
    :: Ptr AEAD_CTX -- ^ @crypto_aead_ctx * __ctx__@.
    -> Ptr Word8   -- ^ @uint8_t * __plain_text__@.
    -> Ptr Word8   -- ^ @const uint8_t __mac__['POLY1305_MAC_SIZE']@.
    -> Ptr Word8   -- ^ @const uint8_t * __ad__@.
    -> CSize       -- ^ @size_t __ad_size__@.
    -> Ptr Word8   -- ^ @const uint8_t * __cipher_text__@.
    -> CSize       -- ^ @size_t __text_size__@.
    -> IO CInt     -- ^ @0@ on successful decryption, @-1@ otherwise.

--------------------------------------------------------------------------------

-- | See [@crypto_blake2b()@](https://monocypher.org/manual/blake2b)
foreign import capi unsafe "monocypher.h crypto_blake2b"
  blake2b
    :: Ptr Word8 -- ^ @uint8_t * __hash__@.
    -> CSize     -- ^ @size_t __hash_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> IO ()

-- | See [@crypto_blake2b_keyed()@](https://monocypher.org/manual/blake2b)
foreign import capi unsafe "monocypher.h crypto_blake2b_keyed"
  blake2b_keyed
    :: Ptr Word8 -- ^ @uint8_t * __hash__@.
    -> CSize     -- ^ @size_t __hash_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __key__@.
    -> CSize     -- ^ @size_t __key_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_blake2b_ctx@](https://monocypher.org/manual/blake2b).
-- Allocate with 'blake2b_ctx_malloc'.
newtype BLAKE2B_CTX = BLAKE2B_CTX (ForeignPtr BLAKE2B_CTX)
  -- ^ The constructor is exposed in case your want to obtain the 'ForeignPtr'
  -- by means other than 'blake2b_ctx_malloc'.
  --
  -- You can use 'withForeignPtr' to obtain the 'Ptr' necessary by many of
  -- the functions in this module.

-- | Peek allocates memory using 'blake2b_ctx_malloc', so it will be automatically
-- wiped when unreachable.
instance Storable BLAKE2B_CTX where
  sizeOf _ = {# sizeof  crypto_blake2b_ctx #}
  alignment _ = {# alignof crypto_blake2b_ctx #}
  poke pd (BLAKE2B_CTX fps) = withForeignPtr fps $ \ps -> copyArray pd ps 1
  peek ps = do BLAKE2B_CTX fpd <- blake2b_ctx_malloc
               withForeignPtr fpd $ \pd -> copyArray pd ps 1
               pure (BLAKE2B_CTX fpd)

-- | Allocated with 'Foreign.Ptr.mallocForeignPtr', but also automatically
-- 'wipe'd when not reachable anymore, before being freed.
blake2b_ctx_malloc :: IO BLAKE2B_CTX
blake2b_ctx_malloc = do
  fp <- mallocForeignPtr
  addForeignPtrFinalizer finalizer_blake2b_ctx fp
  pure (BLAKE2B_CTX fp)

foreign import capi unsafe
  "hs_monocypher.h &hs_monocypher_finalizer_blake2b_ctx"
  finalizer_blake2b_ctx :: FinalizerPtr BLAKE2B_CTX

--------------------------------------------------------------------------------

-- | See [@crypto_blake2b_init()@](https://monocypher.org/manual/blake2b)
foreign import capi unsafe "monocypher.h crypto_blake2b_init"
  blake2b_init
    :: Ptr BLAKE2B_CTX -- ^ @crypto_blake2b_ctx * __ctx__@.
                       -- Allocate with 'blake2b_ctx_malloc'.
    -> CSize           -- ^ @size_t __hash_size__@.
    -> IO ()

-- | See [@crypto_blake2b_keyed_init()@](https://monocypher.org/manual/blake2b)
foreign import capi unsafe "monocypher.h crypto_blake2b_keyed_init"
  blake2b_keyed_init
    :: Ptr BLAKE2B_CTX -- ^ @crypto_blake2b_ctx * __ctx__@.
                       -- Allocate with 'blake2b_ctx_malloc'.
    -> CSize           -- ^ @size_t __hash_size__@.
    -> Ptr Word8       -- ^ @const uint8_t * __key__@.
    -> CSize           -- ^ @size_t __key_size__@.
    -> IO ()

-- | See [@crypto_blake2b_update()@](https://monocypher.org/manual/blake2b)
foreign import capi unsafe "monocypher.h crypto_blake2b_update"
  blake2b_update
    :: Ptr BLAKE2B_CTX -- ^ @crypto_blake2b_ctx * __ctx__@.
    -> Ptr Word8       -- ^ @const uint8_t * __message__@.
    -> CSize           -- ^ @size_t __message_size__@.
    -> IO ()

-- | See [@crypto_blake2b_final()@](https://monocypher.org/manual/blake2b)
foreign import capi unsafe "monocypher.h crypto_blake2b_final"
  blake2b_final
    :: Ptr BLAKE2B_CTX -- ^ @crypto_blake2b_ctx * __ctx__@.
    -> Ptr Word8       -- ^ @uint8_t * __hash__@.
    -> IO ()

--------------------------------------------------------------------------------

{#enum define Argon2Algorithm
  { CRYPTO_ARGON2_D  as Argon2d
  , CRYPTO_ARGON2_I  as Argon2i
  , CRYPTO_ARGON2_ID as Argon2id
  } deriving (Eq, Ord, Show) #}

-- | See [@crypto_argon2()@](https://monocypher.org/manual/argon2)
--
-- Contrary to the C version of @crypto_argon2()@, this version takes all the
-- inputs individually, rather than in the separate @crypto_argon2_config@,
-- @crypto_argon2_inputs@ and @crypto_argon2_extras@ structures, and a
-- sufficiently large @work_area@ is automatically provided.
argon2
  :: Ptr Word8        -- ^ @uint8_t * __hash__@.
  -> Word32           -- ^ @uint32_t __hash_size__@.
  -> Argon2Algorithm  -- ^ @uint32_t __algorithm__@.
  -> Word32           -- ^ @uint32_t __nb_blocks__@.
  -> Word32           -- ^ @uint32_t __nb_passes__@.
  -> Word32           -- ^ @uint32_t __nb_lanes__@.
  -> Ptr Word8        -- ^ @const uint8_t * __pass__@.
  -> Word32           -- ^ @uint32_t __pass_size__@.
  -> Ptr Word8        -- ^ @const uint8_t * __salt__@.
  -> Word32           -- ^ @uint32_t __salt_size__@.
  -> Ptr Word8        -- ^ @const uint8_t * __key__@.
  -> Word32           -- ^ @uint32_t __key_size__@.
  -> Ptr Word8        -- ^ @const uint8_t * __ad__@.
  -> Word32           -- ^ @uint32_t __ad_size__@.
  -> IO ()
argon2 hash hash_size algorithm0 nb_blocks nb_passes nb_lanes pass pass_size
       salt salt_size key key_size ad ad_size = do
  let algorithm1 = fromIntegral (fromEnum algorithm0)
  work_area_size <- maybe (fail "nb_blocks too large") pure $
    -- this will never fail in 64 bits systems.
    toIntegralSized (toInteger nb_blocks * 1024)
  allocaBytes work_area_size $ \work_area ->
    -- work_area is wiped by _argon2
    _argon2 hash hash_size work_area algorithm1 nb_blocks nb_passes nb_lanes
            pass pass_size salt salt_size key key_size ad ad_size

foreign import capi unsafe "hs_monocypher.h hs_monocypher_crypto_argon2"
  _argon2
    :: Ptr Word8        -- ^ @uint8_t * __hash__@.
    -> Word32           -- ^ @uint32_t __hash_size__@.
    -> Ptr Word8        -- ^ @void * __work_area__@.
    -> Word32           -- ^ @uint32_t __algorithm__@.
    -> Word32           -- ^ @uint32_t __nb_blocks__@.
    -> Word32           -- ^ @uint32_t __nb_passes__@.
    -> Word32           -- ^ @uint32_t __nb_lanes__@.
    -> Ptr Word8        -- ^ @const uint8_t * __pass__@.
    -> Word32           -- ^ @uint32_t __pass_size__@.
    -> Ptr Word8        -- ^ @const uint8_t * __salt__@.
    -> Word32           -- ^ @uint32_t __salt_size__@.
    -> Ptr Word8        -- ^ @const uint8_t * __key__@.
    -> Word32           -- ^ @uint32_t __key_size__@.
    -> Ptr Word8        -- ^ @const uint8_t * __ad__@.
    -> Word32           -- ^ @uint32_t __ad_size__@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_x25519_public_key()@](https://monocypher.org/manual/x25519)
foreign import capi unsafe "monocypher.h crypto_x25519_public_key"
  x25519_public_key
    :: Ptr Word8 -- ^ @uint8_t __public_key__['X25519_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __secret_key__['X25519_SECRET_KEY_SIZE']@.
    -> IO ()

-- | See [@crypto_x25519()@](https://monocypher.org/manual/x25519)
foreign import capi unsafe "monocypher.h crypto_x25519"
  x25519
    :: Ptr Word8 -- ^ @uint8_t __raw_shared_secret__['X25519_SHARED_SECRET_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __your_secret_key__['X25519_SECRET_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __their_public_key__['X25519_PUBLIC_KEY_SIZE']@.
    -> IO ()

-- | See [@crypto_x25519_to_eddsa()@](https://monocypher.org/manual/x25519)
foreign import capi unsafe "monocypher.h crypto_x25519_to_eddsa"
  x25519_to_eddsa
    :: Ptr Word8 -- ^ @uint8_t __eddsa__['EDDSA_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __x25519__['X25519_PUBLIC_KEY_SIZE']@.
    -> IO ()

-- | See [@crypto_x25519_inverse()@](https://monocypher.org/manual/x25519)
foreign import capi unsafe "monocypher.h crypto_x25519_inverse"
  x25519_inverse
    :: Ptr Word8 -- ^ @uint8_t __blind_salt__['X25519_POINT_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __private_key__['X25519_SECRET_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __curve_point__['X25519_POINT_SIZE']@.
    -> IO ()

-- | See [@crypto_x25519_dirty_small()@](https://monocypher.org/manual/x25519)
foreign import capi unsafe "monocypher.h crypto_x25519_dirty_small"
  x25519_dirty_small
    :: Ptr Word8 -- ^ @uint8_t __pk__['X25519_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __sk__['X25519_SECRET_KEY_SIZE']@.
    -> IO ()

-- | See [@crypto_x25519_dirty_fast()@](https://monocypher.org/manual/x25519)
foreign import capi unsafe "monocypher.h crypto_x25519_dirty_fast"
  x25519_dirty_fast
    :: Ptr Word8 -- ^ @uint8_t __pk__['X25519_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __sk__['X25519_SECRET_KEY_SIZE']@.
    -> IO ()

--------------------------------------------------------------------------------
-- $eddsa
--
-- EdDSA on Curve25519 using BLAKE2b as hash algorithm.
--
-- __Warning:__ This is /not/ compatible with the more commonly deployed
-- Ed25519, which is EdDSA on Curve25519 using SHA512 as hash algorithm.

-- | See [@crypto_eddsa_key_pair()@](https://monocypher.org/manual/eddsa).
--
-- Contrary to the C version of @crypto_eddsa_key_pair()@, this version
-- does not 'wipe' the passed in @seed@.
eddsa_key_pair
  :: Ptr Word8 -- ^ @uint8_t __secret_key__['EDDSA_SECRET_KEY_SIZE']@.
  -> Ptr Word8 -- ^ @uint8_t __public_key__['EDDSA_PUBLIC_KEY_SIZE']@.
  -> Ptr Word8 -- ^ @const uint8_t __seed__['EDDSA_SEED_SIZE']@.
  -> IO ()
eddsa_key_pair hidden secret seed0 =
  -- _crypto_eddsa_key_pair wipes the seed, so we pass a copy instead.
  allocaBytes 32 $ \seed1 -> do
    copyBytes seed1 seed0 32
    _eddsa_key_pair hidden secret seed1

foreign import capi unsafe "monocypher.h crypto_eddsa_key_pair"
  _eddsa_key_pair
    :: Ptr Word8 -- ^ @uint8_t __secret_key__['EDDSA_SECRET_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @uint8_t __public_key__['EDDSA_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @uint8_t __signature__['EDDSA_SEED_SIZE']@.
    -> IO ()

-- | See [@crypto_eddsa_sign()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_sign"
  eddsa_sign
    :: Ptr Word8 -- ^ @uint8_t __signature__['EDDSA_SIGNATURE_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __secret_key__['EDDSA_SECRET_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> IO ()

-- | See [@crypto_eddsa_check()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_check"
  eddsa_check
    :: Ptr Word8 -- ^ @const uint8_t __signature__['EDDSA_SIGNATURE_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __public_key__['EDDSA_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> IO CInt   -- ^ @0@ if signature is legitimate, @-1@ otherwise.

-- | See [@crypto_eddsa_to_x25519()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_to_x25519"
  eddsa_to_x25519
    :: Ptr Word8 -- ^ @uint8_t __x25519__['X25519_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __eddsa__['EDDSA_PUBLIC_KEY_SIZE']@.
    -> IO ()

-- | See [@crypto_eddsa_trim_scalar()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_trim_scalar"
  eddsa_trim_scalar
    :: Ptr Word8 -- ^ @uint8_t __out__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __in__[32]@.
    -> IO ()

-- | See [@crypto_eddsa_reduce()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_reduce"
  eddsa_reduce
    :: Ptr Word8 -- ^ @uint8_t __reduced__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __expanded__[64]@.
    -> IO ()

-- | See [@crypto_eddsa_mul_add()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_mul_add"
  eddsa_mul_add
    :: Ptr Word8 -- ^ @uint8_t __r__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __a__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __b__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __c__[32]@.
    -> IO ()

-- | See [@crypto_eddsa_scalarbase()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_scalarbase"
  eddsa_scalarbase
    :: Ptr Word8 -- ^ @uint8_t __point__['EDDSA_POINT_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __scalar__[32]@.
    -> IO ()

-- | See [@crypto_eddsa_check_equation()@](https://monocypher.org/manual/eddsa)
foreign import capi unsafe "monocypher.h crypto_eddsa_check_equation"
  eddsa_check_equation
    :: Ptr Word8 -- ^ @const uint8_t __signature__['EDDSA_SIGNATURE_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __public_key__['EDDSA_PUBLIC_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __h_ram__['BLAKE2B_HASH_MAX_SIZE']@.
    -> IO CInt   -- ^ @0@ if all checks hold, @-1@ otherwise.

--------------------------------------------------------------------------------


-- | See [@crypto_chacha20_h()@](https://monocypher.org/manual/chacha20)
foreign import capi unsafe "monocypher.h crypto_chacha20_h"
  chacha20_h
    :: Ptr Word8 -- ^ @uint8_t __out__['CHACHA20_OUT_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __in__['HCHACHA20_NONCE_SIZE']@.
    -> IO ()

-- | See [@crypto_chacha20_djb()@](https://monocypher.org/manual/chacha20)
foreign import capi unsafe "monocypher.h crypto_chacha20_djb"
  chacha20_djb
    :: Ptr Word8 -- ^ @uint8_t * __cipher_text__@.
    -> Ptr Word8 -- ^ @const uint8_t * __plain_text__@.
    -> CSize     -- ^ @size_t __text_size__@.
    -> Ptr Word8 -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __nonce__['CHACHA20_DJB_NONCE_SIZE']@.
    -> Word64    -- ^ @uint64_t __ctr__@.
    -> IO Word64 -- ^ Next @ctr@ to use with the same key and nonce values.

-- | See [@crypto_chacha20_ietf()@](https://monocypher.org/manual/chacha20)
foreign import capi unsafe "monocypher.h crypto_chacha20_ietf"
  chacha20_ietf
    :: Ptr Word8 -- ^ @uint8_t * __cipher_text__@.
    -> Ptr Word8 -- ^ @const uint8_t * __plain_text__@.
    -> CSize     -- ^ @size_t __text_size__@.
    -> Ptr Word8 -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __nonce__['CHACHA20_IETF_NONCE_SIZE']@.
    -> Word32    -- ^ @uint32_t __ctr__@.
    -> IO Word32 -- ^ Next @ctr@ to use with the same key and nonce values.

-- | See [@crypto_chacha20_x()@](https://monocypher.org/manual/chacha20)
foreign import capi unsafe "monocypher.h crypto_chacha20_x"
  chacha20_x
    :: Ptr Word8 -- ^ @uint8_t * __cipher_text__@.
    -> Ptr Word8 -- ^ @const uint8_t * __plain_text__@.
    -> CSize     -- ^ @size_t __text_size__@.
    -> Ptr Word8 -- ^ @const uint8_t __key__['CHACHA20_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __nonce__['CHACHA20_X_NONCE_SIZE']@.
    -> Word64    -- ^ @uint64_t __ctr__@.
    -> IO Word64 -- ^ Next @ctr@ to use with the same key and nonce values.

--------------------------------------------------------------------------------


-- | See [@crypto_poly1305()@](https://monocypher.org/manual/poly1305)
foreign import capi unsafe "monocypher.h crypto_poly1305"
  poly1305
    :: Ptr Word8 -- ^ @uint8_t __mac__['POLY1305_MAC_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> Ptr Word8 -- ^ @const uint8_t __key__['POLY1305_KEY_SIZE']@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_poly1305@](https://monocypher.org/manual/poly1305)
--
-- Allocate with 'poly1305_ctx_malloc'.
newtype POLY1305_CTX = POLY1305_CTX (ForeignPtr POLY1305_CTX)
  -- ^ The constructor is exposed in case your want to obtain the 'ForeignPtr'
  -- by means other than 'poly1305_ctx_malloc'.
  --
  -- You can use 'withForeignPtr' to obtain the 'Ptr' necessary by many of
  -- the functions in this module.

-- | Peek allocates memory using 'poly1305_ctx_malloc', so it will be automatically
-- wiped when unreachable.
instance Storable POLY1305_CTX where
  sizeOf _ = {# sizeof  crypto_poly1305_ctx #}
  alignment _ = {# alignof crypto_poly1305_ctx #}
  poke pd (POLY1305_CTX fps) = withForeignPtr fps $ \ps -> copyArray pd ps 1
  peek ps = do POLY1305_CTX fpd <- poly1305_ctx_malloc
               withForeignPtr fpd $ \pd -> copyArray pd ps 1
               pure (POLY1305_CTX fpd)

-- | Allocated with 'Foreign.Ptr.mallocForeignPtr', but also automatically
-- 'wipe'd when not reachable anymore, before being freed.
poly1305_ctx_malloc :: IO POLY1305_CTX
poly1305_ctx_malloc = do
  fp <- mallocForeignPtr
  addForeignPtrFinalizer finalizer_poly1305_ctx fp
  pure (POLY1305_CTX fp)

foreign import capi unsafe
  "hs_monocypher.h &hs_monocypher_finalizer_poly1305_ctx"
  finalizer_poly1305_ctx :: FinalizerPtr POLY1305_CTX

--------------------------------------------------------------------------------

-- | See [@crypto_poly1305_init()@](https://monocypher.org/manual/poly1305)
foreign import capi unsafe "monocypher.h crypto_poly1305_init"
  poly1305_init
    :: Ptr POLY1305_CTX -- ^ @crypto_poly1305_ctx * __ctx__@.
                        -- Allocate with 'poly1305_ctx_malloc'.
    -> Ptr Word8        -- ^ @const uint8_t __key__['POLY1305_KEY_SIZE']@.
    -> IO ()

-- | See [@crypto_poly1305_update()@](https://monocypher.org/manual/poly1305)
foreign import capi unsafe "monocypher.h crypto_poly1305_update"
  poly1305_update
    :: Ptr POLY1305_CTX -- ^ @crypto_poly1305_ctx * __ctx__@.
    -> Ptr Word8        -- ^ @const uint8_t * __message__@.
    -> CSize            -- ^ @size_t __message_size__@.
    -> IO ()

-- | See [@crypto_poly1305_final()@](https://monocypher.org/manual/poly1305)
foreign import capi unsafe "monocypher.h crypto_poly1305_final"
  poly1305_final
    :: Ptr POLY1305_CTX -- ^ @crypto_poly1305_ctx * __ctx__@.
    -> Ptr Word8        -- ^ @uint8_t __mac__['POLY1305_MAC_SIZE']@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_elligator_map()@](https://monocypher.org/manual/elligator)
foreign import capi unsafe "monocypher.h crypto_elligator_map"
  elligator_map
    :: Ptr Word8 -- ^ @uint8_t __point__['X25519_POINT_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __hidden__['ELLIGATOR_HIDDEN_SIZE']@.
    -> IO ()

-- | See [@crypto_elligator_rev()@](https://monocypher.org/manual/elligator)
foreign import capi unsafe "monocypher.h crypto_elligator_rev"
  elligator_rev
    :: Ptr Word8 -- ^ @uint8_t __hidden__['ELLIGATOR_HIDDEN_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t __public_key__['X25519_PUBLIC_KEY_SIZE']@.
    -> Word8     -- ^ @uint8_t __tweak__@.
    -> IO CInt   -- ^ @0@ on success, @-1@ if the given curve argument is unsuitable for hiding.

-- | See [@crypto_elligator_key_pair()@](https://monocypher.org/manual/elligator).
--
-- Contrary to the C version of @crypto_elligator_key_pair()@, this version
-- does not 'wipe' the passed in @seed@.
elligator_key_pair
  :: Ptr Word8 -- ^ @uint8_t __hidden__['ELLIGATOR_HIDDEN_SIZE']@.
  -> Ptr Word8 -- ^ @uint8_t __secret_key__['X25519_SECRET_KEY_SIZE']@.
  -> Ptr Word8 -- ^ @const uint8_t __seed__['ELLIGATOR_SEED_SIZE']@.
  -> IO ()
elligator_key_pair hidden secret seed0 =
  -- _crypto_elligator_key_pair wipes the seed, so we pass a copy instead.
  allocaBytes 32 $ \seed1 -> do
    copyBytes seed1 seed0 32
    _elligator_key_pair hidden secret seed1

foreign import capi unsafe "monocypher.h crypto_elligator_key_pair"
  _elligator_key_pair
    :: Ptr Word8 -- ^ @uint8_t __hidden__['ELLIGATOR_HIDDEN_SIZE']@.
    -> Ptr Word8 -- ^ @uint8_t __secret_key__['X25519_SECRET_KEY_SIZE']@.
    -> Ptr Word8 -- ^ @uint8_t __seed__['ELLIGATOR_SEED_SIZE']@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_sha512()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512"
  sha512
    :: Ptr Word8 -- ^ @uint8_t __hash__['SHA512_HASH_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t message_size@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_sha512_ctx@](https://monocypher.org/manual/sha512)
--
-- Allocate with 'sha512_ctx_malloc'.
newtype SHA512_CTX = SHA512_CTX (ForeignPtr SHA512_CTX)
  -- ^ The constructor is exposed in case your want to obtain the 'ForeignPtr'
  -- by means other than 'sha512_ctx_malloc'.
  --
  -- You can use 'withForeignPtr' to obtain the 'Ptr' necessary by many of
  -- the functions in this module.

-- | Peek allocates memory using 'sha512_ctx_malloc', so it will be automatically
-- wiped when unreachable.
instance Storable SHA512_CTX where
  sizeOf _ = {# sizeof  crypto_sha512_ctx #}
  alignment _ = {# alignof crypto_sha512_ctx #}
  poke pd (SHA512_CTX fps) = withForeignPtr fps $ \ps -> copyArray pd ps 1
  peek ps = do SHA512_CTX fpd <- sha512_ctx_malloc
               withForeignPtr fpd $ \pd -> copyArray pd ps 1
               pure (SHA512_CTX fpd)

-- | Allocated with 'Foreign.Ptr.mallocForeignPtr', but also automatically
-- 'wipe'd when not reachable anymore, before being freed.
sha512_ctx_malloc :: IO SHA512_CTX
sha512_ctx_malloc = do
  fp <- mallocForeignPtr
  addForeignPtrFinalizer finalizer_sha512_ctx fp
  pure (SHA512_CTX fp)

foreign import capi unsafe
  "hs_monocypher.h &hs_monocypher_finalizer_sha512_ctx"
  finalizer_sha512_ctx :: FinalizerPtr SHA512_CTX

--------------------------------------------------------------------------------

-- | See [@crypto_sha512_init()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_init"
  sha512_init
    :: Ptr SHA512_CTX -- ^ @crypto_sha512_ctx * __ctx__@.
    -> IO ()

-- | See [@crypto_sha512_update()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_update"
  sha512_update
    :: Ptr SHA512_CTX -- ^ @crypto_sha512_ctx * __ctx__@.
    -> Ptr Word8      -- ^ @const uint8_t * __message__@.
    -> CSize          -- ^ @size_t __message_size__@.
    -> IO ()

-- | See [@crypto_sha512_final()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_final"
  sha512_final
    :: Ptr SHA512_CTX -- ^ @crypto_sha512_ctx * __ctx__@
    -> Ptr Word8      -- ^ @uint8_t __hash__['SHA512_HASH_SIZE']@.
    -> IO ()

-- | See [@crypto_sha512_hmac()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_hmac"
  sha512_hmac
    :: Ptr Word8 -- ^ @uint8_t __hmac__['SHA512_HASH_SIZE']@.
    -> Ptr Word8 -- ^ @const uint8_t * __key__@.
    -> CSize     -- ^ @size_t __key_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> IO ()

--------------------------------------------------------------------------------

-- | See [@crypto_sha512_hmac_ctx@](https://monocypher.org/manual/sha512)
--
-- Allocate with 'sha512_hmac_ctx_malloc'.
newtype SHA512_HMAC_CTX = SHA512_HMAC_CTX (ForeignPtr SHA512_HMAC_CTX)
  -- ^ The constructor is exposed in case your want to obtain the 'ForeignPtr'
  -- by means other than 'sha512_hmac_ctx_malloc'.
  --
  -- You can use 'withForeignPtr' to obtain the 'Ptr' necessary by many of
  -- the functions in this module.

-- | Peek allocates memory using 'sha512_hmac_ctx_malloc', so it will be automatically
-- wiped when unreachable.
instance Storable SHA512_HMAC_CTX where
  sizeOf _ = {# sizeof  crypto_sha512_hmac_ctx #}
  alignment _ = {# alignof crypto_sha512_hmac_ctx #}
  poke pd (SHA512_HMAC_CTX fps) = withForeignPtr fps $ \ps -> copyArray pd ps 1
  peek ps = do SHA512_HMAC_CTX fpd <- sha512_hmac_ctx_malloc
               withForeignPtr fpd $ \pd -> copyArray pd ps 1
               pure (SHA512_HMAC_CTX fpd)

-- | Allocated with 'Foreign.Ptr.mallocForeignPtr', but also automatically
-- 'wipe'd when not reachable anymore, before being freed.
sha512_hmac_ctx_malloc :: IO SHA512_HMAC_CTX
sha512_hmac_ctx_malloc = do
  fp <- mallocForeignPtr
  addForeignPtrFinalizer finalizer_sha512_hmac_ctx fp
  pure (SHA512_HMAC_CTX fp)

foreign import capi unsafe
  "hs_monocypher.h &hs_monocypher_finalizer_sha512_hmac_ctx"
  finalizer_sha512_hmac_ctx :: FinalizerPtr SHA512_HMAC_CTX

--------------------------------------------------------------------------------

-- | See [@crypto_sha512_hmac_init()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_hmac_init"
  sha512_hmac_init
    :: Ptr SHA512_HMAC_CTX -- ^ @crypto_sha512_hmac_ctx * __ctx__@.
    -> Ptr Word8           -- ^ @const uint8_t * __key__@.
    -> CSize               -- ^ @size_t __key_size__@.
    -> IO ()

-- | See [@crypto_sha512_hmac_update()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_hmac_update"
  sha512_hmac_update
    :: Ptr SHA512_HMAC_CTX -- ^ @crypto_sha512_hmac_ctx * __ctx__@.
    -> Ptr Word8           -- ^ @const uint8_t * __message__@.
    -> CSize               -- ^ @size_t __message_size__@.
    -> IO ()

-- | See [@crypto_sha512_hmac_final()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_hmac_final"
  sha512_hmac_final
    :: Ptr SHA512_HMAC_CTX -- ^ @crypto_sha512_hmac_ctx * __ctx__@.
    -> Ptr Word8           -- ^ @uint8_t hmac['SHA512_HASH_SIZE']@.
    -> IO ()

-- | See [@crypto_sha512_hkdf_expand()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_hkdf_expand"
  sha512_hkdf_expand
    :: Ptr Word8 -- ^ @uint8_t * __okm__@.
    -> CSize     -- ^ @size_t __okm_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __prk__@.
    -> CSize     -- ^ @size_t __prk_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __info__@.
    -> CSize     -- ^ @size_t __info_size__@.
    -> IO ()

-- | See [@crypto_sha512_hkdf()@](https://monocypher.org/manual/sha512).
foreign import capi unsafe "monocypher-ed25519.h crypto_sha512_hkdf"
  sha512_hkdf
    :: Ptr Word8 -- ^ @uint8_t * __okm__@.
    -> CSize     -- ^ @size_t __okm_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __ikm__@.
    -> CSize     -- ^ @size_t __ikm_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __salt__@.
    -> CSize     -- ^ @size_t __salt_size__@.
    -> Ptr Word8 -- ^ @const uint8_t * __info__@.
    -> CSize     -- ^ @size_t __info_size__@.
    -> IO ()

--------------------------------------------------------------------------------
-- $ed25519
--
-- EdDSA on Curve25519 using SHA512 as hash algorithm.

-- | See [@crypto_ed5519_key_pair()@](https://monocypher.org/manual/ed25519).
foreign import capi unsafe "monocypher-ed25519.h crypto_ed25519_key_pair"
  ed25519_key_pair
    :: Ptr Word8 -- ^ @uint8_t __secret_key__[64]@.
    -> Ptr Word8 -- ^ @uint8_t __public_key__[32]@.
    -> Ptr Word8 -- ^ @uint8_t __seed__[32]@.
    -> IO ()

-- | See [@crypto_ed5519_sing()@](https://monocypher.org/manual/ed25519).
foreign import capi unsafe "monocypher-ed25519.h crypto_ed25519_sign"
  ed25519_sign
    :: Ptr Word8 -- ^ @uint8_t __signature__[64]@.
    -> Ptr Word8 -- ^ @const uint8_t __secret_key__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> IO ()

-- | See [@crypto_ed5519_check()@](https://monocypher.org/manual/ed25519).
foreign import capi unsafe "monocypher-ed25519.h crypto_ed25519_check"
  ed25519_check
    :: Ptr Word8 -- ^ @const uint8_t __signature__[64]@.
    -> Ptr Word8 -- ^ @const uint8_t __public_key__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t * __message__@.
    -> CSize     -- ^ @size_t __message_size__@.
    -> IO CInt   -- ^ @0@ if signature is legitimate, @-1@ otherwise.

--------------------------------------------------------------------------------
-- $ed25519ph
--
-- Pre-hashed EdDSA on Curve25519 using SHA512 as hash algorithm.
--
-- __Warning:__ This is /not/ compatible with the more commonly deployed
-- Ed25519, which is EdDSA on Curve25519 using SHA512 as hash algorithm
-- /without pre-hashing/.

-- | See [@crypto_ed25519_ph_sign()@](https://monocypher.org/manual/ed25519).
foreign import capi unsafe "monocypher-ed25519.h crypto_ed25519_ph_sign"
  ed25519_ph_sign
    :: Ptr Word8 -- ^ @uint8_t __signature__[64]@.
    -> Ptr Word8 -- ^ @const uint8_t __secret_key__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __message_hash__[64]@.
    -> IO ()

-- | See [@crypto_ed25519_ph_check()@](https://monocypher.org/manual/ed25519).
foreign import capi unsafe "monocypher-ed25519.h crypto_ed25519_ph_check"
  ed25519_ph_check
    :: Ptr Word8 -- ^ @const uint8_t __signature__[64]@.
    -> Ptr Word8 -- ^ @const uint8_t __public_key__[32]@.
    -> Ptr Word8 -- ^ @const uint8_t __message_hash__[64]@.
    -> IO CInt   -- ^ @0@ if signature is legitimate, @-1@ otherwise.

--------------------------------------------------------------------------------
-- $constants
--
-- For your convenience, "Monocypher" exports type-level constants for sizes
-- and alignments used throughout this module. The names of these constants are
-- not official, in the sense that the C library doesn't use any names for
-- constants, and instead it mentions numbers like @32@ or @64@ directly.

type AEAD_CTX_SIZE = {#sizeof crypto_aead_ctx #}
type AEAD_CTX_ALIGNMENT = {#alignof crypto_aead_ctx #}

type BLAKE2B_HASH_MAX_SIZE = 64
type BLAKE2B_KEY_MAX_SIZE = 64
type BLAKE2B_CTX_SIZE = {#sizeof crypto_blake2b_ctx #}
type BLAKE2B_CTX_ALIGNMENT = {#alignof crypto_blake2b_ctx #}

type X25519_POINT_SIZE = 32
type X25519_PUBLIC_KEY_SIZE = 32
type X25519_SECRET_KEY_SIZE = 32
type X25519_SHARED_SECRET_SIZE = 32

type EDDSA_POINT_SIZE = 32
type EDDSA_PUBLIC_KEY_SIZE = 32
type EDDSA_SECRET_KEY_SIZE = 64
type EDDSA_SEED_SIZE = 32
type EDDSA_SHARED_SECRET_SIZE = 32
type EDDSA_SIGNATURE_SIZE = 64

type CHACHA20_OUT_SIZE = 32
type CHACHA20_KEY_SIZE = 32
type CHACHA20_DJB_NONCE_SIZE = 8
type CHACHA20_IETF_NONCE_SIZE = 12
type CHACHA20_X_NONCE_SIZE = 24
type HCHACHA20_NONCE_SIZE = 16

type POLY1305_KEY_SIZE = 32
type POLY1305_MAC_SIZE = 16

type POLY1305_CTX_SIZE = {#sizeof crypto_poly1305_ctx #}
type POLY1305_CTX_ALIGNMENT = {#alignof crypto_poly1305_ctx #}

type ELLIGATOR_HIDDEN_SIZE = 32
type ELLIGATOR_SEED_SIZE = 32

type SHA512_HASH_SIZE = 64

type SHA512_CTX_SIZE = {#sizeof crypto_sha512_ctx #}
type SHA512_CTX_ALIGNMENT = {#alignof crypto_sha512_ctx #}

type SHA512_HMAC_CTX_SIZE = {#sizeof crypto_sha512_hmac_ctx #}
type SHA512_HMAC_CTX_ALIGNMENT = {#alignof crypto_sha512_hmac_ctx #}

