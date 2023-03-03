{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE LambdaCase #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Data.Char
import Data.Foldable
import Data.List (groupBy)
import Data.Traversable
import Data.Word (Word8)
import Debug.Trace
import Foreign.Ptr (Ptr, plusPtr)
import Foreign.C.Types (CSize(..))
import Foreign.C.String (CString, peekCString)
import Foreign.ForeignPtr (ForeignPtr, mallocForeignPtrBytes,
  mallocForeignPtr, withForeignPtr)
import Foreign.Marshal.Array (peekArray, pokeArray, allocaArray)
import Foreign.Storable (Storable(..))
import GHC.ForeignPtr (mallocForeignPtrAlignedBytes)
import Numeric (readHex, showHex)
import System.IO.Unsafe (unsafePerformIO)

import Monocypher.C qualified as C

main :: IO ()
main = do
  putStrLn "test_sha512"
  for_ test_vectors_sha512 test_sha512
  putStrLn "test_sha512_incremental"
  for_ test_vectors_sha512 test_sha512_incremental
  putStrLn "test_blake2b"
  for_ test_vectors_blake2b test_blake2b
  putStrLn "test_blake2b_incremental"
  for_ test_vectors_blake2b test_blake2b_incremental

test_sha512 :: (String, String) -> IO ()
test_sha512 (msgB16, okmB16) =
  expectB16 okmB16 $ \okmBinL okmBinP ->
  allocaB16 msgB16 $ \msgBinL msgBinP ->
  C.sha512 okmBinP msgBinP (fromIntegral msgBinL)

test_sha512_incremental :: (String, String) -> IO ()
test_sha512_incremental (msgB16, okmB16) = do
  C.SHA512_CTX ctxFP <- C.sha512_ctx_malloc
  withForeignPtr ctxFP $ \ctxP -> do
    C.sha512_init ctxP
    msgPartsB16 <- maybe (fail "msgPartsB16") pure $ groupPseudoN 2 33 msgB16
    for_ msgPartsB16 $ \msgPartB16 -> do
      allocaB16 msgPartB16 $ \msgPartBinL msgPartBinP -> do
        C.sha512_update ctxP msgPartBinP (fromIntegral msgPartBinL)
    expectB16 okmB16 $ \okmBinL okmBinP ->
      C.sha512_final ctxP okmBinP

test_blake2b :: (String, String, String) -> IO ()
test_blake2b (msgB16, "", okmB16) =
  expectB16 okmB16 $ \okmBinL okmBinP ->
  allocaB16 msgB16 $ \msgBinL msgBinP ->
  C.blake2b okmBinP (fromIntegral okmBinL)
            msgBinP (fromIntegral msgBinL)
test_blake2b (msgB16, keyB16, okmB16) =
  expectB16 okmB16 $ \okmBinL okmBinP ->
  allocaB16 keyB16 $ \keyBinL keyBinP ->
  allocaB16 msgB16 $ \msgBinL msgBinP ->
  C.blake2b_keyed okmBinP (fromIntegral okmBinL)
                  keyBinP (fromIntegral keyBinL)
                  msgBinP (fromIntegral msgBinL)

test_blake2b_incremental :: (String, String, String) -> IO ()
test_blake2b_incremental (msgB16, keyB16, okmB16) =
  expectB16 okmB16 $ \okmBinL okmBinP ->
  C.blake2b_ctx_malloc >>= \(C.BLAKE2B_CTX ctxFP) ->
  withForeignPtr ctxFP $ \ctxP -> do
    case keyB16 of
      "" -> C.blake2b_init ctxP (fromIntegral okmBinL)
      _  -> allocaB16 keyB16 $ \keyBinL keyBinP ->
            C.blake2b_keyed_init ctxP (fromIntegral okmBinL) keyBinP
                                (fromIntegral keyBinL)
    msgPartsB16 <- maybe (fail "msgPartsB16") pure $ groupPseudoN 2 33 msgB16
    for_ msgPartsB16 $ \msgPartB16 -> do
      allocaB16 msgPartB16 $ \msgPartBinL msgPartBinP -> do
        C.blake2b_update ctxP msgPartBinP (fromIntegral msgPartBinL)
    C.blake2b_final ctxP okmBinP

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

-- | @'groupN' n xs@ splits @xs@ into lists of length @n@.
-- If @n@ is less than @1@, or if @'mod' ('length' xs) n != 0@, then 'Nothing'.
--
-- @
-- > groupN 2 [1,2,3,4,5,6]
-- Just [[1,2],[3,4],[5,6]]
-- > groupN 3 [1,2,3,4,5,6]
-- Just [[1,2,3],[4,5,6]]
-- > groupN 6 [1,2,3,4,5,6]
-- Just [[1,2,3,4,5,6]]
-- @
--
-- If not 'Nothing', then:
--
-- @
-- 'Just' xs == fmap join (groupN n xs)
-- @
groupN :: forall a. Int -> [a] -> Maybe [[a]]
groupN n0
  | n0 < 1    = const Nothing
  | otherwise = g . foldr f (n0, [], [])
  where
    f :: a -> (Int, [a], [[a]]) -> (Int, [a], [[a]])
    f a (1, acc, out) = (n0, [], (a : acc) : out)
    f a (n, acc, out) = (n - 1, a : acc, out)
    g :: (Int, [a], [[a]]) -> Maybe [[a]]
    g (n, [], out@(_:_)) | n == n0 = Just out
    g _ = Nothing

-- | @'groupPseudoN' n z xs@ splits @xs@ into groups whose 'length's are
-- multiples of @n@ and at most @z@. The length of each group is
-- calculated taking the 'chr' value of its first character into account.
--
-- Returns 'Nothing' if @n@ is less than @1@, or if @z@ is less than @1@,
-- or if the 'String' length is not a multiple of @n@.
--
-- If not 'Nothing', then:
--
-- @
-- forall n z xs.
--   'Just' xs == fmap (join . fmap snd) (groupPseudoN n z xs)
-- @
groupPseudoN :: Int -> Int -> String -> Maybe [String]
groupPseudoN n z
  | n < 1 || z < 1 = const Nothing
  | otherwise = f
  where
    f :: String -> Maybe [String]
    f [] = Just []
    f (a : as) = do
      let m = n * (div (mod (ord a) z) n + 1)
          (pre, pos) = splitAt m (a : as)
      case length pre of
        preL | preL < z, mod preL n /= 0 -> Nothing
             | otherwise -> fmap (pre :) (f pos)

-- | Given a base16-encoded string, expect that the continuation writes
-- its binary representation into the 'Int' bytes starting at 'Ptr'.
expectB16 :: String -> (Int -> Ptr Word8 -> IO a) -> IO a
expectB16 expB16 f =
  case fromB16 expB16 of
    Nothing -> fail "expectB16: expected even-length hex string"
    Just (expBinL, expBin :: [Word8]) ->
      allocaArray expBinL $ \outBinP -> do
        a <- f expBinL outBinP
        actBin <- peekArray expBinL outBinP
        when (actBin /= expBin) $ fail $ ($ mempty) $
          showString "expectB16: expected [" .
          showB16 expBin .
          showString "] got [" .
          showB16 actBin .
          showChar ']'
        pure a

-- | Decodes the base16-encoded string. Returns the bytes, as well as
-- the number thereof. 'Nothing' if the input 'String' is not valid base16.
fromB16 :: String -> Maybe (Int, [Word8])
fromB16 = \case
  [] -> Just (0, [])
  h : l : xs | [(w, "")] <- readHex [h, l] -> do
    (len, ws) <- fromB16 xs
    let !len' = len + 1
    pure (len', w : ws)
  _ -> Nothing

-- | Allocates memory that holds the binary representation of the
-- given base16-encoded bytes. The binary length is passed in.
allocaB16 :: String -> (Int -> Ptr Word8 -> IO a) -> IO a
allocaB16 s f = case fromB16 s of
  Nothing -> fail ("allocaB16: not base16 string [" <> show s <> "]")
  Just (len, ws) -> allocaArray len $ \p -> do
                      pokeArray p ws
                      f len p

-- | @'peekB16' n p@ reads @n@ bytes starting at @p@, and returns them encoded
-- as base16.
peekB16 :: Int -> Ptr Word8 -> IO String
peekB16 len p = flip showB16 "" <$> peekArray len p

-- | Encodes as base16.
showB16 :: [Word8] -> ShowS
showB16 = foldr (.) id . map f
  where f :: Word8 -> ShowS
        f n = (if n <= 0xf then showChar '0' else id) . showHex n

lengthAtLeast :: Int -> [a] -> Bool
lengthAtLeast n as0
  | n <= 0      = True
  | []   <- as0 = False
  | a:as <- as0 = lengthAtLeast (n - 1) as

--------------------------------------------------------------------------------

test_vectors_sha512 :: [(String, String)]
{-# NOINLINE test_vectors_sha512 #-}
test_vectors_sha512 = unsafePerformIO $ do
  p1 <- peekArray @CString (fromIntegral c_nb_sha512_vectors) (c_sha512_vectors)
  Just p1s <- pure $ groupN 2 p1
  for p1s $ \[msgP, okmP] ->
     (,) <$> peekCString msgP
         <*> peekCString okmP

foreign import capi "vectors.h value nb_sha512_vectors"
  c_nb_sha512_vectors :: CSize
foreign import capi "vectors.h value sha512_vectors"
  c_sha512_vectors :: Ptr CString

test_vectors_blake2b :: [(String, String, String)]
{-# NOINLINE test_vectors_blake2b #-}
test_vectors_blake2b = unsafePerformIO $ do
  p1 <- peekArray @CString (fromIntegral c_nb_blake2b_vectors) (c_blake2b_vectors)
  Just p1s <- pure $ groupN 3 p1
  for p1s $ \[msgP, keyP, okmP] ->
     (,,) <$> peekCString msgP
          <*> peekCString keyP
          <*> peekCString okmP

foreign import capi "vectors.h value nb_blake2b_vectors"
  c_nb_blake2b_vectors :: CSize
foreign import capi "vectors.h value blake2b_vectors"
  c_blake2b_vectors :: Ptr CString
