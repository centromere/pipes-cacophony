----------------------------------------------------------------
-- |
-- Module      : Pipes.Noise
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Pipes.Noise
  ( -- * Types
    InboundNoisePipe
  , OutboundNoisePipe
    -- * Pipes
  , mkNoisePipes
  ) where

import Data.ByteString     (ByteString)
import Pipes               (Pipe, await, yield)

import Crypto.Noise
import Crypto.Noise.Cipher (Cipher)
import Crypto.Noise.DH     (DH)
import Crypto.Noise.Hash   (Hash)

-- | Pipe used for inbound Noise messages.
type InboundNoisePipe  = Pipe ByteString ScrubbedBytes

-- | Pipe used for outbound Noise messages.
type OutboundNoisePipe = Pipe ScrubbedBytes ByteString

-- | Creates a pair of Pipes, the first used for inbound messages and the
--   second used for outbound messages. Note: The handshake for the given
--   'NoiseState' must be complete. If it is not, this function will return
--   'Nothing'.
mkNoisePipes :: (Monad m, Cipher c, DH d, Hash h)
             => NoiseState c d h
             -> Maybe (InboundNoisePipe  m (NoiseResult c d h),
                       OutboundNoisePipe m (NoiseResult c d h))
mkNoisePipes ns | handshakeComplete ns = return (inboundPipe ns, outboundPipe ns)
                | otherwise            = Nothing

inboundPipe :: (Monad m, Cipher c, DH d, Hash h)
            => NoiseState c d h
            -> InboundNoisePipe m (NoiseResult c d h)
inboundPipe ns = do
  msg <- await

  let result = readMessage (convert msg) ns
  case result of
    NoiseResultMessage pt ns' -> do
      yield pt
      inboundPipe ns'
    NoiseResultNeedPSK   _ -> return result
    NoiseResultException _ -> return result

outboundPipe :: (Monad m, Cipher c, DH d, Hash h)
             => NoiseState c d h
             -> OutboundNoisePipe m (NoiseResult c d h)
outboundPipe ns = do
  msg <- await

  let result = writeMessage msg ns
  case result of
    NoiseResultMessage ct ns' -> do
      yield . convert $ ct
      outboundPipe ns'
    NoiseResultNeedPSK   _ -> return result
    NoiseResultException _ -> return result
