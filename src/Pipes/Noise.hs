{-# LANGUAGE OverloadedStrings #-}
----------------------------------------------------------------
-- |
-- Module      : Pipes.Noise
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Pipes.Noise
  ( -- * Types
    MessagePipe,
    -- * Pipes
    messageEncryptPipe,
    messageDecryptPipe
  ) where

import Control.Concurrent.MVar (MVar, putMVar, takeMVar)
import Control.Monad           (forever)
import Data.ByteString         (ByteString)
import Pipes                   (Pipe, await, yield, lift)

import Crypto.Noise.Cipher     (Cipher)
import Crypto.Noise.Handshake
import Crypto.Noise.Types
import Data.ByteArray.Extend

-- | Message pipes transform ByteStrings.
type MessagePipe = Pipe ByteString ByteString

-- | Creates a new 'MessagePipe' exclusively for encryption.
messageEncryptPipe :: Cipher c
                   => MVar (SendingCipherState c)
                   -> MessagePipe IO r
messageEncryptPipe csmv = forever $ do
  msg <- await

  encState <- lift $ takeMVar csmv
  let pt = Plaintext . bsToSB' $ msg
      (ct, encState') = encryptPayload pt encState
  lift $ putMVar csmv encState'

  yield ct

-- | Creates a new 'MessagePipe' exclusively for decryption.
messageDecryptPipe :: Cipher c
                   => MVar (ReceivingCipherState c)
                   -> MessagePipe IO r
messageDecryptPipe csmv = forever $ do
  msg <- await

  decState <- lift $ takeMVar csmv
  let (Plaintext pt, decState') = decryptPayload msg decState
  lift $ putMVar csmv decState'

  yield . sbToBS' $ pt
