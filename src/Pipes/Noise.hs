{-# LANGUAGE OverloadedStrings #-}
----------------------------------------------------------------
-- |
-- Module      : Pipes.Noise
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Pipes.Noise
  ( -- * Types
    CipherStatePair,
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
import Crypto.Noise.Types      (Plaintext(..), bsToSB', sbToBS')

type CipherStatePair c = (SendingCipherState c, ReceivingCipherState c)
type MessagePipe       = Pipe ByteString ByteString

messageEncryptPipe :: Cipher c
                   => MVar (CipherStatePair c)
                   -> MessagePipe IO r
messageEncryptPipe csmv = forever $ do
  msg <- await

  (encState, unused) <- lift $ takeMVar csmv
  let pt = Plaintext . bsToSB' $ msg
      (ct, encState') = encryptPayload pt encState
  lift $ putMVar csmv (encState', unused)

  yield ct

messageDecryptPipe :: Cipher c
                   => MVar (CipherStatePair c)
                   -> MessagePipe IO r
messageDecryptPipe csmv = forever $ do
  msg <- await

  (unused, decState) <- lift $ takeMVar csmv
  let (Plaintext pt, decState') = decryptPayload msg decState
  lift $ putMVar csmv (unused, decState')

  yield . sbToBS' $ pt
