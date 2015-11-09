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
    HandshakePipe,
    MessagePipe,
    -- * Pipes
    -- ** Noise_NN
    noiseNNIPipe,
    noiseNNRPipe,
    -- ** Noise_KN
    noiseKNIPipe,
    noiseKNRPipe,
    -- ** Noise_NK
    noiseNKIPipe,
    noiseNKRPipe,
    -- ** Noise_KK
    noiseKKIPipe,
    noiseKKRPipe,
    -- ** Noise_NE
    noiseNEIPipe,
    noiseNERPipe,
    -- ** Noise_KE
    noiseKEIPipe,
    noiseKERPipe,
    -- ** Noise_NX
    noiseNXIPipe,
    noiseNXRPipe,
    -- ** Noise_KX
    noiseKXIPipe,
    noiseKXRPipe,
    -- ** Noise_XN
    noiseXNIPipe,
    noiseXNRPipe,
    -- ** Noise_IN
    noiseINIPipe,
    noiseINRPipe,
    -- ** Noise_XK
    noiseXKIPipe,
    noiseXKRPipe,
    -- ** Noise_IK
    noiseIKIPipe,
    noiseIKRPipe,
    -- ** Noise_XE
    noiseXEIPipe,
    noiseXERPipe,
    -- ** Noise_IE
    noiseIEIPipe,
    noiseIERPipe,
    -- ** Noise_XX
    noiseXXIPipe,
    noiseXXRPipe,
    -- ** Noise_IX
    noiseIXIPipe,
    noiseIXRPipe,
    -- ** Noise_N
    noiseNIPipe,
    noiseNRPipe,
    -- ** Noise_K
    noiseKIPipe,
    noiseKRPipe,
    -- ** Noise_X
    noiseXIPipe,
    noiseXRPipe,
    -- ** Message pipes
    messageEncryptPipe,
    messageDecryptPipe
  ) where

import Control.Concurrent.MVar (MVar, putMVar, takeMVar)
import Control.Monad           (forever)
import Data.ByteString         (ByteString)
import Pipes                   (Pipe, await, yield, lift)

import Crypto.Noise.Cipher     (Plaintext(..), Cipher)
import Crypto.Noise.Curve      (Curve)
import Crypto.Noise.Hash       (Hash)
import Crypto.Noise.Handshake
import Crypto.Noise.Types      (bsToSB', sbToBS')

type CipherStatePair c = (CipherState c, CipherState c)
type HandshakePipe     = Pipe ByteString ByteString
type MessagePipe       = Pipe ByteString ByteString

emptyPT :: Plaintext
emptyPT = Plaintext . bsToSB' $ ""

noiseNNIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNNIPipe = twoMessageI

noiseNNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNNRPipe = twoMessageR

noiseKNIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKNIPipe = twoMessageI

noiseKNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKNRPipe = twoMessageR

noiseNKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNKIPipe = twoMessageI

noiseNKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNKRPipe = twoMessageR

noiseKKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKKIPipe = twoMessageI

noiseKKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKKRPipe = twoMessageR

noiseNEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNEIPipe = twoMessageI

noiseNERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNERPipe = twoMessageR

noiseKEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKEIPipe = twoMessageI

noiseKERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKERPipe = twoMessageR

noiseNXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNXIPipe = twoMessageI

noiseNXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNXRPipe = twoMessageR

noiseKXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKXIPipe = twoMessageI

noiseKXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKXRPipe = twoMessageR

noiseXNIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXNIPipe = threeMessageI

noiseXNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXNRPipe = threeMessageR

noiseINIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseINIPipe = twoMessageI

noiseINRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseINRPipe = twoMessageR

noiseXKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXKIPipe = threeMessageI

noiseXKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXKRPipe = threeMessageR

noiseIKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIKIPipe = twoMessageI

noiseIKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIKRPipe = twoMessageR

noiseXEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXEIPipe = threeMessageI

noiseXERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXERPipe = threeMessageR

noiseIEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIEIPipe = twoMessageI

noiseIERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIERPipe = twoMessageR

noiseXXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXXIPipe = threeMessageI

noiseXXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXXRPipe = threeMessageR

noiseIXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIXIPipe = twoMessageI

noiseIXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIXRPipe = twoMessageR

noiseNIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNIPipe = oneMessageI

noiseNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNRPipe = oneMessageR

noiseKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKIPipe = oneMessageI

noiseKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKRPipe = oneMessageR

noiseXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXIPipe = oneMessageI

noiseXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXRPipe = oneMessageR

messageEncryptPipe :: Cipher c
            => MVar (CipherStatePair c)
            -> MessagePipe IO ()
messageEncryptPipe csmv = forever $ do
  msg <- await

  (encState, unused) <- lift $ takeMVar csmv
  let pt = Plaintext . bsToSB' $ msg
      (ct, encState') = encryptPayload pt encState
  lift $ putMVar csmv (encState', unused)

  yield ct

messageDecryptPipe :: Cipher c
            => MVar (CipherStatePair c)
            -> MessagePipe IO ()
messageDecryptPipe csmv = forever $ do
  msg <- await

  (unused, decState) <- lift $ takeMVar csmv
  let (Plaintext pt, decState') = decryptPayload msg decState
  lift $ putMVar csmv (unused, decState')

  yield . sbToBS' $ pt

oneMessageI :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
oneMessageI hs csmv = do
  (msg1, cs1, _) <- lift $ writeMessageFinal hs emptyPT
  yield msg1

  lift $ putMVar csmv (cs1, undefined)

oneMessageR :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
oneMessageR hs csmv = do
  msg1 <- await

  let (_, cs1, _) = readMessageFinal hs msg1
  lift $ putMVar csmv (undefined, cs1)

twoMessageI :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
twoMessageI hs csmv = do
  (msg1, hs') <- lift $ writeMessage hs emptyPT
  yield msg1

  msg2 <- await
  let (_, cs1, cs2) = readMessageFinal hs' msg2
  lift $ putMVar csmv (cs1, cs2)

twoMessageR :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
twoMessageR hs csmv = do
  msg1 <- await

  let (_, hs') = readMessage hs msg1
  (msg2, cs1, cs2) <- lift $ writeMessageFinal hs' emptyPT
  lift $ putMVar csmv (cs2, cs1)

  yield msg2

threeMessageI :: (Cipher c, Curve d, Hash h)
              => HandshakeState c d h
              -> MVar (CipherStatePair c)
              -> HandshakePipe IO ()
threeMessageI hs csmv = do
  (msg1, hs') <- lift $ writeMessage hs emptyPT
  yield msg1

  msg2 <- await
  let (_, hs'') = readMessage hs' msg2
  (msg3, cs1, cs2) <- lift $ writeMessageFinal hs'' emptyPT
  lift $ putMVar csmv (cs1, cs2)

  yield msg3

threeMessageR :: (Cipher c, Curve d, Hash h)
              => HandshakeState c d h
              -> MVar (CipherStatePair c)
              -> HandshakePipe IO ()
threeMessageR hs csmv = do
  msg1 <- await

  let (_, hs') = readMessage hs msg1
  (msg2, hs'') <- lift $ writeMessage hs' emptyPT
  yield msg2

  msg3 <- await
  let (_, cs1, cs2) = readMessageFinal hs'' msg3
  lift $ putMVar csmv (cs2, cs1)
