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
import Crypto.Noise.Descriptors
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
noiseNNIPipe hs csmv = twoMessageI hs csmv noiseNNI1 noiseNNI2

noiseNNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNNRPipe hs csmv = twoMessageR hs csmv noiseNNR1 noiseNNR2

noiseKNIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKNIPipe hs csmv = twoMessageI hs csmv noiseKNI1 noiseKNI2

noiseKNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKNRPipe hs csmv = twoMessageR hs csmv noiseKNR1 noiseKNR2

noiseNKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNKIPipe hs csmv = twoMessageI hs csmv noiseNKI1 noiseNKI2

noiseNKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNKRPipe hs csmv = twoMessageR hs csmv noiseNKR1 noiseNKR2

noiseKKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKKIPipe hs csmv = twoMessageI hs csmv noiseKKI1 noiseKKI2

noiseKKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKKRPipe hs csmv = twoMessageR hs csmv noiseKKR1 noiseKKR2

noiseNEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNEIPipe hs csmv = twoMessageI hs csmv noiseNEI1 noiseNEI2

noiseNERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNERPipe hs csmv = twoMessageR hs csmv noiseNER1 noiseNER2

noiseKEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKEIPipe hs csmv = twoMessageI hs csmv noiseKEI1 noiseKEI2

noiseKERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKERPipe hs csmv = twoMessageR hs csmv noiseKER1 noiseKER2

noiseNXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNXIPipe hs csmv = twoMessageI hs csmv noiseNXI1 noiseNXI2

noiseNXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNXRPipe hs csmv = twoMessageR hs csmv noiseNXR1 noiseNXR2

noiseKXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKXIPipe hs csmv = twoMessageI hs csmv noiseKXI1 noiseKXI2

noiseKXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKXRPipe hs csmv = twoMessageR hs csmv noiseKXR1 noiseKXR2

noiseXNIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXNIPipe hs csmv = threeMessageI hs csmv noiseXNI1 noiseXNI2 noiseXNI3

noiseXNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXNRPipe hs csmv = threeMessageR hs csmv noiseXNR1 noiseXNR2 noiseXNR3

noiseINIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseINIPipe hs csmv = twoMessageI hs csmv noiseINI1 noiseINI2

noiseINRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseINRPipe hs csmv = twoMessageR hs csmv noiseINR1 noiseINR2

noiseXKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXKIPipe hs csmv = threeMessageI hs csmv noiseXKI1 noiseXKI2 noiseXKI3

noiseXKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXKRPipe hs csmv = threeMessageR hs csmv noiseXKR1 noiseXKR2 noiseXKR3

noiseIKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIKIPipe hs csmv = twoMessageI hs csmv noiseIKI1 noiseIKI2

noiseIKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIKRPipe hs csmv = twoMessageR hs csmv noiseIKR1 noiseIKR2

noiseXEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXEIPipe hs csmv = threeMessageI hs csmv noiseXEI1 noiseXEI2 noiseXEI3

noiseXERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXERPipe hs csmv = threeMessageR hs csmv noiseXER1 noiseXER2 noiseXER3

noiseIEIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIEIPipe hs csmv = twoMessageI hs csmv noiseIEI1 noiseIEI2

noiseIERPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIERPipe hs csmv = twoMessageR hs csmv noiseIER1 noiseIER2

noiseXXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXXIPipe hs csmv = threeMessageI hs csmv noiseXXI1 noiseXXI2 noiseXXI3

noiseXXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXXRPipe hs csmv = threeMessageR hs csmv noiseXXR1 noiseXXR2 noiseXXR3

noiseIXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIXIPipe hs csmv = twoMessageI hs csmv noiseIXI1 noiseIXI2

noiseIXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseIXRPipe hs csmv = twoMessageR hs csmv noiseIXR1 noiseIXR2

noiseNIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNIPipe hs csmv = oneMessageI hs csmv noiseNI1

noiseNRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseNRPipe hs csmv = oneMessageR hs csmv noiseNR1

noiseKIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKIPipe hs csmv = oneMessageI hs csmv noiseKI1

noiseKRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseKRPipe hs csmv = oneMessageR hs csmv noiseKR1

noiseXIPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXIPipe hs csmv = oneMessageI hs csmv noiseXI1

noiseXRPipe :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> HandshakePipe IO ()
noiseXRPipe hs csmv = oneMessageR hs csmv noiseXR1

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
             -> DescriptorIO c d h ByteString
             -> HandshakePipe IO ()
oneMessageI hs csmv desc1 = do
  (msg1, cs1, _) <- lift $ writeHandshakeMsgFinal hs desc1 emptyPT
  yield msg1

  lift $ putMVar csmv (cs1, undefined)

oneMessageR :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> (ByteString -> Descriptor c d h ByteString)
             -> HandshakePipe IO ()
oneMessageR hs csmv desc1 = do
  msg1 <- await

  let (_, cs1, _) = readHandshakeMsgFinal hs msg1 desc1
  lift $ putMVar csmv (undefined, cs1)

twoMessageI :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> DescriptorIO c d h ByteString
             -> (ByteString -> Descriptor c d h ByteString)
             -> HandshakePipe IO ()
twoMessageI hs csmv desc1 desc2 = do
  (msg1, hs') <- lift $ writeHandshakeMsg hs desc1 emptyPT
  yield msg1

  msg2 <- await
  let (_, cs1, cs2) = readHandshakeMsgFinal hs' msg2 desc2
  lift $ putMVar csmv (cs1, cs2)

twoMessageR :: (Cipher c, Curve d, Hash h)
             => HandshakeState c d h
             -> MVar (CipherStatePair c)
             -> (ByteString -> Descriptor c d h ByteString)
             -> DescriptorIO c d h ByteString
             -> HandshakePipe IO ()
twoMessageR hs csmv desc1 desc2 = do
  msg1 <- await

  let (_, hs') = readHandshakeMsg hs msg1 desc1
  (msg2, cs1, cs2) <- lift $ writeHandshakeMsgFinal hs' desc2 emptyPT
  lift $ putMVar csmv (cs2, cs1)

  yield msg2

threeMessageI :: (Cipher c, Curve d, Hash h)
              => HandshakeState c d h
              -> MVar (CipherStatePair c)
              -> DescriptorIO c d h ByteString
              -> (ByteString -> Descriptor c d h ByteString)
              -> DescriptorIO c d h ByteString
              -> HandshakePipe IO ()
threeMessageI hs csmv desc1 desc2 desc3 = do
  (msg1, hs') <- lift $ writeHandshakeMsg hs desc1 emptyPT
  yield msg1

  msg2 <- await
  let (_, hs'') = readHandshakeMsg hs' msg2 desc2
  (msg3, cs1, cs2) <- lift $ writeHandshakeMsgFinal hs'' desc3 emptyPT
  lift $ putMVar csmv (cs1, cs2)

  yield msg3

threeMessageR :: (Cipher c, Curve d, Hash h)
              => HandshakeState c d h
              -> MVar (CipherStatePair c)
              -> (ByteString -> Descriptor c d h ByteString)
              -> DescriptorIO c d h ByteString
              -> (ByteString -> Descriptor c d h ByteString)
              -> HandshakePipe IO ()
threeMessageR hs csmv desc1 desc2 desc3 = do
  msg1 <- await

  let (_, hs') = readHandshakeMsg hs msg1 desc1
  (msg2, hs'') <- lift $ writeHandshakeMsg hs' desc2 emptyPT
  yield msg2

  msg3 <- await
  let (_, cs1, cs2) = readHandshakeMsgFinal hs'' msg3 desc3
  lift $ putMVar csmv (cs2, cs1)
