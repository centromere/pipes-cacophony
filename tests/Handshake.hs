{-# LANGUAGE OverloadedStrings, RankNTypes #-}
module Handshake where

import Imports
import Instances()
import HandshakeStates

import Control.Concurrent.Async (concurrently)
import Control.Concurrent.MVar  (MVar, newEmptyMVar, takeMVar,
                                 putMVar, newMVar)
import Control.Monad            (forever)
import Data.ByteString          (ByteString)

import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Types

import Pipes hiding (Proxy)
import Pipes.Noise

is :: KeyPair Curve25519
is = curveBytesToPair . bsToSB' $ "I\f\232\218A\210\230\147\FS\222\167\v}l\243!\168.\ESC\t\SYN\"\169\179A`\DC28\211\169tC"

rs :: KeyPair Curve25519
rs = curveBytesToPair . bsToSB' $ "\ETB\157\&7\DC2\252\NUL\148\172\148\133\218\207\&8\221y\144\209\168FX\224Ser_\178|\153.\FSg&"

re :: KeyPair Curve25519
re = curveBytesToPair . bsToSB' $ "<\231\151\151\180\217\146\DLEI}\160N\163iKc\162\210Y\168R\213\206&gm\169r\SUB[\\'"

handshakeKeys :: HandshakeKeys
handshakeKeys = HandshakeKeys is rs re

data HandshakeType = NoiseNN
                   | NoiseKN
                   | NoiseNK
                   | NoiseKK
                   | NoiseNE
                   | NoiseKE
                   | NoiseNX
                   | NoiseKX
                   | NoiseXN
                   | NoiseIN
                   | NoiseXK
                   | NoiseIK
                   | NoiseXE
                   | NoiseIE
                   | NoiseXX
                   | NoiseIX
                   | NoiseN
                   | NoiseK
                   | NoiseX
                   deriving (Eq)

mkHandshakePipe :: HandshakeType
                -> HandshakeKeys
                -> MVar (CipherStatePair ChaChaPoly1305)
                -> MVar (CipherStatePair ChaChaPoly1305)
                -> (HandshakePipe IO (), HandshakePipe IO ())
mkHandshakePipe ht hks csmv1 csmv2 =
  case ht of
    NoiseNN -> (noiseNNIPipe noiseNNIHS csmv1,
                noiseNNRPipe noiseNNRHS csmv2)
    NoiseKN -> (noiseKNIPipe (noiseKNIHS hks) csmv1,
                noiseKNRPipe (noiseKNRHS hks) csmv2)
    NoiseNK -> (noiseNKIPipe (noiseNKIHS hks) csmv1,
                noiseNKRPipe (noiseNKRHS hks) csmv2)
    NoiseKK -> (noiseKKIPipe (noiseKKIHS hks) csmv1,
                noiseKKRPipe (noiseKKRHS hks) csmv2)
    NoiseNE -> (noiseNEIPipe (noiseNEIHS hks) csmv1,
                noiseNERPipe (noiseNERHS hks) csmv2)
    NoiseKE -> (noiseKEIPipe (noiseKEIHS hks) csmv1,
                noiseKERPipe (noiseKERHS hks) csmv2)
    NoiseNX -> (noiseNXIPipe (noiseNXIHS hks) csmv1,
                noiseNXRPipe (noiseNXRHS hks) csmv2)
    NoiseKX -> (noiseKXIPipe (noiseKXIHS hks) csmv1,
                noiseKXRPipe (noiseKXRHS hks) csmv2)
    NoiseXN -> (noiseXNIPipe (noiseXNIHS hks) csmv1,
                noiseXNRPipe (noiseXNRHS hks) csmv2)
    NoiseIN -> (noiseINIPipe (noiseINIHS hks) csmv1,
                noiseINRPipe (noiseINRHS hks) csmv2)
    NoiseXK -> (noiseXKIPipe (noiseXKIHS hks) csmv1,
                noiseXKRPipe (noiseXKRHS hks) csmv2)
    NoiseIK -> (noiseIKIPipe (noiseIKIHS hks) csmv1,
                noiseIKRPipe (noiseIKRHS hks) csmv2)
    NoiseXE -> (noiseXEIPipe (noiseXEIHS hks) csmv1,
                noiseXERPipe (noiseXERHS hks) csmv2)
    NoiseIE -> (noiseIEIPipe (noiseIEIHS hks) csmv1,
                noiseIERPipe (noiseIERHS hks) csmv2)
    NoiseXX -> (noiseXXIPipe (noiseXXIHS hks) csmv1,
                noiseXXRPipe (noiseXXRHS hks) csmv2)
    NoiseIX -> (noiseIXIPipe (noiseIXIHS hks) csmv1,
                noiseIXRPipe (noiseIXRHS hks) csmv2)
    NoiseN  -> (noiseNIPipe  (noiseNIHS  hks) csmv1,
                noiseNRPipe  (noiseNRHS  hks) csmv2)
    NoiseK  -> (noiseKIPipe  (noiseKIHS  hks) csmv1,
                noiseKRPipe  (noiseKRHS  hks) csmv2)
    NoiseX  -> (noiseXIPipe  (noiseXIHS  hks) csmv1,
                noiseXRPipe  (noiseXRHS  hks) csmv2)

aggregator :: MVar [ByteString]
           -> Consumer' ByteString IO ()
aggregator mv = forever $ do
  bs <- await
  l <- lift $ takeMVar mv
  lift $ putMVar mv (bs : l)

mVarProducer :: MVar ByteString
             -> Producer' ByteString IO ()
mVarProducer mv = forever $ do
  x <- lift $ takeMVar mv
  yield x

mVarConsumer :: MVar ByteString
             -> Consumer' ByteString IO ()
mVarConsumer mv = forever $ do
  x <- await
  lift $ putMVar mv x

runPipe :: HandshakeType -> Property
runPipe ht = ioProperty $ do
  resultsmv <- newMVar []
  msgmv1    <- newEmptyMVar
  msgmv2    <- newEmptyMVar
  csmv1     <- newEmptyMVar
  csmv2     <- newEmptyMVar

  let (initPipe, respPipe) = mkHandshakePipe ht handshakeKeys csmv1 csmv2

  _ <- concurrently (runEffect (mVarProducer msgmv1 >-> initPipe >-> mVarConsumer msgmv2))
                    (runEffect (mVarProducer msgmv2 >-> respPipe >-> mVarConsumer msgmv1))

  testData <- generate . listOf1 $ arbitrary

  if ht == NoiseN || ht == NoiseK || ht == NoiseX then
    runEffect $
      each testData
      >-> messageEncryptPipe csmv1
      >-> messageDecryptPipe csmv2
      >-> aggregator resultsmv
  else
    runEffect $
      each testData
      >-> messageEncryptPipe csmv1
      >-> messageDecryptPipe csmv2
      >-> messageEncryptPipe csmv2
      >-> messageDecryptPipe csmv1
      >-> aggregator resultsmv

  results <- takeMVar resultsmv
  return $ reverse results === testData

tests :: TestTree
tests = testGroup "Handshakes"
  [ testProperty "Noise_NN" . property . runPipe $ NoiseNN
  , testProperty "Noise_KN" . property . runPipe $ NoiseKN
  , testProperty "Noise_NK" . property . runPipe $ NoiseNK
  , testProperty "Noise_KK" . property . runPipe $ NoiseKK
  , testProperty "Noise_NE" . property . runPipe $ NoiseNE
  , testProperty "Noise_KE" . property . runPipe $ NoiseKE
  , testProperty "Noise_NX" . property . runPipe $ NoiseNX
  , testProperty "Noise_KX" . property . runPipe $ NoiseKX
  , testProperty "Noise_XN" . property . runPipe $ NoiseXN
  , testProperty "Noise_IN" . property . runPipe $ NoiseIN
  , testProperty "Noise_XK" . property . runPipe $ NoiseXK
  , testProperty "Noise_IK" . property . runPipe $ NoiseIK
  , testProperty "Noise_XE" . property . runPipe $ NoiseXE
  , testProperty "Noise_IE" . property . runPipe $ NoiseIE
  , testProperty "Noise_XX" . property . runPipe $ NoiseXX
  , testProperty "Noise_IX" . property . runPipe $ NoiseIX
  , testProperty "Noise_N"  . property . runPipe $ NoiseN
  , testProperty "Noise_K"  . property . runPipe $ NoiseK
  , testProperty "Noise_X"  . property . runPipe $ NoiseX
  ]
