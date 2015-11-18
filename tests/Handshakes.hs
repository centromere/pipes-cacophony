{-# LANGUAGE OverloadedStrings, RankNTypes #-}
module Handshakes where

import Control.Concurrent.Async (concurrently)
import Control.Concurrent.MVar  (MVar, newEmptyMVar, takeMVar,
                                 putMVar, newMVar)
import Control.Monad            (forever)
import Data.ByteString          (ByteString)

import Crypto.Noise.Cipher.ChaChaPoly1305

import Pipes hiding (Proxy)
import Pipes.Noise

import HandshakeStates
import Imports
import Instances()

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
                -> MVar (CipherStatePair ChaChaPoly1305)
                -> MVar (CipherStatePair ChaChaPoly1305)
                -> (HandshakePipe IO (), HandshakePipe IO ())
mkHandshakePipe ht csmv1 csmv2 =
  case ht of
    NoiseNN -> (noiseNNIPipe noiseNNIHS csmv1,
                noiseNNRPipe noiseNNRHS csmv2)
    NoiseKN -> (noiseKNIPipe noiseKNIHS csmv1,
                noiseKNRPipe noiseKNRHS csmv2)
    NoiseNK -> (noiseNKIPipe noiseNKIHS csmv1,
                noiseNKRPipe noiseNKRHS csmv2)
    NoiseKK -> (noiseKKIPipe noiseKKIHS csmv1,
                noiseKKRPipe noiseKKRHS csmv2)
    NoiseNE -> (noiseNEIPipe noiseNEIHS csmv1,
                noiseNERPipe noiseNERHS csmv2)
    NoiseKE -> (noiseKEIPipe noiseKEIHS csmv1,
                noiseKERPipe noiseKERHS csmv2)
    NoiseNX -> (noiseNXIPipe noiseNXIHS csmv1,
                noiseNXRPipe noiseNXRHS csmv2)
    NoiseKX -> (noiseKXIPipe noiseKXIHS csmv1,
                noiseKXRPipe noiseKXRHS csmv2)
    NoiseXN -> (noiseXNIPipe noiseXNIHS csmv1,
                noiseXNRPipe noiseXNRHS csmv2)
    NoiseIN -> (noiseINIPipe noiseINIHS csmv1,
                noiseINRPipe noiseINRHS csmv2)
    NoiseXK -> (noiseXKIPipe noiseXKIHS csmv1,
                noiseXKRPipe noiseXKRHS csmv2)
    NoiseIK -> (noiseIKIPipe noiseIKIHS csmv1,
                noiseIKRPipe noiseIKRHS csmv2)
    NoiseXE -> (noiseXEIPipe noiseXEIHS csmv1,
                noiseXERPipe noiseXERHS csmv2)
    NoiseIE -> (noiseIEIPipe noiseIEIHS csmv1,
                noiseIERPipe noiseIERHS csmv2)
    NoiseXX -> (noiseXXIPipe noiseXXIHS csmv1,
                noiseXXRPipe noiseXXRHS csmv2)
    NoiseIX -> (noiseIXIPipe noiseIXIHS csmv1,
                noiseIXRPipe noiseIXRHS csmv2)
    NoiseN  -> (noiseNIPipe  noiseNIHS  csmv1,
                noiseNRPipe  noiseNRHS  csmv2)
    NoiseK  -> (noiseKIPipe  noiseKIHS  csmv1,
                noiseKRPipe  noiseKRHS  csmv2)
    NoiseX  -> (noiseXIPipe  noiseXIHS  csmv1,
                noiseXRPipe  noiseXRHS  csmv2)

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

  let (initPipe, respPipe) = mkHandshakePipe ht csmv1 csmv2

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
