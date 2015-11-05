{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.ByteString          (readFile, writeFile)
import Data.Traversable         (forM)
import Pipes.Network.TCP
import Prelude                  hiding (readFile, writeFile)
import System.Directory         (doesFileExist)
import System.Environment       (getArgs)

import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Types       (bsToSB', sbToBS')

import Handshakes

readKey :: FilePath -> IO (KeyPair Curve25519)
readKey f = fmap (curveBytesToPair . bsToSB') (readFile f)

genAndWriteKey :: FilePath -> IO (KeyPair Curve25519)
genAndWriteKey f = do
  pair@(sec, pub) <- curveGenKey
  writeFile f $ (sbToBS' . curveSecToBytes) sec
  writeFile (f `mappend` ".pub") $ (sbToBS' . curvePubToBytes) pub
  return pair

processKey :: FilePath -> IO (KeyPair Curve25519)
processKey f = do
  exists <- doesFileExist f
  if exists then
    readKey f
  else
    genAndWriteKey f

main :: IO ()
main = do
  [host, port, htStr] <- getArgs
  [is, rs, re] <- forM ["init_static", "resp_static", "resp_ephemeral"] processKey

  let keys = HandshakeKeys is rs re
      ht = case htStr of
        "NN" -> NoiseNN
        "KN" -> NoiseKN
        "NK" -> NoiseNK
        "KK" -> NoiseKK
        "NE" -> NoiseNE
        "KE" -> NoiseKE
        "NX" -> NoiseNX
        "KX" -> NoiseKX
        "XN" -> NoiseXN
        "IN" -> NoiseIN
        "XK" -> NoiseXK
        "IK" -> NoiseIK
        "XE" -> NoiseXE
        "IE" -> NoiseIE
        "XX" -> NoiseXX
        "IX" -> NoiseIX
        _    -> undefined

  connect host port $ \(s, _) -> do
    let clientSender = toSocket s
        clientReceiver = fromSocketTimeout 120000000 s 4096

    processHandshake keys (clientSender, clientReceiver) ht
