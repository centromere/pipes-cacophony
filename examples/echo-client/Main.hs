{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.ByteString          (readFile, writeFile)
import Data.ByteString.Char8    (pack)
import Data.Traversable         (forM)
import Pipes.Network.TCP
import Prelude                  hiding (readFile, writeFile)
import System.Directory         (doesFileExist)
import System.Environment       (getArgs)

import Crypto.Noise.Cipher      (Plaintext(..))
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Types       (bsToSB', sbToBS')

import Handshakes

readPrivateKey :: FilePath -> IO (KeyPair Curve25519)
readPrivateKey f = fmap (curveBytesToPair . bsToSB') (readFile f)

readPublicKey :: FilePath -> IO (PublicKey Curve25519)
readPublicKey f = fmap (curveBytesToPub . bsToSB') (readFile f)

genAndWriteKey :: FilePath -> IO (KeyPair Curve25519)
genAndWriteKey f = do
  pair@(sec, pub) <- curveGenKey
  writeFile f $ (sbToBS' . curveSecToBytes) sec
  writeFile (f `mappend` ".pub") $ (sbToBS' . curvePubToBytes) pub
  return pair

processPrivateKey :: FilePath -> IO (KeyPair Curve25519)
processPrivateKey f = do
  exists <- doesFileExist f
  if exists then
    readPrivateKey f
  else
    genAndWriteKey f

main :: IO ()
main = do
  [host, port, htStr, preshared] <- getArgs

  is <- processPrivateKey "init_static"
  [rs, re] <- forM ["resp_static.pub", "resp_ephemeral.pub"] readPublicKey

  let preshared' = if not (null preshared) then
                     Just . Plaintext . bsToSB' . pack $ preshared
                   else
                     Nothing
      keys = HandshakeKeys preshared' is rs re
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
