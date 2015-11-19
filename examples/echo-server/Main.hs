{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.AutoUpdate       (mkAutoUpdate, defaultUpdateSettings, updateAction)
import Control.Exception        (SomeException, displayException, handle)
import Data.Aeson               (encode, object, (.=))
import Data.ByteString          (ByteString, readFile, writeFile)
import Data.ByteString.Char8    (pack, unpack)
import Data.ByteString.Lazy.Char8 (append)
import Data.Traversable         (forM)
import Data.UnixTime            (formatUnixTime, fromEpochTime)
import Pipes.Network.TCP
import Prelude                  hiding (readFile, writeFile)
import System.Directory         (doesFileExist)
import System.Environment       (getArgs)
import System.Log.FastLogger    (toLogStr, pushLogStr, LoggerSet, newFileLoggerSet)
import System.Posix             (epochTime)
import System.Posix.Files       (setFileCreationMask)

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
  [port, preshared] <- getArgs
  [rs, re] <- forM ["resp_static", "resp_ephemeral"] processPrivateKey
  is <- readPublicKey "init_static.pub"

  logHandle <- openLog "debug.log"
  au <- mkAutoUpdate defaultUpdateSettings { updateAction = getDateTime }
  let exLogger   = logException logHandle au
      preshared' = if not (null preshared) then
                     Just . Plaintext . bsToSB' . pack $ preshared
                   else
                     Nothing
      keys       = HandshakeKeys preshared' is rs re

  serve HostAny port $ \(s, ip) -> do
    let clientReceiver = fromSocketTimeout 120000000 s 4096
        clientSender   = toSocket s

    logMsg logHandle au ip "connection established"
    handle (exLogger ip) $ processHandshake
                           keys
                           (clientReceiver, clientSender)
                           (logMsg logHandle au ip)
    logMsg logHandle au ip "connection closed"

openLog :: FilePath -> IO LoggerSet
openLog file = do
  _ <- setFileCreationMask 0o000
  newFileLoggerSet 1 file

logMsg :: LoggerSet
       -> IO ByteString
       -> SockAddr
       -> ByteString
       -> IO ()
logMsg ls getCachedDate ip msg = do
  zdt <- getCachedDate
  (pushLogStr ls . toLogStr) . (`append` "\n") . encode $
    object [ "date"    .= unpack zdt
           , "message" .= unpack msg
           , "ip"      .= show ip
           ]

logException :: LoggerSet
             -> IO ByteString
             -> SockAddr
             -> SomeException
             -> IO ()
logException ls getCachedDate ip ex = do
  zdt <- getCachedDate
  (pushLogStr ls . toLogStr) . (`append` "\n") . encode $
    object [ "date"      .= unpack zdt
           , "exception" .= displayException ex
           , "ip"        .= show ip
           ]

getDateTime :: IO ByteString
getDateTime = epochTime >>= formatUnixTime "%Y-%m-%d %H:%M:%S %z" . fromEpochTime
